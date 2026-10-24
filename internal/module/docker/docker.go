package docker

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"NexHomeGo/internal/core"
	"NexHomeGo/internal/web"
)

// Docker 容器观测服务：容器列表（实时内存/CPU/磁盘/IP/端口/Compose 归属）、
// 容器详情、Compose 项目与编排脚本读取、整体概况，以及容器起停/日志/清理等写操作。
// stats 单次采样耗时 1~2 秒，按需在请求线程内并行拉取，不注册任何周期性轮询任务。
// 路径、方法、响应结构逐一复刻 Java DockerService，前端零改动。

// idRe 容器 id / 名称合法性校验（拼入 Daemon 请求行，防注入）。
var idRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

var client = newDockerClient()

// loggedConnected 首次连接成功仅记录一次日志。
var loggedConnected = false

// RegisterRoutes 注册 Docker 接口（由主程序在 Web 启动前调用）。
func RegisterRoutes() {
	web.Route("GET", "/api/docker/overview", func(c *web.Ctx) error {
		c.Ok(overview())
		return nil
	})
	web.Route("GET", "/api/docker/containers", func(c *web.Ctx) error {
		list, err := containers("1" == c.Query("stats"))
		if err != nil {
			return err
		}
		c.Ok(list)
		return nil
	})
	web.Route("GET", "/api/docker/containers/{id}", func(c *web.Ctx) error {
		id, err := checkId(c.Param("id"))
		if err != nil {
			return err
		}
		row, err := detail(id)
		if err != nil {
			return err
		}
		c.Ok(row)
		return nil
	})
	web.Route("GET", "/api/docker/compose", func(c *web.Ctx) error {
		list, err := compose()
		if err != nil {
			return err
		}
		c.Ok(list)
		return nil
	})
	web.Route("GET", "/api/docker/compose/file", func(c *web.Ctx) error {
		row, err := composeFile(c.Query("project"))
		if err != nil {
			return err
		}
		c.Ok(row)
		return nil
	})
	// ---------- 写操作（容器起停/重启、日志、清理）：宿主特权操作，谨慎使用 ----------
	web.Route("POST", "/api/docker/containers/{id}/start", func(c *web.Ctx) error {
		id, err := checkId(c.Param("id"))
		if err != nil {
			return err
		}
		if _, err := client.post("/containers/" + id + "/start"); err != nil {
			return err
		}
		core.LogInfo(core.LogDocker, "启动容器: "+id)
		c.Ok("容器已启动")
		return nil
	})
	web.Route("POST", "/api/docker/containers/{id}/stop", func(c *web.Ctx) error {
		id, err := checkId(c.Param("id"))
		if err != nil {
			return err
		}
		if _, err := client.post("/containers/" + id + "/stop?t=10"); err != nil {
			return err
		}
		core.LogInfo(core.LogDocker, "停止容器: "+id)
		c.Ok("容器已停止")
		return nil
	})
	web.Route("POST", "/api/docker/containers/{id}/restart", func(c *web.Ctx) error {
		id, err := checkId(c.Param("id"))
		if err != nil {
			return err
		}
		if _, err := client.post("/containers/" + id + "/restart?t=10"); err != nil {
			return err
		}
		core.LogInfo(core.LogDocker, "重启容器: "+id)
		c.Ok("容器已重启")
		return nil
	})
	web.Route("GET", "/api/docker/containers/{id}/logs", func(c *web.Ctx) error {
		id, err := checkId(c.Param("id"))
		if err != nil {
			return err
		}
		tail := 200
		if q := strings.TrimSpace(c.Query("tail")); q != "" {
			if n, e := strconv.Atoi(q); e == nil {
				tail = n
				if tail < 1 {
					tail = 1
				}
				if tail > 5000 {
					tail = 5000
				}
			}
		}
		logs, err := client.logs("/containers/" + id + "/logs?stdout=1&stderr=1&tail=" + strconv.Itoa(tail))
		if err != nil {
			return err
		}
		c.Ok(core.NewRow().Set("tail", tail).Set("logs", logs))
		return nil
	})
	web.Route("GET", "/api/docker/prune/preview", func(c *web.Ctx) error {
		list, err := danglingImages()
		if err != nil {
			return err
		}
		c.Ok(list)
		return nil
	})
	web.Route("POST", "/api/docker/prune", func(c *web.Ctx) error {
		row, err := prune(c.Body())
		if err != nil {
			return err
		}
		c.Ok(row)
		return nil
	})
}

// DashboardSummary 仪表盘专用轻量概览：仅取连接状态与容器计数（注入 web.DockerSummaryProvider）。
func DashboardSummary() *core.Row {
	r := core.NewRow()
	text, err := client.get("/info")
	if err != nil {
		r.Set("connected", false)
		return r
	}
	i, err := parseJSON(text)
	if err != nil {
		r.Set("connected", false)
		return r
	}
	r.Set("connected", true)
	r.Set("containers", i.long("Containers"))
	r.Set("running", i.long("ContainersRunning"))
	r.Set("stopped", i.long("ContainersStopped"))
	r.Set("images", i.long("Images"))
	return r
}

// ---------- 数据组装 ----------

// overview Docker 整体概况：连接状态 + 版本 + 容器/镜像统计 + 磁盘占用。
func overview() *core.Row {
	r := core.NewRow()
	r.Set("host", client.describe)
	text, err := client.get("/version")
	if err != nil {
		r.Set("connected", false)
		r.Set("error", friendly(err))
		return r
	}
	v, err := parseJSON(text)
	if err != nil {
		r.Set("connected", false)
		r.Set("error", friendly(err))
		return r
	}
	r.Set("connected", true)
	r.Set("version", core.NewRow().
		Set("version", v.str("Version")).
		Set("apiVersion", v.str("ApiVersion")).
		Set("os", v.str("Os")).
		Set("arch", v.str("Arch")))
	if !loggedConnected {
		loggedConnected = true
		core.LogInfo(core.LogDocker, "Docker 已连接: "+client.describe+" (v"+v.str("Version")+")")
	}
	if text, err := client.get("/info"); err == nil {
		if i, e := parseJSON(text); e == nil {
			r.Set("info", core.NewRow().
				Set("containers", i.long("Containers")).
				Set("running", i.long("ContainersRunning")).
				Set("paused", i.long("ContainersPaused")).
				Set("stopped", i.long("ContainersStopped")).
				Set("images", i.long("Images")).
				Set("memTotal", i.long("MemTotal")).
				Set("os", i.str("OperatingSystem")).
				Set("kernel", i.str("KernelVersion")))
		}
	}
	if text, err := client.get("/system/df"); err == nil {
		if d, e := parseJSON(text); e == nil {
			df := core.NewRow()
			images := d.arr("Images")
			var imgSize int64
			for _, el := range images {
				imgSize += asObj(el).long("Size")
			}
			df.Set("imagesCount", len(images))
			df.Set("imagesSize", imgSize)
			containersArr := d.arr("Containers")
			var cSize int64
			for _, el := range containersArr {
				cSize += asObj(el).long("SizeRootFs")
			}
			df.Set("containersSize", cSize)
			volumes := d.arr("Volumes")
			var vSize int64
			for _, el := range volumes {
				vSize += asObj(el).obj("UsageData").long("Size")
			}
			df.Set("volumesCount", len(volumes))
			df.Set("volumesSize", vSize)
			r.Set("df", df)
		}
	}
	return r
}

// containers 容器列表：all=1 全量 + size=1 磁盘占用；withStats 时并行补充实时内存/CPU。
func containers(withStats bool) ([]*core.Row, error) {
	text, err := client.get("/containers/json?all=1&size=1")
	if err != nil {
		return nil, err
	}
	arr, err := parseJSONArray(text)
	if err != nil {
		return nil, err
	}
	list := make([]*core.Row, 0, len(arr))
	for _, el := range arr {
		list = append(list, brief(asObj(el)))
	}
	if withStats {
		fetchStats(list)
	}
	sort.SliceStable(list, func(i, j int) bool {
		return list[i].Get("created").(int64) > list[j].Get("created").(int64)
	})
	return list, nil
}

// brief 列表项精简组装：名称/镜像/状态/IP/端口/磁盘/Compose 归属。
func brief(c *jobj) *core.Row {
	o := core.NewRow()
	id := c.str("Id")
	o.Set("id", id)
	short := id
	if len(short) > 12 {
		short = short[:12]
	}
	o.Set("shortId", short)
	names := c.arr("Names")
	name := ""
	if len(names) > 0 {
		name = asStr(names[0])
	}
	o.Set("name", strings.TrimPrefix(name, "/"))
	o.Set("image", c.str("Image"))
	o.Set("command", c.str("Command"))
	o.Set("state", c.str("State"))
	o.Set("status", c.str("Status"))
	o.Set("created", c.long("Created"))

	labels := c.obj("Labels")
	o.Set("composeProject", labels.str("com.docker.compose.project"))
	o.Set("composeService", labels.str("com.docker.compose.service"))

	// 容器内 IP：NetworkSettings.Networks 取第一个有地址的网络（通常为主网络）
	ip, network := "", ""
	nets := c.obj("NetworkSettings").obj("Networks")
	for _, k := range nets.keys {
		if a := nets.obj(k).str("IPAddress"); a != "" {
			ip = a
			network = k
			break
		}
	}
	o.Set("ip", ip)
	o.Set("network", network)

	// 暴露端口：PublicPort 存在表示已映射到宿主机
	ports := core.NewRowList()
	for _, el := range c.arr("Ports") {
		p := asObj(el)
		np := core.NewRow()
		np.Set("privatePort", p.long("PrivatePort"))
		if p.hasNonNull("PublicPort") {
			np.Set("publicPort", p.long("PublicPort"))
			np.Set("ip", p.str("IP"))
		}
		np.Set("type", p.str("Type"))
		ports.Append(np)
	}
	o.Set("ports", ports)

	// 磁盘占用：SizeRw=可写层，SizeRootFs=含镜像层的总占用
	o.Set("sizeRw", c.long("SizeRw"))
	o.Set("sizeRootFs", c.long("SizeRootFs"))
	return o
}

// fetchStats 并行拉取运行中容器的实时 stats（互不占用共享调度池）。
func fetchStats(containers []*core.Row) {
	byID := map[string]*core.Row{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, c := range containers {
		if str(c.Get("state")) != "running" {
			continue
		}
		id := str(c.Get("id"))
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			if s := stats(id); s != nil {
				mu.Lock()
				byID[str(s.Get("id"))] = s
				mu.Unlock()
			}
		}(id)
	}
	wg.Wait()
	for _, c := range containers {
		if s, ok := byID[str(c.Get("id"))]; ok {
			for _, k := range []string{"memUsed", "memLimit", "cpuPercent", "netRx", "netTx", "pids"} {
				if s.Has(k) {
					c.Set(k, s.Get(k))
				}
			}
		}
	}
}

// stats 单容器实时资源（内存/CPU/网络/进程数），失败返回 nil。
func stats(id string) *core.Row {
	text, err := client.get("/containers/" + id + "/stats?stream=false")
	if err != nil {
		return nil
	}
	s, err := parseJSON(text)
	if err != nil {
		return nil
	}
	o := core.NewRow()
	o.Set("id", id)

	// 内存：usage 需扣除缓存页（cgroup v1: stats.cache / total_inactive_file，v2: inactive_file）
	m := s.obj("memory_stats")
	ms := m.obj("stats")
	usage := m.long("usage")
	cache := max64(max64(ms.long("inactive_file"), ms.long("total_inactive_file")), ms.long("cache"))
	var memUsed int64 = usage - cache
	if memUsed < 0 {
		memUsed = 0
	}
	o.Set("memUsed", memUsed)
	o.Set("memLimit", m.long("limit"))

	// CPU：与 precpu 采样差值折算百分比
	cs := s.obj("cpu_stats")
	ps2 := s.obj("precpu_stats")
	cpuPercent := 0.0
	online := int64(0)
	cu := cs.obj("cpu_usage")
	cpuTotal := cu.long("total_usage")
	sysTotal := cs.long("system_cpu_usage")
	preCpu := ps2.obj("cpu_usage").long("total_usage")
	preSys := ps2.long("system_cpu_usage")
	cpuDelta := cpuTotal - preCpu
	sysDelta := sysTotal - preSys
	online = cs.long("online_cpus")
	if online <= 0 {
		if per, ok := cu.get("percpu_usage").([]interface{}); ok {
			online = int64(len(per))
		}
	}
	if sysDelta > 0 && cpuDelta >= 0 {
		n := online
		if n < 1 {
			n = 1
		}
		cpuPercent = float64(cpuDelta) * 100.0 * float64(n) / float64(sysDelta)
	}
	// Math.round(x*10)/10.0：始终保留 1 位有效小数的 double（Gson 输出 12.0 形态）
	o.Set("cpuPercent", fmtDouble(float64(int64(cpuPercent*10+0.5))/10.0))
	o.Set("cpus", online)

	// 网络收发汇总（所有网卡）
	var rx, tx int64
	nets := s.obj("networks")
	for _, k := range nets.keys {
		nw := nets.obj(k)
		rx += nw.long("rx_bytes")
		tx += nw.long("tx_bytes")
	}
	o.Set("netRx", rx)
	o.Set("netTx", tx)
	o.Set("pids", s.obj("pids_stats").long("current"))
	return o
}

// detail 容器详情：inspect 基础信息 + 启动命令 + 挂载 + 网络 + 端口映射 + 实时资源。
func detail(id string) (*core.Row, error) {
	text, err := client.get("/containers/" + id + "/json")
	if err != nil {
		return nil, err
	}
	c, err := parseJSON(text)
	if err != nil {
		return nil, err
	}
	config := c.obj("Config")
	host := c.obj("HostConfig")
	state := c.obj("State")
	ns := c.obj("NetworkSettings")

	o := core.NewRow()
	o.Set("id", c.str("Id"))
	o.Set("name", strings.TrimPrefix(c.str("Name"), "/"))
	o.Set("image", config.str("Image"))
	o.Set("created", c.str("Created"))
	o.Set("state", state.str("Status"))
	o.Set("running", state.boolean("Running", false))
	o.Set("startedAt", state.str("StartedAt"))
	o.Set("finishedAt", state.str("FinishedAt"))
	o.Set("exitCode", state.long("ExitCode"))
	o.Set("restartCount", c.long("RestartCount"))

	// 启动命令：entrypoint + cmd（等价 docker inspect 的完整命令行）
	entrypoint := joinArr(config.arr("Entrypoint"))
	cmd := joinArr(config.arr("Cmd"))
	o.Set("entrypoint", entrypoint)
	o.Set("cmd", cmd)
	o.Set("command", strings.TrimSpace(entrypoint+" "+cmd))
	o.Set("workingDir", config.str("WorkingDir"))

	// 环境变量
	env := make([]string, 0)
	for _, el := range config.arr("Env") {
		env = append(env, asStr(el))
	}
	o.Set("env", env)

	// 资源限制与重启策略
	o.Set("memoryLimit", host.long("Memory"))
	o.Set("nanoCpus", host.long("NanoCpus"))
	o.Set("networkMode", host.str("NetworkMode"))
	o.Set("restartPolicy", host.obj("RestartPolicy").str("Name"))

	// 挂载（bind / volume）
	mounts := core.NewRowList()
	for _, el := range c.arr("Mounts") {
		m := asObj(el)
		mounts.Append(core.NewRow().
			Set("type", m.str("Type")).
			Set("source", m.str("Source")).
			Set("destination", m.str("Destination")).
			Set("mode", m.str("Mode")))
	}
	o.Set("mounts", mounts)

	// 网络：各网络内的 IP / 网关 / MAC
	networks := core.NewRowList()
	nets := ns.obj("Networks")
	for _, name := range nets.keys {
		nw := nets.obj(name)
		networks.Append(core.NewRow().
			Set("name", name).
			Set("ip", nw.str("IPAddress")).
			Set("gateway", nw.str("Gateway")).
			Set("mac", nw.str("MacAddress")))
	}
	o.Set("networks", networks)

	// 端口映射：NetworkSettings.Ports（"80/tcp" -> [{HostIp,HostPort}]，null 表示未映射）
	mappings := core.NewRowList()
	ports := ns.obj("Ports")
	for _, portKey := range ports.keys {
		bindings, isArray := ports.get(portKey).([]interface{})
		if !isArray {
			mappings.Append(core.NewRow().Set("containerPort", portKey))
			continue
		}
		for _, b := range bindings {
			bo := asObj(b)
			mappings.Append(core.NewRow().
				Set("containerPort", portKey).
				Set("hostIp", bo.str("HostIp")).
				Set("hostPort", bo.str("HostPort")))
		}
	}
	o.Set("portMappings", mappings)

	// Compose 归属
	labels := config.obj("Labels")
	o.Set("composeProject", labels.str("com.docker.compose.project"))
	o.Set("composeService", labels.str("com.docker.compose.service"))
	o.Set("composeWorkdir", labels.str("com.docker.compose.project.working_dir"))
	o.Set("composeFiles", labels.str("com.docker.compose.project.config_files"))

	// 运行中容器补充实时资源
	if b, _ := o.Get("running").(bool); b {
		if s := stats(id); s != nil {
			for _, k := range []string{"memUsed", "memLimit", "cpuPercent", "cpus", "netRx", "netTx", "pids"} {
				if s.Has(k) {
					o.Set(k, s.Get(k))
				}
			}
		}
	}
	return o, nil
}

// compose Compose 项目列表：按 com.docker.compose.project 标签对全量容器分组。
func compose() ([]*core.Row, error) {
	text, err := client.get("/containers/json?all=1")
	if err != nil {
		return nil, err
	}
	arr, err := parseJSONArray(text)
	if err != nil {
		return nil, err
	}
	order := []string{}
	projects := map[string]*core.Row{}
	for _, el := range arr {
		c := asObj(el)
		labels := c.obj("Labels")
		project := labels.str("com.docker.compose.project")
		if strings.TrimSpace(project) == "" {
			continue
		}
		p, ok := projects[project]
		if !ok {
			p = core.NewRow().
				Set("name", project).
				Set("workdir", labels.str("com.docker.compose.project.working_dir")).
				Set("configFiles", labels.str("com.docker.compose.project.config_files")).
				Set("containers", int64(0)).
				Set("running", int64(0)).
				Set("services", []interface{}{}).
				Set("images", []interface{}{})
			projects[project] = p
			order = append(order, project)
		}
		p.Set("containers", toInt64(p.Get("containers"))+1)
		if c.str("State") == "running" {
			p.Set("running", toInt64(p.Get("running"))+1)
		}
		addUnique(p, "services", labels.str("com.docker.compose.service"))
		addUnique(p, "images", c.str("Image"))
	}
	out := make([]*core.Row, 0, len(order))
	for _, k := range order {
		out = append(out, projects[k])
	}
	return out, nil
}

// composeFile Compose 编排脚本：按项目标签（working_dir + config_files）定位配置文件，从本进程可见的文件系统读取。
func composeFile(project string) (*core.Row, error) {
	if project == "" || !idRe.MatchString(project) {
		return nil, core.NewBadRequest("非法的项目名称")
	}
	r := core.NewRow()
	r.Set("project", project)
	workdir, configFiles := "", ""
	text, err := client.get("/containers/json?all=1")
	if err != nil {
		return nil, err
	}
	arr, err := parseJSONArray(text)
	if err != nil {
		return nil, err
	}
	for _, el := range arr {
		labels := asObj(el).obj("Labels")
		if project != labels.str("com.docker.compose.project") {
			continue
		}
		workdir = labels.str("com.docker.compose.project.working_dir")
		configFiles = labels.str("com.docker.compose.project.config_files")
		if strings.TrimSpace(configFiles) != "" {
			break
		}
	}
	r.Set("workdir", workdir)
	files := []*core.Row{}
	r.Set("files", files)
	if strings.TrimSpace(configFiles) == "" {
		r.Set("error", "容器标签（com.docker.compose.project.config_files）中未获取到编排文件路径，该项目可能非 docker compose 部署")
		return r, nil
	}
	// config_files 可能为逗号分隔的多个文件，相对路径以 working_dir 为基准
	missing := false
	for _, f := range strings.Split(configFiles, ",") {
		name := strings.TrimSpace(f)
		if name == "" {
			continue
		}
		p := name
		if !filepath.IsAbs(name) && strings.TrimSpace(workdir) != "" {
			p = filepath.Join(workdir, name)
		}
		item := core.NewRow().Set("name", name).Set("path", p)
		content, ok := readComposeFile(p)
		if !ok {
			missing = true
			item.Set("error", "无法读取文件："+p)
		} else {
			item.Set("content", content)
		}
		files = append(files, item)
	}
	r.Set("files", files)
	if missing {
		r.Set("hint", "本服务运行在容器内时无法直接读取宿主机路径：请将宿主机目录挂载进本服务容器（如 -v /:/hostfs:ro），"+
			"并以环境变量 NEXHOME_HOST_ROOT=/hostfs 声明挂载前缀；或直接裸机运行本服务")
	}
	return r, nil
}

// readComposeFile 读取编排文件：先试原路径，再试环境变量 NEXHOME_HOST_ROOT 挂载前缀；限 512KB 内常规文件。
func readComposeFile(p string) (string, bool) {
	candidates := []string{p}
	root := strings.TrimSpace(os.Getenv("NEXHOME_HOST_ROOT"))
	if root != "" && strings.HasPrefix(p, "/") {
		candidates = append(candidates, filepath.Join(root, p[1:]))
	}
	for _, t := range candidates {
		st, err := os.Stat(t)
		if err != nil || st.IsDir() || st.Size() > 512*1024 {
			continue
		}
		f, err := os.Open(t)
		if err != nil {
			continue
		}
		b, err := io.ReadAll(f)
		_ = f.Close()
		if err == nil {
			return string(b), true
		}
	}
	return "", false
}

// danglingImages 悬空（无标签）镜像列表：清理前预览，字段 id/shortId/name/tag/size/reclaimable/created。
// reclaimable = Size − SharedSize（独占层，取自 /system/df；失败回退虚拟大小），与 docker system df 口径一致。
func danglingImages() ([]*core.Row, error) {
	filters := url.QueryEscape(`{"dangling":{"true":true}}`)
	text, err := client.get("/images/json?all=1&filters=" + filters)
	if err != nil {
		return nil, err
	}
	arr, err := parseJSONArray(text)
	if err != nil {
		return nil, err
	}
	// 从 /system/df 取各镜像共享层大小，用于估算实际可回收空间；失败则回退虚拟大小
	sharedSizes := map[string]int64{}
	if dfText, e := client.get("/system/df"); e == nil {
		if d, e := parseJSON(dfText); e == nil {
			for _, el := range d.arr("Images") {
				im := asObj(el)
				sharedSizes[im.str("Id")] = im.long("SharedSize")
			}
		}
	}
	list := make([]*core.Row, 0, len(arr))
	for _, el := range arr {
		img := asObj(el)
		id := img.str("Id")
		// 名称/标签：优先 RepoTags（name:tag）；无标签镜像回退 RepoDigests 取仓库名，标签仍为 <none>
		name, tag := "<none>", "<none>"
		rt := img.arr("RepoTags")
		if len(rt) > 0 {
			t := asStr(rt[0])
			i := strings.LastIndex(t, ":")
			if i > 0 && !strings.Contains(t[i+1:], "/") { // 排除仅含仓库分隔的冒号
				name = t[:i]
				tag = t[i+1:]
			} else {
				name = t
			}
		} else if rd := img.arr("RepoDigests"); len(rd) > 0 {
			d := asStr(rd[0])
			if at := strings.Index(d, "@"); at > 0 {
				name = d[:at]
			} else {
				name = d
			}
		}
		size := img.long("Size")
		reclaimable := size
		if shared, ok := sharedSizes[id]; ok {
			reclaimable = size - shared
			if reclaimable < 0 {
				reclaimable = 0
			}
		}
		shortId := id
		if strings.HasPrefix(shortId, "sha256:") {
			s := shortId[7:]
			if len(s) > 12 {
				s = s[:12]
			}
			shortId = s
		}
		list = append(list, core.NewRow().
			Set("id", id).
			Set("shortId", shortId).
			Set("name", name).
			Set("tag", tag).
			Set("size", size).
			Set("reclaimable", reclaimable).
			Set("created", img.long("Created")))
	}
	sort.SliceStable(list, func(i, j int) bool {
		return toInt64(list[i].Get("reclaimable")) > toInt64(list[j].Get("reclaimable"))
	})
	return list, nil
}

// danglingImageIDSet 悬空镜像 ID 集合（仅统计用，不读取层共享信息）；查询失败返回 nil。
func danglingImageIDSet() map[string]bool {
	filters := url.QueryEscape(`{"dangling":{"true":true}}`)
	text, err := client.get("/images/json?all=1&filters=" + filters)
	if err != nil {
		return nil
	}
	arr, err := parseJSONArray(text)
	if err != nil {
		return nil
	}
	ids := make(map[string]bool, len(arr))
	for _, el := range arr {
		if id := asObj(el).str("Id"); id != "" {
			ids[id] = true
		}
	}
	return ids
}

// prune 资源清理：kind=images（悬空/未用镜像）或 containers（已停止容器），返回 Daemon 回收结果。
func prune(b map[string]interface{}) (*core.Row, error) {
	kind := strings.ToLower(strings.TrimSpace(core.BodyStr(b, "kind")))
	if kind != "images" && kind != "containers" {
		return nil, core.NewBadRequest("不支持的清理类型: %s（仅 images / containers）", kind)
	}
	// 镜像清理前记录悬空镜像 ID：ImagesDeleted 同时包含镜像本身与被删的层条目，
	// 直接数条目会把层数量当镜像数量，故以清理前后悬空镜像差集统计实际删除个数。
	var before map[string]bool
	if kind == "images" {
		before = danglingImageIDSet()
	}
	resp, err := client.post("/" + kind + "/prune")
	if err != nil {
		return nil, err
	}
	r, err := parseJSON(resp)
	if err != nil {
		return nil, err
	}
	deletedKey := "ContainersDeleted"
	if kind == "images" {
		deletedKey = "ImagesDeleted"
	}
	deleted := r.arr(deletedKey)
	count := len(deleted) // 容器清理：ContainersDeleted 每项即一个容器
	if kind == "images" && before != nil {
		if after := danglingImageIDSet(); after != nil {
			count = 0
			for id := range before {
				if !after[id] {
					count++
				}
			}
		}
	}
	out := core.NewRow().
		Set("kind", kind).
		Set("spaceReclaimed", r.long("SpaceReclaimed")).
		Set("deletedCount", count)
	core.LogInfo(core.LogDocker, "Docker 清理("+kind+")：删除 "+strconv.Itoa(count)+
		" 项，回收 "+strconv.FormatInt(r.long("SpaceReclaimed")/1024/1024, 10)+" MB")
	return out, nil
}

// ---------- 工具方法 ----------

func checkId(id string) (string, error) {
	if id == "" || !idRe.MatchString(id) {
		return "", core.NewBadRequest("非法的容器标识")
	}
	return id, nil
}

// friendly 连接失败转为对用户友好的提示。
func friendly(err error) string {
	m := err.Error()
	if strings.HasPrefix(m, "DOCKER_HOST 配置无效") {
		return m + "；正确格式：unix:///var/run/docker.sock 或 tcp://host:2375"
	}
	ml := strings.ToLower(m)
	if strings.Contains(ml, "no such file") || strings.Contains(ml, "connection refused") ||
		strings.Contains(ml, "permission denied") || strings.Contains(ml, "cannot find the file") ||
		strings.Contains(ml, "unavailable") {
		return "无法连接 Docker Daemon（" + m + "），请检查 docker.sock 挂载/读写权限或 DOCKER_HOST 配置"
	}
	return m
}

// addUnique 数组字段去重追加（按字符串值）。
func addUnique(o *core.Row, key, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	lst, _ := o.Get(key).([]interface{})
	for _, e := range lst {
		if s, _ := e.(string); s == value {
			return
		}
	}
	o.Set(key, append(lst, value))
}

func joinArr(arr []interface{}) string {
	parts := make([]string, 0, len(arr))
	for _, el := range arr {
		parts = append(parts, asStr(el))
	}
	return strings.Join(parts, " ")
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func str(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func toInt64(v interface{}) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case float64:
		return int64(x)
	}
	return 0
}
