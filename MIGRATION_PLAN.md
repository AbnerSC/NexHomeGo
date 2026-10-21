# NexHome（Java）→ NexHomeGo 迁移技术方案

> 目标：**完整迁移全部功能、一次性完整交付**，且对**已部署用户近乎无缝**——用户只需把 compose 里的 `image:` 行改为 **`babyfly/nex-home-go`**（仅此一处），**不修改环境变量 / 挂载 / 端口 / 数据目录**即可平滑切换。
>
> **已确认决策**：① 内存诊断页按 Go 特性重做（`diag.js` 相应重写，随镜像交付）；② SQLite 用成熟的 cgo 驱动 `mattn/go-sqlite3`；③ 一次性完整交付（不分模块灰度上线）；④ 镜像仓库名 `babyfly/nex-home-go`；⑤ **运行中产生的文件全部落 `/app/data`，不得产生匿名卷**；⑥ Go 1.27 工具链，**其余依赖均取最新兼容版**。

---

## 一、现状分析（被迁移系统）

NexHome 是一个**前后端一体化、单进程、单端口**的 Java 内网节点守护工具（`com.nexhome`，`Java 25`，`v1.3.0`，约 **46 个类 / 1.5 万行**）。

- Web 框架：**Javalin 7 + Jetty**，端口默认 **8090**（`network_mode: host`），同端口提供 REST `/api/**` + 前端静态资源（原生 JS/HTML/CSS，**无构建步骤**）。
- 存储：**SQLite**（`data/nexhome.db`，WAL + 外键），引导配置 `data/nexhome.properties`，业务配置全在库表 `app_config`。
- 关键第三方库：`sqlite-jdbc`、`gson`、`acme4j + BouncyCastle`（SSL 证书）、`jakarta.mail/angus`（告警邮件）、`netty`（反向代理引擎）、`ip2region`（离线 IP 归属地 xdb）。
- 虚拟线程调度（`Tasks`）承载 DDNS 定时、证书续期、监控探测、流量落库、日志清理等周期任务。

### 模块清单（代码量 / 难度）

| 模块 | 主要文件（行数） | 迁移难度 | Go 落点 |
|---|---|---|---|
| core 基础 | AppConfig74 / Database174 / JsonUtils55 / Logs76 / Tasks79 | 低 | `internal/core` |
| auth 鉴权 | AuthService184 | 低 | `internal/auth` |
| web 服务与路由 | WebServer597 / WebAccessConfig240 / Ctx102 / SystemRoutes336 / Dashboard197 / Diag403 | 中 | `internal/web` |
| ddns | AliyunClient364 / DdnsService436 / IpResolver101 | 中 | `internal/ddns` |
| stun 穿透 | StunRunner1497 / TcpPunch716 / StunClient537 / StunService493 / StunEsaSync371 / Upnp275 / Webhook214 / Server202 / Traffic196 / Notify120 | **高** | `internal/stun` |
| cert 证书 | CertService759（ACME） | 中高 | `internal/cert` |
| docker | DockerService668 / DockerClient249（Unix socket HTTP） | 中 | `internal/docker` |
| monitor 监控 | MonitorService484 | 低 | `internal/monitor` |
| nav 导航 | NavService194 / NavIconStore128 | 低 | `internal/nav` |
| notify 告警 | NotifyService577（Webhook/Email/DingTalk） | 中 | `internal/notify` |
| provider 凭证 | ProviderConfigService144 | 低 | `internal/provider` |
| **proxy 反代引擎** | ProxyCenter1487 / ProxyHandler766 / BackendRelay489 / ProxyCache381 / ProxyAdvanced315 / ProxyService319 / GeoResolver201 / SslStore215 / VisitStats183 / ProxySite144 | **最高** | `internal/proxy` |
| wol 唤醒 | WolService167 | 低 | `internal/wol` |

### REST 接口面（须逐一复刻，共约 **100 个端点**）

12 个业务模块 + system/auth/diag/dashboard 各自 `registerRoutes()` 注册到 `WebServer.route(METHOD, pattern, handler)`。路径参数形如 `/api/{module}/tasks/{id}`。完整清单见附录 A。

---

## 二、无缝迁移的「兼容性红线」（本方案核心）

**部署侧外部契约（用户 compose/env/volume 不变）—— 绝对红线：**

1. **镜像引用**：Go 构建产物发布为新仓库 **`babyfly/nex-home-go`**（如 `babyfly/nex-home-go:latest`）。用户切换仅改 compose 的 `image:` 一行，其余（`network_mode: host`、`volumes`、`env`、`healthcheck`、资源限制）全部不动。
2. **`WORKDIR /app` 不变**：Go 进程工作目录必须是 `/app`，使 `./data` → `/app/data`（用户挂载 `./data:/app/data`）。数据目录 = `运行目录/data`。
3. **监听端口不变**：默认 8090；`network_mode: host` 下反代端口、HTTPS 端口、STUN bind 端口全部由库内配置驱动 → 只要 Go 读取同一份配置并绑定同一端口即无缝。
4. **`network_mode: host`**：Go 无需做端口映射，直接监听宿主任意端口，与 Java 行为一致。
5. **env 兼容**：必须识别 `TZ`（决定 `time.Local`，影响所有时间字符串）与 `DOCKER_HOST`（`unix:///var/run/docker.sock` 或 `tcp://host:port`）。
6. **healthcheck 不变**：用户用 `bash /dev/tcp/127.0.0.1/8090` 探测，Go 只要监听 8090 即通过（Go 镜像同样无需 curl/wget）。
7. **资源限制不变**：`memory: 512m` + `ulimits nofile 65535`。Go 常驻内存远低于 Java，余量更充足。

**持久化数据契约（`data/` 目录里的旧文件必须被 Go 原样读写）—— 绝对红线：**

8. **SQLite 库文件二进制兼容**：Go 驱动读写的是标准 SQLite 格式，与 `sqlite-jdbc` 完全互操作。`data/nexhome.db`（含 `-wal`/`-shm`）**直接沿用，禁止重建**。
9. **`schema.sql` 原样复用**：启动执行同一份脚本（全 `CREATE TABLE IF NOT EXISTS`，幂等），**不改表结构**，保证旧数据列名列序一致。
10. **`nexhome.properties` 兼容**：Java Properties（`key=value`）格式。Go 需按同格式读取既有文件（键：`server.port`、`server.port.autoFallback`、`server.web.dir`）。
11. **`app_config` 行为键同名同义**：`auth.password`(SHA-256 hex)、`security.login.*`、`web.*`、`proxy.enabled/http.port/https.port/realip.trust_header/visit.retention_months/last_error`、`acme.email`、`zerossl.eab_*`、`cert.account.*`、`stun.tcpLastServer` 等，Go 必须用**完全相同的键名与取值编码**读写。
12. **文件布局一致**：证书 `data/certs/task-{id}/{fullchain.pem|cert.pem,domain.key.pem}`、证书任务默认落盘 `data/ssl`（DB 内 `save_dir` 存的是 `/app/data/ssl` 绝对路径，换 Go 镜像后该路径仍有效）、导航图标 `data/nav-icons/`、归属地库 `data/ip2region_v4.xdb`/`v6.xdb`（存在则覆盖内置库）。

**API/前端契约（前端随镜像一并替换，但为降低风险尽量零改动）：**

13. **响应 JSON 结构逐字节对齐**：成功 `{"ok":true,"data":...}`，失败 `{"ok":false,"error":"..."}`；HTTP 状态码语义（401 未登录、400 参数错、429 锁定、500 兜底）保持一致（前端 `app.js` 依赖 401→跳登录）。
14. **JSON null 必须输出**：Gson 用 `serializeNulls()`，所有字段（含 null）都会出现。Go 序列化**不得使用 `omitempty`**，缺失字段要显式给 `null`，以免前端读到 `undefined`。
15. **列表行直接映射数据库列名**：`SELECT *` 结果按**列名原样**（小写下划线）输出为对象；SQLite 布尔列以 **0/1 数字**（非 true/false）输出，与 Java `rs.getObject` 一致。
16. **时间格式统一**：`Database.now()` = `yyyy-MM-dd HH:mm:ss`（→ Go layout `2006-01-02 15:04:05`）；`cert_task.not_after` 为 ISO/RFC3339（`Instant.parse` 口径），保持一致。
17. **鉴权流程不变**：SHA-256 十六进制（大小写不敏感比较）、48 hex token、24h TTL、内存态单点登录与失败锁定、`X-Token`/`?token=` 取值顺序、安全入口前缀剥离逻辑，逐条复刻。

**落盘范围红线（决策⑤）：运行中产生的文件必须全部落在 `/app/data`，容器不得产生匿名卷：**

18. **Dockerfile 禁止 `VOLUME` 指令**：匿名卷的唯一来源是镜像内 `VOLUME` 声明（基础镜像 `debian:12-slim` 本身无 VOLUME，构建时不得新增）；用户只保留两个显式 bind mount（`./data:/app/data` 与 `docker.sock`）。
19. **全部写路径收敛到 DATA_DIR**（含 SQLite `-wal`/`-shm` 旁文件），禁止写容器可写层其他位置。Java 现有两处违规，Go 实现必须纠正（见 6.10 落盘清单）。

> ℹ️ **按决策①重做处**：`DiagService` 的 `/api/diag/*`（含原 `/api/diag/nmt`）依赖 JVM 专有的 `NativeMemoryTracking` 与 JDK 内存模型，Go 无对应。方案是**按 Go 运行时特性重新设计**：以 `runtime.ReadMemStats`（HeapAlloc/HeapSys/StackSys/MSpanSys/GCSys/BuckHashSys/OtherSys…）+ cgroup 内存限制（`/sys/fs/cgroup`）+ `/proc/meminfo` 组织新的内存分类与跳变分析口径，并**同步重写诊断页 `diag.js`**（该页随新镜像一并交付，属镜像内资产，不影响用户 compose）。其余模块目标仍是 JSON 逐字节对齐、前端零改动。

---

## 三、Go 技术选型

| 关注点 | Java | Go 选型 | 理由 |
|---|---|---|---|
| 语言/运行时 | Java 25 | **Go 1.27**（`go.mod` 已就位） | std 路由支持 `METHOD /path/{name}` 通配 |
| HTTP 框架 | Javalin/Jetty | **net/http + 标准库路由**（必要时 `chi`） | 轻、可控；进程内重启/双连接器可用两个 `http.Server` |
| SQLite | sqlite-jdbc | **`mattn/go-sqlite3`（cgo）** ✅ 已选定 | 生态最成熟、与 sqlite-jdbc 同为 SQLite 官方内核，库文件二进制完全互操作；支持 `VACUUM INTO`/`PRAGMA`/WAL。代价：多架构构建需 CGO 交叉工具链（见第七节） |
| JSON | Gson | `encoding/json` | 注意红线 14/15/16 |
| 定时任务 | 虚拟线程 + ScheduledExecutor | **goroutine + `time.Ticker` 轻量调度器**（同任务串行/防重入语义复刻） | 直接映射 `Tasks.every/delay/run` |
| ACME 证书 | acme4j + BouncyCastle | **`golang.org/x/crypto/acme`** + `crypto/x509`/`crypto/tls`/`crypto/ecrsa` | Go 原生完备，无需 BC 三件套 |
| 反向代理 | Netty | **`net/http/httputil.ReverseProxy`** + 自定义 `Transport` + `tls.Config.GetConfigForClient`（SNI 多证书）+ HTTP/2（ALPN 内置）+ WebSocket（`gorilla/websocket`） | 复用 std，SNI/ALPN/HTTP2 是 Go 强项 |
| IP 归属地 | ip2region(xdb) | **ip2region 官方 Go binding（xdb）** + `go:embed` 内置 v4/v6 库 | xdb 文件格式跨语言一致 |
| 邮件 | Jakarta Mail/Angus | `net/smtp`（STARTTLS/SMTPS）或 `gopkg.in/gomail.v2` | 标准库覆盖 SMTP 全场景 |
| Docker | 手写 UDS HTTP | **`net.Dial("unix")` + 自定义 `http.Transport.DialContext`** | 直连 `/var/run/docker.sock` 裸 API，逻辑直译 |
| 阿里云签名 | 手写 | `crypto/hmac`+`crypto/sha1/sha256`+`net/url` | 严格复刻签名算法与参数顺序 |
| 前端静态资源 | jar 内 `/web` | **`go:embed web/**`** 编译进二进制 | 保持同路径与内容 |
| 大文件/带宽测速 | 流式 | `http.Flusher` 逐块 flush | 复刻 in-band 语义 |

> **镜像内 `data/` 与内置 xdb 的关系**：`/app/data` 被宿主机 bind mount 覆盖，故**不能**把内置 xdb 放到 `/app/data`。方案：`go:embed` 把 `ip2region_v4.xdb`/`v6.xdb` 编进二进制，运行时若 `data/*.xdb` 存在则优先文件模式（与 Java 优先级一致），否则用内置字节以**内存/cursor 模式**直接检索（**不落临时文件**，见决策⑤）。

### 依赖版本策略（决策⑥：其余依赖均取最新兼容版）

- **原则**：在 Go 1.27 工具链上，所有直接依赖均固定到**当前最新稳定（或非预发布）且相互兼容**的版本；Phase 0 统一用 `go get <module>@latest` 拉取并 `go mod tidy` 固化到 `go.mod`/`go.sum`，不人为锁旧版。
- **优先标准库**（降低依赖与兼容面）：HTTP 路由/静态/TLS/ALPN·HTTP2/密码学/编码/SMTP 等均优先用 std，能不引第三方就不引。
- **预计的直接依赖**（以拉取时的最新兼容版为准）：
  | 模块 | 用途 | 备注 |
  |---|---|---|
  | `github.com/mattn/go-sqlite3` | SQLite（cgo） | 取最新；验证与 `VACUUM INTO`/WAL 兼容 |
  | `golang.org/x/crypto/acme` | ACME 证书 | 取最新 x/crypto |
  | ip2region Go binding（xdb） | IP 归属地 | 取上游最新；兼容既有 v4/v6 xdb 格式 |
  | `github.com/gorilla/websocket` | 反代 WebSocket | 仅当 std 不足时引入 |
  | `github.com/go-chi/chi` | 路由（备选） | 若 std `ServeMux` 能力不够时才引入 |
- **约束**：新增/升级依赖不得破坏五项既有决策与数据/JSON 契约；间接依赖由 `go mod tidy` 自动拉齐至兼容最低版本。构建时国内环境可注入 `GOPROXY=https://mirrors.aliyun.com/goproxy/,direct` 加速。

---

## 四、Go 工程结构

```
NexHomeGo/
├── go.mod
├── cmd/nexhome/main.go            # 对应 NexHomeApp.main：加载配置→DB→auth→注册路由→启动任务→Web→优雅退出
├── internal/
│   ├── core/      config.go  db.go  json.go  logs.go  scheduler.go
│   ├── auth/      auth.go
│   ├── web/       server.go  ctx.go  access_config.go  system_routes.go  dashboard.go  diag.go
│   │              static/  (go:embed 前端资源)
│   ├── ddns/      aliyun.go  ddns.go  ipresolver.go
│   ├── stun/      runner.go  punch_tcp.go  client.go  service.go  esa_sync.go  upnp.go ...
│   ├── cert/      acme.go  service.go
│   ├── docker/    client.go  service.go
│   ├── monitor/   monitor.go
│   ├── nav/       nav.go  icons.go
│   ├── notify/    notify.go
│   ├── provider/  provider.go
│   ├── proxy/     center.go  handler.go  relay.go  cache.go  advanced.go  geo.go  sslstore.go  stats.go
│   └── wol/       wol.go
├── resources/     schema.sql (原样复制)  web/ (原样复制)  db/*.xdb (原样复制)
└── Dockerfile     (见第七节)
```

**移植原则**：以 Java 类为单位一一对应移植；先移植契约层（core/auth/web/Ctx）打通「读旧库 + 返回旧结构」，再按**低难度→高难度**逐模块替换（wol → nav → provider → logs → auth → monitor → ddns → notify → docker → cert → stun → proxy）。

---

## 五、分阶段实施路线图

**Phase 0 — 基线与夹具（1 周）**
- 用现网 Java 镜像跑一份**黄金样本**：抓取全部约 100 个接口的请求/响应对（含空库、含数据两种），落 `testdata/golden/`。
- 复制 `schema.sql`、`web/`、`db/*.xdb` 到 Go 工程；用 Java 产出一个真实 `data/nexhome.db` 作为 Go 的兼容测试夹具。
- 按决策⑥初始化依赖：`go get` 拉取各直接依赖的**最新兼容版**（Go 1.27）+ `go mod tidy` 固化 `go.mod`/`go.sum`；先跑通 `mattn/go-sqlite3` 打开旧库与 `VACUUM INTO`。

**Phase 1 — 骨架与契约层（1–1.5 周）**
- `core`：配置加载、SQLite（WAL/foreign_keys/`VACUUM INTO`/批量事务）、`app_config` 读写、日志（op_log + 分页 + truncate 20000）、调度器、JSON 工具。
- `auth` + `web`（server/ctx/access_config/system_routes）：进程内重启、端口自愈、HTTPS 双连接器、安全入口前缀、鉴权前置、统一异常、静态资源、ACME well-known、测速。
- 验收：Go 能**打开旧库、登录、返回与 Java 逐字节一致的 `system/info`、`logs`、`web-settings`**。

**Phase 2 — 简单业务模块（1.5 周）**
- wol / nav(+图标上传/embed) / provider / monitor（HTTP/TCP/UDP 探测 + 告警去抖）/ ddns（阿里云签名严格复刻 + IP 解析）/ notify（Webhook/Email/DingTalk）。
- 每个模块以黄金样本做**响应 diff**。

**Phase 3 — 证书与 Docker（1.5–2 周）**
- cert：`x/crypto/acme` 重写 HTTP01/DNS01、账号密钥、EAB、自动续期、证书落盘目录、`serveChallenge`、webhook 推送。
- docker：`net.Dial unix` 裸 API（containers/compose/stats/logs/prune + start/stop/restart），读 `DOCKER_HOST`。

**Phase 4 — STUN 穿透（2–2.5 周，难点）**
- UDP/TCP STUN 客户端、NAT 类型判定、`StunRunner` 状态机、`TcpPunch` 打洞、UPnP（SSDP/IGD）、流量统计（`stun_traffic` 分桶落库）、ESA 同步、Webhook、按渠道通知。
- 高保真复刻端口绑定、保活周期、映射变化检测。

**Phase 5 — 反向代理引擎（2.5–3 周，最难）**
- `ReverseProxy` 转发（host/path 匹配、通配、路径改写、请求/响应头改写、超时、限流、BasicAuth、IP 白名单、后端 TLS 校验开关、XFF 真实 IP）、SNI 多证书（`GetConfigForClient` + `SslStore`）、文件缓存（`ProxyCache`）、访问统计（`VisitStats` 按月分表 + ip2region 归属地）、HTTP/2、WebSocket。
- 独立监听 `proxy.http.port/https.port`，开关与热加载语义对齐。

**Phase 6 — 全链路对等验证 + 灰度（1.5 周）**
- 见第八节。

**总量级估算**：约 **12–15 人周**（单人），可按模块并行压缩。

---

## 六、关键难点与处理

1. **SQLite 驱动（已定 cgo `mattn/go-sqlite3`）**：与 `sqlite-jdbc` 同基于 SQLite 官方内核，读写同一份 `nexhome.db`（含 WAL/`-shm`）二进制互操作，支持 `VACUUM INTO`/`PRAGMA journal_mode=WAL`/`foreign_keys`/批量事务/`last_insert_rowid`。代价：`CGO_ENABLED=1` 使多架构交叉编译需带 C 工具链——采用 `docker buildx` **按目标平台模拟编译**（QEMU，简单可靠）或 **zig cc 交叉**（更快，免 QEMU），见第七节。运行时基础镜像必须含 glibc/musl（不能再用 distroless/static）。
2. **进程内重启**：Java `WebServer.restart()` 停旧建新并回滚。Go 用两个可启停的 `http.Server` + `context` 取消 + 端口预探测（`net.Listen` 试探）复刻；**重启期间进程不能退出**（对应 Java「非守护线程」注意点），主协程用信号 + `select{}` 常驻。
3. **JSON 逐字节对齐**：Gson `serializeNulls` + 数字/布尔列原样 → Go 统一用 `map[string]any`（DB 行直转）并保证整数列输出数字、null 输出。禁止结构体 `omitempty`。
4. **虚拟线程 → goroutine**：`Tasks.every` 的「同任务串行、上次未完则跳过」用每任务 `sync/atomic` 标志位复刻。
5. **ACME**：Go 原生比 acme4j 更简洁，但**账号密钥/订单流程/EAB 语义**要与既有已签发证书目录布局兼容（`data/certs/task-{id}/` 文件名不变），避免旧 HTTPS 证书失效。
6. **Netty → std 反代**：Netty 的池化直接内存/高水位背压、`MaxDirectMemorySize` 等在 Go 无对应，也不需要；重点是**行为等价**（改写规则、SNI、缓存命中、统计维度、超时）而非结构等价。
7. **ip2region**：用官方 Go binding 读取**同一份 xdb 文件**，归属地归一化口径（国内到省市、国外仅国家、内网「局域网」）与 Java `GeoResolver.search` 完全一致。
8. **诊断页按 Go 重做（决策①）**：以 `runtime.ReadMemStats` 的堆/栈/MSpan/GC/other 分类 + cgroup v2（`memory.current`/`memory.max`）+ `/proc/meminfo` 组装新内存快照与趋势分析；原 `nmt` 端点替换为 Go 运行时内存分项。`/api/diag/snapshot|analysis|<新内存端点>` 的响应体与 `diag.js` 一同重写（新口径，无需强行对齐 Java NMT 字段）。Go 常驻内存远低于 JVM，无 Metaspace/CodeCache/`MaxDirectMemorySize` 等概念，诊断维度相应简化。
9. **JVM 调优 ENV 失效**：`MALLOC_ARENA_MAX`、`-XX:*` 对 Go 无意义，新 Dockerfile 移除；不影响用户侧。
10. **落盘清单与 `/tmp` 违规纠正（决策⑤）**：

| 运行期写入 | Java 现状 | Go 方案 |
|---|---|---|
| `nexhome.db` + `-wal`/`-shm` | `data/` ✅ | 同路径，SQL 用 `?pathname&mode=rw` 显式锁定，防相对路径漂移 |
| `nexhome.properties`（首次生成） | `data/` ✅ | 同路径 |
| 证书 `certs/task-{id}/*.pem`、`certs/acme/{provider}/account.pem`、`ssl/` 导出 | `data/` ✅ | 同布局 |
| 导航图标 `nav-icons/`、`images/` | `data/` ✅ | 同布局 |
| 反代文件缓存 `proxy-cache/` | `data/` ✅ | 同布局 |
| 配置备份快照（`VACUUM INTO`） | ⚠️ `createTempFile` 写系统临时目录 `/tmp` | **改在 `data/tmp/` 生成、下载后立即删除**；失败路径兼做启动时残留清理 |
| ip2region 内置库释放临时文件 | ⚠️ `createTempFile` 写 `/tmp` | **零临时文件**：`go:embed` 的 xdb 字节直接用 ip2region Go binding 的内存/cursor 模式检索；`data/*.xdb` 存在则优先文件模式 |
| 日志 | stdout + `op_log` 表 ✅ | 维持 stdout（Docker logging driver 接管，非容器内文件）+ `op_log` |

自查方式：验收时 `docker inspect` 容器 `Mounts` 应仅有用户声明的两项 bind mount（无 `Type: volume` 匿名卷），且容器可写层（`docker diff <容器>`）在完整功能回归后不出现 `/tmp`、`/app`（除 `/app/data` 外）的新增文件。

---

## 七、Dockerfile（多架构，cgo）

> 因选定 `mattn/go-sqlite3`（cgo），编译阶段**按目标平台构建**（不再固定 `$BUILDPLATFORM`），依赖 `docker buildx` + QEMU 模拟；如需提速可改用 zig cc 交叉（免 QEMU，见下方备注）。产物为动态链接二进制，**运行时基础镜像须含 libc**。

```dockerfile
# ---------- 阶段一：按目标平台编译（cgo，buildx 会为每个 TARGETARCH 分别执行） ----------
FROM golang:1.27 AS build            # 不固定 --platform，buildx 自动按目标架构（含 QEMU）运行
WORKDIR /build
# 阿里云代理：GOPROXY=https://mirrors.aliyun.com/goproxy/,direct
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO_ENABLED=1；mattn/go-sqlite3 内置 sqlite amalgamation，静态链接 libsqlite，仅依赖 libc
RUN CGO_ENABLED=1 go build -trimpath -tags "" \
    -ldflags "-s -w -X main.version=1.3.0" -o nexhome ./cmd/nexhome

# ---------- 阶段二：运行时镜像（glibc 基础镜像，多架构官方支持） ----------
FROM debian:12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/nexhome /app/nexhome
EXPOSE 8090
ENTRYPOINT ["/app/nexhome"]
```
构建（与 Java 镜像一致的多架构）：
```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -t babyfly/nex-home-go:latest --push .
```

要点：
- `WORKDIR /app`（数据落 `/app/data`）、`EXPOSE 8090`、镜像名发布为 **`babyfly/nex-home-go`**。
- **不得声明任何 `VOLUME`**（决策⑤：避免匿名卷）；全部运行期写入（含 `VACUUM INTO` 快照、xdb）均限制在 `/app/data`，不使用 `/tmp`（见 6.10）。
- 含 `tzdata` 以保证 `TZ=Asia/Shanghai` 生效（时间格式依赖 `time.Local`）；`ca-certificates` 供 HTTPS/ACME/阿里云 API 验证。
- healthcheck 仍用 `bash /dev/tcp/127.0.0.1/8090` 即可（无需 curl/wget）。
- 移除 Java 的 `MALLOC_ARENA_MAX` 与所有 `-XX:*` JVM 参数（Go 不适用）；Go 常驻内存远低于 512m 限制。
- **可选 zig 交叉**（免 QEMU、构建更快）：`CC_FOR_TARGET=$CC` 配 `zig cc -target aarch64-linux-gnu`，将编译阶段固定回 `--platform=$BUILDPLATFORM` 并对每个 GOARCH 交叉编译。

---

## 八、API 对等验证与一次性切换（决策③）

> **交付方式：一次性完整交付**（不分模块灰度上线）。Phase 0–5 是**内部构建顺序**（先易后难），但只在一个完整版本回归全部达标后，**单次整体切换**。

**对等测试（切换前置门槛 / Definition of Done）**
- 契约层黄金样本 diff：同请求（含 body/参数/token）打 Java 与 Go，逐字段比较 JSON（键集合、类型、null、时间格式）。约 100 端点全部纳入（诊断页 `/api/diag/*` 除外，按新口径单独验收）。
- 数据兼容：Go 打开 Java 产出的 `nexhome.db` → 跑一轮 CRUD/定时任务 → 再由 Java 打开验证无损坏。
- 端到端：旧 `data/` 挂载 → 登录 → DDNS/STUN/证书/反代/Docker/监控/告警各跑一遍真实/模拟链路。
- 部署演练：host 网络 + 512m + docker.sock，验证端口自愈、HTTPS、安全入口、测速、备份下载。

**预切换验证（staging，非生产灰度）**
- 在预发布环境把 Java 与 Go 分别监听不同端口**并行读同一份 `data/`**（WAL 多进程共享，写需串行）——仅只读比对，避免同时写。
- 正式切换：停 Java → 将 compose 的 `image:` 改为 `babyfly/nex-home-go` → `docker compose up -d`。因数据/配置/端口全兼容，异常时**回滚只需把 `image:` 换回原 Java 镜像**，旧库仍可被 Java 打开（前提是 Go 期间未改表结构，方案已保证）。

---

## 九、主要风险

| 风险 | 等级 | 缓解 |
|---|---|---|
| 反代引擎行为不等价（SNI/改写/缓存/统计/HTTP2/WS） | 高 | Phase 5 单列 + 全量黄金样本 + 真实站点回归 |
| STUN/TCP 打洞状态机复刻偏差 | 高 | 逐状态用例 + NAT 类型判定实测 |
| ACME 与旧证书目录/账号密钥兼容 | 中 | 保持 `data/certs/task-*` 布局；新签测试域验证 |
| SQLite cgo 驱动构建/兼容性 | 中 | `mattn/go-sqlite3` 与 jdbc 同内核；建库/备份/批量事务用例覆盖；多架构用 buildx+QEMU 或 zig cc |
| JSON null / 0-1 布尔 / 时间格式不一致 | 中 | 契约层封装统一 + diff 把关 |
| 诊断页 NMT 无法等价（决策①已重做） | 中 | 按 Go runtime 重做字段 + 重写 `diag.js`（随镜像交付，不影响用户 compose） |
| 运行期文件落到 `/app/data` 外产生残留/匿名卷（决策⑤） | 中 | Dockerfile 禁 `VOLUME`；备份/xdb 写入均收敛 `data/`；`docker inspect`+`docker diff` 自查 |
| cgo 使多架构构建变重（无 QEMU 时较慢） | 中 | 首选 buildx+QEMU；或 zig cc 交叉编译提速；优先验证 amd64，arm64 同步构建 |

---

## 十、已确认决策（本轮定调）

1. ✅ **内存诊断页按 Go 特性重做**（决策①）：`/api/diag/*` + `diag.js` 一同重写；`system/info` 的 `usedMemoryMB/maxMemoryMB/javaVersion` 同步改为 Go runtime 口径（前端“Java”标签改为 Go 运行时展示）。
2. ✅ **SQLite 用 cgo `mattn/go-sqlite3`**（决策②）：多架构用 `docker buildx`+QEMU（或 zig cc）。
3. ✅ **一次性完整交付**（决策③）：不分模块灰度上线；单版本全量回归达标后一次切换（见第八节）。
4. ✅ **镜像仓库名 `babyfly/nex-home-go`**（决策④）：用户切换仅改 compose `image:` 行。

### 尚待细化的排期输入（非阻塞，可边做边定）
- 工期/人力约束（当前估算 **12–15 人周**单人，一次性交付）。
- 是否需保留 `latest` 之外的语义化版本 tag（建议同步 Java 当前 `1.3.0` 以免用户困惑）。

---

## 附录 A：REST 接口清单（按模块，共约 100 端点）

- **auth**：`POST /api/auth/login` `GET /api/auth/check` `POST /api/auth/logout` `POST /api/auth/change-password` `GET|PUT /api/auth/security`
- **system**：`GET /api/system/info|metrics|web-settings` `PUT /api/system/web-settings` `GET /api/system/backup` `GET /api/system/speedtest/ping|down` `POST /api/system/speedtest/up` `GET /api/net/source`
- **logs**：`GET /api/logs`
- **dashboard**：`GET /api/dashboard`
- **diag**：`GET /api/diag/snapshot|analysis`（原 `nmt` 按决策①重做为 Go 运行时内存端点）
- **provider**：`GET /api/provider/configs|types` `POST /api/provider/configs` `PUT|DELETE /api/provider/configs/{id}`
- **ddns**：`GET /api/ddns/tasks|nics|public-ip` `POST /api/ddns/tasks` `PUT|DELETE /api/ddns/tasks/{id}` `POST /api/ddns/tasks/{id}/sync` `POST /api/ddns/preview-ip` `POST /api/ddns/esa/sites`
- **stun**：`GET /api/stun/tasks` `POST /api/stun/tasks` `PUT|DELETE /api/stun/tasks/{id}` `POST /api/stun/tasks/{id}/start|stop|test|verify|issue` `POST /api/stun/tasks/{id}/esa-sync|notify-test` `GET /api/stun/tasks/{id}/traffic` `GET /api/stun/servers` `POST /api/stun/servers` `PUT|DELETE /api/stun/servers/{id}` `POST /api/stun/servers/{id}/move|probe-tcp` `POST /api/stun/esa/sites|records|origin-rules`
- **wol**：`GET /api/wol/devices` `POST /api/wol/devices` `PUT|DELETE /api/wol/devices/{id}` `POST /api/wol/devices/{id}/wake` `POST /api/wol/wake-batch`
- **cert**：`GET /api/cert/tasks|settings` `POST /api/cert/tasks` `PUT|DELETE /api/cert/tasks/{id}` `POST /api/cert/tasks/{id}/issue|validate` `GET /api/cert/tasks/{id}/detail|download` `PUT /api/cert/settings`
- **nav**：`GET /api/nav/items|settings|images` `POST /api/nav/items|icons` `PUT /api/nav/items/{id}` `DELETE /api/nav/items/{id}` `DELETE /api/nav/images/{file}` `PUT /api/nav/reorder` `PUT /api/nav/settings` `GET /images/{file}` `GET /nav-icons/{file}`
- **docker**：`GET /api/docker/overview|containers|compose|compose/file|prune/preview` `GET /api/docker/containers/{id}|/logs` `POST /api/docker/containers/{id}/start|stop|restart` `POST /api/docker/prune`
- **notify**：`GET /api/notify/channels|logs` `POST /api/notify/channels` `PUT|DELETE /api/notify/channels/{id}` `POST /api/notify/channels/test|{id}/test`
- **monitor**：`GET /api/monitor/tasks` `POST /api/monitor/tasks` `PUT|DELETE /api/monitor/tasks/{id}` `POST /api/monitor/tasks/{id}/run`
- **proxy**：`GET /api/proxy/sites|settings|status|certs|defaults` `POST /api/proxy/sites` `PUT /api/proxy/sites/{id}` `DELETE /api/proxy/sites/{id}` `POST /api/proxy/sites/toggle|cache/purge|certs/reload` `POST /api/proxy/settings`
