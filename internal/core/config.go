package core

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// AppConfig：全局基础配置。
// 配置文件为数据目录下的 nexhome.properties（Java Properties 格式），首次启动自动生成默认文件。
// 仅含少量引导项（端口等），业务配置全部持久化在 SQLite 中。
//
// 兼容性红线：
//   - WORK_DIR = 进程当前工作目录（容器内 WORKDIR /app），DATA_DIR = WORK_DIR/data；
//     运行期产生的文件必须全部落在 DATA_DIR（决策⑤）。
//   - properties 读写格式必须与 Java Properties 兼容，以便用户回滚到 Java 镜像时仍可读取。
var (
	workDir    string
	dataDir    string
	configFile string

	propsMu sync.RWMutex
	props   = map[string]string{}
)

// 引导配置键（与 Java AppConfig 完全一致）。
const (
	keyPort          = "server.port"
	keyPortFallback  = "server.port.autoFallback"
	keyWebDir        = "server.web.dir"
	defaultPort      = 8090
	defaultFallback  = 5
	defaultConfigCom = "NexHome configuration. server.port: Web service port." +
		" server.port.autoFallback: startup port self-healing span, 0 = random port only." +
		" server.web.dir: optional external web static dir (use forward slashes)."
)

// InitPaths 解析工作目录与数据目录，须在任何 IO 前调用（一般由 LoadConfig 内部完成）。
func InitPaths() error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	workDir = wd
	dataDir = filepath.Join(wd, "data")
	configFile = filepath.Join(dataDir, "nexhome.properties")
	return nil
}

// WorkDir / DataDir / ConfigFile 暴露目录（供证书、图标、备份等落盘收敛到 data 下）。
func WorkDir() string   { return workDir }
func DataDir() string   { return dataDir }
func ConfigFile() string { return configFile }

// LoadConfig 加载配置，文件不存在则写入默认配置。
func LoadConfig() error {
	if workDir == "" {
		if err := InitPaths(); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		// 默认仅写入 server.port（与 Java 行为一致），其余项读取时用内置默认。
		f, err := os.Create(configFile)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := f.WriteString("#" + defaultConfigCom + "\n" + keyPort + "=" + strconv.Itoa(defaultPort) + "\n"); err != nil {
			return err
		}
		propsMu.Lock()
		props = map[string]string{keyPort: strconv.Itoa(defaultPort)}
		propsMu.Unlock()
		return nil
	}
	b, err := os.ReadFile(configFile)
	if err != nil {
		return err
	}
	propsMu.Lock()
	props = parseProperties(string(b))
	propsMu.Unlock()
	return nil
}

func getProperty(key, def string) string {
	propsMu.RLock()
	defer propsMu.RUnlock()
	if v, ok := props[key]; ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

// Port Web 服务端口，默认 8090。
func Port() int {
	if p, err := strconv.Atoi(getProperty(keyPort, "")); err == nil && p > 0 {
		return p
	}
	return defaultPort
}

// PortFallbackSpan 启动期端口自愈跨度（server.port.autoFallback，默认 5，负值回退 5）。
func PortFallbackSpan() int {
	raw := getProperty(keyPortFallback, "")
	if raw == "" {
		return defaultFallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return defaultFallback
	}
	if v < 0 {
		return defaultFallback
	}
	return v
}

// WebDir 外部前端资源目录（可选 server.web.dir），未配置返回 ""；相对路径基于工作目录解析。
func WebDir() string {
	v := getProperty(keyWebDir, "")
	if v == "" {
		return ""
	}
	if filepath.IsAbs(v) {
		return filepath.FromSlash(v)
	}
	return filepath.Join(workDir, filepath.FromSlash(v))
}

// parseProperties 解析 Java Properties 文本：跳过空行与以 # / ! 开头的注释行，
// 以首个 = 或 : 分割键值（键两侧空白裁剪，值保留至行尾并裁剪）。
func parseProperties(text string) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "!") {
			continue
		}
		var key, val string
		if i := strings.IndexByte(line, '='); i >= 0 {
			key, val = line[:i], line[i+1:]
		} else if i := strings.IndexByte(line, ':'); i >= 0 {
			key, val = line[:i], line[i+1:]
		} else {
			key, val = line, ""
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if key != "" {
			m[key] = val
		}
	}
	return m
}
