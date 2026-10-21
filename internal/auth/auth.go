package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	"NexHomeGo/internal/core"
)

// 内置鉴权：密码以 SHA-256 哈希保存在 app_config（key=auth.password）。
// 首次启动随机生成高强度初始密码并打印控制台；登录颁发随机 Token（内存态，24 小时），
// 前端经请求头 X-Token 携带。含「失败锁定」与「单点登录」。

const (
	KeyPassword    = "auth.password"
	KeyMaxFails    = "security.login.maxFails"
	KeyLockMinutes = "security.login.lockMinutes"

	initPasswordLength = 16
	tokenTTLms         = int64(24 * 3600 * 1000)
	defaultMaxFails    = 3
	defaultLockMinutes = 30
)

// NotifyBroadcast 由通知中心在启动时注入：锁定事件扇出（解耦，auth 不直接依赖 notify 包）。
var NotifyBroadcast func(event, title, message string)

var (
	tokensMu sync.Mutex
	tokens   = map[string]int64{} // token -> 过期时间戳(ms)

	failsMu sync.Mutex
	fails   = map[string]*failState{} // ip -> 失败/锁定状态
)

type failState struct {
	count       int
	lockUntilMs int64
}

// Init 初始化随机密码（仅首次启动），明文只打印控制台，不落日志表。
func Init() error {
	v, err := core.GetConfig(KeyPassword)
	if err != nil {
		return err
	}
	if v == "" {
		password, err := randomPassword(initPasswordLength)
		if err != nil {
			return err
		}
		if err := core.SetConfig(KeyPassword, sha256Hex(password)); err != nil {
			return err
		}
		// 与 Java 控制台输出对齐，便于运维从日志读取初始密码。
		println("============================================================")
		println(" 首次启动，已生成随机初始密码，请登录后尽快在设置中修改！")
		println(" 初始密码: " + password)
		println("============================================================")
	}
	return nil
}

// Login 登录校验（含失败锁定与单点登录）。成功返回 token；密码错误返回空串。
// 调用方应先经 LockRemainingMs 拦截锁定态。
func Login(password, ip string) (string, error) {
	hash, err := core.GetConfig(KeyPassword)
	if err != nil {
		return "", err
	}
	if hash != "" && strings.EqualFold(hash, sha256Hex(password)) {
		token, err := randomHex(24)
		if err != nil {
			return "", err
		}
		failsMu.Lock()
		delete(fails, ip)
		failsMu.Unlock()
		// 单点登录：新登录自动注销其余会话。
		tokensMu.Lock()
		tokens = map[string]int64{token: time.Now().UnixMilli() + tokenTTLms}
		tokensMu.Unlock()
		core.LogInfo(core.LogAuth, "用户登录成功")
		return token, nil
	}
	recordFailure(ip)
	core.LogWarn(core.LogAuth, "登录失败：密码错误 (IP="+ip+")")
	return "", nil
}

func recordFailure(ip string) {
	max, _ := GetMaxFails()
	failsMu.Lock()
	st := fails[ip]
	if st == nil {
		st = &failState{}
		fails[ip] = st
	}
	now := time.Now().UnixMilli()
	if st.lockUntilMs > now {
		failsMu.Unlock()
		return // 已锁定不重复计数
	}
	st.count++
	if st.count >= max {
		minutes, _ := GetLockMinutes()
		st.lockUntilMs = now + int64(minutes)*60_000
		st.count = 0
		failsMu.Unlock()
		core.LogWarn(core.LogAuth, ipStr(max, minutes, ip))
		if NotifyBroadcast != nil {
			NotifyBroadcast("auth.lockout", "登录安全锁定",
				"来源 IP "+ip+" 连续登录失败 "+itoa(max)+" 次，已锁定 "+itoa(minutes)+" 分钟。")
		}
		return
	}
	failsMu.Unlock()
}

// LockRemainingMs 该 IP 剩余锁定毫秒数，0 表示未锁定。
func LockRemainingMs(ip string) int64 {
	failsMu.Lock()
	defer failsMu.Unlock()
	st := fails[ip]
	if st == nil {
		return 0
	}
	remain := st.lockUntilMs - time.Now().UnixMilli()
	if remain < 0 {
		return 0
	}
	return remain
}

// Check 校验 token 是否有效。
func Check(token string) bool {
	if token == "" {
		return false
	}
	tokensMu.Lock()
	defer tokensMu.Unlock()
	expire, ok := tokens[token]
	if !ok {
		return false
	}
	if expire < time.Now().UnixMilli() {
		delete(tokens, token)
		return false
	}
	return true
}

func Logout(token string) {
	if token != "" {
		tokensMu.Lock()
		delete(tokens, token)
		tokensMu.Unlock()
		core.LogInfo(core.LogAuth, "用户退出登录")
	}
}

// ChangePassword 校验旧密码后更新；修改后强制全部重新登录。
func ChangePassword(oldPwd, newPwd string) (bool, error) {
	hash, err := core.GetConfig(KeyPassword)
	if err != nil {
		return false, err
	}
	if hash == "" || !strings.EqualFold(hash, sha256Hex(oldPwd)) {
		return false, nil
	}
	if err := core.SetConfig(KeyPassword, sha256Hex(newPwd)); err != nil {
		return false, err
	}
	tokensMu.Lock()
	tokens = map[string]int64{}
	tokensMu.Unlock()
	core.LogInfo(core.LogAuth, "登录密码已修改，所有会话已失效")
	return true, nil
}

// GetMaxFails / GetLockMinutes 读取登录安全参数（缺失/非法回退默认并夹到合法区间）。
func GetMaxFails() (int, error) {
	return readIntConfig(KeyMaxFails, defaultMaxFails, 1, 100)
}

func GetLockMinutes() (int, error) {
	return readIntConfig(KeyLockMinutes, defaultLockMinutes, 1, 1440)
}

// SetSecurity 设置登录安全参数。
func SetSecurity(maxFails, lockMinutes int) error {
	if maxFails < 1 || maxFails > 100 {
		return core.NewBadRequest("最大失败次数需在 1~100 之间")
	}
	if lockMinutes < 1 || lockMinutes > 1440 {
		return core.NewBadRequest("锁定时间需在 1~1440 分钟之间")
	}
	if err := core.SetConfig(KeyMaxFails, itoa(maxFails)); err != nil {
		return err
	}
	return core.SetConfig(KeyLockMinutes, itoa(lockMinutes))
}

// ---------- 内部工具 ----------

func readIntConfig(key string, def, min, max int) (int, error) {
	v, err := core.GetConfig(key)
	if err != nil || v == "" {
		return def, err
	}
	n, perr := atoi(v)
	if perr != nil {
		return def, nil
	}
	if n < min {
		return min, nil
	}
	if n > max {
		return max, nil
	}
	return n, nil
}

func sha256Hex(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// randomPassword 大小写字母 + 数字 + 特殊符号，各类至少一次，末尾打乱（字符集与 Java 完全一致）。
func randomPassword(length int) (string, error) {
	const (
		upper  = "ABCDEFGHJKLMNPQRSTUVWXYZ"
		lower  = "abcdefghijkmnpqrstuvwxyz"
		digit  = "23456789"
		symbol = "!@#$%^&*-_=+"
	)
	all := upper + lower + digit + symbol
	n := length
	if n < 4 {
		n = 4
	}
	buf := make([]byte, n)
	pick := func(charset string) (byte, error) {
		i, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return 0, err
		}
		return charset[i.Int64()], nil
	}
	var err error
	if buf[0], err = pick(upper); err != nil {
		return "", err
	}
	if buf[1], err = pick(lower); err != nil {
		return "", err
	}
	if buf[2], err = pick(digit); err != nil {
		return "", err
	}
	if buf[3], err = pick(symbol); err != nil {
		return "", err
	}
	for i := 4; i < n; i++ {
		if buf[i], err = pick(all); err != nil {
			return "", err
		}
	}
	// 打乱顺序，避免前几位固定为"大小写+数字+符号"。
	for i := n - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		k := int(j.Int64())
		buf[i], buf[k] = buf[k], buf[i]
	}
	return string(buf), nil
}

func randomHex(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ---------- 轻量辅助 ----------

func itoa(i int) string       { return strconv.Itoa(i) }
func atoi(s string) (int, error) { return strconv.Atoi(strings.TrimSpace(s)) }
func ipStr(max, minutes int, ip string) string {
	return fmt.Sprintf("IP %s 连续登录失败 %d 次，锁定 %d 分钟", ip, max, minutes)
}
