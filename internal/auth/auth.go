package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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
	// KeyAccessToken 接口访问令牌（app_config）：非空时通过请求头 Access-Token 携带可访问全部接口。
	KeyAccessToken = "auth.access_token"

	initPasswordLength = 16
	tokenTTLms         = int64(24 * 3600 * 1000)
	defaultMaxFails    = 3
	defaultLockMinutes = 30

	// MinAccessTokenLen / MaxAccessTokenLen 接口访问令牌长度区间（上限与设置页输入框一致）。
	// 下限取 32：接口令牌权限等同已登录用户（可下载证书私钥、导出配置备份），
	// 且其校验入口 /api/auth/check 免登录，过短令牌可被在线爆破（8 位仅 48bit 以下空间）。
	MinAccessTokenLen = 32
	MaxAccessTokenLen = 64

	// AccessTokenMaxFails / AccessTokenLockMinutes 接口令牌校验失败的锁定阈值（细分桶）：
	// /api/auth/check 是免鉴权的令牌探测入口，必须限速，否则短令牌仍可在线枚举。
	AccessTokenMaxFails    = 10
	AccessTokenLockMinutes = 15
	// AccessTokenPeerMaxFails 绝对桶（TCP 对端）失败上限：为细分桶的 6 倍。
	// 面板挂在反向代理 / ESA 回源之后时，全部客户端共享同一对端地址；若沿用细分阈值，
	// 任何一个外部人员错输 10 次就能把该代理下的合法调用一起锁死 15 分钟。
	// 抬高阈值后仍保留「伪造转发头绕不过 TCP 对端硬上限」的防爆破作用。
	AccessTokenPeerMaxFails = AccessTokenMaxFails * 6
	// maxTrackedAccessIPs 每个计数桶的容量上限：防止海量来源把计数表本身变成内存放大面
	maxTrackedAccessIPs = 4096
	// accessFailIdleMs 接口令牌计数条目空闲回收阈值：超过该时长未再失败的未锁定条目直接回收
	accessFailIdleMs = 10 * 60 * 1000
)

// NotifyBroadcast 由通知中心在启动时注入：锁定事件扇出（解耦，auth 不直接依赖 notify 包）。
var NotifyBroadcast func(event, title, message string)

var (
	tokensMu sync.Mutex
	tokens   = map[string]int64{} // token -> 过期时间戳(ms)

	failsMu sync.Mutex
	fails   = map[string]*failState{} // ip -> 失败/锁定状态

	// 接口令牌校验失败计数（双桶）与登录失败计数分开：
	//   - atPeerFails：绝对桶，键为 TCP 对端地址（不可伪造），任何来源的失败硬上限；
	//   - atClientFails：细分桶，键为「对端|真实客户端」，仅在直连对端是显式可信代理时使用，
	//     避免代理后一人爆破误锁全员；非代理场景为空，不影响判定。
	atFailsMu     sync.Mutex
	atPeerFails   = map[string]*failState{} // peer -> 绝对桶
	atClientFails = map[string]*failState{} // peer|client -> 细分桶
)

type failState struct {
	count       int
	lockUntilMs int64
	// lastMs 最近一次失败时刻（ms）：接口令牌计数表按空闲时长回收条目的依据
	lastMs int64
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
// ip 必须是连接对端地址（Ctx.PeerIP），不得使用客户端可伪造的转发头，否则本轮计数可被绕过。
func Login(password, ip string) (string, error) {
	hash, err := core.GetConfig(KeyPassword)
	if err != nil {
		return "", err
	}
	if hash != "" && hashEqual(hash, sha256Hex(password)) {
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
	if hash == "" || !hashEqual(hash, sha256Hex(oldPwd)) {
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

// GetAccessToken 读取接口访问令牌（空串表示未启用）。
func GetAccessToken() (string, error) {
	return core.GetConfig(KeyAccessToken)
}

// SetAccessToken 保存接口访问令牌：留空表示停用，非空需 MinAccessTokenLen~MaxAccessTokenLen 位字母/数字/中划线/下划线。
// 令牌以明文保存（调用方需复制使用），不参与会话单点登录。
func SetAccessToken(token string) error {
	token = strings.TrimSpace(token)
	if token != "" {
		if len(token) < MinAccessTokenLen || len(token) > MaxAccessTokenLen {
			return core.NewBadRequest("Access-Token 长度需在 %d~%d 位之间", MinAccessTokenLen, MaxAccessTokenLen)
		}
		for _, c := range token {
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
			if !ok {
				return core.NewBadRequest("Access-Token 仅支持字母、数字、中划线与下划线")
			}
		}
	}
	return core.SetConfig(KeyAccessToken, token)
}

// CheckAccessToken 校验请求头携带的接口访问令牌：未配置时一律拒绝；
// 比对使用恒定时间算法，避免按字节短路比较泄露前缀。
func CheckAccessToken(token string) bool {
	token = strings.TrimSpace(token)
	// 长度越界直接拒绝：既省一次查库，也避免对超长输入做比较
	if len(token) < MinAccessTokenLen || len(token) > MaxAccessTokenLen {
		return false
	}
	want, err := core.GetConfig(KeyAccessToken)
	if err != nil || want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(want)) == 1
}

// AccessTokenLockRemainingMs 该来源因接口令牌校验失败被锁定的剩余毫秒数，0 表示未锁定。
// peer 必填（TCP 对端地址）；clientKey 为空表示本次不参与细分计数（对端不是显式可信代理），
// 不为空时取两桶剩余锁定时间的较大值（细分桶可能先于绝对桶触发）。
func AccessTokenLockRemainingMs(peer, clientKey string) int64 {
	now := time.Now().UnixMilli()
	atFailsMu.Lock()
	defer atFailsMu.Unlock()
	a := remainingLocked(atPeerFails[peer], now)
	b := remainingLocked(atClientFails[clientBucketKey(peer, clientKey)], now)
	if b > a {
		return b
	}
	return a
}

// RecordAccessTokenFailure 记录一次接口令牌校验失败：
//   - 细分桶（clientKey 非空）连续失败 AccessTokenMaxFails 次后锁定该客户端；
//   - 绝对桶（TCP 对端）连续失败 AccessTokenPeerMaxFails 次后锁定该来源。
//
// 双桶的意义：代理后所有客户端共享同一 TCP 对端，细分桶让爆破只影响发起者自己；
// 而转发头可伪造，一旦细分键被逐次更换，绝对桶仍提供不可绕过的失败上限。
// 调用方应在校验前先用 AccessTokenLockRemainingMs 拦截锁定态。
func RecordAccessTokenFailure(peer, clientKey string) {
	now := time.Now().UnixMilli()
	atFailsMu.Lock()
	peerLocked := bumpAccessFailLocked(atPeerFails, peer, now, AccessTokenPeerMaxFails)
	clientLocked := bumpAccessFailLocked(atClientFails, clientBucketKey(peer, clientKey), now, AccessTokenMaxFails)
	atFailsMu.Unlock()

	switch {
	case clientLocked:
		reportAccessTokenLockout("客户端 "+peer+"|"+clientKey, AccessTokenMaxFails)
	case peerLocked:
		reportAccessTokenLockout("来源 IP "+peer, AccessTokenPeerMaxFails)
	}
}

// ResetAccessTokenFailures 校验成功：清除该来源的两个失败计数桶。
func ResetAccessTokenFailures(peer, clientKey string) {
	atFailsMu.Lock()
	delete(atPeerFails, peer)
	delete(atClientFails, clientBucketKey(peer, clientKey))
	atFailsMu.Unlock()
}

// clientBucketKey 细分桶键：对端地址 + 真实客户端地址；客户端未知或与对端相同时不细分（返回空）。
func clientBucketKey(peer, clientKey string) string {
	clientKey = strings.TrimSpace(clientKey)
	if clientKey == "" || clientKey == peer {
		return ""
	}
	return peer + "|" + clientKey
}

// remainingLocked 该失败状态下尚未结束的锁定毫秒数（st 为空或未锁定返回 0）
func remainingLocked(st *failState, now int64) int64 {
	if st == nil {
		return 0
	}
	if remain := st.lockUntilMs - now; remain > 0 {
		return remain
	}
	return 0
}

// bumpAccessFailLocked 累加一次失败并在达到阈值时进入锁定态，返回是否本次刚触发锁定。
// 锁定期间不再累加；计数表满时先回收空闲条目，仍满则不计数（优先保证内存安全）。
func bumpAccessFailLocked(bucket map[string]*failState, key string, now int64, maxFails int) bool {
	if key == "" {
		return false
	}
	st := bucket[key]
	if st == nil {
		if len(bucket) >= maxTrackedAccessIPs {
			purgeAccessFailsLocked(bucket, now)
			if len(bucket) >= maxTrackedAccessIPs {
				return false
			}
		}
		st = &failState{}
		bucket[key] = st
	}
	if st.lockUntilMs > now {
		return false // 已锁定不重复计数
	}
	st.count++
	st.lastMs = now
	if st.count < maxFails {
		return false
	}
	st.count = 0
	st.lockUntilMs = now + int64(AccessTokenLockMinutes)*60_000
	return true
}

// reportAccessTokenLockout 锁定告警：写日志并扇出通知（与登录锁定同事件类型）
func reportAccessTokenLockout(who string, maxFails int) {
	core.LogWarn(core.LogAuth, who+" 接口令牌连续校验失败 "+itoa(maxFails)+
		" 次，已锁定 "+itoa(AccessTokenLockMinutes)+" 分钟")
	if NotifyBroadcast != nil {
		NotifyBroadcast("auth.lockout", "接口令牌爆破锁定",
			who+" 连续接口令牌校验失败 "+itoa(maxFails)+" 次，已锁定 "+
				itoa(AccessTokenLockMinutes)+" 分钟。")
	}
}

// purgeAccessFailsLocked 回收计数桶条目（调用方持 atFailsMu）：锁定中的条目保留，
// 其余「计数已清零」或「空闲超过 accessFailIdleMs」的条目一律删除。
func purgeAccessFailsLocked(bucket map[string]*failState, now int64) {
	for k, st := range bucket {
		if st.lockUntilMs > now {
			continue // 锁定中：保留至解锁
		}
		if st.count == 0 || now-st.lastMs > accessFailIdleMs {
			delete(bucket, k)
		}
	}
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

// hashEqual 恒定时间比对两个十六进制哈希，避免按字节短路比较泄露前缀信息。
func hashEqual(a, b string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
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

func itoa(i int) string          { return strconv.Itoa(i) }
func atoi(s string) (int, error) { return strconv.Atoi(strings.TrimSpace(s)) }
func ipStr(max, minutes int, ip string) string {
	return fmt.Sprintf("IP %s 连续登录失败 %d 次，锁定 %d 分钟", ip, max, minutes)
}
