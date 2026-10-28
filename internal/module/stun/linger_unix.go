//go:build unix

package stun

// STUN-over-TCP 与端口轮换重建依赖「关闭即发 RST」的 socket 语义（等价 Java 的
// setSoLinger(true, 0)）：TCP 连接正常关闭走 FIN 四次挥手，NAT 映射会保持
// TIME_WAIT 一段时间，导致同端口立即复用时被拒或映射状态含糊；
// RST 关闭则对端与中间 NAT 立即回收映射，同端口可在毫秒级重建。
//
// Go 标准库无法在已建立的连接上事后设置 SO_LINGER，故在 socket 出生时
// （net.Dialer.Control 回调）设置，仅对本包主动 dial 的连接生效，
// 不影响监听 socket 与其他包内连接。
// Linger 字段名各平台统一为 Onoff（Linux/BSD/macOS），Windows 见 linger_windows.go。
// 同时设置 SO_REUSEADDR + SO_REUSEPORT：Java 侧出站 socket 均 setReuseAddress(true)，监听开启后
// 同端口轮换新建出站连接（keepaliveOnce 轮换/备用重连）依赖它与 LISTEN 共存。
// 但仅有 SO_REUSEADDR 不够：Linux 的 bind 冲突判定中，只要已存在 socket 处于 TCP_LISTEN 状态，
// 新 socket 绑定与其重叠的通配 addr:port 就会被拒（EADDRINUSE），SO_REUSEADDR 的放宽不适用于
// LISTEN。要让「已连接出站 socket」与「同端口 LISTEN socket」共存，必须二者都设 SO_REUSEPORT
// （同 UID 校验由内核保证，跨进程/跨用户不会误共享）。故 dial（lingerControl）与 listen
// （listenControl）两条路径都要设置，缺一即回退到出站重建全部失败的旧行为。

import "syscall"

// lingerControl Dialer.Control 回调：SO_LINGER(Onoff=1, Linger=0) close 即发 RST；
// SO_REUSEADDR + SO_REUSEPORT 允许与同端口 LISTEN socket 共存（见文件头说明）。
func lingerControl(network, address string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1)
		opErr = syscall.SetsockoptLinger(int(fd), syscall.SOL_SOCKET, syscall.SO_LINGER,
			&syscall.Linger{Onoff: 1, Linger: 0})
	})
	if err != nil {
		return err
	}
	return opErr
}

// listenControl ListenConfig.Control 回调：监听 socket 设 SO_REUSEADDR + SO_REUSEPORT，
// 与出站 dial socket 的 lingerControl 对称——二者都带 SO_REUSEPORT 后，保活链路死亡重建时
// 才能从「已被本监听占用的同一本地端口」再次出站绑定（CGNAT 映射挂在出站五元组上，本地端口
// 必须与监听一致，否则映射端口漂移）。SO_REUSEPORT 的入站负载均衡仅在同端口的多个 LISTEN
// socket 间生效，已连接的出站 socket 不在其列，不会窃取入站连接。
func listenControl(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		// SO_REUSEPORT best-effort：Linux（soReusePort=15）恒成功；个别 unix 平台不支持时
		// 忽略错误，监听照常工作（仅退化回「出站同端口重建可能失败」的旧行为），
		// 绝不因该选项失败而拒绝监听
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1)
	})
}
