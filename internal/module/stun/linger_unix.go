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
// 同时设置 SO_REUSEADDR：Java 侧出站 socket 均 setReuseAddress(true)，监听开启后
// 同端口轮换新建出站连接（keepaliveOnce 轮换/备用重连）依赖它与 LISTEN 共存。

import "syscall"

// lingerControl Dialer.Control 回调：SO_LINGER(Onoff=1, Linger=0) close 即发 RST；SO_REUSEADDR 允许同端口绑定。
func lingerControl(network, address string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		opErr = syscall.SetsockoptLinger(int(fd), syscall.SOL_SOCKET, syscall.SO_LINGER,
			&syscall.Linger{Onoff: 1, Linger: 0})
	})
	if err != nil {
		return err
	}
	return opErr
}
