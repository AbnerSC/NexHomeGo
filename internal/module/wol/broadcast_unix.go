//go:build unix

package wol

import (
	"context"
	"net"
	"syscall"
)

// newBroadcastConn 创建一个已开启 SO_BROADCAST 的 UDP 连接（Linux 向广播地址发送必需，否则 EACCES）。
func newBroadcastConn() (net.PacketConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
		}); err != nil {
			return err
		}
		return sockErr
	}}
	return lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
}
