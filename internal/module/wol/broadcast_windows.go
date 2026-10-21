//go:build windows

package wol

import (
	"context"
	"net"
	"syscall"
	"unsafe"
)

const (
	wsSolSocket   = 0xffff // SOL_SOCKET
	wsSoBroadcast = 0x20   // SO_BROADCAST
)

var (
	ws2_32         = syscall.NewLazyDLL("ws2_32.dll")
	procSetSockOpt = ws2_32.NewProc("setsockopt")
)

// newBroadcastConn 创建一个已开启 SO_BROADCAST 的 UDP 连接（Windows 通过 ws2_32!setsockopt 设置）。
func newBroadcastConn() (net.PacketConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			val := int32(1)
			r1, _, _ := procSetSockOpt.Call(fd, wsSolSocket, wsSoBroadcast,
				uintptr(unsafe.Pointer(&val)), 4)
			if r1 != 0 {
				sockErr = syscall.Errno(r1)
			}
		}); err != nil {
			return err
		}
		return sockErr
	}}
	return lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
}
