//go:build unix && !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd

package stun

// soReusePort 其余 unix 平台（solaris/illumos/aix/hurd 等）的 SO_REUSEPORT 值不一且本类场景不涉及，
// 统一取 -1：setsockopt 会以 ENOPROTOOPT 无害失败并被调用方忽略，等价「不设置该选项」，
// 退化回不带 SO_REUSEPORT 的旧行为（监听与出站建链照常，仅同端口出站重建可能失败），
// 绝不会把某个整数误设成该平台的其它 socket 选项。
const soReusePort = -1
