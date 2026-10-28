//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package stun

// soReusePort SO_REUSEPORT 在 Darwin/BSD 系的值（0x200）。ios 满足 darwin 构建标签故一并覆盖。
// 语义与 Linux 一致：让「已连接出站 socket」与「同端口 LISTEN socket」共存。
const soReusePort = 0x200
