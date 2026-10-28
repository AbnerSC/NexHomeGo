//go:build linux

package stun

// soReusePort SO_REUSEPORT 的 Linux 值。Go 冻结的 syscall 包未导出该常量（仅 x/sys/unix 有），
// 为避免引入新依赖在此本地定义；Linux 内核 ABI 恒为 15，供 lingerControl / listenControl 使用，
// 让「已连接出站 socket」与「同端口 LISTEN socket」共存（保活链路同端口重建的前提）。
const soReusePort = 15
