package core

// Version 应用版本号，构建期由 -ldflags "-X 'NexHomeGo/internal/core.Version=...'" 注入。
// 默认值与 Java 侧 pom.xml 的当前版本保持一致，避免升级面板时版本号显示异常。
var Version = "2.0.0"
