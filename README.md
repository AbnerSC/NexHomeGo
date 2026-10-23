# NexHome｜联枢

## GitHub
https://github.com/AbnerSC/NexHomeGo.git

[![GitHub Stars](https://img.shields.io/github/stars/AbnerSC/NexHomeGo?style=flat&label=Stars)](https://github.com/AbnerSC/NexHomeGo/stargazers)
[![Docker Pulls](https://img.shields.io/docker/pulls/babyfly/nex-home?label=Docker%20Pulls)](https://hub.docker.com/r/babyfly/nex-home)

> 一站式内网节点守护工具，面向家庭 / 小型机房服务器，把内网能力安全对外打通。

NexHome 是一款单进程、前后端一体化的轻量 Go 服务，内置 Web 服务器与 Web 管理界面，
集成 **DDNS 域名同步、STUN 端口穿透、WOL 网络唤醒、SSL 证书自动申请续期、网站导航、Docker 容器管理与运维、服务可用性监控、统一告警通知、状态仪表盘** 等能力。
只启动一个 Go 程序，面板默认仅占用一个端口（开启 HTTPS、反向代理或穿透任务时会额外监听对应端口），配置与日志全部持久化在 SQLite（程序运行目录 `data/`）。

---

## 一、Docker Compose 部署与使用说明

compose 部署示例（host 网络 + docker.sock 挂载）：

```yaml
services:
  nex-home:
    image: babyfly/nex-home:latest
    container_name: nex-home
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./data:/app/data
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - TZ=Asia/Shanghai
      - DOCKER_HOST=unix:///var/run/docker.sock
    deploy:
      resources:
        limits:
          memory: 256m
    ulimits:
      nofile: { soft: 65535, hard: 65535 }
    healthcheck:
      # 探活方式用 bash /dev/tcp 探测端口（仅验证端口可连，不依赖额外工具）
      test: ["CMD-SHELL", "exec 3<>/dev/tcp/127.0.0.1/8090 && echo -n '' >&3"]
      interval: 10s
      timeout: 3s
      retries: 3
      start_period: 20s
```

启动：

```bash
docker compose up -d
```

使用说明：

- 启动后访问：**http://127.0.0.1:8090**（默认端口）
- 首次启动自动生成配置文件 `nexhome.properties`、数据库 `data/nexhome.db`
- **登录密码**：首次启动由系统**随机生成高强度初始密码并打印到控制台**（形如 `首次启动，已生成随机初始密码……`，16 位含大小写/数字/符号），
  请从控制台日志读取并登录后**立即在「系统设置 → 修改登录密码」中更换**；系统不存在任何固定的默认密码
- **登录安全**：支持「失败锁定」（连续登录失败达上限临时锁定来源 IP，默认 3 次 / 30 分钟，可在「系统设置 → 登录安全设置」调整）
  与「单点登录」（新设备登录自动注销其余会话）
- **访问端口 / HTTPS / 安全入口**：登录后在「系统设置 → 访问与安全设置」中修改，保存后自动重启生效（绑定失败自动回滚）；
  HTTPS 证书自动适配「SSL 证书管理」中已签发的证书；开启安全入口后必须通过 `http://地址:端口/入口路径/` 访问面板
- 挂载 `/var/run/docker.sock` 后，「Docker 容器」模块即可查看宿主机上的容器与 Compose 项目；
  容器内进程需有 socket 读写权限（默认 root 满足，非 root 用户需将其加入宿主 `docker` 组对应的 gid）

> 注意：运行镜像基于 debian:bookworm-slim，已内置 `curl`（未安装 `wget`）；healthcheck 可改用 `curl -f`，也可继续用上面的 bash /dev/tcp 写法。

## 二、功能简介

- **DDNS 域名同步**：阿里云云解析 DNS / ESA 直连，多模式 IP 来源，定时自动同步域名解析记录。
- **STUN 端口穿透**：标准 STUN 协议建立/保活 NAT 映射，支持 UDP、TCP/HTTP 任务转发与打洞，无需公网 IP 即可对外提供服务。
  穿透成功或映射地址变化后，可同步更新阿里云 ESA：把映射 IP 写入勾选的 DNS 解析记录、把映射端口写入勾选回源规则的 HTTPS 端口（站点与记录均由 ESA API 拉取勾选，只更新不新增，失败仅告警不影响穿透）。
  同一时机还可**按任务勾选的通知渠道**（可多选）发送穿透结果通知，以及向任务自定义的 Webhook 地址推送。
- **WOL 网络唤醒**：管理多台机器，一键/批量发送 UDP 魔术包唤醒内网设备。
- **SSL 证书申请与自动续期**：支持 Let's Encrypt / ZeroSSL，HTTP01 全自动、DNS01 半自动，到期前 21 天自动续期。
- **网站导航**：卡片式内/外网双地址入口，自动识别访问来源智能切换，支持排序与拖拽。
- **Docker 容器管理与运维**：直连 docker.sock，展示容器、Compose 项目、资源占用与整体概况；
  并支持容器**启动/停止/重启**、**日志查看**与**资源清理（镜像/已停止容器）**等运维操作。
  ⚠️ 上述写操作直接作用于宿主机 Docker，需挂载 `docker.sock` 且具备读写权限，属高权限操作请谨慎使用。
- **服务/端口可用性监控**：HTTP/HTTPS、TCP、UDP 端口周期探测，故障与恢复自动告警。
- **统一告警通知中心**：集中维护 Webhook / 邮件(SMTP) / 钉钉机器人渠道，监控故障、登录锁定等事件按启用渠道扇出推送；
  穿透任务等也可按任务自选多个渠道投递。
- **统一状态仪表盘**：首页总览聚合系统运行状态、DDNS、STUN、证书到期倒计时、监控 UP/DOWN、Docker 概况、反向代理与近 7 天访问统计。
- **配置备份导出**：一键下载数据库一致性快照（`VACUUM INTO`），用于离线备份与迁移（仅导出，不含导入恢复）。
- **其他**：全模块操作日志、内置登录鉴权（失败锁定 + 单点登录）、异常统一捕获提示。

## 三、常见问题

1. **忘记登录密码**：停止程序，删除 `data/nexhome.db` 中 `app_config` 表的 `auth.password` 行，重启将**重新随机生成一个初始密码并打印到控制台**（注意会丢失已设置的其他配置项，建议优先用「配置备份」定期导出）。
2. **HTTP01 证书申请失败**：确认域名已解析到本机公网 IP，且公网 80 端口能转发到本服务端口；否则改用 DNS01。
3. **DDNS 同步报权限错误**：检查 AccessKey 权限策略是否包含对应产品的解析读写权限。
4. **STUN 探测无响应**：更换 STUN 服务器（如 `stun.qq.com:3478`、`stun.miwifi.com:3478`），并确认本机可访问公网 UDP。
5. **TCP 任务运行中但外网仍无法访问映射地址**：依次排查——① 探测 NAT 类型，对称型无法纯 STUN 穿透，改用路由器端口转发；
   ② 受限锥形需填写「对端公网地址」由本端主动打洞，或在对端配合下互打；③ 确认主机防火墙已放行监听端口（Windows：允许 nexhome 通过专用/公用网络的入站规则）。
6. **Docker 模块提示未连接**：容器部署需 `-v /var/run/docker.sock:/var/run/docker.sock` 挂载；
   报权限错误（Permission denied）说明容器内用户无 socket 读写权限；远程 Docker 检查 `DOCKER_HOST` 与网络连通性。

## 四、参与开发
1. 启动入口：`cmd/nexhome/main.go`
2. 登录密码：首次启动随机生成并打印到控制台，无内置固定密码（源码中的数据库文件`data/nexhome.db`用户密码：123456789012）

## 五、待办
