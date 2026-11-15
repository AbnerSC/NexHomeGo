# ugos-pack — 绿联 NAS（UGOS Pro）UPK 打包工程

按 [docs/绿联NAS应用上架流程说明.md](../docs/绿联NAS应用上架流程说明.md) 建立的打包工程，当前为**方案 A**：bridge 网络 + `15656:15656` 端口映射，不挂载 `docker.sock`（STUN 穿透与 Docker 容器管理功能默认受限，过审优先）。

## 目录结构

```text
ugos-pack/
├── project.yaml                  # 应用配置（方案 A；上架前见下方 TODO）
├── build_num.txt                 # 构建号计数（同一 x.y.z 下必须递增，脚本成功打包后自增）
├── rootfs_amd64/
│   └── images/                   # amd64 镜像 tar（pack 脚本自动生成/清理，勿手工放多版本）
├── rootfs_arm64/
│   └── images/                   # arm64 镜像 tar
├── rootfs_common/
│   ├── icon.png                  # 应用图标（256x256 PNG，官方规范尺寸）
│   └── docker-compose.yaml       # Compose 编排（方案 A；含方案 B 切换注释）
├── pack.ps1                      # Windows 一键：构建/导出镜像 + ugcli check（+可选本地测试包）
├── pack.sh                       # Linux/macOS 一键：check + pack（上架包必须走这里）
└── .gitignore                    # 忽略 build_dir/ 与 *.tar
```

## 快速使用

### Windows（准备物料 + 检查）

```powershell
cd ugos-pack
.\pack.ps1                 # 构建双架构镜像 -> 导出 tar -> ugcli check
.\pack.ps1 -SkipImageBuild # 只对已有 tar 做检查（镜像已构建时）
.\pack.ps1 -Arch amd64     # 只处理 amd64
.\pack.ps1 -Build 3        # 指定构建号（默认读 build_num.txt）
.\pack.ps1 -Pack           # 额外产出 Windows 本地测试包（权限不可靠，严禁上架）
```

### Linux / macOS（出上架包）

```bash
cd ugos-pack
./pack.sh                  # 使用已有 tar：ugcli check + pack
./pack.sh -b               # 现场构建双架构镜像并导出，再 check + pack
./pack.sh --arch amd64     # 只打单架构
./pack.sh --build 5        # 指定构建号
```

产物：`build_dir/pkgs/upk/{arch}_nasync_com.abnersc.docker.nexhome_{version}.upk`
（`version` = project.yaml `version` + 4 位构建号，如 `2.1.1.0001`）

## 前置条件

| 依赖 | 说明 |
| --- | --- |
| ugcli | 加入 PATH（Windows 重命名 `ugcli.exe`）；下载：<https://developer.ugnas.com/doc/tools/ugcli.html> |
| Docker + buildx | 镜像构建导出用；非本机架构（arm64）走 QEMU 模拟，较慢 |
| Linux 环境 | **上架包必须在 Linux 用 `pack.sh` 生成**（Unix 文件权限要求），可用 Debian 12 虚机/WSL2 Docker/CI |

## 版本升级流程（速查）

1. `project.yaml` 的 `version` → 新版本（与 `internal/core.Version` 同步）；
2. `rootfs_common/docker-compose.yaml` 的 `image` tag → 同步新版本（两脚本启动时会校验一致性，不一致直接报错）；
3. `ugos-pack/build_num.txt`：新 `x.y.z` 重置为 `1`（同一 `x.y.z` 迭代则由脚本自动递增）；
4. Windows 跑 `.\pack.ps1` 准备物料并检查 → Linux 跑 `./pack.sh -b` 出上架包。

## 切换方案 B（host 网络 + docker.sock）

过审后如需启用 STUN 穿透与 Docker 容器管理完整功能（需先与绿联商务确认放行），按
`rootfs_common/docker-compose.yaml` 头部注释切换：`network_mode: host`、删 `ports`、
取消 `docker.sock` 挂载与 `DOCKER_HOST` 注释；`project.yaml` 无需改动。

## 上架前 TODO（勿遗漏）

- [ ] `app_id` 组织名 `abnersc` 替换为你的组织英文小写名（**上架后不可修改**）；
- [ ] `project.yaml` 取消 `privacy_policy_link` 注释，指向真实隐私政策 HTTPS 静态页；
- [ ] 确认 `rootfs_common/icon.png` 为最终上架图标（当前为工程默认图标，可自行替换，保持 256x256 PNG）；
- [ ] 测试设备完成开发者授权（`ugdev.sig` + 整机授权，见手册 1.2 节）；
- [ ] 按手册 6.3 自测清单完成双架构安装测试并出具自测报告。
