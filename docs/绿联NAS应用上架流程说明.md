# NexHome｜联枢 绿联 NAS 应用商店上架操作手册

> 依据绿联云开发者平台（<https://developer.ugnas.com>）官方文档整理，结合 NexHomeGo（下称「本应用」）的项目实际情况编写。
> 官方文档入口：<https://developer.ugnas.com/doc/backend/quick-start/prepare.html>
> 官方对接邮箱：**developers_bd@ugreen.com**（邮件模板可在开发者平台首页「联系我们」处下载 `template-zh.docx`）

---

## 〇、结论先行（一图看懂）

| 事项 | 结论 |
| --- | --- |
| 应用形态 | **Docker 应用**（`is_docker_app: true`），复用现有多架构镜像 `babyfly/nex-home` |
| 打包工具 | `ugcli`（当前版本 1.1.0.25），**正式打包必须在 Linux（Debian 12）环境执行** |
| 安装包格式 | `.upk`（UPK），命名格式 `{arch}_{series}_{appid}_{version}.upk` |
| 支持架构 | `amd64` + `arm64`（镜像已具备双架构能力） |
| 产品线 | `nasync`（绿联 NAS）；HomeAgent 需另行与绿联确认 |
| 应用端口 | 固定 `15656`（`project.yaml` 的 `port` 字段与 compose 映射必须一致） |
| 打开方式 | `tab`（浏览器新标签页打开，本应用自带完整 Web 界面与登录体系） |
| 核心依赖 | 依赖绿联 Docker 套件 `com.ugreen.docker`（`depend_docker_version: 1.7.0.0000`） |
| 上架路径 | 邮件申请 → 商务对接 → 自测 → 提交材料 → 审核（资质 3~7 个工作日）→ 官方上架 |
| 主要风险点 | ① 大陆上架资质四件套 ② docker.sock 挂载与 host 网络需提前与商务沟通 ③ STUN 功能需向审核方说明功能边界（非 VPN/IP 代理） |

**上架全流程（官方六步）：**

```text
①基于指南完成应用研发 → ②开发者完成自测 → ③邮件提交基础信息
        ↓                                    ↓
⑥应用上架 ← ⑤提交资料审校 ← ④绿联商务对接沟通
```

---

## 一、前期准备

### 1.1 开发与打包环境

| 环境 | 用途 | 说明 |
| --- | --- | --- |
| Debian 12 Linux | 编译镜像、导出 tar、**正式打包 UPK** | UPK 内的 Unix 文件权限只在 Linux 打包时完整保留 |
| Windows / macOS | 可运行 `ugcli create / config / check` | 仅用于创建项目与改配置，**不要用它出上架包** |
| Docker + buildx | 构建多架构镜像并导出 tar | 本项目 Dockerfile 已支持 amd64/arm64 |
| 绿联 NAS 测试机 | 安装 UPK 实测 | UGOS Pro **≥ 1.13.0.0000**（建议升级到最新） |

**安装 ugcli（Linux x86_64）：**

```bash
chmod +x ugcli-linux-amd64
sudo mv ugcli-linux-amd64 /usr/local/bin/ugcli
ugcli --version   # 验证，当前 1.1.0.25
```

Windows 下载 `ugcli-windows-amd64.exe` 重命名为 `ugcli.exe` 并加入 PATH。
下载地址：开发者平台「开发工具 → ugcli」页面。

### 1.2 测试设备获取开发者授权（装 UPK 的前置条件）

1. 邮件联系绿联官方（developers_bd@ugreen.com），提供测试 NAS 的**序列号、MAC 地址、管理员用户名**（查询路径：控制面板 > 关于本机），申请开发者授权。
2. 收到授权文件后重命名为 **`ugdev.sig`**，上传到设备**管理员用户的个人文件夹**。
3. UGOS Pro **≥ 1.16.0.0000** 还需打开「应用中心 > 设置 > 应用开发设置」，点击「授权」完成整机授权；授权到期后在同一位置上传新授权文件更新。

> 未授权的设备无法通过应用中心「手动安装」UPK，也无法进行上架前自测。

### 1.3 开发者入驻与资质材料

**开发者身份认证**（注册时提交，3~7 个工作日）：

- 中国大陆个人开发者：身份证号 + 手机号。
- 中国大陆企业/组织：营业执照 + 统一社会信用代码。
- 境外主体：身份/地址证明，或公司注册证明 + 授权代表证件 + 授权证明。

**中国大陆地区上架的通用资质四件套**（工具类应用同样适用，缺一需提前邮件沟通豁免口径）：

1. **软件著作权归属证明**：《计算机软件著作权登记证书》/《应用程序电子版权证书》/《软件著作权认证证书》任一；非著作权人提交需附完整授权链证明。
2. **ICP 许可/备案**：有许可交许可证；仅备案的提交工信部平台备案截图及备案号。
3. **应用程序备案证明**：工信部政务服务平台的 APP 备案信息截图。
4. **公安联网备案**：全国互联网安全管理服务平台备案截图。

**开源合规（本应用为 MIT 开源，必填）：**

- `source_code_link`：GitHub 仓库 <https://github.com/AbnerSC/NexHomeGo>
- `license_agreement_link`：仓库 LICENSE 页（MIT）
- 同时整理**第三方依赖清单**（Go 模块、`ip2region` xdb、Debian 基础镜像内的 ca-certificates/tzdata 等），在材料中列明各组件许可证。

**隐私政策（必填，审核重点）：**

- 必须是 **HTTPS 直达的静态网页**，无需登录/注册/跳转，不得用图片、Word、博客正文替代。
- 内容需覆盖本应用全部数据行为：数据**全部本地存储**（SQLite，位于数据目录）；出网行为明示——DDNS 同步（阿里云 API）、ACME 签发（Let's Encrypt/ZeroSSL）、STUN 探测（公共 STUN 服务器）、通知推送（用户自配的 SMTP/Webhook/钉钉）、监控探测（用户自配目标地址）。
- 大陆分发还需在应用内提供「已收集个人信息清单、共享清单、第三方 SDK 清单」（本应用无 SDK，写明即可）。

---

## 二、工程适配改造清单（打包前必须完成）

| # | 改造项 | 原因 |
| --- | --- | --- |
| 1 | **镜像 tag 版本化**：发布 `babyfly/nex-home:2.1.1` 等具体版本 tag | 官方规定 compose 的 `image` **禁止 `latest`**，且必须与 tar 内 tag 完全一致 |
| 2 | **导出单架构单 tag 的 tar**：`docker save` 分别产出 amd64/arm64 各一份 | 每个 tar 只允许一个 tag |
| 3 | **确认默认端口 15656 不变** | `project.yaml.port` 与 compose 端口映射、系统健康探测三方一致；上架版**不要引导用户改监听端口**，否则应用中心判定启动失败 |
| 4 | **数据目录保持 `/app/data`** | compose 将用户选择的数据路径挂载到 `/app/data`，程序配置/SQLite/日志全部落在此目录 |
| 5 | **应用图标 256×256 PNG**（`icon.png`） | 官方规范尺寸；开发阶段可用默认图标，**上架必须正式图标** |
| 6 | **版本号对齐**：`internal/core.Version` ↔ `project.yaml.version` | 避免面板内显示版本与商店版本不一致 |

---

## 三、创建应用项目并编写配置

### 3.1 创建项目骨架

```bash
cd ~/ugwork
ugcli create com.abnersc.docker.nexhome
```

交互问答关键选项（其余按需回车）：

- 应用 ID：`com.abnersc.docker.nexhome`（**上架后不可修改**，格式 `com.组织英文名.应用名`）
- 版本：`2.1.1`（与程序版本对齐，格式 `x.y.z`）
- 类别：`utility`（实用工具）
- 架构：`amd64, arm64`
- 产品线：`nasync`
- **是否 Docker 应用：是**（自动生成 images 目录结构）

生成结构（Docker 应用形态）：

```text
com.abnersc.docker.nexhome
├── project.yaml              # 应用配置（下节定制）
├── rootfs_amd64
│   └── images                # 放 amd64 镜像 tar
├── rootfs_arm64
│   └── images                # 放 arm64 镜像 tar
└── rootfs_common             # 仅允许 icon.png 与 docker-compose.yaml
    ├── icon.png
    └── docker-compose.yaml
```

### 3.2 project.yaml（本应用定制示例）

```yaml
spec_version: "2.1"
app_id: com.abnersc.docker.nexhome
version: 2.1.1
support_arch:
  - amd64
  - arm64
product_series:
  - nasync
supports:
  - app
  - pc
is_docker_app: true
only_admin: true          # 运维类工具，仅管理员可访问
port: 15656                # 与 EXPOSE/compose 映射一致
open_type: tab            # 自带完整 Web + 登录体系，浏览器标签页打开
tag_types:
  - utility
depend_fw_version: 1.13.0.0000
depend_docker_version: 1.7.0.0000   # Docker 应用必填，自动生成对 com.ugreen.docker 的强依赖
# 开源合规：使用开源代码时必填
license_agreement_link:
  - https://github.com/AbnerSC/NexHomeGo/blob/main/LICENSE
source_code_link:
  - https://github.com/AbnerSC/NexHomeGo
privacy_policy_link:
  - https://你的域名/privacy.html       # HTTPS 静态页，直达无跳转
technical_support_link:
  - https://github.com/AbnerSC/NexHomeGo/issues
parameters:
  - key: DATA_PATH                     # 用户安装时选择的数据持久化目录
    type: path
    required: true
    changeable: false                  # 装后不允许改，避免数据目录漂移
    i18n:
      en-US:
        name: Data Directory
        description: Directory for config, database and logs (mounted to /app/data)
      zh-CN:
        name: 数据目录
        description: 应用配置、数据库与日志的持久化目录（将挂载到容器 /app/data）
i18n:
  en-US:
    name: NexHome
    description: >-
      All-in-one home network guardian: DDNS sync, STUN NAT traversal,
      WOL wake-on-LAN, SSL certificate automation, website navigation,
      Docker container management, service monitoring and unified alerts.
    author: AbnerSC
    official: https://github.com/AbnerSC/NexHomeGo
    help: https://github.com/AbnerSC/NexHomeGo/blob/main/README.md
    publisher: AbnerSC
    publisher_link: https://github.com/AbnerSC
  zh-CN:
    name: NexHome｜联枢
    description: >-
      一站式内网节点守护工具：DDNS 域名同步、STUN 端口穿透、WOL 网络唤醒、
      SSL 证书自动申请续期、网站导航、Docker 容器管理运维、服务可用性监控、
      统一告警通知与状态仪表盘。单进程轻量服务，数据全部本地存储。
    author: AbnerSC
    official: https://github.com/AbnerSC/NexHomeGo
    help: https://github.com/AbnerSC/NexHomeGo/blob/main/README.md
    publisher: AbnerSC
    publisher_link: https://github.com/AbnerSC
```

要点说明：

- **原生应用才需要 `start_cmd`**，Docker 应用不配置（由 compose 拉起）。
- `port: 15656` 是系统探测应用存活的依据；系统还会为应用分配专属的 HTTP/HTTPS 网关端口，并原生支持 UGREENlink 远程访问。
- `parameters` 中声明的 key 会作为环境变量/变量注入 compose，`DATA_PATH` 用于数据持久化挂载；**禁止使用 `UGAPP_` 前缀**（系统保留）。
- 若未来声明 `permissions`（本应用不需要），`depend_fw_version` 不得低于权限最低版本。

### 3.3 docker-compose.yaml（本应用定制示例）

```yaml
services:
  nex-home:
    # 必须与 rootfs_{arch}/images/ 内 tar 的镜像 tag 完全一致；禁止 latest
    image: docker.io/babyfly/nex-home:2.1.1
    container_name: nex-home
    restart: unless-stopped
    network_mode: bridge
    ports:
      - "15656:15656"            # 与 project.yaml.port 一致
    volumes:
      - ${DATA_PATH}:/app/data  # 安装参数：用户选择的数据目录
      # - /var/run/docker.sock:/var/run/docker.sock   # 可选：启用 Docker 容器管理模块（见下文风险说明）
    environment:
      - TZ=${TZ}               # 内置变量：系统安装时自动注入时区
      - DOCKER_HOST=unix:///var/run/docker.sock
    deploy:
      resources:
        limits:
          memory: 256m
    ulimits:
      nofile:
        soft: 65535
        hard: 65535
    healthcheck:
      test: ["CMD-SHELL", "exec 3<>/dev/tcp/127.0.0.1/15656 && echo -n '' >&3"]
      interval: 10s
      timeout: 3s
      retries: 3
      start_period: 20s
```

**官方安全红线（打包时会检测告警）：**

- 禁止 `privileged`、`cap_add`、host `pid`/`ipc`；**避免 host 网络**。
- compose 只能引用 `parameters` 声明的 key 或内置变量（当前仅 `TZ`），出现未定义变量会校验失败。

**两个需要提前与绿联商务邮件沟通确认的取舍**（决定最终提交哪个版本）：

| 方案 | 网络模式 | docker.sock | STUN 穿透任务 | 审核风险 |
| --- | --- | --- | --- | --- |
| A（推荐首发） | bridge + 端口映射 | 不挂载 | 不可用（面板提示未连接/受限） | 低，过审概率高 |
| B（功能完整版） | host | 挂载 | 完整可用（打洞+保活） | 中，`host`/`sock` 会触发打包告警，需商务放行 |

> 建议首发提交方案 A，详情页/帮助文档注明「STUN 穿透与 Docker 容器管理功能在绿联商店版中默认关闭，如需完整功能请参考官方文档自行部署」；商务沟通通过后再切换方案 B 提交更新版。

---

## 四、准备镜像 tar 与图标

### 4.1 构建并导出镜像（amd64 与 arm64 各一份）

```bash
# amd64（在 x86_64 机器上）
docker buildx build --platform linux/amd64 \
  --build-arg VERSION=2.1.1 -t docker.io/babyfly/nex-home:2.1.1 --load .
docker save -o nex-home-2.1.1-amd64.tar docker.io/babyfly/nex-home:2.1.1

# arm64（x86_64 上走 QEMU 模拟，较慢；也可在 arm 机器或 CI 中构建）
docker buildx build --platform linux/arm64 \
  --build-arg VERSION=2.1.1 -t docker.io/babyfly/nex-home:2.1.1 --load .
docker save -o nex-home-2.1.1-arm64.tar docker.io/babyfly/nex-home:2.1.1
```

注意事项：

- **每个 tar 只能含一个 tag**，且与 compose `image` 完全一致（含 `docker.io/` 前缀）。
- 若 CI 已推送多架构 manifest，可分别 `docker pull --platform linux/amd64 docker.io/babyfly/nex-home:2.1.1` 后 `docker save` 当前架构镜像。
- tar 放入对应目录：

```bash
cp nex-home-2.1.1-amd64.tar rootfs_amd64/images/
cp nex-home-2.1.1-arm64.tar rootfs_arm64/images/
```

### 4.2 图标

- 尺寸 **256×256**，PNG 格式，命名为 `icon.png` 放入 `rootfs_common/`。
- 风格需与 UGOS Pro 应用中心观感协调；不得使用绿联官方图标或易混淆的相似标识（知识产权审核项）。

---

## 五、检查与打包

```bash
cd com.abnersc.docker.nexhome

# 1. 配置与目录结构检查
ugcli check

# 2. 打包（Linux 环境执行；--build 为构建号，与 version 组成最终版本号）
ugcli pack --build 1
# 只打单架构：ugcli pack --build 1 --arch amd64
# 产品线筛选：ugcli pack --build 1 --product-series nasync（必须在 product_series 列表内）
```

产物位于 `build_dir/pkgs/upk/`（或 `build_dir/`），命名：

```text
amd64_nasync_com.abnersc.docker.nexhome_2.1.1.0001.upk
arm64_nasync_com.abnersc.docker.nexhome_2.1.1.0001.upk
```

版本号规则：`version: 2.1.1` + `--build 1` → `2.1.1.0001`；同一 `x.y.z` 下每次提交新包**构建号必须递增**（`0.1.0.0001 → 0.1.0.0002`），版本比较按四段逐段比大小。

---

## 六、安装测试（自测）

### 6.1 安装

1. 将与设备匹配的 UPK（NAS 设备用 `*_nasync_*.upk`）拷贝到 NAS。
2. 应用中心 → 右上角「手动安装」→ 选择 UPK 文件 → 按向导安装。
3. 安装时按提示填写「数据目录」等安装参数。
4. 安装后在应用中心「已安装」列表找到应用，点击打开。

### 6.2 日志与初始密码

- 应用（容器）标准输出/错误日志：`/var/packages/com.abnersc.docker.nexhome/log/com.abnersc.docker.nexhome.log`；也可在 UGOS Docker 套件的容器日志中查看。
- **首次启动随机初始密码打印在控制台日志**（形如「首次启动，已生成随机初始密码……」，16 位含大小写/数字/符号）。安装后从上述日志读取密码登录，并**立即在「系统设置 → 修改登录密码」更换**。

### 6.3 自测清单（提交自测报告的依据）

| 模块 | 验证点 |
| --- | --- |
| 安装启动 | UPK 双架构（amd64/arm64 机型各测一台）安装成功、应用中心显示「运行中」、点击 tab 正常打开面板 |
| 登录安全 | 初始密码可登录；改密后生效；连续失败 3 次锁定来源 IP 生效 |
| 数据持久化 | 重启应用/设备后配置与数据保留（数据目录卷生效）；应用内「配置备份导出」可用 |
| DDNS | 阿里云凭证配置后同步任务跑通、日志记录正常 |
| SSL 证书 | DNS01 全流程（商店版 bridge 网络下 HTTP01 依赖 80 端口转发，按实际场景测试） |
| WOL | 向局域网设备发送魔术包成功唤醒 |
| 监控告警 | HTTP/TCP/UDP 探测 up/down 切换并触发 Webhook/邮件/钉钉通知 |
| 仪表盘 | 总览数据正常渲染，无 JS 报错 |
| Docker 模块 | 方案 A：应提示未连接（不挂 sock 属预期）；方案 B：容器列表/启停/日志正常 |
| 升级 | 旧版本 UPK → 新版本 UPK 覆盖安装，数据完整保留 |
| 卸载 | 卸载应用（注意：系统会同步删除 data/log/cache 目录，隐私政策中需告知用户先备份） |

> 测试期间若应用运行异常，优先查看上述日志文件排查；应用停止是系统向容器发 SIGTERM，程序已支持优雅退出（10 秒内）。

---

## 七、提交审核与上架

### 7.1 邮件提交基础信息（第③步）

发送至 **developers_bd@ugreen.com**，按官网「联系我们」处的邮件模板（`template-zh.docx`）填写，至少包含：

- 主体信息（个人/企业、身份认证材料）
- 联系方式
- 套件名称与主要功能（NexHome｜联枢 + 功能简介）
- 拟上架产品线：**nasync（绿联 NAS）**；若同时申请 HomeAgent 需分别提交对应安装包并标明

### 7.2 商务对接（第④步）需敲定的事项

1. **docker.sock 挂载与 host 网络是否放行**（方案 A/B 二选一，见 3.3）。
2. **STUN 穿透功能定性说明**：本应用 STUN 模块是基于 RFC 5389/8489 标准协议的 **NAT 穿透工具**，用于让用户**自有**内网服务（NAS、摄像头、Home Assistant 等）在无公网 IP 场景下可被远程访问；**不提供 VPN 隧道、不做流量代理转发、不提供 IP 切换/翻墙能力**。请在材料中主动写明，避免被误判到禁止清单第九类第 3 条（VPN/IP 代理类）。
3. 大陆资质材料适用性确认（个人开发者、免费工具类：软著/备案等四件套的具体口径）。
4. HomeAgent 产品线是否上架（`product_series` 增加后需另打 `homeagent` 包）。

### 7.3 提交审校材料清单（第⑤步）

| 材料 | 要求 |
| --- | --- |
| UPK 安装包 | amd64 + arm64 各一份（`*_nasync_*`），版本/构建号符合规则 |
| 自测报告 | 按 6.3 清单出具，注明测试机型（如 DXP4800 Plus 等）与 UGOS Pro 版本 |
| 承诺函 | 官方模板，签署完整 |
| 主体与身份材料 | 与开发者身份认证一致 |
| 资质四件套 | 软著证书、ICP 备案/许可、APP 备案、公安联网备案（大陆上架） |
| 隐私政策链接 | HTTPS 静态页，内容与应用实际行为一致 |
| 开源声明 | `source_code_link` + `license_agreement_link` + 第三方依赖清单 |
| 功能边界说明 | STUN/DDNS 用途与合规性说明（见 7.2 第 2 条） |
| 应用素材 | 正式图标、应用截图（可复用 `docs/ScreenShot_*.png`，需真实反映功能）、描述文案 |

### 7.4 审核要点自查（对照官方《审核规则与要点》）

- **安全合规**：无病毒/木马/后门；面板自带登录鉴权 + 失败锁定 + 单点登录；不私开管理端口（默认仅监听声明端口）；不挖矿、不暗刷、无勒索行为；动态更新会重新提交审核。
- **隐私合规**：数据本地化存储；出站行为已在隐私政策中逐项披露；不偷扫用户文件（本应用仅按功能访问用户显式配置的目标）。
- **知识产权**：MIT 开源、权利链清晰；图标/文案原创；第三方组件（Go 依赖、ip2region xdb 等）已列明许可。
- **未成年人保护**：纯工具类，建议年龄分级 3+，无相关风险内容。
- **禁止清单核对**：不含政治/暴恐/诈骗/色情/赌博内容；**非 VPN、非 IP 代理切换**；不含「网络兼职/网赚」等类目。

### 7.5 审核与发布

- 平台形式审核 + 功能测试；资质审核通常 **3~7 个工作日**（节假日顺延），整体以平台进度为准。
- 问题项会反馈整改，修复后**构建号递增**重新打包提交，并在备注中说明整改措施。
- 审核期间不能修改已提交版本；如需调整先撤回再提新包。
- 审核通过后由**绿联官方运营统一在应用中心上架发布**，用户即可一键安装。

---

## 八、版本更新流程

1. 代码合入 → CI 出多架构镜像并推送版本 tag（如 `2.2.0`）。
2. 更新 `project.yaml` 的 `version`（`x.y.z`）与 `docker-compose.yaml` 的 `image` tag。
3. 重新导出双架构 tar 放入 `rootfs_{arch}/images/`（删除旧 tar，避免混入多 tag）。
4. `ugcli pack --build N`（同一 `x.y.z` 下 N 递增；新 `x.y.z` 从 1 开始）。
5. 自测（重点：**旧数据升级兼容**、SQLite schema 迁移、配置项兼容）。
6. 邮件提交新 UPK + 更新说明与更新日志，重新审核。
7. 应用中心会向已安装用户推送更新（用户端支持一键更新全部待更新应用）。

---

## 九、常见问题（FAQ）

**Q1：NAS 包装不上 / 应用中心搜不到？**
确认产品线匹配：NAS 只装 `*_nasync_*.upk`；HomeAgent 与 NAS 包互不兼容。应用中心按设备产品线拉取云端列表。

**Q2：安装后打不开面板？**
依次检查：① 应用中心显示的运行状态与日志（`/var/packages/{appid}/log/{appid}.log`）；② compose 端口映射是否与 `port: 15656` 一致；③ 系统网关分配的应用专属端口是否被面板「访问与安全设置」改过端口（商店版禁止改）。

**Q3：忘记初始密码？**
停止应用 → 删除数据目录下 `nexhome.db` 中 `app_config` 表的 `auth.password` 行 → 重启应用重新生成随机密码并打印到日志。

**Q4：为什么因「功能太简单」「套壳」被驳回？**
应用需提供区别于网页打包的独特价值。本应用为原生功能集成，提交时附完整功能截图与自测报告即可；避免与在先上架应用高度相似。

**Q5：隐私政策审核失败的常见原因？**
链接打不开、未列明实际申请的所有敏感权限/数据行为、未同意先收集。对照 1.3 节隐私政策要点逐项自查。

**Q6：可以加急审核吗？**
原则上不支持，先到先审；建议提前 2 周准备材料。

**Q7：同时上架 NAS 和 HomeAgent？**
需要两个包。`product_series` 同时声明 `nasync`/`homeagent` 后 `ugcli pack` 会各打一份，分别提交并标明产品线；Docker 应用能否上 HomeAgent 需先联系绿联确认。

**Q8：Windows 上打出来的包能直接提交吗？**
不能。Windows 文件系统无 Unix 执行位，权限不完整；**上架包必须在 Linux 用 `ugcli pack` 生成**。

---

## 十、附录

### 10.1 官方文档索引

| 文档 | 地址 |
| --- | --- |
| 开发准备 | <https://developer.ugnas.com/doc/backend/quick-start/prepare.html> |
| 打包 Docker 应用 | <https://developer.ugnas.com/doc/backend/quick-start/develop-docker-app.html> |
| 测试应用 | <https://developer.ugnas.com/doc/backend/quick-start/testing.html> |
| 发布应用 | <https://developer.ugnas.com/doc/backend/quick-start/publish.html> |
| project.yaml 配置说明 | <https://developer.ugnas.com/doc/tools/project-yaml.html> |
| ugcli 使用指南 | <https://developer.ugnas.com/doc/tools/ugcli.html> |
| 产品线与机型支持 | <https://developer.ugnas.com/doc/backend/application/product-series.html> |
| 运行环境 | <https://developer.ugnas.com/doc/backend/application/runtime-environment.html> |
| 应用端口 | <https://developer.ugnas.com/doc/backend/application/app-port.html> |
| 登录审核规则 | <https://developer.ugnas.com/doc/review/app-review/audit-key-points.html> |
| 禁止上架应用清单 | <https://developer.ugnas.com/doc/review/app-review/prohibited.html> |
| 上架流程页（含邮件模板下载） | <https://developer.ugnas.com/doc/flow> |

### 10.2 NexHomeGo 关键参数速查

| 参数 | 值 |
| --- | --- |
| 默认端口 | `15656`（`internal/core/config.go` `defaultPort`） |
| 数据目录 | 容器内 `/app/data`（配置 `nexhome.properties`、SQLite `nexhome.db`、日志、证书均在此） |
| 当前版本 | `2.1.1`（`internal/core/version.go`） |
| 镜像 | `docker.io/babyfly/nex-home`（amd64/arm64 双架构，运行时基于 debian:bookworm-slim） |
| Dockerfile 版本注入 | `--build-arg VERSION=x.y.z` → ldflags `-X NexHomeGo/internal/core.Version` |
| 健康检查 | bash `/dev/tcp/127.0.0.1/15656` 探测（镜像内置 curl 可选 `curl -f`） |
| 首次密码 | 随机生成打印控制台日志，无固定默认密码 |

### 10.3 本项目联系方式

- GitHub Issues（技术支持入口）：<https://github.com/AbnerSC/NexHomeGo/issues>
- 交流 QQ 群：见 README「加入群聊」二维码
