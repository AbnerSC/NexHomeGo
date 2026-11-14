# NexHomeGo 安全审计报告

- **审计对象**：NexHomeGo v2.1.0（Go 家庭 NAS 管理面板，`D:\goland-workspace\NexHomeGo`）
- **审计方式**：白盒代码审计 + 黑盒渗透测试（隔离实例实际攻击）
- **重点区域**：登录、代理中心、接口访问令牌（按用户要求），并覆盖全部模块
- **交付范围**：扫描/攻击方式、结论、漏洞说明、修复结果、复测结果

---

## 1. 扫描与攻击方式

### 1.1 白盒审计（源码逐模块审查）

| 模块 | 审计要点 |
|---|---|
| `internal/auth` | 密码哈希算法、恒定时间比较、失败锁定、单点登录、token 生命周期 |
| `internal/web`（access_token / access_config / ctx / server） | Access-Token 校验链、`?token=` 查询参数白名单、来源 IP 解析信任链、安全响应头 |
| `internal/module/proxy`（engine/handler/tunnel/site/static/cache/sslstore/errorpage） | 路径规范化、目录穿越、zip 解压、BasicAuth、Host 处理、回源头改写、缓存键、错误页渲染 |
| `internal/module/{ddns,notify,nav,wol,docker,cert,monitor,diag,stun}` | SQL 参数化、文件白名单、上传校验、SMTP 头注入、凭证回显、ACME 免登录面 |
| 前端（`internal/web/web/js/*`） | XSS 输出转义（`esc`）覆盖面 |

### 1.2 黑盒渗透（隔离实例 `127.0.0.1:8090`，代理监听 `8092`，Node.js 攻击脚本 `.tmp/bb1~bb6_*.js`）

| 脚本 | 攻击内容 |
|---|---|
| bb1_auth.js | 密码爆破触发锁定、锁定态验证、路径变体绕过（`//`、`/./`、`%2e%2e`、大小写）、未授权访问探测 |
| bb2_bypass.js | **X-Forwarded-For / X-Real-IP / CF-Connecting-IP 逐次轮换绕过登录锁定**（V-HIGH-1 实锤）、锁定态 token 实际可用性验证 |
| bb3_token.js | Access-Token 在线爆破、`?token=` 写操作拒绝、单点登录踢出、token 类型隔离 |
| bb4_proxy.js | 代理站点矩阵攻击：V1 错误页泄露复现、BasicAuth 爆破 50 次、恶意 Host 注入、静态站点目录穿越（6 种编码变体）、`guardDataDir` 直取 DB |
| bb5_deep.js | Access-Token 绝对桶 61 次验证、手写 ZIP 构造 zip-slip 恶意包上传、CSP/XFO/nosniff 检查、日志 token 泄露 |
| bb6_retest.js | 修复后完整复测（含正常功能回归） |

---

## 2. 审计结论总览

| 编号 | 漏洞 | 等级 | 状态 |
|---|---|---|---|
| V-HIGH-1 | 登录失败锁定可被伪造转发头完全绕过 | **高危** | ✅ 已修复并复测通过 |
| V1 | 代理 502/504 错误页回显内网后端地址与 OS 错误原文 | 中危 | ✅ 已修复并复测通过 |
| V2 | 代理站点 BasicAuth 无失败锁定（无限在线爆破） | 中危（公网站点） | ✅ 已修复并复测通过 |
| V3 | `basicAuth.pass` 经 API 明文回显 | 低危（定性说明） | 不修改（见 3.4） |
| V6 | DDNS/云厂商 `access_key_secret` 经 API 明文回显 | 低危（定性说明） | 不修改（见 3.4） |
| V4 | Access-Token 明文回显（设置页） | 提示项（设计如此） | 不修改 |
| V5 | 密码 SHA-256 无盐 | 提示项（可接受） | 不修改 |

其余全部攻击面（登录路径变体、未授权访问、令牌探测限速、zip-slip、目录穿越、Host 注入、SMTP 头注入、SVG XSS、上传穿越等）**白盒+黑盒双重验证均未发现可利用问题**（详见第 6 节）。

---

## 3. 漏洞说明

### 3.1 V-HIGH-1：登录失败锁定可被伪造转发头完全绕过【高危】

- **攻击方式**（黑盒实测，bb2_bypass.js）：
  1. 面板默认 `auto` 信任策略下，本机/内网直连者自带 `X-Forwarded-For` 头即可让锁定键包含该头；
  2. 错误密码 + 每次轮换一个伪造 XFF（`X-Forwarded-For: 1.2.3.4` → `1.2.3.5` …），**连续 20 次全部 401，零 429**——失败计数桶被逐次换键清零；
  3. 更严重：触发锁定后，携带 `X-Forwarded-For: 8.8.8.8` + **正确密码** 直接返回 200 并签发有效 token，可正常访问全部 API。
- **根因**（白盒定位）：
  - `internal/web/system_routes.go` 的 `loginLockKey()` 使用 `core.TrustForwardedFrom(peer)`（auto 策略信任私网/回环对端），且锁定仅有**单一细分桶**（键=对端|XFF），无对端维度硬上限；
  - 对比：Access-Token 校验同文件内已采用「显式可信代理 + 双桶」正确实现，登录路径未对齐。
- **危害**：攻击者可对登录口无限速在线爆破；已锁定的会话防线可被一个请求头击穿。

### 3.2 V1：代理错误页泄露内网拓扑【中危】

- **攻击方式**（bb4/bb5 实测）：创建指向不可达内网地址的站点（`http://192.168.99.99:1234`），匿名访客请求该站点，502 错误页「详情」区域原文回显：
  `后端连接失败: dial tcp 192.168.99.99:1234: connectex: No connection could be made because the target machine actively refused it.`
- **根因**：`internal/module/proxy/handler.go` `connectFailed()` 将 `err.Error()` 直接拼入对外错误页；`beginRelay()` 的「请求构造失败」分支同理回显 500 明细。
- **危害**：公网访客可免费测绘内网地址段、端口开放状态（refused=端口无服务 / 连接后关闭=有服务）与操作系统指纹，为内网横向攻击提供情报。

### 3.3 V2：代理站点 BasicAuth 无失败锁定【中危，公网站点】

- **攻击方式**（bb4 实测）：对启用 BasicAuth 的站点连发 50 次错误凭据（`Authorization: Basic admin:wrongN`），**全部 401，零限速、零锁定**。
- **根因**：`handler.go` `checkBasicAuth()` 虽使用恒定时间比较，但调用点无失败计数与锁定逻辑。
- **危害**：BasicAuth 常用于将内网服务暴露公网，凭据可被在线无限爆破。

### 3.4 定性说明（不修改项）

- **V3/V6 凭证明文回显**：`GET /api/proxy/sites`（basicAuth.pass）、`GET /api/ddns/tasks` 与 `GET /api/provider/configs`（access_key_secret）回显明文。经定性：本系统为**单用户面板**，上述接口全部要求登录态，回显对象即管理员本人，**无权限边界突破**；配置编辑场景需要原值回显（Access-Token 同理，见 V4）。**加固建议**：后续版本可改为掩码显示（`****`）+ 留空不更新语义。
- **V5 SHA-256 无盐**：登录口有失败锁定（3 次/30 分钟）+ 16 位随机初始密码，在线爆破不可行；离线拖库场景建议后续换 bcrypt/argon2。**可接受**。

---

## 4. 修复结果

| 修复项 | 文件 | 变更内容 |
|---|---|---|
| Fix-1（V-HIGH-1） | `internal/auth/auth.go` | 登录失败锁定改为**双桶**：细分桶（键=锁定键）+ **绝对桶**（键=TCP 对端 `LoginPeerMaxFails=30`，不可伪造的失败硬上限）；`Login(password, lockKey, peer)` / `recordFailure` / `LockRemainingMs` 取两桶较大锁定时间；成功登录清两桶 |
| Fix-1（V-HIGH-1） | `internal/web/system_routes.go` | `loginLockKey()` 改用 `core.TrustForwardedFromExplicit(peer, core.TrustProxyMode())`——**仅显式配置的可信代理**才采信转发头细分，auto 私网/回环不再作为信任依据；调用点传入 `peer` |
| Fix-1 回归测试 | `internal/auth/hash_test.go` | 适配新签名；新增 `TestFailureLockoutAbsoluteBucket`（伪造转发头逐次换键 30 次后必须整体锁定且不波及其它对端） |
| Fix-2（V1） | `internal/module/proxy/handler.go` | `connectFailed()` 全部对外分支改为通用文案（超时/报文非法/无法访问），`err.Error()` 明细仅入 `noteError()`（管理员可见的站点错误记录）；「请求构造失败」500 分支同理；EOF 分支文案一并通用化（消除端口状态探测差异） |
| Fix-3（V2） | `internal/module/proxy/handler.go` | 新增 BasicAuth 失败锁定：键=TCP 对端（转发头无关、不可伪造）、连续失败 **10 次**锁定 **15 分钟**、锁定期直接 429 并带 `Retry-After`（不再发 401 挑战）、认证成功清零、计数桶容量上限 4096 防内存放大 |

**质量验证**：`go build ./...` 通过；`go test ./...` 全部通过（含新增绝对桶回归测试）。

---

## 5. 复测结果（bb6_retest.js，修复后二进制）

### 5.1 V-HIGH-1（显式可信代理场景还原原攻击路径）

| 测试 | 修复前 | 修复后 | 结论 |
|---|---|---|---|
| 合法 XFF 逐次轮换错误密码 ×40 | 40 次全 401，零锁定 | 首次 429=**第 31 次**（401×30, 429×10），绝对桶 30 次精确生效 | ✅ 爆破封死 |
| 锁定期 XFF+正确密码 | **200**（签发有效 token） | **429** | ✅ 绕过封死 |
| 锁定期 X-Real-IP / CF-Connecting-IP+正确密码 | 200 | **429** ×2 | ✅ 全部伪造头无效 |
| 正常登录 / 已登录会话访问 API | 200 | 200 | ✅ 无误伤 |

### 5.2 V1（不可达后端 192.168.99.99:1234）

| 测试 | 修复前 | 修复后 | 结论 |
|---|---|---|---|
| 502 错误页泄露检测（`192.168.99.99` / `dial tcp` / `connectex` / `refused`） | 命中，明文回显 | **零命中**；文案=「后端暂时无法访问，请稍后重试」 | ✅ 泄露消除 |

### 5.3 V2（BasicAuth 站点 admin/S3cret-Pass-xyz）

| 测试 | 修复前 | 修复后 | 结论 |
|---|---|---|---|
| 错误凭据 ×12 | 12 次全 401，零限速 | 首次 429=**第 11 次**（401×10, 429×2），阈值 10 精确生效 | ✅ 爆破封死 |
| 锁定期正确凭据 | -（可继续爆破） | **429**，`Retry-After: 900` | ✅ 锁定有效 |
| 锁定期无凭据 | 401 挑战 | **429**（不再发挑战） | ✅ |
| 锁定期伪造 XFF | - | **429**（键=TCP 对端不可伪造） | ✅ |
| 锁定桶为空时正确凭据 | 200 | **200 BACKEND-OK** | ✅ 无误伤 |

### 5.4 正常功能回归

| 测试 | 结果 |
|---|---|
| 面板登录 / 会话 API / 代理设置保存 | 200 ✅ |
| 正常反向代理（audit.example.com → 后端） | 200 BACKEND-OK ✅ |
| 通配域名匹配（wild.example.com） | 200 ✅ |

> 附注：复测过程中发现并修复了 Fix-3 实现中的一个缺陷（`basicAuthLockedMs` 曾把「未锁定但在计数」的活跃条目误回收，导致计数永远无法达到阈值），已在本次复测前修正并通过上述全部用例。

---

## 6. 防护面确认清单（攻击未成功项，双重验证）

| # | 攻击面 | 验证结果 |
|---|---|---|
| 1 | 登录接口路径变体绕过（双斜杠/点段/URL 编码/大小写） | 全部 400/404，无法绕过路由规范化 |
| 2 | 未授权访问全部 /api 接口 | 一律 401 |
| 3 | Access-Token 在线爆破 | 双桶限速：细分 10 次/绝对 60 次；第 48 次实测 429，锁定后伪造 XFF 仍 429 |
| 4 | `?token=` 承载写操作 | POST/PUT 带 `?token=` 一律 401（仅 GET/HEAD 放行） |
| 5 | Access-Token 与会话 token 互通 | 互不认可；单点登录不影响 Access-Token |
| 6 | 静态站点目录穿越（6 种编码变体） | 全部 400/307，`hasDotDotSegment` 原始+解码双检 |
| 7 | zip-slip 恶意压缩包上传（手写 ZIP 构造 `../` 条目） | 解压即拒绝：「压缩包包含上跳路径（..），已拒绝」 |
| 8 | 站点根指向 data 目录（拖库） | `guardDataDir` 400 拒绝 |
| 9 | 恶意 Host 注入（XSS 载荷进统计） | Go 原生 `malformed Host header` 400 拒绝，不入库 |
| 10 | 伪造回源头冒充内网来源 | 回源前强制剥离 `X-Real-IP`/`Forwarded`/`CF-Connecting-IP`，XFF 按显式可信代理重写 |
| 11 | 面板登录响应头 | CSP / X-Frame-Options / nosniff 齐全 |
| 12 | 代理错误页安全头 | nosniff + CSP |
| 13 | 日志泄露 `?token=` | 日志中无 token 明文 |
| 14 | SVG 图标 XSS | `nosniff` + `CSP sandbox` 双防护 |
| 15 | SMTP 头注入（收件人拼接换行） | `splitRecipients` 以 CRLF 为分隔符拆解，注入被阻断 |
| 16 | 邮件 HTML 注入 | `htmlEscape` 全量转义 |
| 17 | 上传图标路径穿越 | UUID 重命名 + `iconNameRe` 白名单 + `withinDir` 双保险 |
| 18 | SQL 注入（全部模块） | 全参数化查询，无拼接 |
| 19 | Docker 容器 ID / compose 项目名注入 | `idRe` 白名单正则 |
| 20 | 证书私钥下载越权 | `file` 参数白名单 switch；私钥落盘 0600+原子写 |

---

## 7. 加固建议（非必改）

1. **凭证掩码**：DDNS/云厂商 Secret、BasicAuth 密码改为掩码显示 + 留空不更新（消除 V3/V6 回显面）。
2. **密码哈希升级**：SHA-256 → bcrypt/argon2id（应对离线拖库场景）。
3. **锁定通知**：BasicAuth 锁定目前仅写代理日志，可接入通知中心（对齐登录锁定的 `auth.lockout` 扇出）。
4. **代理口 HTTPS**：测试实例提示「证书库为空 HTTPS 握手终止」，生产启用代理 HTTPS 前需先完成证书签发。

---

*审计与修复脚本存档：`.tmp/bb1_auth.js` ~ `.tmp/bb6_retest.js`（隔离实例数据目录 `.tmp/audit-instance/`，审计后可删除）。*
