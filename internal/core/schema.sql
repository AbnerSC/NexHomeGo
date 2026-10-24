-- =============================================================
-- NexHome SQLite 建表脚本（程序启动时自动执行，均为 IF NOT EXISTS）
-- 数据库文件位于程序运行目录：./data/nexhome.db
-- =============================================================

-- 全局配置表（登录密码哈希、ZeroSSL EAB 凭证、ACME 邮箱等）
CREATE TABLE IF NOT EXISTS app_config (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- 服务商凭证配置表（云服务商 AccessKey 等，DDNS / SSL 证书 DNS01 按名称选择引用）
-- provider_type : 服务商类型（ALIYUN 等，清单见 internal/module/provider/provider.go 的 providerTypes，后续可扩展）
-- esa_site_id   : 可选，仅阿里云 ESA 使用；DDNS 任务选择配置后自动带出（可按任务覆盖），
--                  证书 DNS01 在云解析定位不到域名（托管在 ESA）时自动用该站点写入 TXT
CREATE TABLE IF NOT EXISTS provider_config (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT NOT NULL,
    provider_type     TEXT NOT NULL DEFAULT 'ALIYUN',
    access_key_id     TEXT NOT NULL,
    access_key_secret TEXT NOT NULL,
    esa_site_id       TEXT,
    created_at        TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

-- 全局操作日志表（所有模块统一写入，支持分页查询）
CREATE TABLE IF NOT EXISTS op_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    time    TEXT NOT NULL,
    module  TEXT NOT NULL,
    level   TEXT NOT NULL,
    message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_op_log_id ON op_log (id DESC);

-- DDNS 同步任务表
-- provider : ALIYUN_DNS（云解析） / ALIYUN_ESA（边缘安全加速）
-- ip_mode  : LOCAL（本机网卡） / MANUAL（手动输入） / PUBLIC（公网接口）
-- provider_config_id : 引用服务商凭证配置（provider_config.id）；为空时使用任务内手动填写的 AccessKey
CREATE TABLE IF NOT EXISTS ddns_task (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    name               TEXT NOT NULL,
    provider           TEXT NOT NULL,
    domain             TEXT NOT NULL,
    rr                 TEXT NOT NULL,
    type               TEXT NOT NULL DEFAULT 'A',
    ttl                INTEGER NOT NULL DEFAULT 600,
    ip_mode            TEXT NOT NULL DEFAULT 'PUBLIC',
    manual_ip          TEXT,
    local_nic          TEXT,
    provider_config_id INTEGER,
    access_key_id      TEXT,
    access_key_secret  TEXT,
    esa_site_id        TEXT,
    record_id          TEXT,
    interval_sec       INTEGER NOT NULL DEFAULT 300,
    enabled            INTEGER NOT NULL DEFAULT 1,
    last_ip            TEXT,
    last_sync          TEXT,
    last_status        TEXT,
    created_at         TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

-- STUN 穿透任务表
-- protocol     : TCP / UDP
-- status       : STOPPED / RUNNING / ERROR
-- peer_addr    : TCP 打洞对端公网地址（ip:port，可空）
-- upnp_enabled : 是否启用 UPnP 端口映射（路由器不支持 UPnP 时可关闭，避免无谓的 SSDP 发现等待）
-- punched_at   : 穿透成功时间（本次运行首次取得外网映射地址的时刻）
-- check_time / check_result : 可用性自测（穿透后测试一次）的时间与结果
-- webhook_config : 可选，穿透结果同步的 webhook 列表（JSON 数组，每项 {url,method(GET/POST),headers,params}），
--                  穿透成功 / 外网映射地址变化时推送结果，支持多个、自定义请求头与参数（值支持 ${字段} 占位符）
-- webhook_status : 各 webhook 最近一次调用结果（JSON 对象，url -> {time,result}），result 为成功/失败原因（如 OK(HTTP 200) / FAIL(...)）
-- esa_sync_enabled : 是否把穿透结果同步到阿里云 ESA（边缘安全加速）：映射 IP 写解析记录、映射端口写回源 HTTPS 端口
-- provider_config_id : 引用服务商凭证配置（唯一凭证入口，AK/SK 实时读取；删除配置时本列置空并停用同步）
-- esa_site_id   : 选中的 ESA 站点 SiteId（表单从线上站点列表选择，不手填）
-- esa_records   : 勾选待更新的解析记录（JSON 数组，元素 {id,name}；id 为线上 RecordId，name 为名称快照供 id 失效时回退）
-- esa_rules     : 勾选待更新的回源规则（JSON 数组，元素 {id,name}；id 为 ConfigId，仅 TCP 任务改回源端口）
-- esa_sync_status : 最近一次 ESA 同步结果（JSON 对象 {time,result,mapped_addr,items}），
--                  items 每项 {kind(record|rule),name,from,to,state(OK|SKIP|FAIL),msg}，供前端展示与手动重试
-- notify_enabled  : 是否把穿透结果投递到统一告警通知中心（触发点与 webhook 一致：首次穿透成功、映射地址变化）
-- notify_channels : 勾选的通知渠道 id（JSON 数组，如 [1,3]，引用 notify_channel.id；渠道被删除/停用时投递自动跳过）
CREATE TABLE IF NOT EXISTS stun_task (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    protocol      TEXT NOT NULL DEFAULT 'UDP',
    target_ip     TEXT NOT NULL,
    target_port   INTEGER NOT NULL,
    bind_port     INTEGER NOT NULL DEFAULT 0,
    stun_host     TEXT NOT NULL DEFAULT 'stun.l.google.com',
    stun_port     INTEGER NOT NULL DEFAULT 19302,
    keepalive_sec INTEGER NOT NULL DEFAULT 25,
    peer_addr     TEXT,
    upnp_enabled  INTEGER NOT NULL DEFAULT 1,
    enabled       INTEGER NOT NULL DEFAULT 0,
    status        TEXT NOT NULL DEFAULT 'STOPPED',
    mapped_addr   TEXT,
    nat_type      TEXT,
    punched_at    TEXT,
    check_time    TEXT,
    check_result  TEXT,
    webhook_config TEXT,
    webhook_status TEXT,
    esa_sync_enabled INTEGER NOT NULL DEFAULT 0,
    provider_config_id INTEGER,
    esa_site_id   TEXT,
    esa_records   TEXT,
    esa_rules     TEXT,
    esa_sync_status TEXT,
    notify_enabled INTEGER NOT NULL DEFAULT 0,
    notify_channels TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

-- STUN 穿透流量统计表（按任务累积转发字节，连接重建不清零）
-- period_type : TOTAL（累计总量，period_key 恒为 all）/ HOUR / DAY / MONTH
-- period_key  : HOUR=yyyy-MM-dd HH / DAY=yyyy-MM-dd / MONTH=yyyy-MM / TOTAL=all（键字典序即时间序）
-- bytes       : 该时间桶累计转发的字节数（双向合计）
CREATE TABLE IF NOT EXISTS stun_traffic (
    task_id     INTEGER NOT NULL,
    period_type TEXT NOT NULL,
    period_key  TEXT NOT NULL,
    bytes       INTEGER NOT NULL DEFAULT 0,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    PRIMARY KEY (task_id, period_type, period_key)
);

-- STUN 服务器维护表（穿透任务新增/编辑时下拉选择，按 sort_order 排序展示）
-- tcp_support : 是否支持 STUN-over-TCP（TCP 穿透任务需经支持 TCP 的服务器出站，在 CGNAT 上建立真实 TCP 映射）
CREATE TABLE IF NOT EXISTS stun_server (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    host        TEXT NOT NULL,
    port        INTEGER NOT NULL DEFAULT 3478,
    tcp_support INTEGER NOT NULL DEFAULT 0,
    sort_order  INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

-- WOL 唤醒设备表
-- mac : MAC 地址，多网口设备可配置多个，以逗号/分号/空白分隔
CREATE TABLE IF NOT EXISTS wol_device (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    mac        TEXT NOT NULL,
    broadcast  TEXT NOT NULL DEFAULT '255.255.255.255',
    port       INTEGER NOT NULL DEFAULT 9,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

-- SSL 证书任务表
-- provider       : LETSENCRYPT / ZEROSSL
-- challenge_type : HTTP01（自动，需本机 80 端口可被公网访问） / DNS01（手动添加 TXT 或引用凭证配置自动添加）
-- provider_config_id : DNS01 自动验证引用的服务商凭证配置（阿里云，云解析/ESA 自动探测）；为空时手动添加 TXT
-- status         : IDLE / PENDING_VALIDATION / ISSUED / ERROR
-- save_dir       : 签发成功后保存证书的目录（以主域名作为文件名，不存在时自动新建）；默认 /app/data/ssl，可按任务修改
-- webhook_url    : 可选，签发成功后将证书完整内容（证书/私钥/证书链 PEM）POST 推送到该地址，用于同步到其他系统
CREATE TABLE IF NOT EXISTS cert_task (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    name               TEXT NOT NULL,
    provider           TEXT NOT NULL DEFAULT 'LETSENCRYPT',
    domains            TEXT NOT NULL,
    challenge_type     TEXT NOT NULL DEFAULT 'HTTP01',
    provider_config_id INTEGER,
    status             TEXT NOT NULL DEFAULT 'IDLE',
    message        TEXT,
    dns_hint       TEXT,
    not_after      TEXT,
    auto_renew     INTEGER NOT NULL DEFAULT 1,
    cert_dir       TEXT,
    save_dir       TEXT NOT NULL DEFAULT '/app/data/ssl',
    webhook_url    TEXT,
    created_at     TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

-- 网站导航条目表（同时配置内网 / 外网两套地址）
CREATE TABLE IF NOT EXISTS nav_item (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    icon_url    TEXT,
    description TEXT,
    lan_url     TEXT NOT NULL,
    wan_url     TEXT NOT NULL,
    weight      INTEGER NOT NULL DEFAULT 0,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

-- 反向代理站点表（代理中心：类 nginx 的内置 HTTP 反代，独立端口监听，开关与端口见 app_config proxy.*）
-- mode       : REVERSE=反向代理到后端（默认） / STATIC=静态站点发布（直接对外提供本地目录文件）
-- domains    : Host 匹配列表，逗号分隔，支持 *.example.com 通配
-- paths      : 路径前缀匹配列表，逗号分隔；空 = 整域名全部路径
-- target     : mode=REVERSE 为后端地址 http(s)://host:port[/路径前缀]，带路径时作为回源路径改写的前缀；
--              mode=STATIC 为站点目录绝对路径（如 /var/www/site 或 D:/www/site）
-- force_https: 1 时 HTTP 请求 301 跳转到 https://同域名
-- cert_mode  : AUTO=SNI 自动匹配已签发证书 / TASK=指定证书任务 / NONE=仅 HTTP 不接 TLS
-- advanced   : 高级配置 JSON（请求/响应头改写、路径重写、超时、限流、BasicAuth、
--               IP 白名单、后端 TLS 校验开关、文件缓存、静态站点发布选项等，
--               字段语义见 proxy/advanced.go 文件头注释与 Advanced 结构体）
CREATE TABLE IF NOT EXISTS proxy_site (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    mode         TEXT NOT NULL DEFAULT 'REVERSE',
    domains      TEXT NOT NULL,
    paths        TEXT,
    target       TEXT NOT NULL,
    force_https  INTEGER NOT NULL DEFAULT 0,
    cert_mode    TEXT NOT NULL DEFAULT 'AUTO',
    cert_task_id INTEGER,
    advanced     TEXT,
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

-- 反向代理访问记录（按月分表，表由 proxy/stats.go 的 statsEnsureTable 在首次落库前动态创建，建表语句在源码内维护）
-- 表名   : proxy_visit_stat_yyyymm（当月一张，按天×域名×客户端IP 聚合，无逐请求明细）
-- host      : 请求 Host 头的域名（小写、去端口），非站点名称——同一站点多域名分开记录
-- country/province/city : 客户端 IP 归属地（在线解析，中文）；国内记到省/市，外国仅记国家，
--                          内网为「局域网」，尚未解析到时为空（解析完成后由落库回填）
-- hits      : 该聚合维度累计访问次数（路由命中即计一次，含被访问控制拒绝的请求）
-- 保留策略 : 超过保留期（app_config proxy.visit.retention_months，默认 12 个月）的整月表直接
--            DROP——元数据级操作瞬时完成，规避上亿行大表 DELETE 的写放大与碎片问题

-- 告警通知渠道表（统一通知中心：Webhook / Email / 钉钉，各模块事件按启用渠道扇出；
-- 穿透任务等可按任务自选渠道扇出，见 stun_task.notify_channels）
-- type   : WEBHOOK（通用 HTTP 回调） / EMAIL（SMTP 邮件） / DINGTALK（钉钉自定义机器人）
-- config : 按渠道类型的 JSON 配置（详见 notify/notify.go 文件头注释），含敏感信息如邮箱密码、加签密钥
CREATE TABLE IF NOT EXISTS notify_channel (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    type       TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    config     TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

-- 通知发送记录表（每个渠道每次投递一条，供审计与前端展示，随 Logs 策略清理）
-- result : OK(HTTP xxx) / OK / FAIL(...)
CREATE TABLE IF NOT EXISTS notify_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    time       TEXT NOT NULL,
    channel_id INTEGER,
    channel    TEXT,
    event      TEXT,
    title      TEXT,
    result     TEXT
);
CREATE INDEX IF NOT EXISTS idx_notify_log_id ON notify_log (id DESC);

-- 服务/端口可用性监控任务表
-- type   : HTTP / HTTPS（URL 探测，按状态码/关键字判定） / TCP（连接探测） / UDP（尽力探测）
-- target : HTTP(S) 为完整 URL；TCP/UDP 为 host:port
-- last_status : UP / DOWN / UNKNOWN（UNKNOWN 表示尚未探测）
-- fail_count  : 连续失败次数（用于阈值告警与去抖），恢复成功后清零
CREATE TABLE IF NOT EXISTS monitor_task (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    name               TEXT NOT NULL,
    type               TEXT NOT NULL DEFAULT 'HTTP',
    target             TEXT NOT NULL,
    method             TEXT NOT NULL DEFAULT 'GET',
    keyword            TEXT,
    expect_status      INTEGER NOT NULL DEFAULT 200,
    interval_sec       INTEGER NOT NULL DEFAULT 60,
    timeout_sec        INTEGER NOT NULL DEFAULT 10,
    fail_threshold     INTEGER NOT NULL DEFAULT 1,
    enabled            INTEGER NOT NULL DEFAULT 1,
    notify_on_recovery INTEGER NOT NULL DEFAULT 1,
    last_status        TEXT NOT NULL DEFAULT 'UNKNOWN',
    last_check         TEXT,
    last_latency_ms    INTEGER,
    fail_count         INTEGER NOT NULL DEFAULT 0,
    created_at         TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

-- 内存诊断采样表（每 60 秒入库一条，保留 7 天；页面时间线只展示最近 24 小时）
-- ts      : 采样时刻（Unix 毫秒，范围查询与过期清理的主键，建索引）
-- time    : 采样时刻（yyyy-MM-dd HH:mm:ss，本地时区，供前端展示）
-- 内存列均为字节数（-1 表示当前平台不可读，如非 Linux 拿不到 RSS）
CREATE TABLE IF NOT EXISTS diag_memory (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    time     TEXT NOT NULL,
    rss      INTEGER NOT NULL,
    heap     INTEGER NOT NULL,
    heap_sys INTEGER NOT NULL,
    heap_obj INTEGER NOT NULL,
    stack    INTEGER NOT NULL,
    sys      INTEGER NOT NULL,
    thr      INTEGER NOT NULL,
    gc       INTEGER NOT NULL,
    gc_ms    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_diag_memory_ts ON diag_memory (ts);
