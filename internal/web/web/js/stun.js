/* ============ STUN 端口穿透模块 ============ */
'use strict';

/** 拉取任务并只重写表格数据行（<tbody>），不动 tip/工具栏/表头，避免定时刷新整页重绘导致闪烁、滚动位置丢失 */
async function refreshStunRows() {
    const tbody = $('#stunTbody');
    if (!tbody) return; // 已离开本页（tbody 被替换），静默退出
    const tasks = await api('GET', '/api/stun/tasks');
    tbody.innerHTML = tasks.map(t => `
      <tr>
        <td>${esc(t.name)} <div class="small muted">${esc(t.protocol)}</div></td>
        <td>${esc(t.target_ip)}:${t.target_port}${t.peer_addr ? `<div class="small muted">对端: ${esc(t.peer_addr)}</div>` : ''}</td>
        <td class="small">${esc(t.stun_host)}:${t.stun_port}${t.upnp_enabled === 0 ? '<div class="small muted">UPnP 已关闭</div>' : ''}</td>
        <td>${t.status === 'RUNNING' ? badge('运行中', 'ok') : t.status === 'ERROR' ? badge('错误', 'err') : badge('已停止', 'gray')}</td>
        <td>${t.nat_type ? `<div class="small">${esc(t.nat_type)}</div>` : '-'}</td>
        <td>${t.mapped_addr ? badge(t.mapped_addr, 'info') : '-'}</td>
        <td>${t.punched_at ? `<span class="small">${esc(t.punched_at)}</span>` : '-'}</td>
        <td>${fmtTrafficBytes(t.total_bytes)}</td>
        <td>${esaCell(t)}</td>
        <td>${notifyCell(t)}</td>
        <td>${t.check_result
            ? `<div>${badge(t.check_result, t.check_result.startsWith('OK') ? 'ok'
                : t.check_result.startsWith('FAIL') ? 'err' : 'warn')}</div>
               ${t.check_time ? `<div class="small muted">${esc(t.check_time)}</div>` : ''}`
            : '<span class="muted small">未自测</span>'}</td>
        <td><div class="ops">
          ${t.status === 'RUNNING'
            ? `<button class="btn small icon danger" title="停止" onclick="stunCmd(${t.id},'stop')">⏸</button>`
            : `<button class="btn small icon success" title="启动" onclick="stunCmd(${t.id},'start')">▶</button>`}
          <button class="btn small icon" title="探测 NAT 类型" onclick="stunCmd(${t.id},'test')">📡</button>
          <button class="btn small icon${t.status === 'RUNNING' ? '' : ' invisible'}" title="可达性自测" onclick="stunCmd(${t.id},'verify')">🔎</button>
          <button class="btn small icon${t.esa_sync_enabled === 1 ? '' : ' invisible'}" title="ESA 同步" onclick="stunEsaSync(${t.id})">🌐</button>
          <button class="btn small icon${t.notify_enabled === 1 ? '' : ' invisible'}" title="通知测试" onclick="stunNotifyTest(${t.id})">🔔</button>
          <button class="btn small icon" title="流量统计" onclick="stunTraffic(${t.id})">📊</button>
          <button class="btn small icon" title="编辑" onclick="stunForm(${t.id})">✏️</button>
          <button class="btn small icon danger" title="删除" onclick="stunDelete(${t.id})">🗑️</button>
        </div></td>
      </tr>`).join('') || '<tr><td colspan="12" class="muted">暂无任务</td></tr>';
}

/** 首次进入穿透任务页：绘制页面骨架（tip/工具栏/表头 + 空 tbody），随后只填充数据行 */
async function renderStun() {
    $('#pageBody').innerHTML = `
      <div class="tip">
        <b>穿透通道支持承载 UDP / TCP / HTTP 数据传输；任务运行中 ≠ 外网可访问。</b>
        受限锥形 NAT 仅允许已打洞的对端连入，<b>对称型（Symmetric）NAT 纯 STUN 无法穿透</b>，请改用路由器端口转发，并确认防火墙已放行监听端口。
        穿透启动时自动尝试 <b>UPnP 端口映射</b>（WAN 口为公网时即权威入站通道）；CGNAT 或未启用 UPnP 时，TCP 任务按优先级自动选择出站通道：STUN 长连接精确映射 →
        <b>双链路模式</b>（参考 natmap：公共端点出站保活 + 同端口 STUN 短连接探测精确映射，单事务型 STUN 服务器亦可复用）→ 端口保留兜底。
        穿透成功后系统自动自测一次（映射保活 + 公网入站可达），可在操作列点「自测」手动复测。
        启用 <b>ESA 同步</b>后，穿透成功与映射地址变化时会自动把映射 IP 写入 ESA 解析记录、映射端口写入回源 HTTPS 端口，
        可在操作列点「ESA」手动补一次。
        启用 <b>通知推送</b>后，穿透成功、映射地址变化以及<b>可用性自测确认失效（FAIL）</b>时，按任务勾选的渠道（在「告警通知」页集中维护，可多选）发送通知，
        发送记录见「告警通知」页。
      </div>
      <div class="toolbar"><div class="spacer"></div>
        <button class="btn" onclick="renderStunServers()">🛠 管理STUN服务器</button>
        <button class="btn primary" onclick="stunForm()">＋ 新增穿透任务</button></div>
      <div class="panel"><div class="table-scroll"><table style="min-width:1690px">
        <thead>
            <tr>
                <th style="width: 100px">任务</th>
                <th style="width: 150px">内网目标</th>
                <th style="width: 150px">STUN服务器</th>
                <th style="width: 100px">状态</th>
                <th style="width: 120px">NAT类型</th>
                <th style="width: 180px">外网映射地址</th>
                <th style="width: 145px">穿透成功时间</th>
                <th style="width: 90px">流量</th>
                <th style="width: 145px">ESA 同步</th>
                <th style="width: 110px">通知推送</th>
                <th style="width: 145px">可用性自测</th>
                <th style="width: 310px">操作</th>
            </tr>
        </thead>
        <tbody id="stunTbody"><tr><td colspan="12" class="muted">加载中...</td></tr></tbody>
      </table></div></div>`;
    await refreshStunRows();
    setRefresh(refreshStunRows, 5000);
}

/** ESA 同步状态单元格：未启用置灰，否则按最近一次结果着色（OK / PARTIAL / FAIL） */
function esaCell(t) {
    if (t.esa_sync_enabled !== 1) return '<span class="muted small">未启用</span>';
    let st = {};
    try { st = t.esa_sync_status ? JSON.parse(t.esa_sync_status) : {}; } catch (e) { st = {}; }
    const result = st.result || '';
    if (!result) return '<span class="muted small">待同步</span>';
    const kind = result.startsWith('OK') ? 'ok' : result.startsWith('PARTIAL') ? 'warn' : 'err';
    return `<div>${badge(result, kind)}</div>${st.time ? `<div class="small muted">${esc(st.time)}</div>` : ''}`;
}

/** 通知推送单元格：投递结果不落在任务行（写入 notify_log，在「告警通知」页查看），此处只展示启用与渠道数 */
function notifyCell(t) {
    if (t.notify_enabled !== 1) return '<span class="muted small">未启用</span>';
    const n = notifySnapshot(t.notify_channels).length;
    return n ? badge(n + ' 个渠道', 'info') : '<span class="small" style="color:var(--red)">未选渠道</span>';
}

/** 通知渠道勾选列解析（非法/缺失时为空数组），元素为渠道 id 字符串 */
function notifySnapshot(text) {
    try {
        const a = text ? JSON.parse(text) : [];
        return Array.isArray(a) ? a.map(x => String(x)).filter(x => x && x !== 'null') : [];
    } catch (e) { return []; }
}

/** ESA 勾选快照列解析（非法/缺失时为空数组），元素为 {id,name} */
function esaSnapshot(text) {
    try {
        const a = text ? JSON.parse(text) : [];
        return Array.isArray(a) ? a.filter(x => x && x.id) : [];
    } catch (e) { return []; }
}

/** 收集已勾选的 ESA 项（id 保持字符串，避免大整数在 JS Number 下丢精度） */
function esaCollect(sel) {
    return [...document.querySelectorAll(sel + ' input[data-id]:checked')]
        .map(i => ({ id: i.dataset.id, name: i.dataset.name }));
}

/** 勾选行统一结构（外观见 style.css .pick-row）：复选框 + 名称/说明 + 右侧状态标，
 *  ESA 解析记录、回源规则与通知渠道三处共用；side 传 HTML（徽标/状态胶囊） */
function pickRow(o) {
    return `<label class="pick-row">
        <input type="checkbox" data-id="${esc(String(o.id))}" data-name="${esc(o.name)}" ${o.on ? 'checked' : ''}>
        <span class="pick-main"><span class="pick-name">${esc(o.name)}</span>${o.desc ? `<span class="pick-desc">${esc(o.desc)}</span>` : ''}</span>
        ${o.side ? `<span class="pick-side">${o.side}</span>` : ''}
      </label>`;
}

/** 手动立即同步一次 ESA，弹窗展示逐条明细（记录值 / 回源端口的 from→to 与结果） */
window.stunEsaSync = async id => {
    toast('正在同步 ESA 解析记录与回源端口...');
    try {
        const r = await api('POST', `/api/stun/tasks/${id}/esa-sync`);
        const items = (r.items || []).map(i => `
          <tr>
            <td>${i.kind === 'rule' ? '回源规则' : '解析记录'}</td>
            <td class="small">${esc(i.name)}</td>
            <td class="small">${esc(i.from || '-')} → <b>${esc(i.to || '-')}</b></td>
            <td>${badge(i.state === 'OK' ? '已更新' : i.state === 'SKIP' ? '跳过' : '失败',
                i.state === 'OK' ? 'ok' : i.state === 'SKIP' ? 'gray' : 'err')}</td>
            <td class="small">${esc(i.msg || '')}</td>
          </tr>`).join('');
        modal('ESA 同步结果', `<p>结果：<b>${esc(r.result || '')}</b>
          ${r.mapped_addr ? `（映射地址 ${esc(r.mapped_addr)}）` : ''}</p>
          <div class="panel" style="margin-top:10px"><table>
            <thead><tr><th style="width:80px">类型</th><th>名称</th><th style="width:180px">变更</th>
              <th style="width:100px">状态</th><th>说明</th></tr></thead>
            <tbody>${items || '<tr><td colspan="5" class="muted">无可同步项</td></tr>'}</tbody>
          </table></div>
          <p class="muted small" style="margin-top:10px">本功能只更新已勾选的解析记录与回源规则，不会新增或删除云端配置。</p>`, 'wide');
        refreshStunRows();
    } catch (e) { toast(e.message, 'err'); }
};

/** 手动试发一次穿透通知（按任务勾选的渠道；投递异步，结果到「告警通知」页看） */
window.stunNotifyTest = async id => {
    try { toast(await api('POST', `/api/stun/tasks/${id}/notify-test`), 'ok'); }
    catch (e) { toast(e.message, 'err'); }
};

window.stunCmd = async (id, cmd) => {
    try {
        if (cmd === 'test') {
            toast('正在探测 NAT 类型...');
            const r = await api('POST', `/api/stun/tasks/${id}/test`);
            modal('STUN 探测结果', `<p>NAT 类型：<b>${esc(r.natType)}</b></p>
              <p style="margin-top:8px">外网映射地址(UDP)：<b>${esc(r.mapped || '无')}</b>
                ${r.live ? '<span class="muted small">（任务运行中，为任务实际映射地址）</span>'
                  : '<span class="muted small">（临时端口探测结果，对称型 NAT 下与任务端口映射不同）</span>'}</p>
              ${r.tcpMapped ? `<p style="margin-top:8px">TCP 映射地址：<b>${esc(r.tcpMapped)}</b>
                <span class="muted small">${r.live ? '（任务运行中，为任务实际映射地址）' : '（TCP 入站以此为准）'}</span></p>` : ''}
              <p class="muted small" style="margin-top:10px">对称型 NAT 下每次探测映射端口可能不同，属正常现象；
              任务运行中不代表外网可访问，受限/对称型需端口转发或已打洞对端。</p>`);
        } else if (cmd === 'verify') {
            toast('正在自测外网可达性（TCP 连接外网映射地址）...');
            const r = await api('POST', `/api/stun/tasks/${id}/verify`);
            toast('自测结果: ' + r.result, r.result.startsWith('OK') ? 'ok' : 'err');
        } else {
            await api('POST', `/api/stun/tasks/${id}/${cmd}`);
            toast(cmd === 'start' ? '已启动' : '已停止');
        }
        refreshStunRows();
    } catch (e) { toast(e.message, 'err'); }
};

window.stunDelete = async id => {
    if (!(await confirmBox({ title: '删除穿透任务', message: '确定删除该穿透任务？', confirmText: '删除', danger: true }))) return;
    try { await api('DELETE', '/api/stun/tasks/' + id); toast('已删除'); refreshStunRows(); }
    catch (e) { toast(e.message, 'err'); }
};

window.stunForm = async (id) => {
    let t = {};
    if (id) t = (await api('GET', '/api/stun/tasks')).find(x => x.id === id);
    let servers = [];
    try { servers = await api('GET', '/api/stun/servers'); } catch (e) { /* ignore */ }
    const matched = servers.find(s => s.host === t.stun_host && Number(s.port) === Number(t.stun_port));
    const serverOpts = servers.map(s =>
        `<option value="${s.id}" ${matched && matched.id === s.id ? 'selected' : ''}>${esc(s.name)}（${esc(s.host)}:${s.port}${s.tcp_support === 1 ? '，支持TCP' : ''}）</option>`).join('');
    const custom = !matched && (!!t.stun_host || !servers.length);
    // ESA 同步凭证：只列阿里云类型的服务商配置（与 ddns 一致），已引用的保留以免编辑时回显丢失
    let configs = [];
    try { configs = await api('GET', '/api/provider/configs'); } catch (e) { /* ignore */ }
    const credOpts = configs
        .filter(c => (c.provider_type || 'ALIYUN') === 'ALIYUN' || c.id === t.provider_config_id)
        .map(c => `<option value="${c.id}" ${t.provider_config_id === c.id ? 'selected' : ''}>${esc(c.name)}（${esc(maskAk(c.access_key_id))}）</option>`).join('');
    // 勾选快照（[{id,name}]）：先按快照回显勾选项，拉取线上列表后再与线上核对
    const esaSiteOpt = t.esa_site_id
        ? `<option value="${esc(t.esa_site_id)}" selected>${esc(t.esa_site_id)}（原站点，点「拉取站点」核对）</option>` : '';
    const recChecked = new Map(esaSnapshot(t.esa_records).map(p => [String(p.id), p.name]));
    const ruleChecked = new Map(esaSnapshot(t.esa_rules).map(p => [String(p.id), p.name]));
    let esaRecOnline = null, esaRuleOnline = null; // 线上列表，null=尚未拉取
    // 通知中心渠道（统一在「告警通知」页维护，任务只勾选用哪些，可多选）
    let notifyChannels = [];
    try { notifyChannels = await api('GET', '/api/notify/channels'); } catch (e) { /* ignore */ }
    const notifyChecked = new Set(notifySnapshot(t.notify_channels));
    // 类型徽标与「已停用」状态标统一落在行右侧，行内只留渠道名（外观共用 .pick-row）
    const notifySide = c => notifyTypeBadge(c.type)
        + (c.enabled === 1 ? '' : '<span class="pick-tag err">已停用 · 不会发送</span>');
    const notifyList = notifyChannels.map(c => pickRow({
        id: c.id, name: c.name, side: notifySide(c), on: notifyChecked.has(String(c.id))
    })).join('')
        // 快照中已被删除的渠道：保留可取消（与 ESA 勾选快照同样处理），投递时后端自动跳过
        + [...notifyChecked]
            .filter(id => !notifyChannels.some(c => String(c.id) === id))
            .map(id => pickRow({
                id, name: '渠道 #' + id, desc: '已从「告警通知」页删除',
                side: '<span class="pick-tag err">已删除 · 不会发送</span>', on: true
            })).join('');
    modal(id ? '编辑穿透任务' : '新增穿透任务', `
      <form id="stunFormEl" class="form-grid">
        <div class="field"><label>任务名称 <b>*</b></label><input name="name" required value="${esc(t.name || '')}"></div>
        <div class="field"><label>穿透协议 <b>*</b></label>
          <select name="protocol"><option ${t.protocol !== 'TCP' ? 'selected' : ''}>UDP</option><option ${t.protocol === 'TCP' ? 'selected' : ''}>TCP</option></select></div>
        <div class="field"><label>内网目标 IP <b>*</b></label><input name="target_ip" required value="${esc(t.target_ip || '')}" placeholder="192.168.1.10"></div>
        <div class="field"><label>内网目标端口 <b>*</b></label><input name="target_port" required type="number" min="1" max="65535" value="${t.target_port ?? ''}"></div>
        <div class="field"><label>本地绑定端口</label><input name="bind_port" type="number" min="0" max="65535" value="${t.bind_port ?? 0}" placeholder="0=随机"></div>
        <div class="field"><label>保活间隔（秒）</label><input name="keepalive_sec" type="number" min="10" value="${t.keepalive_sec ?? 25}"></div>
        <div class="field"><label>对端公网地址（TCP 打洞选填）</label><input name="peer_addr" value="${esc(t.peer_addr || '')}" placeholder="如 203.0.113.5:8080，留空则仅接受入站连接"></div>
        <div class="field"><label>UPnP 端口映射</label>
          <select name="upnp_enabled">
            <option value="true" ${t.upnp_enabled !== 0 ? 'selected' : ''}>启用（需路由器支持UPnP）</option>
            <option value="false" ${t.upnp_enabled === 0 ? 'selected' : ''}>停用（路由器不支持UPnP）</option>
          </select></div>
        <div class="field full"><label>STUN 服务器 <b>*</b></label>
          <select name="stun_server" onchange="stunServerChanged(this.value)">
            ${serverOpts}
            <option value="custom" ${custom ? 'selected' : ''}>自定义...</option>
          </select></div>
        <div class="field ${custom ? '' : 'hidden'}" id="fStunHost"><label>STUN 地址 <b>*</b></label><input name="stun_host" value="${esc(t.stun_host || '')}" placeholder="stun.miwifi.com"></div>
        <div class="field ${custom ? '' : 'hidden'}" id="fStunPort"><label>STUN 端口</label><input name="stun_port" type="number" min="1" max="65535" value="${t.stun_port ?? 3478}"></div>
        <div class="field full form-section">
          <label>ESA 边缘安全加速同步 <span class="sec-opt">可选</span></label>
          <div class="sec-desc">穿透成功 / 映射地址变化后，把映射 IP 写入解析记录、映射端口写入回源 HTTPS 端口。</div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
            <select name="esa_sync_enabled" style="width:150px" onchange="stunEsaToggle(this.value)">
              <option value="false" ${t.esa_sync_enabled === 1 ? '' : 'selected'}>停用</option>
              <option value="true" ${t.esa_sync_enabled === 1 ? 'selected' : ''}>启用</option>
            </select>
            <select name="provider_config_id" id="fEsaCred" style="flex:1;min-width:240px" onchange="stunEsaCredChanged()">
              <option value="">${credOpts ? '请选择服务商凭证配置...' : '无阿里云凭证，请先到「服务商配置」添加'}</option>${credOpts}
            </select>
          </div>
          <div id="esaSyncCfg" class="${t.esa_sync_enabled === 1 ? '' : 'hidden'}"
               style="margin-top:10px;display:flex;flex-direction:column;gap:12px">
            <div>
              <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
                <select name="esa_site_id" id="fEsaSite" style="flex:1;min-width:240px" onchange="stunEsaSiteChanged()">
                  <option value="">请先点击「拉取站点」</option>${esaSiteOpt}
                </select>
                <button type="button" class="btn small" onclick="stunEsaLoadSites()">拉取站点</button>
              </div>
              <div id="esaTip" class="small muted" style="margin-top:5px"></div>
            </div>
            <div>
              <div class="pick-head">
                <button type="button" class="btn small" onclick="stunEsaLoadRecords()">拉取 DNS 解析记录</button>
                <span class="pick-hint">勾选需要写入映射 IP 的记录（仅 A / AAAA 生效）</span>
              </div>
              <div id="esaRecList" class="pick-list"></div>
            </div>
            <div>
              <div class="pick-head">
                <button type="button" class="btn small" onclick="stunEsaLoadRules()">拉取回源规则</button>
                <span class="pick-hint">勾选需要写入映射端口的回源规则（仅 TCP 任务生效）</span>
              </div>
              <div id="esaRuleList" class="pick-list"></div>
            </div>
            <div class="small muted" style="line-height:1.8;padding:10px;background:var(--code-bg);border:1px solid var(--border);border-radius:8px">
              只更新<b>已勾选</b>的解析记录（记录值）与回源规则（回源 HTTPS 端口），<b>不会新增或删除</b>云端配置；
              现值与目标一致时跳过写入，多值记录、IPv4↔IPv6 地址族不一致的记录不会被覆盖。
              <b>UDP 任务</b>的映射端口对 HTTPS 回源无意义，仅同步解析记录。
              回源协议沿用规则线上现值，本功能只改端口。同步失败仅记日志与任务列表「ESA 同步」列，<b>不影响穿透</b>，
              可在任务列表点「ESA」手动补一次。</div>
          </div>
        </div>
        <div class="field full form-section">
          <label>Webhook 同步 <span class="sec-opt">可选</span></label>
          <div class="sec-desc">穿透成功 / 映射地址变化时，将结果推送到以下地址，支持多个。</div>
          <div id="stunWhList"></div>
          <div style="margin-top:6px"><button type="button" class="btn small" onclick="stunWhAdd()">＋ 添加 Webhook</button></div>
          <details class="ph-ref">
            <summary><b>可用占位符</b>（在 URL、请求头、参数值、JSON 请求体中引用，共 17 个，点击展开）</summary>
            <div class="ph-ref-body">
            <div style="display:flex;gap:16px;align-items:flex-start;margin-top:6px">
              <table style="flex:1">
                <thead><tr><th style="width:38%">占位符</th><th>说明</th></tr></thead>
                <tbody>
                  <tr><td><code>\${event}</code></td><td>事件类型（stun.punched / stun.mapped_changed）</td></tr>
                  <tr><td><code>\${id}</code></td><td>任务 ID（如 1）</td></tr>
                  <tr><td><code>\${name}</code></td><td>任务名称（如 Local-https）</td></tr>
                  <tr><td><code>\${protocol}</code></td><td>穿透协议（UDP / TCP）</td></tr>
                  <tr><td><code>\${target_ip}</code></td><td>内网目标 IP（如 172.17.1.213）</td></tr>
                  <tr><td><code>\${target_port}</code></td><td>内网目标端口（如 443）</td></tr>
                  <tr><td><code>\${bind_port}</code></td><td>本地绑定端口（0=随机）</td></tr>
                  <tr><td><code>\${stun_host}</code></td><td>STUN 服务器地址（如 stun.nextcloud.com）</td></tr>
                  <tr><td><code>\${stun_port}</code></td><td>STUN 服务器端口（如 3478）</td></tr>
                  <tr><td><code>\${peer_addr}</code></td><td>对端公网地址（如 203.0.113.5:8080）</td></tr>
                </tbody>
              </table>
              <table style="flex:1">
                <thead><tr><th style="width:38%">占位符</th><th>说明</th></tr></thead>
                <tbody>
                  <tr><td><code>\${mapped_addr}</code></td><td>穿透后外网映射地址（如 1.2.3.4:5678）</td></tr>
                  <tr><td><code>\${mapped_ip}</code></td><td>穿透后外网 IP（如 1.2.3.4）</td></tr>
                  <tr><td><code>\${mapped_port}</code></td><td>穿透后外网端口（如 5678）</td></tr>
                  <tr><td><code>\${nat_type}</code></td><td>NAT 类型（如 受限锥形、对称型）</td></tr>
                  <tr><td><code>\${punched_at}</code></td><td>穿透成功时间（如 2026-10-08 13:50:49）</td></tr>
                  <tr><td><code>\${check_result}</code></td><td>自测结果（OK / FAIL / 重建中）</td></tr>
                  <tr><td><code>\${status}</code></td><td>任务状态（RUNNING / STOPPED / ERROR）</td></tr>
                </tbody>
              </table>
            </div>
            </div>
          </details>
          <div class="small muted" style="margin-top:6px;line-height:1.7">
            每条可选 <b>GET / POST</b>：<b>POST</b> 支持填写自定义 JSON 请求体（占位符会被替换为实际值）；<b>GET</b> 将结果字段+自定义参数拼为查询串。
            <b>请求头</b>每行一个 <code>key: value</code>（如 <code>Authorization: Bearer xxx</code>）。触发时机：首次穿透成功、外网映射地址变化。
            推送失败仅记日志，不影响穿透。</div></div>
        <div class="field full form-section">
          <label>通知中心推送 <span class="sec-opt">可选</span></label>
          <div class="sec-desc">穿透成功 / 映射地址变化 / 可用性自测失效（FAIL）时，按勾选渠道发送通知，支持多个。</div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
            <select name="notify_enabled" style="width:150px" onchange="stunNotifyToggle(this.value)">
              <option value="false" ${t.notify_enabled === 1 ? '' : 'selected'}>停用</option>
              <option value="true" ${t.notify_enabled === 1 ? 'selected' : ''}>启用</option>
            </select>
            <span class="small muted">渠道（Webhook / 邮件 / 钉钉机器人）在「告警通知」页集中维护</span>
          </div>
          <div id="notifyCfg" class="pick-list ${t.notify_enabled === 1 ? '' : 'hidden'}">
            ${notifyList || '<div class="pick-empty">暂无通知渠道，请先到「告警通知」页新增渠道。</div>'}
          </div>
          <div class="small muted" style="margin-top:6px;line-height:1.7">
            通知正文包含任务名、协议、内网目标、外网映射地址与 NAT 类型；投递结果写入「告警通知」页的
            <b>最近发送记录</b>，渠道被删除或停用时自动跳过，<b>不影响穿透</b>。
            保存后可在任务列表点<b>「通知」</b>试发一次，验证渠道勾选与投递链路是否正常。</div></div>
        <div class="form-foot full">
          <button type="button" class="btn" onclick="closeModal()">取消</button>
          <button class="btn primary">保存</button>
        </div>
      </form>`, 'xwide');
    window.stunServerChanged = v => {
        $('#fStunHost').classList.toggle('hidden', v !== 'custom');
        $('#fStunPort').classList.toggle('hidden', v !== 'custom');
    };
    // ---------- ESA 同步：站点/记录/规则均由 ESA API 实时拉取供勾选，不手填 ID ----------
    const esaVal = sel => { const el = $(sel); return el ? el.value : ''; };
    const esaTip = html => { const el = $('#esaTip'); if (el) el.innerHTML = html; };

    /** 单行勾选项：tag 为右侧状态标（线上未找到 / 未核对） */
    const esaPickRow = (id, name, desc, tag, on) => pickRow({ id, name, desc, side: tag, on });

    /** 渲染记录勾选列表：线上记录 + 快照中线上已不存在的项（保留可取消，避免默认丢掉用户的勾选） */
    const renderEsaRecs = () => {
        const box = $('#esaRecList');
        if (!box) return;
        const seen = new Set();
        const rows = (esaRecOnline || []).map(r => {
            seen.add(String(r.record_id));
            const desc = [r.record_type, r.value || '无记录值', r.proxied ? '代理加速' : '直连',
                r.comment ? '备注 ' + r.comment : ''].filter(Boolean).join(' · ');
            return esaPickRow(r.record_id, r.record_name, desc, '', recChecked.has(String(r.record_id)));
        });
        const orphans = [...recChecked].filter(([id]) => !seen.has(id)).map(([id, name]) => esaPickRow(id, name,
            '快照 ID ' + id,
            esaRecOnline ? '<span class="pick-tag err">线上未找到 · 只更新不新增</span>' : '<span class="pick-tag">未与线上核对</span>',
            true));
        box.innerHTML = rows.concat(orphans).join('')
            || '<div class="pick-empty">尚未拉取。可点击“拉取 DNS 解析记录”后勾选。</div>';
    };

    /** 渲染回源规则勾选列表（全局回源配置不适用规则端口同步，不列出） */
    const renderEsaRules = () => {
        const box = $('#esaRuleList');
        if (!box) return;
        const seen = new Set();
        const rows = (esaRuleOnline || []).filter(r => (r.config_type || '').toLowerCase() !== 'global').map(r => {
            seen.add(String(r.config_id));
            const desc = [r.origin_scheme ? '回源 ' + r.origin_scheme : '',
                r.origin_https_port ? 'HTTPS 端口 ' + r.origin_https_port : '未设 HTTPS 端口',
                r.rule_enable ? r.rule_enable : ''].filter(Boolean).join(' · ');
            return esaPickRow(r.config_id, r.rule_name, desc, '', ruleChecked.has(String(r.config_id)));
        });
        const orphans = [...ruleChecked].filter(([id]) => !seen.has(id)).map(([id, name]) => esaPickRow(id, name,
            '快照 ID ' + id,
            esaRuleOnline ? '<span class="pick-tag err">线上未找到 · 只更新不新增</span>' : '<span class="pick-tag">未与线上核对</span>',
            true));
        box.innerHTML = rows.concat(orphans).join('')
            || '<div class="pick-empty">尚未拉取。可点击“拉取回源规则”后勾选（UDP 任务不会改动回源端口）。</div>';
    };

    window.stunEsaToggle = v => $('#esaSyncCfg').classList.toggle('hidden', v !== 'true');

    window.stunNotifyToggle = v => $('#notifyCfg').classList.toggle('hidden', v !== 'true');

    window.stunEsaCredChanged = () => { // 凭证变了，站点/记录/规则归属都可能变：清空重新选
        const sel = $('#fEsaSite');
        if (sel) sel.innerHTML = '<option value="">请先点击「拉取站点」</option>';
        recChecked.clear(); ruleChecked.clear();
        esaRecOnline = null; esaRuleOnline = null;
        renderEsaRecs(); renderEsaRules();
        esaTip('');
    };

    window.stunEsaSiteChanged = () => { // 换站点后旧列表失效，但保留已勾选项（拉到新列表后核对）
        esaRecOnline = null; esaRuleOnline = null;
        renderEsaRecs(); renderEsaRules();
        esaTip('');
    };

    window.stunEsaLoadSites = async () => {
        const cfg = esaVal('#fEsaCred');
        if (!cfg) { esaTip('<span style="color:var(--red)">请先选择服务商凭证配置</span>'); return; }
        const sel = $('#fEsaSite');
        const cur = sel.value || String(t.esa_site_id || '');
        sel.innerHTML = '<option value="">站点加载中…</option>';
        esaTip('正在拉取 ESA 站点...');
        try {
            const r = await api('POST', '/api/stun/esa/sites', { provider_config_id: cfg });
            const sites = r.sites || [];
            if (!sites.length) {
                sel.innerHTML = '<option value="">无可用站点</option>';
                esaTip('<span style="color:var(--red)">该账号下未找到 ESA 站点，请先到阿里云 ESA 控制台添加站点。</span>');
                return;
            }
            sel.innerHTML = '<option value="">请选择站点</option>' + sites.map(s =>
                `<option value="${esc(s.site_id)}" ${cur === String(s.site_id) ? 'selected' : ''}>${esc(s.site_name)}（SiteId: ${esc(s.site_id)}${s.status ? '，' + esc(s.status) : ''}）</option>`).join('');
            // 编辑时原站点不在列表：保留该项并提示，避免回显丢失
            if (cur && !sites.some(s => String(s.site_id) === cur)) {
                sel.insertAdjacentHTML('afterbegin', `<option value="${esc(cur)}" selected>${esc(cur)}（原站点，未在阿里云列表中找到）</option>`);
            }
            esaTip('');
        } catch (e) {
            sel.innerHTML = '<option value="">站点加载失败</option>';
            esaTip(`<span style="color:var(--red)">${esc(e.message)}</span>`);
        }
    };

    window.stunEsaLoadRecords = async () => {
        const site = esaVal('#fEsaSite');
        if (!site) { toast('请先选择 ESA 站点（可点“拉取站点”）', 'err'); return; }
        const box = $('#esaRecList');
        box.innerHTML = '<div class="pick-empty">解析记录加载中…</div>';
        try {
            esaRecOnline = (await api('POST', '/api/stun/esa/records',
                { provider_config_id: esaVal('#fEsaCred'), site_id: site })).records || [];
            // 拉取后的勾选中只剩仍在线上存在的项（多出的失效项由 render 标灰保留）
            renderEsaRecs();
        } catch (e) {
            esaRecOnline = null; renderEsaRecs(); toast(e.message, 'err');
        }
    };

    window.stunEsaLoadRules = async () => {
        const site = esaVal('#fEsaSite');
        if (!site) { toast('请先选择 ESA 站点（可点“拉取站点”）', 'err'); return; }
        const box = $('#esaRuleList');
        box.innerHTML = '<div class="pick-empty">回源规则加载中…</div>';
        try {
            esaRuleOnline = (await api('POST', '/api/stun/esa/origin-rules',
                { provider_config_id: esaVal('#fEsaCred'), site_id: site })).rules || [];
            renderEsaRules();
        } catch (e) {
            esaRuleOnline = null; renderEsaRules(); toast(e.message, 'err');
        }
    };

    renderEsaRecs();
    renderEsaRules();
    if (t.esa_sync_enabled === 1 && t.provider_config_id) stunEsaLoadSites();
    let whs = [], whst = {};
    try { whs = t.webhook_config ? JSON.parse(t.webhook_config) : []; } catch (e) { whs = []; }
    try { whst = t.webhook_status ? JSON.parse(t.webhook_status) : {}; } catch (e) { whst = {}; }
    whs.forEach(w => window.stunWhAdd(w, whst[w.url]));
    $('#stunFormEl').addEventListener('submit', async e => {
        e.preventDefault();
        const body = Object.fromEntries(new FormData(e.target).entries());
        const sv = body.stun_server;
        delete body.stun_server;
        if (sv && sv !== 'custom') {
            const s = servers.find(x => String(x.id) === String(sv));
            body.stun_host = s.host;
            body.stun_port = Number(s.port);
        } else {
            body.stun_port = Number(body.stun_port || 3478);
        }
        body.target_port = Number(body.target_port); body.bind_port = Number(body.bind_port || 0);
        body.keepalive_sec = Number(body.keepalive_sec || 25);
        body.upnp_enabled = body.upnp_enabled === 'true';
        body.esa_sync_enabled = body.esa_sync_enabled === 'true';
        body.provider_config_id = body.provider_config_id ? Number(body.provider_config_id) : null;
        body.esa_site_id = (body.esa_site_id || '').trim();
        // 勾选项从 DOM 收集为 [{id,name}]：id 为线上 RecordId/ConfigId，name 为名称快照（id 失效时回退匹配）
        body.esa_records = esaCollect('#esaRecList');
        body.esa_rules = esaCollect('#esaRuleList');
        body.notify_enabled = body.notify_enabled === 'true';
        // 勾选的通知渠道 id：与 ESA 勾选同样从列表 DOM 收集（停用时保留勾选，重新启用即恢复）
        body.notify_channels = [...document.querySelectorAll('#notifyCfg input[data-id]:checked')]
            .map(i => Number(i.dataset.id));
        body.webhooks = [...document.querySelectorAll('#stunWhList .wh-row')].map(r => {
            const method = r.querySelector('.wh-method').value;
            const headers = {};
            r.querySelector('.wh-headers').value.split(/\r?\n/).forEach(line => {
                const i = line.indexOf(':');
                if (i > 0) headers[line.slice(0, i).trim()] = line.slice(i + 1).trim();
            });
            const w = { method, url: r.querySelector('.wh-url').value.trim(), headers };
            if (method === 'POST') {
                // POST 模式：取 JSON 请求体
                const bodyText = r.querySelector('.wh-body').value.trim();
                if (bodyText) w.body = bodyText;
            } else {
                // GET 模式：保留 key=value 参数
                const params = {};
                r.querySelector('.wh-params').value.split(/\r?\n/).forEach(line => {
                    const i = line.indexOf('=');
                    if (i > 0) params[line.slice(0, i).trim()] = line.slice(i + 1).trim();
                });
                if (Object.keys(params).length) w.params = params;
            }
            return w;
        }).filter(w => w.url);
        try {
            if (id) await api('PUT', '/api/stun/tasks/' + id, body);
            else await api('POST', '/api/stun/tasks', body);
            closeModal(); toast('保存成功'); refreshStunRows();
        } catch (err) { toast(err.message, 'err'); }
    });
};

/** 新增一条 Webhook 编辑行（w 为空时为空白新行；编辑时回填已存配置；status 为上次调用结果 {time,result}） */
window.stunWhAdd = (w, status) => {
    w = w || { url: '', method: 'POST', headers: {}, params: {}, body: '' };
    const list = document.getElementById('stunWhList');
    if (!list) return;
    const row = document.createElement('div');
    row.className = 'wh-row';
    const headersText = Object.entries(w.headers || {}).map(([k, v]) => k + ': ' + v).join('\n');
    const paramsText = Object.entries(w.params || {}).map(([k, v]) => k + '=' + v).join('\n');
    const bodyText = w.body || '';
    const st = status && status.result
        ? `上次调用：<span>${esc(status.time || '')}</span> `
          + `<b style="color:${String(status.result).startsWith('OK') ? '#34d399' : '#fb7185'}">${esc(status.result)}</b>`
        : '尚未调用';
    const isPost = w.method !== 'GET';
    row.innerHTML = `
      <div class="wh-row-head">
        <select class="wh-method"><option ${w.method !== 'GET' ? 'selected' : ''}>POST</option><option ${w.method === 'GET' ? 'selected' : ''}>GET</option></select>
        <input class="wh-url" placeholder="https://example.com/hooks/stun" value="${esc(w.url || '')}">
        <button type="button" class="btn small danger" title="删除此条">✕</button>
      </div>
      <div class="wh-fields">
        <div>
          <label class="small muted">请求头（每行 key: value，如 Authorization: Bearer xxx）</label>
          <textarea class="wh-headers" placeholder="Authorization: Bearer xxx\nX-Custom: value">${esc(headersText)}</textarea>
        </div>
        <div class="wh-body-wrap" style="${isPost ? '' : 'display:none'}">
          <label class="small muted">JSON 请求体（支持 <code>\${字段}</code> 占位符，留空则自动发送全部结果字段）</label>
          <textarea class="wh-body" placeholder='{"event":"\${event}","task":"\${name}","ip":"\${mapped_ip}","port":"\${mapped_port}","extra":{"key":"value"}}'>${esc(bodyText)}</textarea>
        </div>
        <div class="wh-params-wrap" style="${!isPost ? '' : 'display:none'}">
          <label class="small muted">自定义参数（GET 查询串，每行 key=value，支持 <code>\${字段}</code> 占位符）</label>
          <textarea class="wh-params" placeholder="token=abc123\naddr=\${mapped_addr}">${esc(paramsText)}</textarea>
        </div>
      </div>
      <div class="wh-status small muted">${st}</div>`;
    row.querySelector('button').addEventListener('click', () => row.remove());
    // 切换 GET/POST 时显示/隐藏对应字段
    row.querySelector('.wh-method').addEventListener('change', e => {
        const post = e.target.value !== 'GET';
        row.querySelector('.wh-body-wrap').style.display = post ? '' : 'none';
        row.querySelector('.wh-params-wrap').style.display = post ? 'none' : '';
    });
    list.appendChild(row);
};

/** STUN 服务器维护视图：穿透任务表单下拉选择的数据源 */
async function renderStunServers() {
    const servers = await api('GET', '/api/stun/servers');
    const rows = servers.map(s => `
      <tr>
        <td>${esc(s.name)}</td>
        <td class="small">${esc(s.host)}:${s.port}</td>
        <td>${s.tcp_support === 1 ? badge('支持', 'ok') : badge('不支持', 'gray')}</td>
        <td>
          <button class="btn small" onclick="stunServerMove(${s.id},'up')">↑</button>
          <button class="btn small" onclick="stunServerMove(${s.id},'down')">↓</button>
          <button class="btn small" onclick="stunServerForm(${s.id})">编辑</button>
          <button class="btn small danger" onclick="stunServerDelete(${s.id})">删除</button>
        </td>
      </tr>`).join('');
    $('#pageBody').innerHTML = `
      <div class="tip">维护常用 STUN 服务器列表，穿透任务新增/编辑时从下拉中选择（按列表顺序展示）。
        可用 <b>↑/↓</b> 调整顺序：排在前面的服务器优先作为穿透探测与保活的兜底候选。
        <b>支持 TCP</b> 表示服务器支持 STUN-over-TCP：TCP 穿透任务经支持 TCP 的服务器出站，才能在运营商 CGNAT 上建立真实 TCP 映射；
        双链路模式下服务器只需响应一次绑定请求即可提供精确映射（不要求保持长连接）。</div>
      <div class="toolbar">
        <button class="btn small" onclick="renderStun()">← 返回穿透任务</button>
        <div class="spacer"></div>
        <button class="btn primary small" onclick="stunServerForm()">＋ 新增STUN服务器</button>
      </div>
      <div class="panel"><table>
        <thead><tr><th>名称</th><th>地址</th><th>STUN-over-TCP</th><th>操作</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="4" class="muted">暂无服务器，新增穿透任务时需自定义填写地址</td></tr>'}</tbody>
      </table></div>`;
    setRefresh(null);
}
window.renderStunServers = renderStunServers;

window.stunServerForm = async (id) => {
    let s = {};
    if (id) s = (await api('GET', '/api/stun/servers')).find(x => x.id === id);
    modal(id ? '编辑STUN服务器' : '新增STUN服务器', `
      <form id="stunServerFormEl" class="form-grid">
        <div class="field full"><label>服务器名称 <b>*</b></label><input name="name" required value="${esc(s.name || '')}" placeholder="小米 / 谷歌"></div>
        <div class="field"><label>服务器地址 <b>*</b></label><input name="host" required value="${esc(s.host || '')}" placeholder="stun.miwifi.com"></div>
        <div class="field"><label>端口</label><input name="port" type="number" min="1" max="65535" value="${s.port ?? 3478}"></div>
        <div class="field full"><label>STUN-over-TCP 支持</label>
          <div style="display:flex;gap:8px;align-items:center">
            <select name="tcp_support" style="flex:1">
              <option value="true" ${s.tcp_support === 1 ? 'selected' : ''}>支持</option>
              <option value="false" ${s.tcp_support !== 1 ? 'selected' : ''}>不支持 / 未知</option>
            </select>
            <button type="button" class="btn small" id="btnProbeTcp">探测</button>
          </div>
          <div id="probeTcpTip" class="muted small" style="margin-top:6px">探测：经 TCP 向上述地址发送 STUN 绑定请求，自动判定并回填支持状态。</div></div>
        <div class="form-foot full">
          <button type="button" class="btn" onclick="closeModal()">取消</button>
          <button class="btn primary">保存</button>
        </div>
      </form>`);
    $('#btnProbeTcp').addEventListener('click', async () => {
        const f = $('#stunServerFormEl');
        const host = f.host.value.trim();
        const port = Number(f.port.value || 3478);
        if (!host) { toast('请先填写服务器地址', 'err'); return; }
        const btn = $('#btnProbeTcp'), tip = $('#probeTcpTip');
        btn.disabled = true; btn.textContent = '探测中…';
        tip.textContent = '正在经 TCP 发送 STUN 绑定请求，请稍候（最长约 3 秒）…';
        try {
            const r = await api('POST', '/api/stun/servers/probe-tcp', { host, port });
            f.tcp_support.value = r.supported ? 'true' : 'false';
            tip.innerHTML = r.supported
                ? `探测结果：<b>支持</b> STUN-over-TCP，外网映射地址 ${esc(r.mapped)}`
                : '探测结果：<b>不支持</b> STUN-over-TCP（连接失败或无有效响应）';
        } catch (e) {
            tip.textContent = '探测失败: ' + e.message;
        } finally {
            btn.disabled = false; btn.textContent = '探测';
        }
    });
    $('#stunServerFormEl').addEventListener('submit', async e => {
        e.preventDefault();
        const f = new FormData(e.target);
        const body = { name: f.get('name').trim(), host: f.get('host').trim(),
            port: Number(f.get('port') || 3478), tcp_support: f.get('tcp_support') === 'true' };
        try {
            if (id) await api('PUT', '/api/stun/servers/' + id, body);
            else await api('POST', '/api/stun/servers', body);
            closeModal(); toast('保存成功'); renderStunServers();
        } catch (err) { toast(err.message, 'err'); }
    });
};

window.stunServerDelete = async id => {
    if (!(await confirmBox({ title: '删除 STUN 服务器', message: '确定删除该 STUN 服务器？已创建的穿透任务不受影响。', confirmText: '删除', danger: true }))) return;
    try { await api('DELETE', '/api/stun/servers/' + id); toast('已删除'); renderStunServers(); }
    catch (e) { toast(e.message, 'err'); }
};

/** 上移/下移调整服务器顺序 */
window.stunServerMove = async (id, dir) => {
    try {
        await api('POST', `/api/stun/servers/${id}/move`, { dir });
        renderStunServers();
    } catch (e) { toast(e.message, 'err'); }
};

/** 字节数转人类可读（B/KB/MB/GB/TB/PB）；独立命名避免与 docker.js 的全局 fmtBytes 相互覆盖 */
function fmtTrafficBytes(b) {
    b = Number(b || 0);
    if (b < 1024) return b + ' B';
    const u = ['KB', 'MB', 'GB', 'TB', 'PB'];
    let i = -1;
    do { b /= 1024; i++; } while (b >= 1024 && i < u.length - 1);
    return b.toFixed(b >= 100 ? 0 : b >= 10 ? 1 : 2) + ' ' + u[i];
}

/* ---------- 流量折线图（纯 SVG 实现，无第三方依赖） ---------- */

/** 三个维度的主题色与标题（小时蓝 / 天紫 / 月绿，避免同色单调） */
const TF_THEMES = {
    hour: { color: '#0ea5e9', label: '按小时（近 24 小时）' },
    day: { color: '#8b5cf6', label: '按天（近 30 天）' },
    month: { color: '#10b981', label: '按月（近 12 月）' },
};

const tfPad = n => String(n).padStart(2, '0');
const tfDateKey = d => `${d.getFullYear()}-${tfPad(d.getMonth() + 1)}-${tfPad(d.getDate())}`;

/**
 * 倒序明细序列 → 升序完整时间窗（缺失时段补 0）：
 * 折线图横轴连续、空档归零，比仅画有流量的孤立点更直观。
 */
function tfFillWindow(list, span, keyOf) {
    const m = new Map((list || []).map(x => [x.key, x.bytes]));
    const out = [];
    for (let i = span - 1; i >= 0; i--) {
        const k = keyOf(i);
        out.push({ key: k, bytes: m.get(k) || 0 });
    }
    return out;
}

/** 取“好看”的纵轴上限（1/2/2.5/5 × 10^n），网格刻度避免零碎小数 */
function tfNiceMax(v) {
    const exp = Math.pow(10, Math.floor(Math.log10(Math.max(v, 1))));
    for (const f of [1, 2, 2.5, 5, 10]) if (v <= f * exp * 1.0001) return f * exp;
    return 10 * exp;
}

/**
 * 渲染单个流量折线图：Catmull-Rom 平滑曲线 + 主题色渐变面积 + 虚线网格
 * + 悬浮十字引导线与最近点吸附气泡，最新时段末端常亮高亮点。
 */
function tfRenderChart(host, name, points, theme, tickFmt, tipFmt) {
    const W = Math.max(host.clientWidth || 0, 240), H = 170;
    const P = { l: 46, r: 12, t: 14, b: 22 };
    const iw = W - P.l - P.r, ih = H - P.t - P.b;
    const peak = Math.max(...points.map(p => p.bytes));
    const nice = tfNiceMax(peak);
    const c = theme.color;
    const X = i => P.l + (points.length < 2 ? iw / 2 : (iw * i) / (points.length - 1));
    const Y = v => P.t + ih - (Math.max(v, 0) / nice) * ih;
    const pts = points.map((p, i) => ({ x: +X(i).toFixed(1), y: +Y(p.bytes).toFixed(1), key: p.key, bytes: p.bytes }));

    // Catmull-Rom 转三次贝塞尔（控制点钳制在绘图区内，防平滑越界穿过基线）
    const line = (() => {
        if (!pts.length) return '';
        if (pts.length === 1) return `M${pts[0].x},${pts[0].y}`;
        const cl = y => Math.min(P.t + ih, Math.max(P.t, y));
        let d = `M${pts[0].x},${pts[0].y}`;
        for (let i = 0; i < pts.length - 1; i++) {
            const p0 = pts[i - 1] || pts[i], p1 = pts[i], p2 = pts[i + 1], p3 = pts[i + 2] || p2;
            d += `C${(p1.x + (p2.x - p0.x) / 6).toFixed(1)},${cl(p1.y + (p2.y - p0.y) / 6).toFixed(1)} `
                + `${(p2.x - (p3.x - p1.x) / 6).toFixed(1)},${cl(p2.y - (p3.y - p1.y) / 6).toFixed(1)} `
                + `${p2.x},${p2.y}`;
        }
        return d;
    })();
    const area = pts.length > 1 ? `${line}L${pts[pts.length - 1].x},${P.t + ih}L${pts[0].x},${P.t + ih}Z` : '';

    // 网格 + 纵轴刻度（基线实线，其余虚线）
    let grid = '';
    for (let g = 0; g <= 4; g++) {
        const y = (P.t + ih - (ih * g) / 4).toFixed(1);
        grid += `<line x1="${P.l}" y1="${y}" x2="${W - P.r}" y2="${y}" stroke="${g ? 'rgba(148,163,200,.10)' : 'rgba(148,163,200,.24)'}" stroke-dasharray="${g ? '3 4' : ''}"/>`
            + `<text x="${P.l - 7}" y="${+y + 3.5}" text-anchor="end" font-size="9.5" fill="#aab6d8">${fmtTrafficBytes((nice * g) / 4)}</text>`;
    }
    // 横轴刻度（最多 ~6 个，末尾必显）
    let ticks = '';
    const step = Math.max(1, Math.ceil(pts.length / 5));
    pts.forEach((p, i) => {
        if (i % step && i !== pts.length - 1) return;
        ticks += `<text x="${p.x}" y="${H - 6}" text-anchor="middle" font-size="9.5" fill="#aab6d8">${esc(tickFmt(p.key))}</text>`;
    });

    const last = pts[pts.length - 1];
    host.innerHTML = `
      <svg width="${W}" height="${H}" style="display:block;overflow:visible">
        <defs>
          <linearGradient id="tfa-${name}" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stop-color="${c}" stop-opacity=".30"/>
            <stop offset=".65" stop-color="${c}" stop-opacity=".07"/>
            <stop offset="1" stop-color="${c}" stop-opacity="0"/>
          </linearGradient>
          <filter id="tfg-${name}" x="-30%" y="-30%" width="160%" height="160%">
            <feDropShadow dx="0" dy="2" stdDeviation="2.5" flood-color="${c}" flood-opacity=".35"/>
          </filter>
        </defs>
        ${grid}${ticks}
        ${area ? `<path d="${area}" fill="url(#tfa-${name})"/>` : ''}
        <path d="${line}" fill="none" stroke="${c}" stroke-width="2.25" stroke-linecap="round" stroke-linejoin="round" filter="url(#tfg-${name})"/>
        ${peak > 0 && last ? `<circle cx="${last.x}" cy="${last.y}" r="3.4" fill="#fff" stroke="${c}" stroke-width="2.2"/>` : ''}
        ${peak === 0 ? `<text x="${P.l + iw / 2}" y="${P.t + ih / 2}" text-anchor="middle" font-size="11" fill="#b7c1cf">该时段暂无流量</text>` : ''}
        <line id="tf-guide-${name}" y1="${P.t}" y2="${P.t + ih}" stroke="${c}" stroke-width="1.2" stroke-dasharray="4 3" opacity="0"/>
        <circle id="tf-cursor-${name}" r="4.2" fill="${c}" stroke="#fff" stroke-width="1.6" opacity="0"/>
        <rect id="tf-hit-${name}" x="${P.l}" y="${P.t}" width="${iw}" height="${ih}" fill="transparent" style="cursor:crosshair"/>
      </svg>
      <div class="tf-tip" id="tf-tip-${name}" style="display:none"></div>`;

    // 悬浮交互：最近点吸附 + 十字引导线 + 深色气泡提示
    const svg = host.querySelector('svg');
    const guide = host.querySelector(`#tf-guide-${name}`);
    const cursor = host.querySelector(`#tf-cursor-${name}`);
    const tip = host.querySelector(`#tf-tip-${name}`);
    const move = e => {
        const mx = e.clientX - svg.getBoundingClientRect().left;
        let best = 0, dist = Infinity;
        pts.forEach((p, i) => { const dd = Math.abs(p.x - mx); if (dd < dist) { dist = dd; best = i; } });
        const p = pts[best];
        guide.setAttribute('x1', p.x); guide.setAttribute('x2', p.x); guide.setAttribute('opacity', '.55');
        cursor.setAttribute('cx', p.x); cursor.setAttribute('cy', p.y); cursor.setAttribute('opacity', '1');
        tip.style.display = '';
        tip.innerHTML = `${esc(tipFmt(p.key))}<br><b>${fmtTrafficBytes(p.bytes)}</b>`;
        const half = tip.offsetWidth / 2 || 40; // 靠近左右边缘时钳制，防气泡溢出
        tip.style.left = Math.max(half + 2, Math.min(W - half - 2, p.x)) + 'px';
        tip.style.top = Math.max(p.y - 10, 30) + 'px';
    };
    const leave = () => {
        guide.setAttribute('opacity', '0'); cursor.setAttribute('opacity', '0'); tip.style.display = 'none';
    };
    const hit = host.querySelector(`#tf-hit-${name}`);
    hit.addEventListener('mousemove', move);
    hit.addEventListener('mouseleave', leave);
}

/** 单任务流量明细弹窗：总量 + 按小时/天/月三张折线图 */
window.stunTraffic = async id => {
    try {
        const d = await api('GET', `/api/stun/tasks/${id}/traffic`);
        const now = new Date();
        const hours = tfFillWindow(d.hours, 24, i => {
            const t = new Date(now); t.setHours(t.getHours() - i);
            return tfDateKey(t) + ' ' + tfPad(t.getHours());
        });
        const days = tfFillWindow(d.days, 30, i => {
            const t = new Date(now); t.setDate(t.getDate() - i);
            return tfDateKey(t);
        });
        const months = tfFillWindow(d.months, 12, i => {
            const t = new Date(now); t.setMonth(t.getMonth() - i);
            return `${t.getFullYear()}-${tfPad(t.getMonth() + 1)}`;
        });
        const data = { hour: hours, day: days, month: months };
        const peak = k => fmtTrafficBytes(Math.max(...data[k].map(p => p.bytes), 0));
        modal('流量统计', `
          <div class="tip">总流量：<b>${fmtTrafficBytes(d.total)}</b>（连接重建不清零，统计含双向转发字节；按小时/天/月归档，数值为已落库 + 实时增量）</div>
          <div class="tf-grid">
            ${['hour', 'day', 'month'].map(k => `
              <div class="tf-card">
                <div class="tf-head"><span class="tf-dot" style="background:${TF_THEMES[k].color};box-shadow:0 0 0 3px ${TF_THEMES[k].color}22"></span>${TF_THEMES[k].label}
                  <span class="tf-peak">峰值 ${peak(k)}</span></div>
                <div class="tf-body" id="tf-chart-${k}"></div>
              </div>`).join('')}
          </div>`, 'wide');
        tfRenderChart($('#tf-chart-hour'), 'hour', hours, TF_THEMES.hour,
            k => k.slice(11) + '时', k => k + '时');
        tfRenderChart($('#tf-chart-day'), 'day', days, TF_THEMES.day,
            k => k.slice(5), k => k);
        tfRenderChart($('#tf-chart-month'), 'month', months, TF_THEMES.month,
            k => k.slice(5) + '月', k => k.replace('-', '年') + '月');
    } catch (e) { toast(e.message, 'err'); }
};
