/* ============ 反向代理中心模块 ============ */
'use strict';

/** 字节 -> 人类可读 */
function pxBytes(n) {
    n = Number(n || 0);
    if (n >= 1048576) return (n / 1048576).toFixed(1) + ' MB';
    if (n >= 1024) return (n / 1024).toFixed(0) + ' KB';
    return n + ' B';
}

function pxCertBadge(expIso) {
    if (!expIso) return badge('无', 'gray');
    const days = (new Date(expIso) - Date.now()) / 86400000;
    if (days < 0) return badge('已过期', 'err');
    if (days < 15) return badge('将到期 ' + Math.ceil(days) + '天', 'warn');
    return badge('有效', 'ok');
}

/* ---------------- 页面骨架 ---------------- */

async function renderProxy() {
    $('#pageBody').innerHTML = `
      <div class="tip">反向代理中心：独立监听端口对外提供 <b>HTTP/1.1 + HTTP/2</b> 反向代理，
        按 <b>域名 + 路径前缀</b> 路由到内后端；HTTPS 依据 <b>SNI</b> 自动匹配「SSL 证书」模块已签发的证书，
        证书续期后自动热加载。支持 WebSocket 透传、强制 HTTPS、IP 白名单、BasicAuth、限流与
        <b>nginx 风格磁盘文件缓存</b>。默认监听 <b>80 / 443</b>，功能默认<b>关闭</b>，开启后面板其余流量不受影响。</div>

      <div id="proxyAlert"></div>

      <div class="panel">
        <div class="panel-title">服务设置与监听状态</div>
        <form id="proxySetForm" class="form-inline">
          <span class="inline-switch" title="开启后绑定端口对外提供代理服务">
            <label class="switch"><input type="checkbox" name="enabled" id="pxEnabled"><span class="slider"></span></label>
            <span class="muted small">启用代理</span>
          </span>
          <span class="field-inline">HTTP 端口 <input name="httpPort" id="pxHttp" type="number" min="1" max="65535" placeholder="80"></span>
          <span class="field-inline">HTTPS 端口 <input name="httpsPort" id="pxHttps" type="number" min="1" max="65535" placeholder="443"></span>
          <span class="inline-switch" title="前置代理/CDN 场景按 X-Forwarded-For / X-Real-IP / CF-Connecting-IP 解析访客真实来源 IP（用于访问统计与 IP 白名单）；直连暴露且需以真实 socket 对端为准时关闭">
            <label class="switch"><input type="checkbox" id="pxRealIp"><span class="slider"></span></label>
            <span class="muted small">解析真实来源 IP</span>
          </span>
          <button class="btn primary" type="submit">保存并应用</button>
          <span id="pxListenStatus" class="small muted"></span>
        </form>
      </div>

      <div class="panel">
        <div class="panel-title">SNI 证书清单
          <button class="btn small" style="float:right" onclick="pxReloadCerts()">⟳ 重载证书</button></div>
        <table>
          <thead><tr><th style="width:200px">任务名称</th><th>证书域名 (SAN)</th><th style="width:120px">到期状态</th><th style="width:200px">notAfter</th></tr></thead>
          <tbody id="pxCertBody"><tr><td colspan="4" class="muted">加载中...</td></tr></tbody>
        </table>
        <div class="small muted" id="pxCacheInfo" style="margin-top:8px"></div>
      </div>

      <div class="toolbar">
        <div class="spacer"></div>
        <button class="btn small" onclick="pxPurgeAll()">🧹 清空缓存</button>
        <button class="btn primary" onclick="pxForm()">＋ 新增站点</button>
      </div>
      <div class="panel"><table>
        <thead><tr>
          <th style="width:250px">站点</th>
          <th>域名 / 路径</th>
          <th style="width: 400px">后端</th>
          <th style="width:80px">证书</th>
          <th style="width:130px">流量 / 错误</th>
          <th style="width:80px">启用</th>
          <th style="width:120px">操作</th>
        </tr></thead>
        <tbody id="pxTbody"><tr><td colspan="7" class="muted">加载中...</td></tr></tbody>
      </table></div>`;

    $('#proxySetForm').addEventListener('submit', pxSaveSettings);
    await refreshProxy();
    setRefresh(refreshProxyRows, 8000);
}

/** 刷新：状态总览（监听/证书/告警/缓存）+ 站点行 */
async function refreshProxy() {
    const st = await api('GET', '/api/proxy/status');
    const L = st.listen || {};
    // 设置表单回填实际配置值
    $('#pxEnabled').checked = !!L.enabled;
    $('#pxHttp').value = L.httpPort || '';
    $('#pxHttps').value = L.httpsPort || '';
    $('#pxRealIp').checked = L.trustRealIp !== false; // 默认开启
    pxRenderListen(L);
    // 告警条
    const err = st.lastError || '';
    $('#proxyAlert').innerHTML = err
        ? `<div class="tip" style="border-left:4px solid var(--red);background:rgba(255,80,80,.08)">⚠️ ${esc(err)}</div>`
        : '';
    // 证书清单
    const certs = L.certs || [];
    $('#pxCertBody').innerHTML = certs.map(c => `
      <tr><td>${esc(c.name)}</td>
        <td class="docker-mono small" style="word-break:break-all">${esc(c.domains)}</td>
        <td>${pxCertBadge(c.notAfter)}</td>
        <td class="small muted">${esc((c.notAfter || '').replace('T', ' ').slice(0, 19))}</td></tr>`).join('')
        || '<tr><td colspan="4" class="muted">暂无可用证书（未签发或已过期）。到「SSL 证书」模块签发后点「重载证书」。</td></tr>';
    // 缓存概览
    const c = st.cache || {};
    $('#pxCacheInfo').textContent = `磁盘缓存：共 ${c.entries || 0} 项，占用 ${pxBytes(c.totalBytes)}。`;
    await refreshProxyRows(st.sites);
}

function pxRenderListen(L) {
    const el = $('#pxListenStatus');
    if (!L.enabled) { el.innerHTML = badge('已停用', 'gray') + ' <span class="muted">开启后绑定端口</span>'; return; }
    const http = L.boundHttp > 0 ? badge('HTTP:' + L.boundHttp, 'ok') : badge('HTTP 未绑定', 'err');
    const https = L.boundHttps > 0 ? badge('HTTPS:' + L.boundHttps, 'ok') : badge('HTTPS 未监听', 'warn');
    el.innerHTML = '监听状态 ' + http + ' ' + https;
}

/** 仅刷新站点数据行（合并状态统计） */
async function refreshProxyRows(preferedStatus) {
    const tbody = $('#pxTbody');
    if (!tbody) return;
    const sites = await api('GET', '/api/proxy/sites');
    let status = preferedStatus;
    if (!status) {
        const st = await api('GET', '/api/proxy/status');
        status = st.sites || [];
    }
    const sm = {};
    (status || []).forEach(s => sm[s.id] = s);
    tbody.innerHTML = sites.map(s => {
        const m = sm[s.id] || {};
        const cert = s.cert_mode === 'TASK' ? '指定' : s.cert_mode === 'NONE' ? 'HTTP' : '自动';
        return `<tr>
          <td>${esc(s.name)}</td>
          <td class="small" style="word-break:break-all">${esc(s.domains)}
            ${s.paths ? `<div class="muted">路径 ${esc(s.paths)}</div>` : ''}</td>
          <td class="docker-mono small" style="word-break:break-all">${esc(s.target)}</td>
          <td class="small">${cert}${s.force_https ? '<div class="muted">强跳</div>' : ''}</td>
          <td class="small">${m.active ? '活跃 ' + m.active + ' · ' : ''}${(m.qpm || 0) + ' 次/分'}
            ${(m.errors || 0) > 0 ? `<div class="small" style="color:var(--red)">${m.errors} 错误</div>` : ''}
            ${m.lastError ? `<div class="small muted" title="${esc(m.lastError)}">最近: ${esc(String(m.lastError).slice(0, 28))}…</div>` : ''}</td>
          <td><label class="switch"><input type="checkbox" ${s.enabled === 1 ? 'checked' : ''} onchange="pxToggle(${s.id}, this.checked)"><span class="slider"></span></label></td>
          <td>
            <button class="btn small" title="编辑" onclick="pxForm(${s.id})">✎</button>
            <button class="btn small danger" title="删除" onclick="pxDelete(${s.id}, '${esc(s.name)}')">🗑</button>
          </td>
        </tr>`;
    }).join('') || '<tr><td colspan="7" class="muted">暂无代理站点，点击右上角「新增站点」添加。</td></tr>';
}

/* ---------------- 服务设置 ---------------- */

window.pxSaveSettings = async e => {
    e.preventDefault();
    const f = new FormData(e.target);
    const body = {
        enabled: f.get('enabled') === 'on' || $('#pxEnabled').checked,
        httpPort: Number(f.get('httpPort') || 0),
        httpsPort: Number(f.get('httpsPort') || 0),
        trustRealIp: $('#pxRealIp').checked
    };
    try {
        const r = await api('POST', '/api/proxy/settings', body);
        toast(r.warning ? ('已应用，注意：' + r.warning) : '设置已保存');
        await refreshProxy();
    } catch (err) { toast(err.message, 'err'); }
};

window.pxReloadCerts = async () => {
    try { await api('POST', '/api/proxy/certs/reload'); toast('证书已重载'); refreshProxy(); }
    catch (e) { toast(e.message, 'err'); }
};

window.pxPurgeAll = async () => {
    if (!(await confirmBox({ title: '清空代理缓存', message: '确定清空全部站点的磁盘缓存文件？', confirmText: '清空', danger: true }))) return;
    try { const msg = await api('POST', '/api/proxy/cache/purge', {}); toast(msg); refreshProxy(); }
    catch (e) { toast(e.message, 'err'); }
};

window.pxToggle = async (id, enabled) => {
    try { await api('POST', '/api/proxy/sites/toggle', { id, enabled }); toast(enabled ? '已启用' : '已停用'); refreshProxyRows(); }
    catch (e) { toast(e.message, 'err'); refreshProxyRows(); }
};

window.pxDelete = async (id, name) => {
    if (!(await confirmBox({ title: '删除代理站点', message: `确定删除站点「${name}」？其磁盘缓存将一并清理。`, confirmText: '删除', danger: true }))) return;
    try { const msg = await api('DELETE', '/api/proxy/sites/' + id); toast(msg); refreshProxyRows(); }
    catch (e) { toast(e.message, 'err'); }
};

/* ---------------- 站点表单（基础 + 高级结构化 + 自定义 JSON） ---------------- */

// 编辑态：site 基础字段 + adv 高级配置工作对象
let _px = null;

window.pxForm = async (id) => {
    const certs = await api('GET', '/api/proxy/certs');
    let site, adv;
    if (id) {
        site = (await api('GET', '/api/proxy/sites')).find(x => x.id === id);
        try { adv = site.advanced ? JSON.parse(site.advanced) : {}; } catch (e) { adv = {}; }
    } else {
        site = { name: '', domains: '', paths: '', target: '', force_https: 0, cert_mode: 'AUTO', cert_task_id: null, enabled: 1 };
        const d = await api('GET', '/api/proxy/defaults');
        adv = d.advanced || {};
    }
    _px = { id, site, adv, certs };

    modal(id ? '编辑代理站点' : '新增代理站点', `
      <div class="px-tabs">
        <button type="button" class="px-tab active" data-tab="basic">基础配置</button>
        <button type="button" class="px-tab" data-tab="adv">高级配置</button>
        <button type="button" class="px-tab" data-tab="json">自定义 JSON</button>
      </div>

      <form id="pxFormEl">
        <div class="px-pane" data-tab="basic">
          <div class="field"><label>站点名称 <b>*</b></label><input name="name" required value="${esc(site.name || '')}"></div>
          <div class="field full"><label>匹配域名 <b>*</b></label>
            <input name="domains" required value="${esc(site.domains || '')}" placeholder="a.example.com, *.example.com">
            <div class="small muted">逗号分隔，支持 <b>*.example.com</b> 通配（同时匹配 example.com 本身）。</div></div>
          <div class="field full"><label>路径前缀</label>
            <input name="paths" value="${esc(site.paths || '')}" placeholder="/api, /portal（留空=整域名）">
            <div class="small muted">仅这些前缀走本站点；留空表示该域名全部路径。</div></div>
          <div class="field full"><label>后端地址 <b>*</b></label>
            <input name="target" required value="${esc(site.target || '')}" placeholder="http://127.0.0.1:3000 或 https://192.168.1.10:8443/base">
            <div class="small muted">http(s)://host:port，可带路径前缀作为回源基础路径。</div></div>
          <div class="field"><label>证书模式</label>
            <select name="cert_mode" id="pxCertMode" onchange="pxCertModeChanged()">
              ${['AUTO', 'TASK', 'NONE'].map(v => `<option value="${v}" ${site.cert_mode === v ? 'selected' : ''}>${
                    v === 'AUTO' ? '自动 (SNI 匹配)' : v === 'TASK' ? '指定证书任务' : '仅 HTTP (不接 TLS)'}</option>`).join('')}
            </select></div>
          <div class="field" id="pxCertTaskField"><label>指定证书任务</label>
            <select name="cert_task_id">
              <option value="">— 请选择已签发证书 —</option>
              ${certs.map(c => `<option value="${c.taskId}" ${String(site.cert_task_id) === String(c.taskId) ? 'selected' : ''}>${esc(c.name)}（${esc(c.domains)}）</option>`).join('')}
            </select></div>
          <div class="field"><label>强制 HTTPS 跳转</label>
            <select name="force_https"><option value="1" ${site.force_https ? 'selected' : ''}>是（HTTP 请求 301 到 https）</option><option value="0" ${!site.force_https ? 'selected' : ''}>否</option></select></div>
          <div class="field"><label>启用站点</label>
            <select name="enabled"><option value="1" ${site.enabled !== 0 ? 'selected' : ''}>启用</option><option value="0" ${site.enabled === 0 ? 'selected' : ''}>停用</option></select></div>
        </div>

        <div class="px-pane hidden" data-tab="adv">
          <div class="field"><label>连接超时（秒）</label><input id="aConnect" type="number" min="1" max="120"></div>
          <div class="field"><label>读空闲超时（秒）</label><input id="aIdle" type="number" min="5"></div>
          <div class="field"><label>请求体上限（MB，0=不限）</label><input id="aMaxBody" type="number" min="0"></div>
          <div class="field"><label>限流（QPS，0=不限）</label><input id="aRate" type="number" min="0" step="0.1"></div>
          <div class="field full"><label>路径前缀剥离 stripPrefix</label><input id="aStrip" placeholder="/portal（与路径重写二选一）"></div>
          <div class="field"><label>路径重写 from</label><input id="aRwFrom" placeholder="/api"></div>
          <div class="field"><label>路径重写 to</label><input id="aRwTo" placeholder="/v2"></div>
          <div class="field"><label>BasicAuth 用户</label><input id="aAuthUser" autocomplete="off"></div>
          <div class="field"><label>BasicAuth 密码</label><input id="aAuthPass" type="password" autocomplete="new-password"></div>
          <div class="field full"><label>IP 白名单</label><input id="aIpAllow" placeholder="192.168.1., 10.0.0.5（精确 IP 或以点结尾的网段前缀，逗号分隔，留空=不限）"></div>
          <div class="field"><label>后端 TLS 免校验（自签 https 后端）</label>
            <select id="aInsecure"><option value="true">是</option><option value="false">否</option></select></div>
          <div class="field"><label>前端协议（浏览器 → 代理）</label>
            <select id="aFrontProto"><option value="h2">HTTP/2（默认）</option><option value="http1">HTTP/1.1（关闭 h2）</option></select></div>
          <div class="small muted full">h2 是信用制流控：浏览器给每条流的窗口从 64KB 起步、按其观测的 BDP 自调，
            单流下载速率会被钉在「窗口 / 往返」。大文件下载型站点若跑不满带宽可改 <b>HTTP/1.1</b>
            （socket 缓冲由内核自调，无这层额度；实测经代理吞吐高于 h2）。仅影响 HTTPS 的 ALPN 通告，
            明文端口的 h2c prior-knowledge 不受此项约束。</div>
          <div class="field full adv-cache-title"><b>回源协议 / HTTP/2</b></div>
          <div class="field"><label>回源协议</label>
            <select id="aBackendProto"><option value="http1">HTTP/1.1</option><option value="h2">HTTP/2（h2c / ALPN h2）</option></select></div>
          <div class="field"><label>h2 单连接并发流上限</label><input id="aH2Streams" type="number" min="1" max="1000"></div>
          <div class="field"><label>h2 后端连接上限</label><input id="aH2Conns" type="number" min="1" max="1024"></div>
          <div class="small muted full">选 <b>HTTP/2</b> 时：明文后端走 h2c prior-knowledge，https 后端经 ALPN 协商 h2（协商不到 h2 直接报 502，不静默降级）；
            一条后端连接并发承载多事务，只开关流不重建连接，可显著降低后端 fd 消耗。
            此模式忽略下方「回源连接池」的开关（空闲回收秒数仍用于 h2 连接），且不支持 Upgrade/WebSocket 与 HTTP/1.1 前端的 gRPC。</div>
          <div class="field full adv-cache-title"><b>回源长连接（upstream keepalive）</b></div>
          <div class="field"><label>启用回源连接池</label>
            <select id="aUpstreamKa"><option value="true">启用（复用空闲连接）</option><option value="false">关闭（每请求短连接）</option></select></div>
          <div class="field"><label>空闲连接回收（秒）</label><input id="aUpstreamIdle" type="number" min="1" max="3600"></div>
          <div class="field"><label>每后端空闲连接上限</label><input id="aUpstreamMax" type="number" min="1" max="4096"></div>
          <div class="small muted full">对 <b>https 回源</b> 与 <b>跨主机后端</b> 收益明显（省去每请求 TLS/TCP 建连）；纯 localhost HTTP 后端收益有限，可按需开启。</div>
          <div class="field full adv-cache-title"><b>文件缓存</b></div>
          <div class="field"><label>启用缓存</label><select id="cEnabled"><option value="true">是</option><option value="false">否</option></select></div>
          <div class="field"><label>缓存时长（秒）</label><input id="cTtl" type="number" min="1"></div>
          <div class="field"><label>单文件上限（MB）</label><input id="cMaxItem" type="number" min="1"></div>
          <div class="field"><label>站点容量上限（MB）</label><input id="cMax" type="number" min="1"></div>
          <div class="field full"><label>缓存扩展名</label><input id="cExt" placeholder="js, css, png, jpg, woff2（逗号分隔）"></div>
          <div class="small muted full">请求/响应头改写（reqHeaders/respHeaders）等进阶项请在「自定义 JSON」页编辑，切换页签会自动同步。</div>
        </div>

        <div class="px-pane hidden" data-tab="json">
          <div class="field full"><label>advanced 完整 JSON</label>
            <textarea id="aJson" rows="18" class="docker-mono" style="width:100%"></textarea>
            <div class="small muted" id="aJsonHint">直接编辑高级配置；保存前会做格式与字段校验。</div></div>
        </div>

        <div class="form-foot full">
          <button type="button" class="btn" onclick="closeModal()">取消</button>
          <button class="btn primary">保存站点</button>
        </div>
      </form>`);

    pxFillAdvControls();
    $('.px-pane[data-tab="basic"]').classList.remove('hidden');
    pxCertModeChanged();

    // 页签切换：adv <-> json 双向同步
    $$('.px-tab').forEach(t => t.addEventListener('click', () => {
        const to = t.dataset.tab;
        const cur = $('.px-tab.active').dataset.tab;
        if (cur === 'adv' && to === 'json') { pxReadAdvControls(); $('#aJson').value = JSON.stringify(_px.adv, null, 2); }
        if (cur === 'json' && to === 'adv') { if (!pxParseJson()) return; pxFillAdvControls(); }
        $$('.px-tab').forEach(x => x.classList.toggle('active', x === t));
        $$('.px-pane').forEach(p => p.classList.toggle('hidden', p.dataset.tab !== to));
    }));

    $('#pxFormEl').addEventListener('submit', async e => {
        e.preventDefault();
        const tab = $('.px-tab.active').dataset.tab;
        if (tab === 'json') { if (!pxParseJson()) return; }
        else if (tab === 'adv') pxReadAdvControls();
        const f = new FormData(e.target);
        const body = {
            name: (f.get('name') || '').trim(),
            domains: (f.get('domains') || '').trim(),
            paths: (f.get('paths') || '').trim(),
            target: (f.get('target') || '').trim(),
            forceHttps: f.get('force_https') === '1',
            certMode: f.get('cert_mode'),
            certTaskId: f.get('cert_task_id') ? Number(f.get('cert_task_id')) : 0,
            enabled: f.get('enabled') !== '0',
            advanced: _px.adv
        };
        try {
            if (id) await api('PUT', '/api/proxy/sites/' + id, body);
            else await api('POST', '/api/proxy/sites', body);
            closeModal(); toast('保存成功'); refreshProxyRows();
        } catch (err) { toast(err.message, 'err'); }
    });
};

window.pxCertModeChanged = () => {
    const m = $('#pxCertMode').value;
    $('#pxCertTaskField').classList.toggle('hidden', m !== 'TASK');
};

/** 把 _px.adv 拆到结构化控件（缺省用后端默认值语义） */
function pxFillAdvControls() {
    const a = _px.adv, t = a.timeout || {}, c = a.cache || {}, ba = a.basicAuth || {}, rw = a.pathRewrite || {};
    $('#aConnect').value = t.connectSec ?? 10;
    $('#aIdle').value = t.idleSec ?? 300;
    $('#aMaxBody').value = a.maxBodyMB ?? 0;
    $('#aRate').value = a.rateLimitRps ?? 0;
    $('#aStrip').value = a.stripPrefix || '';
    $('#aRwFrom').value = rw.from || '';
    $('#aRwTo').value = rw.to || '';
    $('#aAuthUser').value = ba.user || '';
    $('#aAuthPass').value = ba.pass || '';
    $('#aIpAllow').value = (a.ipAllow || []).join(', ');
    $('#aInsecure').value = String(!!a.backendInsecure);
    $('#aFrontProto').value = a.frontProtocol === 'http1' ? 'http1' : 'h2';
    $('#aBackendProto').value = a.backendProtocol === 'h2' ? 'h2' : 'http1';
    $('#aH2Streams').value = a.h2MaxConcurrentStreams ?? 100;
    $('#aH2Conns').value = a.h2MaxConns ?? 4;
    $('#aUpstreamKa').value = String(!!a.upstreamKeepalive);
    $('#aUpstreamIdle').value = a.upstreamIdleSec ?? 60;
    $('#aUpstreamMax').value = a.upstreamMaxIdleConns ?? 32;
    $('#cEnabled').value = String(!!c.enabled);
    $('#cTtl').value = c.ttlSec ?? 3600;
    $('#cMaxItem').value = c.maxItemMB ?? 8;
    $('#cMax').value = c.maxMB ?? 256;
    $('#cExt').value = (c.extensions || []).join(', ');
}

/** 结构化控件值写回 _px.adv（保留未覆盖字段如 reqHeaders/respHeaders） */
function pxReadAdvControls() {
    const a = _px.adv;
    const num = v => { const n = Number(v); return isNaN(n) ? 0 : n; };
    const csv = v => v.split(',').map(s => s.trim()).filter(Boolean);
    a.timeout = { connectSec: num($('#aConnect').value) || 10, idleSec: num($('#aIdle').value) || 300 };
    a.maxBodyMB = num($('#aMaxBody').value);
    a.rateLimitRps = num($('#aRate').value);
    const strip = $('#aStrip').value.trim();
    const rwF = $('#aRwFrom').value.trim(), rwT = $('#aRwTo').value.trim();
    delete a.stripPrefix; delete a.pathRewrite;
    if (strip) a.stripPrefix = strip;
    else if (rwF && rwT) a.pathRewrite = { from: rwF, to: rwT };
    const user = $('#aAuthUser').value.trim(), pass = $('#aAuthPass').value;
    if (user) a.basicAuth = { user, pass }; else delete a.basicAuth;
    const ip = csv($('#aIpAllow').value);
    if (ip.length) a.ipAllow = ip; else delete a.ipAllow;
    a.backendInsecure = $('#aInsecure').value === 'true';
    a.frontProtocol = $('#aFrontProto').value === 'http1' ? 'http1' : 'h2';
    const proto = $('#aBackendProto').value === 'h2' ? 'h2' : 'http1';
    a.backendProtocol = proto;
    a.h2MaxConcurrentStreams = Math.min(1000, Math.max(1, num($('#aH2Streams').value) || 100));
    a.h2MaxConns = Math.min(1024, Math.max(1, num($('#aH2Conns').value) || 4));
    a.upstreamKeepalive = $('#aUpstreamKa').value === 'true';
    a.upstreamIdleSec = num($('#aUpstreamIdle').value) || 60;
    a.upstreamMaxIdleConns = num($('#aUpstreamMax').value) || 32;
    a.cache = {
        enabled: $('#cEnabled').value === 'true',
        ttlSec: num($('#cTtl').value) || 3600,
        maxItemMB: num($('#cMaxItem').value) || 8,
        maxMB: num($('#cMax').value) || 256,
        respectUpstream: (a.cache && a.cache.respectUpstream !== false),
        extensions: csv($('#cExt').value)
    };
}

/** 解析 JSON 页到 _px.adv；非法给提示并返回 false */
function pxParseJson() {
    const txt = $('#aJson').value.trim() || '{}';
    try {
        const o = JSON.parse(txt);
        if (typeof o !== 'object' || Array.isArray(o)) throw new Error('必须是 JSON 对象');
        _px.adv = o;
        $('#aJsonHint').className = 'small muted';
        $('#aJsonHint').textContent = '格式校验通过。';
        return true;
    } catch (e) {
        $('#aJsonHint').className = 'small';
        $('#aJsonHint').style.color = 'var(--red)';
        $('#aJsonHint').textContent = 'JSON 解析失败：' + e.message;
        return false;
    }
}
