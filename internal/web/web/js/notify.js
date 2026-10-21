/* ============ 统一告警通知中心模块 ============ */
'use strict';

const NOTIFY_TYPES = { WEBHOOK: 'Webhook 回调', EMAIL: '邮件 (SMTP)', DINGTALK: '钉钉机器人' };

function notifyTypeBadge(type) {
    return badge(NOTIFY_TYPES[type] || type, type === 'EMAIL' ? 'info' : type === 'DINGTALK' ? 'warn' : 'gray');
}

/** 只刷新两张表格的数据行（渠道表 + 最近发送记录表），不重绘 tip/工具栏/表头 */
async function refreshNotifyRows() {
    const chBody = $('#notifyChTbody');
    if (!chBody) return; // 已离开本页，静默退出
    const [channels, logs] = await Promise.all([
        api('GET', '/api/notify/channels'),
        api('GET', '/api/notify/logs?limit=10')
    ]);
    chBody.innerHTML = channels.map(c => `
      <tr>
        <td>${esc(c.name)}</td>
        <td>${notifyTypeBadge(c.type)}</td>
        <td><label class="switch"><input type="checkbox" ${c.enabled === 1 ? 'checked' : ''} onchange="notifyToggle(${c.id}, this.checked)"><span class="slider"></span></label>
          <span class="small muted">${c.enabled === 1 ? '启用' : '停用'}</span></td>
        <td>
          <button class="btn small success" onclick="notifyTest(${c.id})">测试发送</button>
          <button class="btn small" onclick="notifyForm(${c.id})">编辑</button>
          <button class="btn small danger" onclick="notifyDelete(${c.id})">删除</button>
        </td>
      </tr>`).join('') || '<tr><td colspan="4" class="muted">暂无通知渠道，点击右上角「新增渠道」添加。</td></tr>';
    const logBody = $('#notifyLogTbody');
    if (logBody) logBody.innerHTML = logs.map(l => {
        const ok = String(l.result || '').startsWith('OK');
        return `<tr>
          <td class="log-cell-time">${esc(l.time || '')}</td>
          <td>${esc(l.channel || '-')}</td>
          <td class="small muted">${esc(l.event || '')}</td>
          <td>${esc(l.title || '')}</td>
          <td>${badge(ok ? '成功' : '失败', ok ? 'ok' : 'err')}<span class="small muted"> ${esc(l.result || '')}</span></td>
        </tr>`;
    }).join('') || '<tr><td colspan="5" class="muted">暂无发送记录</td></tr>';
}

/** 首次进入通知页：绘制页面骨架（tip/工具栏/两张表的表头 + 空 tbody），随后只填充数据行 */
async function renderNotify() {
    $('#pageBody').innerHTML = `
      <div class="tip">集中维护通知渠道（<b>Webhook</b> / <b>邮件</b> / <b>钉钉机器人</b>），可用性监控故障恢复、登录锁定等事件将按启用渠道自动扇出推送。
        各模块事件通过统一接口投递，发送失败仅记录不影响主流程。</div>
      <div class="toolbar"><div class="spacer"></div><button class="btn primary" onclick="notifyForm()">＋ 新增渠道</button></div>
      <div class="panel"><table>
        <thead><tr><th>名称</th><th>类型</th><th>状态</th><th style="width:230px">操作</th></tr></thead>
        <tbody id="notifyChTbody"><tr><td colspan="4" class="muted">加载中...</td></tr></tbody>
      </table></div>
      <div class="panel">
        <h3 class="dash-panel-title">📬 最近发送记录 <span class="muted small" style="font-weight:400">（最多 10 条）</span></h3>
        <table><thead><tr><th style="width:150px">时间</th><th style="width:150px">渠道</th><th style="width:200px">事件</th><th>标题</th><th>结果</th></tr></thead>
          <tbody id="notifyLogTbody"><tr><td colspan="5" class="muted">加载中...</td></tr></tbody></table>
      </div>`;
    await refreshNotifyRows();
}

window.notifyToggle = async (id, enabled) => {
    const c = (await api('GET', '/api/notify/channels')).find(x => x.id === id);
    try {
        await api('PUT', '/api/notify/channels/' + id, { name: c.name, type: c.type, enabled, config: JSON.parse(c.config || '{}') });
        toast(enabled ? '已启用渠道' : '已停用');
    } catch (e) { toast(e.message, 'err'); }
    refreshNotifyRows();
};

window.notifyTest = async id => {
    try { const msg = await api('POST', `/api/notify/channels/${id}/test`); toast(msg, String(msg).startsWith('测试发送成功') ? 'ok' : 'err'); }
    catch (e) { toast(e.message, 'err'); }
    refreshNotifyRows();
};

window.notifyDelete = async id => {
    if (!(await confirmBox({ title: '删除通知渠道', message: '确定删除该通知渠道？', confirmText: '删除', danger: true }))) return;
    try { const msg = await api('DELETE', '/api/notify/channels/' + id); toast(msg); refreshNotifyRows(); }
    catch (e) { toast(e.message, 'err'); }
};

/** 按渠道类型渲染配置表单字段（editVal 为已保存 config 的对象） */
function notifyConfigFields(type, cfg) {
    const v = k => esc(cfg[k] ?? '');
    switch (type) {
        case 'EMAIL': return `
          <div class="field"><label>SMTP 服务器 <b>*</b></label><input name="c_host" required value="${v('host')}" placeholder="smtp.qq.com"></div>
          <div class="field"><label>端口</label><input name="c_port" type="number" value="${cfg.port ?? 465}"></div>
          <div class="field"><label>加密方式</label>
            <select name="c_secure">
              <option value="ssl" ${cfg.starttls ? '' : 'selected'}>SSL (465, smtps)</option>
              <option value="starttls" ${cfg.starttls ? 'selected' : ''}>STARTTLS (587)</option>
              <option value="none" ${!cfg.starttls && cfg.ssl === false ? 'selected' : ''}>不加密 (25)</option>
            </select></div>
          <div class="field"><label>用户名</label><input name="c_username" value="${v('username')}" placeholder="发件邮箱"></div>
          <div class="field"><label>密码 / 授权码</label><input name="c_password" type="password" value="${v('password')}"></div>
          <div class="field"><label>发件人 (From)</label><input name="c_from" value="${v('from')}" placeholder="留空则用用户名"></div>
          <div class="field full"><label>收件人 (To) <b>*</b></label><input name="c_to" required value="${v('to')}" placeholder="多个收件人以逗号分隔"></div>
          <div class="field full" style="margin-top:2px"><label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:13px;color:var(--text)">
            <input type="checkbox" name="c_saveSent" ${cfg.saveSent ? 'checked' : ''}
              onchange="document.querySelectorAll('.imap-only').forEach(e=>e.style.display=this.checked?'':'none')">
            保存到「已发送」文件夹（经 IMAP 存档）</label></div>
          <div class="field imap-only" style="display:${cfg.saveSent ? '' : 'none'}"><label>IMAP 服务器</label>
            <input name="c_imapHost" value="${v('imapHost')}" placeholder="留空同 SMTP 服务器"></div>
          <div class="field imap-only" style="display:${cfg.saveSent ? '' : 'none'}"><label>IMAP 端口</label>
            <input name="c_imapPort" type="number" value="${cfg.imapPort ?? 993}"></div>
          <div class="field imap-only" style="display:${cfg.saveSent ? '' : 'none'}"><label>IMAP 加密方式</label>
            <select name="c_imapSecure">
              <option value="ssl" ${cfg.imapStarttls || cfg.imapSsl === false ? '' : 'selected'}>SSL (993, imaps)</option>
              <option value="starttls" ${cfg.imapStarttls ? 'selected' : ''}>STARTTLS (143)</option>
              <option value="none" ${!cfg.imapStarttls && cfg.imapSsl === false ? 'selected' : ''}>不加密</option>
            </select></div>
          <div class="field full imap-only" style="display:${cfg.saveSent ? '' : 'none'}"><label>已发送文件夹名</label>
            <input name="c_sentFolder" value="${v('sentFolder')}" placeholder="留空自动探测（mailu 默认 Sent）"></div>`;
        case 'DINGTALK': return `
          <div class="field full"><label>机器人 Webhook <b>*</b></label>
            <input name="c_webhook" required value="${v('webhook')}" placeholder="https://oapi.dingtalk.com/robot/send?access_token=..."></div>
          <div class="field full"><label>加签密钥 Secret（可选）</label>
            <input name="c_secret" value="${v('secret')}" placeholder="机器人安全设置开启「加签」时填写"></div>`;
        default: return `
          <div class="field full"><label>回调地址 URL <b>*</b></label>
            <input name="c_url" required value="${v('url')}" placeholder="https://example.com/hook?title=${'${title}'}"></div>
          <div class="field"><label>请求方法</label>
            <select name="c_method"><option ${cfg.method !== 'GET' ? 'selected' : ''}>POST</option><option ${cfg.method === 'GET' ? 'selected' : ''}>GET</option></select></div>
          <div class="field"><label>请求头（JSON，可选）</label>
            <input name="c_headers" value="${cfg.headers ? esc(JSON.stringify(cfg.headers)) : ''}" placeholder='{"Authorization":"Bearer xxx"}'></div>
          <div class="field full"><label>请求体模板（可选，留空用默认 JSON）</label>
            <textarea name="c_bodyTemplate" rows="3" placeholder='支持占位符 \${title} \${message} \${event} \${time}'>${v('bodyTemplate')}</textarea></div>`;
    }
}

/** 从表单收集指定类型的 config 对象 */
function notifyCollectConfig(type, f) {
    const n = s => { const x = f.get(s); return x === '' || x == null ? undefined : x; };
    if (type === 'EMAIL') {
        const secure = f.get('c_secure');
        const cfg = {
            host: f.get('c_host'), port: Number(f.get('c_port') || 465),
            ssl: secure === 'ssl', starttls: secure === 'starttls',
            username: n('c_username'), password: n('c_password'),
            from: n('c_from'), to: f.get('c_to')
        };
        if (f.get('c_saveSent') === 'on') {
            const is = f.get('c_imapSecure');
            cfg.saveSent = true;
            cfg.imapHost = n('c_imapHost');
            cfg.imapPort = Number(f.get('c_imapPort') || 993);
            cfg.imapSsl = is !== 'starttls' && is !== 'none';
            cfg.imapStarttls = is === 'starttls';
            cfg.sentFolder = n('c_sentFolder');
        }
        return cfg;
    }
    if (type === 'DINGTALK') return { webhook: f.get('c_webhook'), secret: n('c_secret') };
    const cfg = { url: f.get('c_url'), method: f.get('c_method') };
    const h = f.get('c_headers');
    if (h && h.trim()) { try { cfg.headers = JSON.parse(h); } catch (e) { throw new Error('请求头需为合法 JSON'); } }
    const bt = f.get('c_bodyTemplate');
    if (bt && bt.trim()) cfg.bodyTemplate = bt;
    return cfg;
}

window.notifyForm = async (id) => {
    let c = { type: 'WEBHOOK', enabled: 1 }, cfg = {};
    if (id) {
        c = (await api('GET', '/api/notify/channels')).find(x => x.id === id);
        try { cfg = JSON.parse(c.config || '{}'); } catch (e) { cfg = {}; }
    }
    modal(id ? '编辑通知渠道' : '新增通知渠道', `
      <form id="notifyFormEl" class="form-grid">
        <div class="field"><label>渠道名称 <b>*</b></label><input name="name" required value="${esc(c.name || '')}"></div>
        <div class="field"><label>渠道类型 <b>*</b></label>
          <select name="type" onchange="notifyTypeChanged(this.value)">
            ${Object.entries(NOTIFY_TYPES).map(([k, n]) => `<option value="${k}" ${c.type === k ? 'selected' : ''}>${n}</option>`).join('')}
          </select></div>
        <div class="field"><label>启用</label><select name="enabled"><option value="true" ${c.enabled !== 0 ? 'selected' : ''}>启用</option><option value="false" ${c.enabled === 0 ? 'selected' : ''}>停用</option></select></div>
        <div class="field full"><label id="cfgLabel" style="margin-top:4px">渠道配置</label></div>
        <div id="cfgFields" class="full">${notifyConfigFields(c.type, cfg)}</div>
        <div class="form-foot full">
          <button type="button" class="btn" onclick="notifyDraftTest()">试发测试</button>
          <span style="flex:1"></span>
          <button type="button" class="btn" onclick="closeModal()">取消</button>
          <button class="btn primary">保存</button>
        </div>
      </form>`);

    window.notifyTypeChanged = type => {
        // 切换类型时用当前类型下的默认空配置重绘（编辑同名类型时保留原值由后端回显，切换即重置表单字段）
        $('#cfgFields').innerHTML = notifyConfigFields(type, {});
    };

    window.notifyDraftTest = async () => {
        const f = new FormData($('#notifyFormEl'));
        let config;
        try { config = notifyCollectConfig(f.get('type'), f); } catch (e) { toast(e.message, 'err'); return; }
        try { const msg = await api('POST', '/api/notify/channels/test', { type: f.get('type'), config }); toast(msg, String(msg).startsWith('测试发送成功') ? 'ok' : 'err'); }
        catch (e) { toast(e.message, 'err'); }
    };

    $('#notifyFormEl').addEventListener('submit', async e => {
        e.preventDefault();
        const f = new FormData(e.target);
        let config;
        try { config = notifyCollectConfig(f.get('type'), f); } catch (err) { toast(err.message, 'err'); return; }
        const body = { name: f.get('name'), type: f.get('type'), enabled: f.get('enabled') === 'true', config };
        try {
            if (id) await api('PUT', '/api/notify/channels/' + id, body);
            else await api('POST', '/api/notify/channels', body);
            closeModal(); toast('保存成功'); refreshNotifyRows();
        } catch (err) { toast(err.message, 'err'); }
    });
};
