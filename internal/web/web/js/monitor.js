/* ============ 服务/端口可用性监控模块 ============ */
'use strict';

/** 监控状态徽章：UP 绿 / DOWN 红 / UNKNOWN 灰 */
function monStatusBadge(s) {
    if (s === 'UP') return badge('UP 正常', 'ok');
    if (s === 'DOWN') return badge('DOWN 故障', 'err');
    return badge('未探测', 'gray');
}

/** 只刷新监控任务表格数据行（<tbody>），不重绘 tip/工具栏/表头 */
async function refreshMonitorRows() {
    const tbody = $('#monitorTbody');
    if (!tbody) return; // 已离开本页，静默退出
    const tasks = await api('GET', '/api/monitor/tasks');
    const monSub = t => (t.type === 'HTTP' || t.type === 'HTTPS')
        ? `${esc(t.type)} · ${esc(t.method || 'GET')}` : esc(t.type);
    tbody.innerHTML = tasks.map(t => `
      <tr>
        <td>${esc(t.name)}<div class="small muted">${monSub(t)}</div></td>
        <td class="docker-mono small" style="word-break:break-all">${esc(t.target)}</td>
        <td>${monStatusBadge(t.last_status)}
          ${t.last_status === 'DOWN' && t.fail_count > 1 ? `<div class="small muted">连续失败 ${t.fail_count}</div>` : ''}</td>
        <td>${t.last_latency_ms != null ? t.last_latency_ms + ' ms' : '<span class="muted">-</span>'}</td>
        <td class="small muted">${esc(t.last_check || '-')}</td>
        <td><label class="switch"><input type="checkbox" ${t.enabled === 1 ? 'checked' : ''} onchange="monToggle(${t.id}, this.checked)"><span class="slider"></span></label>
          <span class="small muted">${t.enabled === 1 ? '每' + t.interval_sec + 's' : '停用'}</span></td>
        <td>
          <button class="btn small success" onclick="monRun(${t.id})">立即探测</button>
          <button class="btn small" onclick="monForm(${t.id})">编辑</button>
          <button class="btn small danger" onclick="monDelete(${t.id})">删除</button>
        </td>
      </tr>`).join('') || '<tr><td colspan="7" class="muted">暂无监控任务，点击右上角「新增监控任务」添加。</td></tr>';
}

/** 首次进入监控页：绘制页面骨架（tip/工具栏/表头 + 空 tbody），随后只填充数据行 */
async function renderMonitor() {
    $('#pageBody').innerHTML = `
      <div class="tip">支持 <b>HTTP</b>（URL 可为 http/https，按期望状态码 + 可选关键字判定）、<b>TCP</b>（端口连接可达）、
        <b>UDP</b>（尽力探测：收到回包判可达；无回包但未收到 ICMP 端口不可达差错也按可达处理，因为多数 UDP 服务不会回应未知报文；
        53 端口会发送标准 DNS 查询，按应答判定）三类探测。抗抖动：单个探测周期内对连接超时、DNS 解析失败等
        瞬时故障自动重试 3 次（单次超时最少 3 秒），且「异常→恢复」需连续多个周期成功才确认，避免链路抖动刷屏。
        目标不可用时向「通知中心」已启用渠道推送告警，恢复时可推送恢复通知。探测在独立线程执行且各任务错峰触发，不影响其他定时任务。</div>
      <div class="toolbar"><div class="spacer"></div><button class="btn primary" onclick="monForm()">＋ 新增监控任务</button></div>
      <div class="panel"><table>
        <thead><tr>
          <th style="width:200px">任务</th>
          <th>目标</th>
          <th style="width:150px">状态</th>
          <th style="width:100px">延迟</th>
          <th style="width:180px">最近探测</th>
          <th style="width:130px">定时</th>
          <th style="width:230px">操作</th>
        </tr></thead>
        <tbody id="monitorTbody"><tr><td colspan="7" class="muted">加载中...</td></tr></tbody>
      </table></div>`;
    await refreshMonitorRows();
    setRefresh(refreshMonitorRows, 15000);
}

window.monToggle = async (id, enabled) => {
    const t = (await api('GET', '/api/monitor/tasks')).find(x => x.id === id);
    try {
        await api('PUT', '/api/monitor/tasks/' + id, monBody(t, { enabled }));
        toast(enabled ? '已启用监控' : '已停用');
    } catch (e) { toast(e.message, 'err'); }
    refreshMonitorRows();
};

window.monRun = async id => {
    try {
        const msg = await api('POST', `/api/monitor/tasks/${id}/run`);
        toast(msg);
        setTimeout(refreshMonitorRows, 2500);
        setTimeout(refreshMonitorRows, 6000);
    } catch (e) { toast(e.message, 'err'); }
};

window.monDelete = async id => {
    if (!(await confirmBox({ title: '删除监控任务', message: '确定删除该监控任务？', confirmText: '删除', danger: true }))) return;
    try { const msg = await api('DELETE', '/api/monitor/tasks/' + id); toast(msg); refreshMonitorRows(); }
    catch (e) { toast(e.message, 'err'); }
};

/** 任务对象 -> 提交体；覆盖 override 字段（用于开关复用现有值） */
function monBody(t, override) {
    return Object.assign({
        name: t.name, type: t.type, target: t.target, method: t.method || 'GET',
        keyword: t.keyword || '', expect_status: t.expect_status, interval_sec: t.interval_sec,
        timeout_sec: t.timeout_sec, fail_threshold: t.fail_threshold,
        enabled: t.enabled === 1, notify_on_recovery: t.notify_on_recovery === 1
    }, override || {});
}

window.monForm = async (id) => {
    let t = { type: 'HTTP', method: 'GET', expect_status: 200, interval_sec: 60, timeout_sec: 10, fail_threshold: 2, enabled: 1, notify_on_recovery: 1 };
    if (id) t = (await api('GET', '/api/monitor/tasks')).find(x => x.id === id);
    modal(id ? '编辑监控任务' : '新增监控任务', `
      <form id="monFormEl" class="form-grid">
        <div class="field"><label>任务名称 <b>*</b></label><input name="name" required value="${esc(t.name || '')}"></div>
        <div class="field"><label>探测类型 <b>*</b></label>
          <select name="type" onchange="monTypeChanged(this.value)">
            ${['HTTP', 'TCP', 'UDP'].map(v => `<option value="${v}" ${t.type === v ? 'selected' : ''}>${v}</option>`).join('')}
          </select></div>
        <div class="field full"><label>探测目标 <b>*</b></label>
          <input name="target" id="mTarget" required value="${esc(t.target || '')}" autocomplete="off">
          <div class="small muted" id="mTargetHint"></div></div>
        <div class="field" id="mMethodField"><label>请求方法</label>
          <select name="method"><option ${t.method !== 'POST' ? 'selected' : ''}>GET</option><option ${t.method === 'POST' ? 'selected' : ''}>POST</option></select></div>
        <div class="field" id="mExpectField"><label>期望状态码（0=接受 2xx/3xx）</label>
          <input name="expect_status" type="number" min="0" value="${t.expect_status ?? 200}"></div>
        <div class="field full" id="mKeywordField"><label>关键字（响应体包含则判正常，留空不校验）</label>
          <input name="keyword" value="${esc(t.keyword || '')}"></div>
        <div class="field"><label>探测间隔（秒，最小15）</label><input name="interval_sec" type="number" min="15" value="${t.interval_sec ?? 60}"></div>
        <div class="field"><label>超时（秒，最少按 3 秒生效）</label><input name="timeout_sec" type="number" min="1" value="${t.timeout_sec ?? 10}">
          <div class="small muted">经 VPN/穿透链路访问的目标建议 ≥5 秒。</div></div>
        <div class="field"><label>连续失败告警阈值（次）</label><input name="fail_threshold" type="number" min="1" value="${t.fail_threshold ?? 2}">
          <div class="small muted">指连续失败的周期数；设 1 时一次抖动即告警。</div></div>
        <div class="field"><label>启用监控</label><select name="enabled"><option value="true" ${t.enabled !== 0 ? 'selected' : ''}>启用</option><option value="false" ${t.enabled === 0 ? 'selected' : ''}>停用</option></select></div>
        <div class="field"><label>恢复时推送通知</label><select name="notify_on_recovery"><option value="true" ${t.notify_on_recovery !== 0 ? 'selected' : ''}>是</option><option value="false" ${t.notify_on_recovery === 0 ? 'selected' : ''}>否</option></select></div>
        <div class="form-foot full">
          <button type="button" class="btn" onclick="closeModal()">取消</button>
          <button class="btn primary">保存</button>
        </div>
      </form>`);

    window.monTypeChanged = type => {
        // HTTPS 类型已并入 HTTP（按 URL scheme 请求），兼容存量 HTTPS 任务
        const http = type === 'HTTP' || type === 'HTTPS';
        $('#mMethodField').classList.toggle('hidden', !http);
        $('#mExpectField').classList.toggle('hidden', !http);
        $('#mKeywordField').classList.toggle('hidden', !http);
        const target = $('#mTarget'), hint = $('#mTargetHint');
        if (http) {
            target.placeholder = 'https://example.com/health';
            hint.textContent = 'HTTP(S) 需填写完整 URL（含 http:// 或 https://）。';
        } else {
            target.placeholder = type === 'UDP' ? '223.5.5.5:53' : '127.0.0.1:8080';
            hint.textContent = type === 'UDP'
                ? 'UDP 需填写 host:port 格式，如 223.5.5.5:53（53 端口按标准 DNS 查询探测）。'
                : 'TCP 需填写 host:port 格式，如 192.168.1.10:22。';
        }
    };
    window.monTypeChanged(t.type);

    $('#monFormEl').addEventListener('submit', async e => {
        e.preventDefault();
        const f = new FormData(e.target);
        const body = Object.fromEntries(f.entries());
        ['expect_status', 'interval_sec', 'timeout_sec', 'fail_threshold'].forEach(k => body[k] = Number(body[k] || 0));
        body.enabled = body.enabled === 'true';
        body.notify_on_recovery = body.notify_on_recovery === 'true';
        try {
            if (id) await api('PUT', '/api/monitor/tasks/' + id, body);
            else await api('POST', '/api/monitor/tasks', body);
            closeModal(); toast('保存成功'); refreshMonitorRows();
        } catch (err) { toast(err.message, 'err'); }
    });
};
