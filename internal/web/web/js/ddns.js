/* ============ DDNS 域名同步模块 ============ */
'use strict';

/** 只刷新 DDNS 任务表格数据行（<tbody>），不重绘 tip/工具栏/表头 */
async function refreshDdnsRows() {
    const tbody = $('#ddnsTbody');
    if (!tbody) return; // 已离开本页，静默退出
    const tasks = await api('GET', '/api/ddns/tasks');
    tbody.innerHTML = tasks.map(t => `
      <tr>
        <td>${esc(t.name)}<div class="small muted">${esc(t.provider === 'ALIYUN_ESA' ? '阿里云ESA' : '阿里云DNS')}</div></td>
        <td>${esc(t.rr)}.${esc(t.domain)} <span class="muted small">${esc(t.type)}</span></td>
        <td>${badge(t.ip_mode === 'PUBLIC' ? '公网IP' : t.ip_mode === 'LOCAL' ? '本地网卡' : '手动', 'info')}</td>
        <td><label class="switch"><input type="checkbox" ${t.enabled === 1 ? 'checked' : ''} onchange="ddnsToggle(${t.id}, this.checked, ${t.interval_sec})"><span class="slider"></span></label>
            <span class="small muted">${t.enabled === 1 ? '每' + t.interval_sec + 's' : '停用'}</span></td>
        <td>${esc(t.last_ip || '-')}</td>
        <td>${statusBadge(t.last_status)}<div class="small muted">${esc(t.last_sync || '')}</div></td>
        <td>
          <button class="btn small success" onclick="ddnsSync(${t.id})">同步</button>
          <button class="btn small" onclick="ddnsForm(${t.id})">编辑</button>
          <button class="btn small danger" onclick="ddnsDelete(${t.id})">删除</button>
        </td>
      </tr>`).join('') || '<tr><td colspan="7" class="muted">暂无任务</td></tr>';
}

/** 首次进入 DDNS 页：绘制页面骨架（tip/工具栏/表头 + 空 tbody），随后只填充数据行 */
async function renderDdns() {
    $('#pageBody').innerHTML = `
      <div class="tip">IP 来源支持三种模式：<b>公网接口</b>（自动获取出口 IP）/ <b>本地网卡</b> / <b>手动输入</b>。
        阿里云 AccessKey 可在 <a href="#" onclick="setPage('settings')">系统设置 → 服务商凭证配置</a> 中统一维护，表单中直接下拉选择；
        对接阿里云建议使用 RAM 子账号 AccessKey（仅授予 AliyunDNSFullAccess 或 ESA 解析权限）。</div>
      <div class="toolbar"><div class="spacer"></div><button class="btn primary" onclick="ddnsForm()">＋ 新增同步任务</button></div>
      <div class="panel"><table>
        <thead><tr><th>任务</th><th>域名</th><th>IP来源</th><th>定时同步</th><th>当前IP</th><th>最近同步</th><th>操作</th></tr></thead>
        <tbody id="ddnsTbody"><tr><td colspan="7" class="muted">加载中...</td></tr></tbody>
      </table></div>`;
    await refreshDdnsRows();
    setRefresh(refreshDdnsRows, 10000);
}

window.ddnsToggle = async (id, enabled, interval) => {
    const tasks = await api('GET', '/api/ddns/tasks');
    const t = tasks.find(x => x.id === id);
    try {
        await api('PUT', '/api/ddns/tasks/' + id, {
            name: t.name, provider: t.provider, domain: t.domain, rr: t.rr, type: t.type, ttl: t.ttl,
            ip_mode: t.ip_mode, manual_ip: t.manual_ip, local_nic: t.local_nic,
            provider_config_id: t.provider_config_id ?? null,
            access_key_id: t.access_key_id, access_key_secret: t.access_key_secret,
            esa_site_id: t.esa_site_id, interval_sec: t.interval_sec, enabled
        });
        toast(enabled ? '已启用定时同步' : '已停用');
        refreshDdnsRows();
    } catch (e) { toast(e.message, 'err'); refreshDdnsRows(); }
};

window.ddnsSync = async id => {
    try {
        const msg = await api('POST', `/api/ddns/tasks/${id}/sync`);
        toast(msg);
        // 同步为异步执行，延迟两次刷新以展示最新同步状态（含“记录已存在”等取消写入结果）
        setTimeout(refreshDdnsRows, 2000);
        setTimeout(refreshDdnsRows, 6000);
    }
    catch (e) { toast(e.message, 'err'); }
};

window.ddnsDelete = async id => {
    if (!(await confirmBox({ title: '删除同步任务', message: '确定删除该同步任务？', confirmText: '删除', danger: true }))) return;
    // 询问是否一并删除 DNS 服务商上的远程解析记录
    const remote = await confirmBox({
        title: '删除远程解析记录',
        message: '是否同时删除远程服务商上的解析记录？\n\n【删除远程】同步删除远程解析记录\n【仅删本地】仅删除本地任务，保留远程记录',
        confirmText: '删除远程',
        cancelText: '仅删本地',
        danger: true
    });
    try {
        const msg = await api('DELETE', '/api/ddns/tasks/' + id + '?remote=' + remote);
        toast(msg); refreshDdnsRows();
    }
    catch (e) { toast(e.message, 'err'); }
};

window.ddnsForm = async (id) => {
    let t = {};
    if (id) t = (await api('GET', '/api/ddns/tasks')).find(x => x.id === id);
    let nics = [], configs = [];
    try { nics = (await api('GET', '/api/ddns/nics')).nics; } catch (e) { /* ignore */ }
    try { configs = await api('GET', '/api/provider/configs'); } catch (e) { /* ignore */ }
    const nicOpts = nics.map(n => `<option value="${esc(n)}" ${t.local_nic === n ? 'selected' : ''}>${esc(n)}</option>`).join('');
    // 仅列出与任务服务商同类型的凭证配置（ALIYUN_DNS/ALIYUN_ESA -> ALIYUN；后续新服务商按前缀匹配），
    // 已引用的配置始终保留避免编辑时回显丢失
    const credType = (t.provider || 'ALIYUN_DNS').split('_')[0];
    const credOpts = configs
        .filter(c => (c.provider_type || 'ALIYUN') === credType || c.id === t.provider_config_id)
        .map(c => `<option value="${c.id}" ${t.provider_config_id === c.id ? 'selected' : ''}>${esc(c.name)}（${esc(maskAk(c.access_key_id))}）</option>`).join('');
    modal(id ? '编辑同步任务' : '新增同步任务', `
      <form id="ddnsFormEl" class="form-grid">
        <div class="field"><label>任务名称 <b>*</b></label><input name="name" required value="${esc(t.name || '')}"></div>
        <div class="field"><label>服务商 <b>*</b></label>
          <select name="provider" onchange="ddnsProviderChanged(this.value)">
            <option value="ALIYUN_DNS" ${t.provider !== 'ALIYUN_ESA' ? 'selected' : ''}>阿里云DNS</option>
            <option value="ALIYUN_ESA" ${t.provider === 'ALIYUN_ESA' ? 'selected' : ''}>阿里云ESA</option>
          </select></div>
        <div class="field"><label>主域名 <b>*</b></label><input name="domain" required placeholder="example.com" value="${esc(t.domain || '')}"></div>
        <div class="field"><label>主机记录 <b>*</b></label><input name="rr" required placeholder="www 或 @" value="${esc(t.rr || '')}"></div>
        <div class="field"><label>记录类型</label>
          <select name="type"><option ${t.type !== 'AAAA' ? 'selected' : ''}>A</option><option ${t.type === 'AAAA' ? 'selected' : ''}>AAAA</option></select></div>
        <div class="field"><label>TTL（秒）</label><input name="ttl" type="number" min="60" value="${t.ttl ?? 600}"></div>
        <div class="field"><label>IP 来源 <b>*</b></label>
          <select name="ip_mode" onchange="ddnsModeChanged(this.value)">
            <option value="PUBLIC" ${t.ip_mode !== 'LOCAL' && t.ip_mode !== 'MANUAL' ? 'selected' : ''}>公网接口自动获取</option>
            <option value="LOCAL" ${t.ip_mode === 'LOCAL' ? 'selected' : ''}>本机网卡</option>
            <option value="MANUAL" ${t.ip_mode === 'MANUAL' ? 'selected' : ''}>手动输入</option>
          </select></div>
        <div class="field hidden" id="fNic"><label>网卡</label><select name="local_nic"><option value="">自动选择</option>${nicOpts}</select></div>
        <div class="field hidden" id="fManualIp"><label>手动 IP <b>*</b></label><input name="manual_ip" value="${esc(t.manual_ip || '')}"></div>
        <div class="field full" id="fPreview"><label>IP 预览</label>
          <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
            <button type="button" class="btn" onclick="ddnsPreviewIp()">预览即将同步的 IP</button>
            <span id="ipPreview" class="small muted">按当前 IP 来源配置解析</span>
          </div>
        </div>
        <div class="field"><label>阿里云凭证 <b>*</b></label>
          <select name="provider_config_id" onchange="ddnsCredChanged(this.value)">
            <option value="">手动填写 AccessKey</option>${credOpts}
          </select></div>
        <div class="field hidden" id="fAkId"><label>AccessKey ID <b>*</b></label><input name="access_key_id" value="${esc(t.access_key_id || '')}"></div>
        <div class="field hidden" id="fAkSecret"><label>AccessKey Secret <b>*</b></label><input name="access_key_secret" type="password" value="${esc(t.access_key_secret || '')}"></div>
        <div class="field full hidden" id="fSiteId"><label>ESA 站点 <b>*</b></label>
          <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
            <select name="esa_site_id" id="esaSiteSel" style="flex:1;min-width:220px"><option value="">请先选择凭证后点击“加载站点”</option></select>
            <button type="button" class="btn" onclick="ddnsLoadEsaSites()">加载站点</button>
          </div>
          <div id="esaSiteHint" class="small muted" style="margin-top:6px"></div>
        </div>
        <div class="field"><label>同步间隔（秒，最小60）</label><input name="interval_sec" type="number" min="60" value="${t.interval_sec ?? 300}"></div>
        <div class="field"><label>启用定时同步</label><select name="enabled"><option value="true" ${t.enabled !== 0 ? 'selected' : ''}>启用</option><option value="false" ${t.enabled === 0 ? 'selected' : ''}>停用</option></select></div>
        <div class="form-foot full">
          <button type="button" class="btn" onclick="closeModal()">取消</button>
          <button class="btn primary">保存</button>
        </div>
      </form>`);
    window.ddnsProviderChanged = (p, initial) => {
        $('#fSiteId').classList.toggle('hidden', p !== 'ALIYUN_ESA');
        if (!initial && p === 'ALIYUN_ESA') ddnsLoadEsaSites();
    };
    window.ddnsCredChanged = (v, initial) => {
        const manual = !v; // 未选配置时手动填写 AccessKey
        $('#fAkId').classList.toggle('hidden', !manual);
        $('#fAkSecret').classList.toggle('hidden', !manual);
        $('#fAkId input').required = manual;
        $('#fAkSecret input').required = manual;
        // 凭证变化后重新拉取站点列表（ESA 且站点字段可见时）
        if (!initial && !$('#fSiteId').classList.contains('hidden')) ddnsLoadEsaSites();
    };
    window.ddnsLoadEsaSites = async () => {
        const f = new FormData($('#ddnsFormEl'));
        const sel = $('#esaSiteSel');
        const hint = $('#esaSiteHint');
        const cur = sel.value || (t.esa_site_id ? String(t.esa_site_id) : '');
        hint.className = 'small muted'; hint.style.color = ''; hint.textContent = '';
        const cfgId = f.get('provider_config_id') || '', akId = f.get('access_key_id') || '', akSecret = f.get('access_key_secret') || '';
        if (!cfgId && (!akId || !akSecret)) { // 凭证未就绪，不发起无谓请求
            sel.innerHTML = '<option value="">请先选择/填写凭证</option>';
            hint.textContent = '请先选择凭证配置或填写 AccessKey，再加载站点。';
            return;
        }
        sel.innerHTML = '<option value="">站点加载中…</option>';
        try {
            const r = await api('POST', '/api/ddns/esa/sites', {
                provider_config_id: f.get('provider_config_id') || '',
                access_key_id: f.get('access_key_id') || '',
                access_key_secret: f.get('access_key_secret') || ''
            });
            const sites = r.sites || [];
            if (!sites.length) {
                sel.innerHTML = '<option value="">无可用站点</option>';
                hint.className = 'small'; hint.style.color = 'var(--red)';
                hint.textContent = '未在阿里云 ESA 找到可用站点，请先到阿里云 ESA 控制台添加站点后再创建任务。';
                return;
            }
            sel.innerHTML = '<option value="">请选择站点</option>' + sites.map(s =>
                `<option value="${esc(s.site_id)}" ${cur === String(s.site_id) ? 'selected' : ''}>${esc(s.site_name)}（SiteId: ${esc(s.site_id)}${s.status ? '，' + esc(s.status) : ''}）</option>`).join('');
            // 编辑时原 SiteId 不在列表：保留该项并提示，避免回显丢失
            if (cur && !sites.some(s => String(s.site_id) === cur)) {
                sel.insertAdjacentHTML('afterbegin', `<option value="${esc(cur)}" selected>${esc(cur)}（当前站点，未在阿里云列表中找到）</option>`);
            }
        } catch (e) {
            sel.innerHTML = '<option value="">加载失败</option>';
            hint.className = 'small'; hint.style.color = 'var(--red)'; hint.textContent = e.message;
        }
    };
    window.ddnsModeChanged = m => {
        $('#fNic').classList.toggle('hidden', m !== 'LOCAL');
        $('#fManualIp').classList.toggle('hidden', m !== 'MANUAL');
        const p = $('#ipPreview');
        if (p) { p.className = 'small muted'; p.style.color = ''; p.textContent = '按当前 IP 来源配置解析'; }
    };
    window.ddnsPreviewIp = async () => {
        const f = new FormData($('#ddnsFormEl'));
        const p = $('#ipPreview');
        p.className = 'small muted';
        p.style.color = '';
        p.textContent = '解析中…';
        try {
            const r = await api('POST', '/api/ddns/preview-ip', {
                ip_mode: f.get('ip_mode') || 'PUBLIC',
                manual_ip: f.get('manual_ip') || '',
                local_nic: f.get('local_nic') || ''
            });
            p.textContent = '即将同步的 IP: ' + r.ip;
            p.style.color = 'var(--green)';
        } catch (e) {
            p.textContent = e.message;
            p.style.color = 'var(--red)';
        }
    };
    window.ddnsProviderChanged(t.provider || 'ALIYUN_DNS', true);
    window.ddnsModeChanged(t.ip_mode || 'PUBLIC');
    window.ddnsCredChanged(t.provider_config_id ? String(t.provider_config_id) : '', true);
    if ((t.provider || 'ALIYUN_DNS') === 'ALIYUN_ESA') ddnsLoadEsaSites();
    $('#ddnsFormEl').addEventListener('submit', async e => {
        e.preventDefault();
        const f = new FormData(e.target);
        const body = Object.fromEntries(f.entries());
        body.provider_config_id = body.provider_config_id ? Number(body.provider_config_id) : null;
        body.ttl = Number(body.ttl || 600);
        body.interval_sec = Number(body.interval_sec || 300);
        body.enabled = body.enabled === 'true';
        try {
            if (id) await api('PUT', '/api/ddns/tasks/' + id, body);
            else await api('POST', '/api/ddns/tasks', body);
            closeModal(); toast('保存成功'); refreshDdnsRows();
        } catch (err) { toast(err.message, 'err'); }
    });
};
