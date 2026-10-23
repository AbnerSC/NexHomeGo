/* ============ 系统设置模块 ============ */
'use strict';

/** AccessKey ID 脱敏展示（前 4 后 4，中间省略） */
function maskAk(id) {
    const s = String(id || '');
    return s.length <= 8 ? s : s.slice(0, 4) + '****' + s.slice(-4);
}

async function renderSettings() {
    let info = {}, configs = [], types = {}, metrics = {};
    try { info = await api('GET', '/api/system/info'); } catch (e) { /* ignore */ }
    try { configs = await api('GET', '/api/provider/configs'); } catch (e) { /* ignore */ }
    try { types = await api('GET', '/api/provider/types'); } catch (e) { /* ignore */ }
    // 系统物理内存：与顶栏监控同源，避免此处显示进程内存造成混淆
    try { metrics = await api('GET', '/api/system/metrics'); } catch (e) { /* ignore */ }
    // 访问与安全配置（端口 / HTTPS / 安全入口）+ 已签发证书清单（HTTPS 证书下拉）
    let ws = {}, certTasks = [];
    try { ws = await api('GET', '/api/system/web-settings'); } catch (e) { /* ignore */ }
    try { certTasks = (await api('GET', '/api/cert/tasks')).filter(t => t.status === 'ISSUED'); } catch (e) { /* ignore */ }
    // 登录安全配置（失败锁定阈值 / 锁定时长）
    let sec = { maxFails: 3, lockMinutes: 30 };
    try { sec = await api('GET', '/api/auth/security'); } catch (e) { /* ignore */ }
    const memPct = metrics.memTotalMB > 0 ? Math.round(metrics.memUsedMB * 100 / metrics.memTotalMB) : 0;
    // 进程内存（RSS/上限）：来自 /api/system/info，与系统物理内存区分，便于定位进程增长
    const heapPct = info.maxMemoryMB > 0 ? Math.round(info.usedMemoryMB * 100 / info.maxMemoryMB) : 0;
    const typeName = code => types[code] || code;
    const cfgRows = configs.map(c => `
      <tr>
        <td>${esc(c.name)}</td>
        <td>${esc(typeName(c.provider_type))}</td>
        <td class="small">${esc(maskAk(c.access_key_id))}</td>
        <td class="small">${esc(c.esa_site_id || '-')}</td>
        <td>
          <button class="btn small" onclick="provForm(${c.id})">编辑</button>
          <button class="btn small danger" onclick="provDelete(${c.id})">删除</button>
        </td>
      </tr>`).join('');
    $('#pageBody').innerHTML = `
      <div class="panel">
        <h3 style="font-size:14px;margin-bottom:12px">系统信息</h3>
        <table>
          <tr><th style="width:120px">版本</th><td>${esc(info.version || '')}</td></tr>
          <tr><th>Go 运行时</th><td>${esc(info.javaVersion || '')}</td></tr>
          <tr><th>操作系统</th><td>${esc(info.os || '')}</td></tr>
          <tr><th>运行时长</th><td>${Math.floor((info.uptimeSec || 0) / 3600)} 小时 ${Math.floor((info.uptimeSec || 0) % 3600 / 60)} 分钟</td></tr>
          <tr><th>内存占用</th><td>${metrics.memUsedMB != null ? `${fmtMB(metrics.memUsedMB)} / ${fmtMB(metrics.memTotalMB)}（${memPct}%）` : ''}</td></tr>
          <tr><th>进程内存</th><td>${info.maxMemoryMB > 0 ? `${fmtMB(info.usedMemoryMB)} / ${fmtMB(info.maxMemoryMB)}（${heapPct}%）` : ''}</td></tr>
        </table>
      </div>
      <div class="panel">
        <h3 style="font-size:14px;margin-bottom:12px">访问与安全设置</h3>
        ${ws.lastError ? `<div class="tip" style="color:var(--red);margin-bottom:10px">⚠️ ${esc(ws.lastError)}</div>` : ''}
        <div class="tip" style="margin-bottom:12px">端口 / HTTPS / 安全入口保存后，内置 Web 服务将<b>自动重启</b>并应用新配置
          （绑定失败自动回滚，此处配置优先于 nexhome.properties）；重启后需重新登录。
          开启安全入口后必须通过 <b>http://地址:端口/入口路径/</b> 访问面板，其余路径一律 404。
          进程启动时若端口已被占用，会自动改用备选端口继续提供面板（实际端口与原因见 HTTP 端口下方红字提示），不会改写此处配置值。</div>
        <form id="accessForm" class="form-grid">
          <div class="field"><label>HTTP 端口 <b>*</b></label>
            <input name="port" type="number" min="1" max="65535" required value="${ws.port ?? 8090}">
            ${ws.boundPort && ws.boundPort !== ws.port
              ? `<div class="small" style="color:var(--red)">当前实际监听 ${esc(ws.boundPort)}（配置端口被占用，启动时已临时改用）</div>` : ''}</div>
          <div class="field"><label>HTTPS</label>
            <select name="httpsEnabled" onchange="accHttpsChanged(this.value)">
              <option value="0" ${!ws.httpsEnabled ? 'selected' : ''}>关闭</option>
              <option value="1" ${ws.httpsEnabled ? 'selected' : ''}>开启</option>
            </select></div>
          <div class="field" id="accHttpsPort"><label>HTTPS 端口</label>
            <input name="httpsPort" type="number" min="1" max="65535" value="${ws.httpsPort ?? 8443}"></div>
          <div class="field" id="accRedirect"><label>HTTP 跳转 HTTPS（选“否”时 HTTP/HTTPS 均可访问）</label>
            <select name="httpsRedirect">
              <option value="0" ${!ws.httpsRedirect ? 'selected' : ''}>否</option>
              <option value="1" ${ws.httpsRedirect ? 'selected' : ''}>是</option>
            </select></div>
          <div class="field full" id="accCert"><label>HTTPS 证书</label>
            <select name="certTaskId">
              <option value="" ${!ws.certTaskId ? 'selected' : ''}>自动选择（有效期最长的有效证书）</option>
              ${certTasks.map(t => `<option value="${t.id}" ${Number(ws.certTaskId) === t.id ? 'selected' : ''}>${esc(t.name)}（有效期至 ${(t.not_after || '').slice(0, 10)}）</option>`).join('')}
            </select>
            <div class="small muted">自动适应已申请的证书：未指定时自动选用有效期最长的有效证书，续期后自动加载新证书。
              ${ws.activeCertTaskId > 0 ? `当前使用: <b>${esc(ws.activeCertName || ('#' + ws.activeCertTaskId))}</b>，有效期至 ${(ws.activeCertNotAfter || '').slice(0, 10) || '-'}` : ''}
              ${ws.httpsEnabled && !ws.httpsActive ? ' <span style="color:var(--red)">（HTTPS 未生效，已临时降级为仅 HTTP 访问，请检查证书文件或端口占用）</span>' : ''}</div>
          </div>
          <div class="field full"><label>安全入口路径（留空关闭）</label>
            <input name="entryPath" placeholder="如 my-secret-entry，4-64 位字母数字-_，访问时需带上 /路径/" value="${esc(ws.entryPath || '')}"></div>
          <div class="form-foot full" style="margin-top:6px" id="accEditFoot">
            <button type="button" class="btn" onclick="accSetEditing(false)">取消</button>
            <button class="btn primary">保存并应用</button></div>
          <div class="form-foot full" style="margin-top:6px" id="accViewFoot">
            <button type="button" class="btn primary" onclick="accSetEditing(true)">编辑</button></div>
        </form>
      </div>
      <div class="panel">
        <h3 style="font-size:14px;margin-bottom:12px">服务商凭证配置</h3>
        <div class="tip" style="margin-bottom:12px">集中维护云服务商 AccessKey：<b>DDNS 同步</b>与
          <b>SSL 证书 DNS01 自动验证</b>在表单中直接下拉选择引用，无需每次重复输入；
          修改配置后所有引用它的任务自动生效。</div>
        <div class="toolbar" style="margin-bottom:10px"><div class="spacer"></div>
          <button class="btn primary" onclick="provForm()">＋ 新增配置</button></div>
        <table>
          <thead><tr><th>名称</th><th>服务商</th><th>AccessKey ID</th><th>ESA 站点</th><th>操作</th></tr></thead>
          <tbody>${cfgRows || '<tr><td colspan="5" class="muted">暂无配置，可在 DDNS / 证书表单中手动填写凭证</td></tr>'}</tbody>
        </table>
      </div>
      <div class="panel">
        <h3 style="font-size:14px;margin-bottom:12px">修改登录密码</h3>
        <form id="pwdForm">
          <div class="field" style="width: 200px"><label>原密码 <b>*</b></label><input name="old_password" type="password" required></div>
          <div class="field" style="width: 200px"><label>新密码 <b>*</b>（至少12位）</label><input name="new_password" type="password" required minlength="12"></div>
          <div class="field" style="width: 200px"><label>确认新密码 <b>*</b></label><input name="confirm" type="password" required></div>
          <div class="field" style="align-self:end; margin-top: 10px"><button class="btn primary">修改密码</button></div>
        </form>
      </div>
      <div class="panel">
        <h3 style="font-size:14px;margin-bottom:12px">登录安全设置</h3>
        <div class="tip" style="margin-bottom:12px">连续登录失败达到最大次数后，该来源 IP 将被临时锁定指定时长；成功登录后计数清零。
          失败计数为进程内存态，重启后归零。系统强制<b>单点登录</b>：新设备登录会自动注销之前的会话。</div>
        <form id="secForm" class="form-grid">
          <div class="field"><label>最大失败次数（1~100）</label><input name="maxFails" type="number" min="1" max="100" required value="${sec.maxFails ?? 3}"></div>
          <div class="field"><label>锁定时长（分钟，1~1440）</label><input name="lockMinutes" type="number" min="1" max="1440" required value="${sec.lockMinutes ?? 30}"></div>
          <div class="form-foot full"><button class="btn primary">保存安全设置</button></div>
        </form>
      </div>
      <div class="panel">
        <h3 style="font-size:14px;margin-bottom:12px">配置备份</h3>
        <div class="tip" style="margin-bottom:12px">导出当前数据库（所有任务与配置）的一致性快照文件，用于离线备份与迁移；本期仅提供下载导出，不提供导入恢复。</div>
        <button class="btn primary" onclick="downloadBackup()">⬇ 下载配置备份</button>
      </div>`;
    $('#pwdForm').addEventListener('submit', async e => {
        e.preventDefault();
        const f = new FormData(e.target);
        if (f.get('new_password') !== f.get('confirm')) { toast('两次输入的新密码不一致', 'err'); return; }
        try {
            await api('POST', '/api/auth/change-password', {
                old_password: f.get('old_password'), new_password: f.get('new_password')
            });
            toast('密码已修改，请重新登录');
            TOKEN = '';
            localStorage.removeItem('nx_token');
            showLogin();
        } catch (err) { toast(err.message, 'err'); }
    });

    // 登录安全设置保存
    $('#secForm').addEventListener('submit', async e => {
        e.preventDefault();
        const f = new FormData(e.target);
        try {
            const msg = await api('PUT', '/api/auth/security', {
                maxFails: Number(f.get('maxFails')), lockMinutes: Number(f.get('lockMinutes'))
            });
            toast(msg);
        } catch (err) { toast(err.message, 'err'); }
    });

    // 访问与安全设置：默认只读查看，主动点击「编辑」后才可修改与保存
    window.accSetEditing = on => {
        // 取消编辑：重新渲染恢复服务端当前配置与只读状态
        if (!on) { renderSettings(); return; }
        $('#accessForm').querySelectorAll('input,select').forEach(el => { el.disabled = false; });
        $('#accEditFoot').classList.remove('hidden');
        $('#accViewFoot').classList.add('hidden');
    };
    $('#accessForm').querySelectorAll('input,select').forEach(el => { el.disabled = true; });
    $('#accEditFoot').classList.add('hidden');

    // HTTPS 相关字段随开关显示/隐藏
    window.accHttpsChanged = v => {
        ['accHttpsPort', 'accRedirect', 'accCert'].forEach(id => $('#' + id).classList.toggle('hidden', v !== '1'));
    };
    window.accHttpsChanged(ws.httpsEnabled ? '1' : '0');

    // 保存访问与安全设置：确认后提交，服务自动重启，展示新地址并倒计时跳转
    $('#accessForm').addEventListener('submit', async e => {
        e.preventDefault();
        const f = new FormData(e.target);
        const port = f.get('port'), httpsPort = f.get('httpsPort');
        if (f.get('httpsEnabled') === '1' && port === httpsPort) { toast('HTTPS 端口不能与 HTTP 端口相同', 'err'); return; }
        const entry = String(f.get('entryPath') || '').trim().replace(/^\/+|\/+$/g, '');
        const entryPart = entry ? '/' + entry : '';
        const host = location.hostname;
        const httpUrl = `http://${host}:${port}${entryPart}`;
        const httpsUrl = f.get('httpsEnabled') === '1' ? `https://${host}:${httpsPort}${entryPart}` : '';
        const primary = httpsUrl || httpUrl;
        if (!(await confirmBox({
            title: '应用访问配置',
            message: `保存后服务将立即重启并应用新配置（需重新登录），\n请牢记新访问地址：\n${primary}\n\n确定继续？`,
            confirmText: '保存并重启'
        }))) return;
        try {
            await api('PUT', '/api/system/web-settings', {
                port: Number(port),
                httpsEnabled: f.get('httpsEnabled') === '1',
                httpsPort: Number(httpsPort),
                httpsRedirect: f.get('httpsRedirect') === '1',
                certTaskId: f.get('certTaskId') || '',
                entryPath: entry
            });
            let left = 6;
            modal('服务正在重启', `
              <p>新配置应用中，请稍候。新的访问地址：</p>
              <p>${httpsUrl ? `<b><a href="${esc(httpsUrl)}" target="_blank">${esc(httpsUrl)}</a></b><br>` : ''}
                 <b><a href="${esc(httpUrl)}" target="_blank">${esc(httpUrl)}</a></b></p>
              <p class="muted small">重启后需重新登录；若端口或入口已变更，请使用上方新地址访问。</p>
              <p id="accCountdown" class="muted small">${left} 秒后自动跳转 ${esc(primary)} ...</p>`);
            const timer = setInterval(() => {
                const el = $('#accCountdown');
                if (!el) { clearInterval(timer); return; }
                left -= 1;
                if (left <= 0) { clearInterval(timer); location.href = primary; return; }
                el.textContent = `${left} 秒后自动跳转 ${primary} ...`;
            }, 1000);
        } catch (err) { toast(err.message, 'err'); }
    });
}

/** 服务商凭证配置新增/编辑弹窗（服务商清单动态拉取；ESA 站点为阿里云 ESA 专属，从账号站点列表下拉选择） */
window.provForm = async (id) => {
    let c = {}, types = {};
    if (id) c = (await api('GET', '/api/provider/configs')).find(x => x.id === id);
    try { types = await api('GET', '/api/provider/types'); } catch (e) { /* ignore */ }
    const typeOpts = Object.entries(types).map(([code, name]) =>
        `<option value="${esc(code)}" ${(c.provider_type || 'ALIYUN') === code ? 'selected' : ''}>${esc(name)}</option>`).join('');
    const curSite = c.esa_site_id ? String(c.esa_site_id) : '';
    const siteOpt = curSite
        ? `<option value="${esc(curSite)}" selected>${esc(curSite)}（当前站点，点击“加载站点”显示站点名称）</option>`
        : '<option value="">未选择（点击“加载站点”）</option>';
    modal(id ? '编辑服务商凭证配置' : '新增服务商凭证配置', `
      <form id="provFormEl" class="form-grid">
        <div class="field"><label>配置名称 <b>*</b></label><input name="name" required placeholder="如：阿里云主账号" value="${esc(c.name || '')}"></div>
        <div class="field"><label>服务商 <b>*</b></label>
          <select name="provider_type" onchange="provTypeChanged(this.value)">${typeOpts}</select></div>
        <div class="field hidden" id="fEsaSite"><label>ESA 站点（可选）</label>
          <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
            <select name="esa_site_id" id="provEsaSiteSel" style="flex:1;min-width:200px">${siteOpt}</select>
            <button type="button" class="btn" onclick="provLoadEsaSites()">加载站点</button>
          </div>
          <div id="provEsaSiteHint" class="small muted" style="margin-top:6px">填写 AccessKey 后可点击“加载站点”拉取账号下的 ESA 站点列表。</div>
        </div>
        <div class="field full"><label>AccessKey ID <b>*</b></label><input name="access_key_id" required value="${esc(c.access_key_id || '')}"></div>
        <div class="field full"><label>AccessKey Secret <b>*</b></label><input name="access_key_secret" required type="password" value="${esc(c.access_key_secret || '')}"></div>
        <div class="form-foot full">
          <button type="button" class="btn" onclick="closeModal()">取消</button>
          <button class="btn primary">保存</button>
        </div>
      </form>`);
    // 按表单里当前的 AK/SK 实时拉取 ESA 站点（无需先保存配置）；silent 为自动触发，凭证不全时不报错
    window.provLoadEsaSites = async (silent) => {
        const f = new FormData($('#provFormEl'));
        const ak = String(f.get('access_key_id') || '').trim();
        const sk = String(f.get('access_key_secret') || '').trim();
        const sel = $('#provEsaSiteSel'), hint = $('#provEsaSiteHint');
        const cur = sel.value || curSite;
        if (!ak || !sk) {
            if (!silent) {
                hint.className = 'small'; hint.style.color = 'var(--red)';
                hint.textContent = '请先填写 AccessKey ID 与 AccessKey Secret，再加载站点。';
            }
            return;
        }
        hint.className = 'small muted'; hint.style.color = ''; hint.textContent = '正在拉取 ESA 站点…';
        try {
            const r = await api('POST', '/api/ddns/esa/sites', { access_key_id: ak, access_key_secret: sk });
            const sites = r.sites || [];
            if (!sites.length) {
                sel.innerHTML = (cur ? `<option value="${esc(cur)}" selected>${esc(cur)}（当前站点）</option>` : '')
                    + '<option value="">无可用站点</option>';
                hint.className = 'small'; hint.style.color = 'var(--red)';
                hint.textContent = '该账号下未找到 ESA 站点，请先到阿里云 ESA 控制台添加站点后再选择。';
                return;
            }
            sel.innerHTML = '<option value="">不使用 ESA 站点</option>' + sites.map(s =>
                `<option value="${esc(s.site_id)}" ${cur === String(s.site_id) ? 'selected' : ''}>${esc(s.site_name)}（SiteId: ${esc(s.site_id)}${s.status ? '，' + esc(s.status) : ''}）</option>`).join('');
            // 已保存站点不在列表中（如已被删除）：保留原值，避免编辑时静默丢失
            if (cur && !sites.some(s => String(s.site_id) === cur)) {
                sel.insertAdjacentHTML('afterbegin', `<option value="${esc(cur)}" selected>${esc(cur)}（当前站点，未在阿里云列表中找到）</option>`);
            }
            hint.textContent = '仅域名托管在 ESA 时需要选择站点；云解析域名可留空。';
        } catch (e) {
            // 自动触发（如打开编辑弹窗）失败不做强提示，避免历史凭证过期时一进表单就报红
            if (silent) { hint.className = 'small muted'; hint.style.color = ''; }
            else { hint.className = 'small'; hint.style.color = 'var(--red)'; }
            hint.textContent = '站点列表加载失败：' + e.message;
        }
    };
    window.provTypeChanged = v => {
        // ESA 站点为阿里云 ESA 专属，其他服务商隐藏
        $('#fEsaSite').classList.toggle('hidden', v !== 'ALIYUN');
        // AK/SK 已填写时自动拉取站点列表（编辑场景打开弹窗即可看到站点名称）
        if (v === 'ALIYUN') provLoadEsaSites(true);
    };
    // AK 变更后账号可能不同：重新拉取站点列表（仅 ESA 字段可见时）
    ['access_key_id', 'access_key_secret'].forEach(n => {
        const el = $('#provFormEl').querySelector(`[name="${n}"]`);
        if (el) el.addEventListener('change', () => {
            if (!$('#fEsaSite').classList.contains('hidden')) provLoadEsaSites(true);
        });
    });
    window.provTypeChanged(c.provider_type || 'ALIYUN');
    $('#provFormEl').addEventListener('submit', async e => {
        e.preventDefault();
        const body = Object.fromEntries(new FormData(e.target).entries());
        try {
            if (id) await api('PUT', '/api/provider/configs/' + id, body);
            else await api('POST', '/api/provider/configs', body);
            closeModal(); toast('保存成功，引用它的任务将自动生效'); renderSettings();
        } catch (err) { toast(err.message, 'err'); }
    });
};

/** 删除服务商凭证配置：引用的 DDNS 任务回填当前凭证，证书任务回到手动 TXT */
window.provDelete = async id => {
    if (!(await confirmBox({
        title: '删除服务商凭证配置',
        message: '确定删除该凭证配置？\n\n引用它的 DDNS 任务将回填当前凭证继续可用，证书任务回到手动添加 TXT 模式。',
        confirmText: '删除', danger: true
    }))) return;
    try {
        const msg = await api('DELETE', '/api/provider/configs/' + id);
        toast(msg); renderSettings();
    } catch (e) { toast(e.message, 'err'); }
};

/** 配置备份下载：文件流接口需携带 X-Token 手动 fetch，从 Content-Disposition 取文件名后触发浏览器下载 */
window.downloadBackup = async () => {
    toast('正在生成备份…');
    try {
        const resp = await fetch(API_BASE + '/api/system/backup', { headers: { 'X-Token': TOKEN } });
        if (resp.status === 401) { showLogin(); toast('登录已过期，请重新登录', 'err'); return; }
        if (!resp.ok) { toast('备份失败 ' + resp.status, 'err'); return; }
        const cd = resp.headers.get('Content-Disposition') || '';
        const m = /filename="?([^";]+)"?/.exec(cd);
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = m ? decodeURIComponent(m[1]) : 'nexhome-backup.db';
        document.body.appendChild(a); a.click(); a.remove();
        URL.revokeObjectURL(url);
        toast('配置备份已下载');
    } catch (e) { toast(e.message, 'err'); }
};
