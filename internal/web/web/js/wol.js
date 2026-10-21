/* ============ WOL 网络唤醒模块 ============ */
'use strict';

/** 只刷新 WOL 设备表格数据行（<tbody>），不重绘工具栏/表头 */
async function refreshWolRows() {
    const tbody = $('#wolTbody');
    if (!tbody) return; // 已离开本页，静默退出
    const devs = await api('GET', '/api/wol/devices');
    tbody.innerHTML = devs.map(d => `
      <tr>
        <td><input type="checkbox" class="wol-chk" value="${d.id}"></td>
        <td>${esc(d.name)}</td>
        <td>${esc(d.mac).split(',').join('<br>')}</td>
        <td>${esc(d.broadcast)}:${d.port}</td>
        <td>
          <button class="btn small success" onclick="wolWake(${d.id})">⚡ 唤醒</button>
          <button class="btn small" onclick="wolForm(${d.id})">编辑</button>
          <button class="btn small danger" onclick="wolDelete(${d.id})">删除</button>
        </td>
      </tr>`).join('') || '<tr><td colspan="5" class="muted">暂无设备</td></tr>';
    const all = $('#wolAll'); if (all) all.checked = false; // 行重建后清空全选态
}

/** 首次进入 WOL 页：绘制页面骨架（tip/工具栏/表头 + 空 tbody），绑定全选事件，随后只填充数据行 */
async function renderWol() {
    $('#pageBody').innerHTML = `
      <div class="tip">通过局域网广播 UDP 魔术包唤醒设备，被唤醒主机需在网卡与 BIOS 中开启 WOL（Wake on LAN）支持。多网口设备可配置多个 MAC，唤醒时逐个发送魔术包。</div>
      <div class="toolbar">
        <button class="btn" onclick="wolWakeBatch()">⚡ 批量唤醒选中</button>
        <label class="small muted"><input type="checkbox" id="wolAll"> 全选</label>
        <div class="spacer"></div>
        <button class="btn primary" onclick="wolForm()">＋ 新增设备</button>
      </div>
      <div class="panel"><table>
        <thead><tr><th style="width:30px"></th><th>设备名称</th><th>MAC 地址</th><th>广播地址</th><th>操作</th></tr></thead>
        <tbody id="wolTbody"><tr><td colspan="5" class="muted">加载中...</td></tr></tbody>
      </table></div>`;
    $('#wolAll').addEventListener('change', e =>
        $$('.wol-chk').forEach(c => c.checked = e.target.checked));
    setRefresh(null);
    await refreshWolRows();
}

window.wolWake = async id => {
    try { await api('POST', `/api/wol/devices/${id}/wake`); toast('唤醒魔术包已发送'); }
    catch (e) { toast(e.message, 'err'); }
};

window.wolWakeBatch = async () => {
    const ids = [...$$('.wol-chk:checked')].map(c => Number(c.value));
    if (!ids.length) { toast('请先勾选设备', 'err'); return; }
    try {
        const r = await api('POST', '/api/wol/wake-batch', { ids });
        toast('批量唤醒完成: ' + r.results.join('；'));
    } catch (e) { toast(e.message, 'err'); }
};

window.wolDelete = async id => {
    if (!(await confirmBox({ title: '删除设备', message: '确定删除该设备？', confirmText: '删除', danger: true }))) return;
    try { await api('DELETE', '/api/wol/devices/' + id); toast('已删除'); refreshWolRows(); }
    catch (e) { toast(e.message, 'err'); }
};

window.wolForm = async (id) => {
    let d = {};
    if (id) d = (await api('GET', '/api/wol/devices')).find(x => x.id === id);
    modal(id ? '编辑设备' : '新增唤醒设备', `
      <form id="wolFormEl" class="form-grid">
        <div class="field full"><label>机器名称 <b>*</b></label><input name="name" required value="${esc(d.name || '')}"></div>
        <div class="field full"><label>MAC 地址 <b>*</b></label><textarea name="mac" required rows="2" placeholder="00:11:22:33:44:55&#10;多网口可填多个 MAC，用逗号/分号或换行分隔">${esc(d.mac || '').split(',').join('\n')}</textarea></div>
        <div class="field"><label>广播地址 <b>*</b></label><input name="broadcast" required value="${esc(d.broadcast || '255.255.255.255')}"></div>
        <div class="field"><label>WOL 端口</label><input name="port" type="number" value="${d.port ?? 9}"></div>
        <div class="form-foot full">
          <button type="button" class="btn" onclick="closeModal()">取消</button>
          <button class="btn primary">保存</button>
        </div>
      </form>`);
    $('#wolFormEl').addEventListener('submit', async e => {
        e.preventDefault();
        const body = Object.fromEntries(new FormData(e.target).entries());
        body.port = Number(body.port || 9);
        try {
            if (id) await api('PUT', '/api/wol/devices/' + id, body);
            else await api('POST', '/api/wol/devices', body);
            closeModal(); toast('保存成功'); refreshWolRows();
        } catch (err) { toast(err.message, 'err'); }
    });
};
