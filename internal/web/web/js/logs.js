/* ============ 操作日志模块 ============ */
'use strict';

let logPage = 1, logModule = '';
let logAutoRefresh = true;

/** 按当前「自动刷新」开关装时：开则每 5s 只刷新行，关则停定时器 */
function armLogsRefresh() {
    if (logAutoRefresh) setRefresh(refreshLogsRows, 5000); else setRefresh(null);
}

/** 只重拉当前页日志并更新表格行/分页/总数，不重建工具栏（保留模块下拉选择与自动刷新勾选） */
async function refreshLogsRows() {
    const tbody = $('#logTbody');
    if (!tbody) return; // 已离开本页，静默退出
    const r = await api('GET', `/api/logs?page=${logPage}&size=50&module=${encodeURIComponent(logModule)}`);
    const total = Number(r.total);
    const pages = Math.max(1, Math.ceil(total / 50));
    tbody.innerHTML = r.list.map(l => `
      <tr class="${l.level === 'ERROR' ? 'log-row-error' : l.level === 'WARN' ? 'log-row-warn' : ''}">
        <td class="log-cell-time">${esc(l.time)}</td>
        <td>${badge(l.module, 'info')}</td>
        <td>${esc(l.level)}</td>
        <td class="log-cell-msg">${esc(l.message)}</td>
      </tr>`).join('') || '<tr><td colspan="4" class="muted">暂无日志</td></tr>';
    const totalEl = $('#logTotal');
    if (totalEl) totalEl.textContent = '共 ' + total + ' 条';
    const pager = $('#logPager');
    if (pager) pager.innerHTML = `
        <button class="btn small" ${logPage <= 1 ? 'disabled' : ''} onclick="logPage--;refreshLogsRows()">上一页</button>
        <span class="small muted">第 ${logPage} / ${pages} 页</span>
        <button class="btn small" ${logPage >= pages ? 'disabled' : ''} onclick="logPage++;refreshLogsRows()">下一页</button>`;
}

/** 首次进入日志页：绘制工具栏/表头/分页容器骨架，绑定控件事件，随后只刷新数据 */
async function renderLogs() {
    $('#pageBody').innerHTML = `
      <div class="toolbar">
        <select id="logModuleSel">
          <option value="">全部模块</option>
          ${['SYSTEM', 'AUTH', 'DDNS', 'STUN', 'WOL', 'CERT', 'NAV', 'DOCKER'].map(m =>
              `<option value="${m}" ${logModule === m ? 'selected' : ''}>${m}</option>`).join('')}
        </select>
        <button class="btn" onclick="refreshLogsRows()">刷新</button>
        <label class="small muted"><input type="checkbox" id="logAuto" ${logAutoRefresh ? 'checked' : ''}> 自动刷新</label>
        <div class="spacer"></div>
        <span class="muted small" id="logTotal"></span>
      </div>
      <div class="panel"><table>
        <thead><tr><th style="width:150px">时间</th><th style="width:110px">模块</th><th style="width:70px">级别</th><th>内容</th></tr></thead>
        <tbody id="logTbody"><tr><td colspan="4" class="muted">加载中...</td></tr></tbody>
      </table>
      <div class="pager" id="logPager"></div></div>`;
    $('#logModuleSel').addEventListener('change', e => { logModule = e.target.value; logPage = 1; refreshLogsRows(); });
    $('#logAuto').addEventListener('change', e => { logAutoRefresh = e.target.checked; armLogsRefresh(); });
    await refreshLogsRows();
    armLogsRefresh();
}
