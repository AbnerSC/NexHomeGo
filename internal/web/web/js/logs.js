/* ============ 操作日志模块 ============ */
'use strict';

let logPage = 1, logModule = '', logLevel = '', logQuery = '';
let logAutoRefresh = true;

/** 按当前「自动刷新」开关装时：开则每 5s 只刷新行，关则停定时器 */
function armLogsRefresh() {
    if (logAutoRefresh) setRefresh(refreshLogsRows, 5000); else setRefresh(null);
}

/** 只重拉当前页日志并更新表格行/分页/总数，不重建工具栏（保留筛选控件与自动刷新勾选） */
async function refreshLogsRows() {
    const tbody = $('#logTbody');
    if (!tbody) return; // 已离开本页，静默退出
    const r = await api('GET', `/api/logs?page=${logPage}&size=15&module=${encodeURIComponent(logModule)}`
        + `&level=${encodeURIComponent(logLevel)}&q=${encodeURIComponent(logQuery.trim())}`);
    const total = Number(r.total);
    const pages = Math.max(1, Math.ceil(total / 15));
    if (logPage > pages) { logPage = pages; return refreshLogsRows(); } // 筛选后页数变少：收敛到末页
    tbody.innerHTML = r.list.map(l => `
      <tr class="${l.level === 'ERROR' ? 'log-row-error' : l.level === 'WARN' ? 'log-row-warn' : ''}">
        <td class="log-cell-time">${esc(l.time)}</td>
        <td>${badge(l.module, 'info')}</td>
        <td>${esc(l.level)}</td>
        <td class="log-cell-msg">${esc(l.message)}</td>
      </tr>`).join('') || '<tr><td colspan="4" class="muted">暂无日志</td></tr>';
    const totalEl = $('#logTotal');
    if (totalEl) totalEl.textContent = '共 ' + total + ' 条';
    paintLogPager(pages);
}

/** 分页条：上/下一页 + 页码输入直接跳转（大数据量翻页不再一页页点） */
function paintLogPager(pages) {
    const pager = $('#logPager');
    if (!pager) return;
    pager.innerHTML = `
        <button class="btn small" ${logPage <= 1 ? 'disabled' : ''} onclick="logGoto(${logPage - 1})">上一页</button>
        <span class="small muted">第 ${logPage} / ${pages} 页</span>
        <span class="log-jump">跳至 <input id="logJumpInput" type="number" min="1" max="${pages}" value="${logPage}"
            aria-label="页码，范围 1 到 ${pages}"> 页
          <button class="btn small" onclick="logJump()">跳转</button></span>
        <button class="btn small" ${logPage >= pages ? 'disabled' : ''} onclick="logGoto(${logPage + 1})">下一页</button>`;
    const inp = $('#logJumpInput');
    if (inp) inp.addEventListener('keydown', e => { if (e.key === 'Enter') logJump(); });
}

window.logGoto = p => { logPage = p; refreshLogsRows(); };

/** 页码跳转：钳制到有效范围后查询 */
window.logJump = () => {
    const inp = $('#logJumpInput');
    if (!inp) return;
    const p = parseInt(inp.value, 10);
    if (isNaN(p)) return;
    logPage = Math.min(Math.max(1, p), Math.max(1, Number(inp.max) || 1));
    refreshLogsRows();
};

/** 首次进入日志页：绘制工具栏/表头/分页容器骨架，绑定控件事件，随后只刷新数据 */
async function renderLogs() {
    $('#pageBody').innerHTML = `
      <div class="toolbar">
        <select id="logModuleSel">
          <option value="">全部模块</option>
          ${['SYSTEM', 'AUTH', 'DDNS', 'STUN', 'WOL', 'CERT', 'NAV', 'DOCKER'].map(m =>
              `<option value="${m}" ${logModule === m ? 'selected' : ''}>${m}</option>`).join('')}
        </select>
        <select id="logLevelSel">
          <option value="">全部级别</option>
          ${['INFO', 'WARN', 'ERROR'].map(l =>
              `<option value="${l}" ${logLevel === l ? 'selected' : ''}>${l}</option>`).join('')}
        </select>
        <input id="logSearch" placeholder="搜索日志内容..." style="width:220px" value="${esc(logQuery)}">
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
    $('#logLevelSel').addEventListener('change', e => { logLevel = e.target.value; logPage = 1; refreshLogsRows(); });
    // 内容搜索：输入停顿 300ms 后查询（防抖），避免逐键请求
    let searchTimer = null;
    $('#logSearch').addEventListener('input', e => {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => {
            if (e.target.value.trim() === logQuery.trim()) return;
            logQuery = e.target.value;
            logPage = 1;
            refreshLogsRows();
        }, 300);
    });
    $('#logAuto').addEventListener('change', e => { logAutoRefresh = e.target.checked; armLogsRefresh(); });
    await refreshLogsRows();
    armLogsRefresh();
}
