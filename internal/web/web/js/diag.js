/* ============ 内存诊断模块 ============ */
/* 只做两件事：
   1. 当前实时内存使用情况（本进程 Go 运行时 + 进程 RSS）；
   2. 内存时间线——最近 24 小时曲线（每 60 秒采样入库，数据保留 7 天）。
   数据来源：/api/diag/memory（单接口同时返回实时值与时间线）。
   本页仅反映本系统自身占用；宿主机整体资源见顶栏监控（/api/system/metrics）。 */
'use strict';

let diagAutoRefresh = true;
let diagChartState = null; // 时间线图当前数据 { history, maxV }，供悬停 tooltip 读取

/** MB 数值（后端已给 MB 浮点）-> 人类可读；负值表示不可用 */
function fmtDiagMB(mb) {
    if (mb == null || mb < 0) return '--';
    return mb >= 1024 ? (mb / 1024).toFixed(2) + ' GB' : mb.toFixed(1) + ' MB';
}

/** 分解表的一行：标签 + 进度条（used/total）+ 文本值 */
function diagBar(label, used, total, text, cls) {
    const pct = total > 0 ? Math.min(100, Math.round(Math.max(0, used) * 100 / total)) : 0;
    const color = pct >= 85 ? 'var(--red)' : pct >= 60 ? 'var(--orange)' : 'var(--cyan)';
    return `<tr>
      <th>${esc(label)}</th>
      <td><div class="diag-track"><i style="width:${pct}%;background:${color}"></i></div></td>
      <td class="diag-val ${cls || ''}">${text}</td>
    </tr>`;
}

/** 生成一条折线的 SVG points（等分 x，按 maxV 归一 y；缺值/不可读负值按 0） */
function diagSeriesPoints(history, key, maxV, w, h) {
    const n = history.length;
    if (n === 0) return '';
    const step = n > 1 ? w / (n - 1) : 0;
    return history.map((s, i) => {
        const v = Math.max(0, Number(s[key] || 0));
        const y = h - (maxV > 0 ? Math.min(1, v / maxV) * h : 0);
        return `${(i * step).toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');
}

/** "YYYY-MM-DD HH:MM:SS" -> "MM-DD HH:MM"（24 小时跨度下需带日期区分） */
function diagTimeShort(t) {
    if (!t) return '';
    const p = String(t).trim().split(/\s+/);
    if (p.length < 2) return t;
    const d = (p[0] || '').split('-');
    const hm = (p[1] || '').slice(0, 5);
    return d.length >= 3 ? `${d[1]}-${d[2]} ${hm}` : hm;
}

/** 内存时间线双折线图（进程 RSS + Go 堆）：SVG 只画网格线与折线，坐标轴/悬停用 HTML 叠加，
    规避 preserveAspectRatio="none" 对 SVG 文字的拉伸变形。 */
function diagChart(history) {
    const W = 900, H = 220;
    let maxV = 1;
    history.forEach(s => {
        maxV = Math.max(maxV, Number(s.rss || 0), Number(s.heap || 0));
    });
    maxV = Math.ceil(maxV * 1.1);
    diagChartState = { history, maxV };
    const rPts = diagSeriesPoints(history, 'rss', maxV, W, H);
    const hPts = diagSeriesPoints(history, 'heap', maxV, W, H);
    const first = history[0], last = history[history.length - 1];
    const n = history.length;
    // Y 轴刻度（5 档）+ 对应水平网格线
    let yLabels = '', gLines = '';
    for (let i = 0; i <= 4; i++) {
        yLabels += `<span style="top:${i / 4 * 100}%">${fmtDiagMB(maxV * (1 - i / 4))}</span>`;
        const y = i / 4 * H;
        gLines += `<line x1="0" y1="${y}" x2="${W}" y2="${y}" class="diag-grid"/>`;
    }
    // X 轴时间刻度（最多 6 个，首尾贴边避免裁切）
    const ticks = Math.min(6, n);
    let xLabels = '';
    for (let k = 0; k < ticks; k++) {
        const idx = ticks > 1 ? Math.round(k * (n - 1) / (ticks - 1)) : 0;
        const left = n > 1 ? idx / (n - 1) * 100 : 0;
        const cls = k === 0 ? 'edge-l' : (k === ticks - 1 ? 'edge-r' : '');
        xLabels += `<span class="${cls}" style="left:${left}%">${esc(diagTimeShort(history[idx].time))}</span>`;
    }
    return `
      <div class="diag-legend">
        <span><i class="dot" style="background:var(--cyan)"></i>进程 RSS（当前 ${fmtDiagMB(last?.rss)}）</span>
        <span><i class="dot" style="background:var(--green)"></i>Go 堆（当前 ${fmtDiagMB(last?.heap)}）</span>
        <span class="muted small">纵轴满刻度 ${fmtDiagMB(maxV)}，共 ${n} 个样本${first ? `，跨度 ${first.time} ~ ${last.time}` : ''}</span>
      </div>
      <div class="diag-chart">
        <div class="diag-yaxis">${yLabels}</div>
        <div class="diag-plot" id="diagPlot">
          <svg class="diag-svg" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
            ${gLines}
            <polyline fill="none" stroke="var(--cyan)" stroke-width="1.6" vector-effect="non-scaling-stroke" points="${rPts}"/>
            <polyline fill="none" stroke="var(--green)" stroke-width="1.6" vector-effect="non-scaling-stroke" points="${hPts}"/>
          </svg>
          <div class="diag-crosshair" id="diagCross"></div>
          <div class="diag-tip" id="diagTip" hidden></div>
        </div>
        <div class="diag-xaxis">${xLabels}</div>
      </div>`;
}

/** 绑定时间线图悬停交互：十字准线 + tooltip（loadDiag 每次重渲染后调用） */
function bindDiagChart() {
    const plot = document.getElementById('diagPlot');
    if (!plot || !diagChartState) return;
    const tip = document.getElementById('diagTip');
    const cross = document.getElementById('diagCross');
    const history = diagChartState.history;
    const n = history.length;
    plot.addEventListener('mousemove', e => {
        const r = plot.getBoundingClientRect();
        if (r.width <= 0) return;
        let fx = (e.clientX - r.left) / r.width;
        fx = Math.max(0, Math.min(1, fx));
        const idx = Math.round(fx * (n - 1));
        const s = history[idx] || {};
        const xPct = n > 1 ? idx / (n - 1) * 100 : 0;
        cross.style.left = xPct + '%';
        cross.style.display = 'block';
        tip.hidden = false;
        tip.innerHTML = `<div class="t">${esc(s.time || '')}</div>`
            + `<div><i class="dot" style="background:var(--cyan)"></i>进程 RSS ${fmtDiagMB(s.rss)}</div>`
            + `<div><i class="dot" style="background:var(--green)"></i>Go 堆 ${fmtDiagMB(s.heap)}</div>`;
        tip.style.left = xPct + '%';
        tip.classList.toggle('flip', xPct > 62); // 靠近右缘时把气泡翻到准线左侧，避免溢出
    });
    plot.addEventListener('mouseleave', () => {
        cross.style.display = 'none';
        tip.hidden = true;
    });
}

/** 实时内存分解：进程 RSS 为进程视角（含共享页与未归还页），堆/栈/运行时为其构成参考 */
function diagLive(s, rt) {
    const rss = Number(s.rss) > 0 ? Number(s.rss) : 0; // 作为堆/栈/运行时的分母（进程总占用视角）
    const lim = Number(s.memLimit); // 容器内存上限（MB），cgroup 不可读/无限制时为负
    const up = rt.uptimeSec || 0;
    const upTxt = `${Math.floor(up / 3600)}h${Math.floor(up % 3600 / 60)}m`;
    return `
      <div class="panel">
        <h3 style="font-size:14px;margin-bottom:12px">当前实时内存</h3>
        <table>
          ${diagBar('进程 RSS', rss, rss, fmtDiagMB(s.rss) + (s.rss < 0 ? '（非 Linux 不可读）' : '（进程总占用）'))}
          ${lim > 0 ? diagBar('容器上限', rss, lim, `${fmtDiagMB(s.rss)} / ${fmtDiagMB(lim)}`) : ''}
          ${diagBar('Go 堆', s.heap, rss, `${fmtDiagMB(s.heap)} / 已申请 ${fmtDiagMB(s.heapSys)} / ${(s.heapObj || 0).toLocaleString()} 个对象`)}
          ${diagBar('协程栈', s.stack, rss, fmtDiagMB(s.stack))}
          ${diagBar('运行时合计（Sys）', s.sys, rss, fmtDiagMB(s.sys))}
          <tr><th>协程 / GC</th><td></td><td class="diag-val">${s.thr || 0} 协程 · GC ${s.gc || 0} 次 / ${s.gcMs || 0} ms</td></tr>
        </table>
        <div class="small muted" style="margin-top:8px">
          ${esc(rt.version || '')} · PID ${rt.pid || '-'} · 主机 ${esc(rt.hostname || '-')} · ${rt.numCpu || 0} CPU ·
          运行 ${upTxt} · /proc ${rt.proc ? '可用' : '不可用（非 Linux）'}
        </div>
      </div>`;
}

async function loadDiag() {
    let snap;
    try { snap = await api('GET', '/api/diag/memory'); } catch (e) { return; }
    const body = $('#diagBody');
    if (!body) return; // 已离开页面
    diagChartState = null; // 重渲染前先失效，避免悬停读到已卸载的旧图
    const s = snap.latest || {};
    const rt = snap.runtime || {};
    const hist = snap.history || [];
    const chart = hist.length >= 2 ? diagChart(hist)
        : `<p class="muted small">样本不足（需至少 2 个，每 ${snap.intervalSec || 60} 秒入库一次），请稍后刷新。</p>`;
    body.innerHTML = `
      ${diagLive(s, rt)}
      <div class="panel">
        <h3 style="font-size:14px;margin-bottom:12px">内存时间线（最近 24 小时）</h3>
        ${chart}
      </div>`;
    if (hist.length >= 2) bindDiagChart();
}

function armDiagRefresh() {
    // 复用框架的 setRefresh：切换页面时由 setPage 统一清除，避免定时器泄漏。
    if (diagAutoRefresh) setRefresh(loadDiag, 60000); else setRefresh(null);
}

async function renderDiag() {
    $('#pageBody').innerHTML = `
      <div class="toolbar">
        <button class="btn" onclick="loadDiag()">刷新</button>
        <label class="small muted"><input type="checkbox" id="diagAuto" ${diagAutoRefresh ? 'checked' : ''}> 自动刷新（每 60 秒）</label>
        <div class="spacer"></div>
        <span class="muted small">数据每 60 秒入库、保留 7 天，时间线展示最近 24 小时</span>
      </div>
      <div id="diagBody"><p class="muted">加载中...</p></div>`;
    $('#diagAuto').addEventListener('change', e => { diagAutoRefresh = e.target.checked; armDiagRefresh(); });
    await loadDiag();
    armDiagRefresh();
}
