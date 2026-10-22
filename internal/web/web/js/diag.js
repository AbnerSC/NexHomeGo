/* ============ 内存诊断模块 ============ */
/* 实时内存分解 + 时间线曲线 + 内存跳变点与 op_log 时间线的关联分析。
   数据来源：/api/diag/snapshot（采样时间线）、/api/diag/analysis（跳变检测 + 日志关联）。
   Go 运行时版本：堆/GC/协程由 runtime.MemStats 提供，无 JVM 的 Metaspace/NMT 概念。
   本页仅展示本系统（进程 RSS + Go 运行时）的内存占用；宿主机整体资源见顶部监控。 */
'use strict';

let diagAutoRefresh = true;
let diagTimer = null;
let diagChartState = null; // 时间线图当前数据 { history, maxV }，供悬停 tooltip 读取

/** MB 数值（后端已给 MB 浮点）-> 人类可读；-1 表示不可用 */
function fmtDiagMB(mb) {
    if (mb == null || mb < 0) return '--';
    return mb >= 1024 ? (mb / 1024).toFixed(2) + ' GB' : mb.toFixed(1) + ' MB';
}

/** 分解表的一行：标签 + 进度条（used/total）+ 文本值 */
function diagBar(label, used, total, text, cls) {
    const pct = total > 0 ? Math.min(100, Math.round(used * 100 / total)) : 0;
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

/** 时间字符串取 HH:MM:SS 短格式（后端给的是 "YYYY-MM-DD HH:MM:SS"） */
function diagTimeShort(t) {
    if (!t) return '';
    const p = String(t).trim().split(/\s+/);
    return p.length > 1 ? p[1] : t;
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
    // X 轴时间刻度（最多 5 个，首尾贴边避免裁切）
    const ticks = Math.min(5, n);
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

/** 日志密度迷你柱状（每分钟条数），横轴为时间线跨度 */
function diagDensity(rows) {
    if (!rows || !rows.length) return '<p class="muted small">该时间跨度内无日志。</p>';
    const maxC = Math.max(...rows.map(r => Number(r.c)), 1);
    const bars = rows.map(r => `<div class="diag-dbar" title="${esc(r.minute)} — ${r.c} 条"
        style="height:${Math.max(2, Math.round(Number(r.c) * 100 / maxC))}%"></div>`).join('');
    return `<div class="diag-dbars">${bars}</div>
      <div class="small muted">共 ${rows.length} 分钟有日志，单分钟峰值 ${maxC} 条（悬停查看具体分钟）</div>`;
}

function diagLogRows(list, emptyText) {
    if (!list || !list.length) return `<tr><td colspan="4" class="muted">${emptyText}</td></tr>`;
    return list.map(l => `
      <tr class="${l.level === 'ERROR' ? 'log-row-error' : l.level === 'WARN' ? 'log-row-warn' : ''}">
        <td class="log-cell-time">${esc(l.time)}</td>
        <td>${badge(l.module, 'info')}</td>
        <td>${esc(l.level || '')}</td>
        <td class="log-cell-msg">${esc(l.message)}</td>
      </tr>`).join('');
}

/** 实例身份与口径校验：PID / 容器主机名 / cgroup / 监听端口。
 *  用于回答「这个页面到底是不是当前容器在应答」——进程 RSS 远大于 cgroup 记账、
 *  端口发生自愈时给出告警（端口被占用后程序会静默改端口，浏览器可能连到另一个实例）。 */
function diagInstance(go, s) {
    const msgs = [];
    // VmHWM 是内核单调记录的历史峰值，比瞬时 RSS 更能说明「这个进程曾经吃下多少」
    const peak = Number(s.rssPeak) > 0 ? Number(s.rssPeak) : Number(s.rss || 0);
    if (go.containerUsedMB >= 0 && peak > 0 && peak > go.containerUsedMB * 1.5) {
        msgs.push(`进程 RSS 峰值（${fmtDiagMB(peak)}）明显大于容器 cgroup 记账（${fmtDiagMB(go.containerUsedMB)}），`
            + '本页数据很可能来自另一个进程实例（端口被旧实例占用后自愈换端口是常见原因）。');
    }
    if (go.configPort > 0 && go.boundPort > 0 && go.configPort !== go.boundPort) {
        msgs.push(`HTTP 端口已自愈：配置 ${go.configPort}，实际监听 ${go.boundPort}。`
            + '请确认浏览器访问的端口上就是当前容器。');
    }
    if (go.lastError) msgs.push('上次启动告警：' + go.lastError);
    const warn = msgs.length
        ? `<div class="tip" style="margin-top:8px;border-color:var(--orange)">${msgs.map(esc).join('<br>')}</div>`
        : '';
    return `
        <div class="small muted" style="margin-top:8px">
          ${esc(go.version || '')} · PID ${go.pid || '-'} · 主机 ${esc(go.hostname || '-')} · ${go.numCpu || 0} CPU ·
          运行 ${Math.floor((go.uptimeSec || 0) / 3600)}h${Math.floor((go.uptimeSec || 0) % 3600 / 60)}m ·
          监听 ${go.boundPort || '-'}${go.configPort > 0 && go.configPort !== go.boundPort ? `（配置 ${go.configPort}）` : ''} ·
          堆已申请 ${fmtDiagMB(go.maxHeapMB)} · 容器限制 ${go.containerLimitMB >= 0 ? fmtDiagMB(go.containerLimitMB) : '无限制/不可读'} · /proc ${go.proc ? '可用' : '不可用（非 Linux）'}
        </div>
        ${go.cgroup ? `<div class="small muted" style="margin-top:4px">cgroup ${esc(go.cgroup)}</div>` : ''}
        ${warn}`;
}

async function loadDiag() {
    let snap;
    try { snap = await api('GET', '/api/diag/snapshot'); } catch (e) { return; }
    const body = $('#diagLive');
    if (!body) return; // 已离开页面
    diagChartState = null; // 重渲染前先失效，避免悬停读到已卸载的旧图
    const s = snap.latest || {};
    const go = snap.go || {};
    body.innerHTML = `
      <div class="panel">
        <h3 style="font-size:14px;margin-bottom:12px">实时内存分解</h3>
        <div class="small muted" style="margin:-6px 0 10px">进程 RSS 为进程视角（含共享页与未归还页），容器占用/限制以 cgroup 记账为准；宿主机整体资源见顶部监控</div>
        <table>
          ${go.containerLimitMB >= 0 ? diagBar('容器内存（cgroup 记账）', go.containerUsedMB, go.containerLimitMB,
              `${fmtDiagMB(go.containerUsedMB)} / ${fmtDiagMB(go.containerLimitMB)}`) : ''}
          ${diagBar('进程 RSS', s.rss, go.containerLimitMB > 0 ? go.containerLimitMB : Math.max(s.rss || 0, 1),
              `${fmtDiagMB(s.rss)}${s.rss < 0 ? '（非 Linux 不可读）' : `（进程视角，峰值 ${fmtDiagMB(s.rssPeak)}）`}`)}
          ${diagBar('Go 堆', s.heap, s.heapSys, `${fmtDiagMB(s.heap)} / 已向系统申请 ${fmtDiagMB(s.heapSys)} / ${(s.heapObj || 0).toLocaleString()} 个对象`)}
          ${diagBar('协程栈', s.stack, s.sys, fmtDiagMB(s.stack))}
          ${diagBar('运行时合计（Sys）', s.sys, s.rss > 0 ? s.rss : 0, fmtDiagMB(s.sys))}
          <tr><th>协程 / GC</th><td></td><td class="diag-val">${s.thr || 0} 协程 · GC ${s.gc || 0} 次 / ${s.gcMs || 0} ms</td></tr>
          <tr><th>代理文件缓存</th><td></td><td class="diag-val">${s.cacheN || 0} 项 · ${s.cacheMB < 0 ? '未启用' : fmtDiagMB(s.cacheMB) + '（磁盘）'}</td></tr>
        </table>
        ${diagInstance(go, s)}
      </div>
      <div class="panel">
        <h3 style="font-size:14px;margin-bottom:12px">内存时间线</h3>
        ${snap.history && snap.history.length >= 2 ? diagChart(snap.history)
              : '<p class="muted small">样本不足（需至少 2 个，每 ' + (snap.intervalSec || 10) + ' 秒采一次），请稍候再刷新。</p>'}
      </div>`;
    if (snap.history && snap.history.length >= 2) bindDiagChart();
}

async function runDiagAnalysis() {
    const metric = $('#diagMetric').value;
    const box = $('#diagAnalysis');
    box.innerHTML = '<p class="muted">分析中...</p>';
    let a;
    try { a = await api('GET', '/api/diag/analysis?metric=' + encodeURIComponent(metric)); }
    catch (e) { box.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; return; }
    const j = a.jump;
    const summary = a.count >= 2
      ? `<div class="tip">时间线跨度内 ${esc(a.metricLabel)} 从 <b>${fmtDiagMB(a.firstMB)}</b> 变化到 <b>${fmtDiagMB(a.lastMB)}</b>，净增 <b>${a.growthMB} MB</b>。
         ${j ? `最大单周期跳升发生在 <b>${esc(j.time)}</b>：${fmtDiagMB(j.fromMB)} → ${fmtDiagMB(j.toMB)}（<b style="color:var(--red)">+${j.deltaMB} MB</b>），下方为跳变点前后各 2 分钟的日志。`
             : '未检测到明显的单周期跳升（内存曲线相对平稳）。'}</div>`
      : `<p class="muted small">采样不足（当前 ${a.count} 个样本），无法定位跳变点；请让服务运行一段时间后再分析。</p>`;
    box.innerHTML = `
      ${summary}
      <h3 style="font-size:14px;margin:14px 0 8px">跳变点前后日志${j ? '' : '（无跳变点，暂空）'}</h3>
      <table>
        <thead><tr><th style="width:150px">时间</th><th style="width:110px">模块</th><th style="width:70px">级别</th><th>内容</th></tr></thead>
        <tbody>${diagLogRows(a.logsAround, '跳变点附近无日志记录')}</tbody>
      </table>
      <h3 style="font-size:14px;margin:14px 0 8px">关键事件（缓存加载 / 重启 / 监听启动）</h3>
      <table>
        <thead><tr><th style="width:150px">时间</th><th style="width:110px">模块</th><th>内容</th></tr></thead>
        <tbody>${(a.notable && a.notable.length) ? a.notable.map(n =>
            `<tr><td class="log-cell-time">${esc(n.time)}</td><td>${badge(n.module, 'info')}</td><td class="log-cell-msg">${esc(n.message)}</td></tr>`).join('')
            : '<tr><td colspan="3" class="muted">暂无关键事件</td></tr>'}</tbody>
      </table>
      <h3 style="font-size:14px;margin:14px 0 8px">日志密度（每分钟条数）</h3>
      ${diagDensity(a.density)}`;
}

async function exportDiag() {
    try {
        const snap = await api('GET', '/api/diag/snapshot');
        const blob = new Blob([JSON.stringify(snap, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'nexhome-memdiag-' + new Date().toISOString().replace(/[:.]/g, '') + '.json';
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 2000);
        toast('已导出诊断快照 JSON');
    } catch (e) { toast(e.message, 'err'); }
}

function armDiagRefresh() {
    if (diagTimer) { clearInterval(diagTimer); diagTimer = null; }
    if (diagAutoRefresh) diagTimer = setInterval(() => loadDiag().catch(() => { }), 10000);
}

async function renderDiag() {
    $('#pageBody').innerHTML = `
      <div class="toolbar">
        <label class="small muted">分析指标</label>
        <select id="diagMetric">
          <option value="rss">进程 RSS（含运行时）</option>
          <option value="heap">Go 堆</option>
        </select>
        <button class="btn" onclick="runDiagAnalysis()">分析内存跳变</button>
        <button class="btn" onclick="loadDiag()">刷新分解</button>
        <button class="btn" onclick="exportDiag()">导出快照 JSON</button>
        <label class="small muted"><input type="checkbox" id="diagAuto" ${diagAutoRefresh ? 'checked' : ''}> 自动刷新</label>
        <div class="spacer"></div>
        <span class="muted small">采样自本次进程启动，运行越久时间线越完整</span>
      </div>
      <div class="tip" style="margin-bottom:12px">用于定位「内存突然上升且不释放」：先看<b>实时分解</b>判断涨在 Go 堆、协程栈还是运行时/RSS，
        再点<b>分析内存跳变</b>自动找出曲线跳升的时间点，并把该时刻前后的 <b>op_log 事件</b>对齐展示。</div>
      <div id="diagLive"><p class="muted">加载中...</p></div>
      <div class="panel">
        <h3 style="font-size:14px;margin-bottom:12px">关联分析</h3>
        <div id="diagAnalysis"><p class="muted small">点击上方「分析内存跳变」生成结论。</p></div>
      </div>`;
    $('#diagAuto').addEventListener('change', e => { diagAutoRefresh = e.target.checked; armDiagRefresh(); });
    await loadDiag();
    armDiagRefresh();
}
