/* ============ 统一状态仪表盘（总览） ============ */
'use strict';

/** 秒数转可读运行时长 */
function fmtUptime(sec) {
    sec = sec || 0;
    const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
    return (d > 0 ? d + ' 天 ' : '') + h + ' 小时 ' + m + ' 分钟';
}

/** 数字千分位 */
function fmtCount(n) { return (n || 0).toLocaleString(); }

/** 字节/秒 -> Mbps 可读 */
function fmtMbps(bytesPerSec) { return (bytesPerSec * 8 / 1e6).toFixed(1) + ' Mbps'; }

/**
 * 测速结果缓存：页面 15 秒自动刷新（以及测速中途切页再回总览）会整块重绘面板，
 * 数值按缓存复原，测速过程不被打断。
 * pingSub/jitterSub 是卡片下方的附属小字；prog* 是整体进度状态（阶段序号/百分比/文案/按钮百分比），
 * 重绘时据此复原进度条，避免进行中的进度被打回起点。
 */
const speedState = {
    running: false, ping: '', loss: '', down: '', up: '',
    jitter: '', pingSub: '', jitterSub: '', downSub: '',
    progIdx: -1, progPct: 0, progText: ''
};

/** 测速时长：延迟/下载/上传三个阶段统一各测 10 秒 */
const SPEED_TEST_MS = 10000;

/**
 * 延迟阶段最少样本数与最长时长：抖动用的 P95 至少二十来个样本才有意义（样本不足十个时
 * P95 基本就是最大值，与旧的“最高−最低”没差别），而高延迟链路（卫星/3G/拥塞互联网）往返
 * 动辄一两秒，10 秒窗口只够五六个来回。故样本不够就继续探，但最多延长到两倍窗口，
 * 到上限仍不够则按现有样本如实计算（小字里给出样本数，不假装精确）。
 */
const SPEED_PING_MIN_SAMPLES = 20, SPEED_PING_MAX_MS = SPEED_TEST_MS * 2;

/**
 * 测速并发流数：每条 HTTP/1.1 连接的吞吐受服务端单线程 TLS 加解密与 socket 流控限制，
 * 跑不满千兆链路，多路并发才能利用多核压出真实带宽（与主流测速站点做法一致）。
 * 取 6 —— 浏览器同源 HTTP/1.1 连接数上限即 6，测速期间已暂停其他轮询，可全部用于测速；
 * 这也是本地万兆链路能用的并发上限（同源 HTTP/1.1 只给 6 条连接），想再高只能走 HTTP/2 多路复用。
 */
const SPEED_STREAMS = 6;

/** 测速阶段名（进度条步骤与文案），顺序必须与 runSpeedTest 里的三个阶段一致 */
const SPEED_PHASES = ['延迟/丢包', '下载', '上传'];

/**
 * 进度权重：阶段内部预热段最多只占本阶段 12%，测量段封顶 97%（留 3% 给窗口结束后
 * 等待各路收尾排空的尾巴），进入下一阶段时才补满整段权重。
 */
const SPEED_PROG_WARM = 0.12, SPEED_PROG_TAIL = 0.03;

/** 进度步骤条 HTML：cur 高亮进行中阶段，done 标记已完成阶段（测速中整页重绘据缓存复原） */
function speedStepsHtml(active, idx) {
    const mark = ['①', '②', '③'];
    return SPEED_PHASES.map((n, i) =>
        `<span class="st-prog-step${active ? (i < idx ? ' done' : i === idx ? ' cur' : '') : ''}">${mark[i]} ${n}</span>`).join('');
}

/** 数值夹到 [lo,hi]：分片大小、入块大小等各处复用 */
const stClamp = (v, lo, hi) => Math.min(Math.max(v, lo), hi);

/**
 * 下载读流工作线程源码：把“逐块读响应体并计数”从主线程搬走。
 * 主线程每收到一个分片就要回 JS 一次（分配 Uint8Array + 调用 + GC），千兆/万兆链路上
 * 这部分开销既抬高延迟又占用帧预算（上一轮曾观察到它把下载卡在 3Gbps 左右，但同机重跑
 * 主线程循环也能到 4.5Gbps，量级收益与机器负载相关、未必稳定复现）；把计数搬进
 * 每连接各自的 Worker 后，主线程只负责计时与汇总，至少不再让页面卡顿与测速互相干扰。
 * 上传方向无此问题（数据搬运在浏览器内部完成，但请求体必须是 Blob，见 upBody 说明）。
 * Worker 不可用（老浏览器、blob: 脚本被限制）时前端回退主线程读流；回退会被当成成功
 * 路径运行，故调用侧必须传绝对 URL 且另核对每路是否真的收到字节。
 */
const DOWN_WORKER_SRC = `
'use strict';
let bytes = 0, ctrl = null;
const send = t => postMessage({ t: t, b: bytes });
onmessage = e => {
    const d = e.data || {};
    if (d.cmd === 'start') {
        bytes = 0;
        ctrl = new AbortController();
        const hard = setTimeout(() => ctrl.abort(), d.hardMs);   // 链路彻底卡死也要收场
        const iv = setInterval(() => send('p'), d.iv);            // 定期把本路累计字节报给主线程
        (async () => {
            try {
                const r = await fetch(d.url, { headers: { 'X-Token': d.token }, cache: 'no-store', signal: ctrl.signal });
                if (!r.ok) throw new Error('HTTP ' + r.status);
                const rd = r.body.getReader();
                for (;;) {
                    const x = await rd.read();
                    if (x.done) break;
                    bytes += x.value.length;
                }
            } catch (err) {
                // 窗口到点的中断是正常收尾；其余异常报出去，成不了绩时由主线程给出失败原因
                if (!err || err.name !== 'AbortError') postMessage({ t: 'e', b: bytes, m: String((err && err.message) || err) });
            } finally {
                clearTimeout(hard);
                clearInterval(iv);
                send('d');
            }
        })();
    } else if (d.cmd === 'stop') {
        if (ctrl) ctrl.abort();
    }
};
`;

/** 取“好看”的纵轴上限（1/2/2.5/5 × 10^n），网格刻度避免零碎小数 */
function dvNiceMax(v) {
    const exp = Math.pow(10, Math.floor(Math.log10(Math.max(v, 1))));
    for (const f of [1, 2, 2.5, 5, 10]) if (v <= f * exp * 1.0001) return f * exp;
    return 10 * exp;
}

/**
 * 每日总访问折线图：Catmull-Rom 平滑曲线 + 主题色渐变描边与面积 + 虚线网格
 * + 悬浮最近点吸附气泡，最新一天末端常亮高亮点；尺寸按容器实测绘制（纵向填满所在栅格行）。
 */
function drawVisitChart(host, days) {
    if (!host) return;
    if (!days.length) { host.innerHTML = '<p class="muted small" style="margin:0">暂无访问数据</p>'; return; }
    const W = Math.max(host.clientWidth || 0, 240), H = Math.max(host.clientHeight || 0, 140);
    const P = { l: 42, r: 14, t: 14, b: 20 };
    const iw = W - P.l - P.r, ih = H - P.t - P.b;
    const peak = Math.max(...days.map(x => x.hits || 0));
    const nice = dvNiceMax(peak);
    const X = i => P.l + (days.length < 2 ? iw / 2 : (iw * i) / (days.length - 1));
    const Y = v => P.t + ih - (Math.max(v, 0) / nice) * ih;
    const pts = days.map((x, i) => ({ x: +X(i).toFixed(1), y: +Y(x.hits || 0).toFixed(1), day: x.day, hits: x.hits || 0 }));

    // Catmull-Rom 转三次贝塞尔（控制点钳制在绘图区内，防平滑越界穿过基线）
    const line = (() => {
        if (pts.length === 1) return `M${pts[0].x},${pts[0].y}`;
        const cl = y => Math.min(P.t + ih, Math.max(P.t, y));
        let d = `M${pts[0].x},${pts[0].y}`;
        for (let i = 0; i < pts.length - 1; i++) {
            const p0 = pts[i - 1] || pts[i], p1 = pts[i], p2 = pts[i + 1], p3 = pts[i + 2] || p2;
            d += `C${(p1.x + (p2.x - p0.x) / 6).toFixed(1)},${cl(p1.y + (p2.y - p0.y) / 6).toFixed(1)} `
                + `${(p2.x - (p3.x - p1.x) / 6).toFixed(1)},${cl(p2.y + (p3.y - p1.y) / 6).toFixed(1)} `
                + `${p2.x},${p2.y}`;
        }
        return d;
    })();
    const area = pts.length > 1 ? `${line}L${pts[pts.length - 1].x},${P.t + ih}L${pts[0].x},${P.t + ih}Z` : '';

    // 网格 + 纵轴刻度（基线实线，其余虚线）
    let grid = '';
    for (let g = 0; g <= 4; g++) {
        const y = (P.t + ih - (ih * g) / 4).toFixed(1);
        grid += `<line x1="${P.l}" y1="${y}" x2="${W - P.r}" y2="${y}" stroke="${g ? 'rgba(148,163,200,.10)' : 'rgba(148,163,200,.24)'}" stroke-dasharray="${g ? '3 4' : ''}"/>`
            + `<text x="${P.l - 7}" y="${+y + 3.5}" text-anchor="end" font-size="9.5" fill="#aab6d8">${fmtCount((nice * g) / 4)}</text>`;
    }
    // 横轴日期刻度（点少全显，点多隔取样且末尾必显）
    let ticks = '';
    const step = Math.max(1, Math.ceil(pts.length / 5));
    pts.forEach((p, i) => {
        if (i % step && i !== pts.length - 1) return;
        ticks += `<text x="${p.x}" y="${H - 6}" text-anchor="middle" font-size="9.5" fill="#aab6d8">${esc((p.day || '').slice(5))}</text>`;
    });

    const last = pts[pts.length - 1];
    host.innerHTML = `
      <svg width="${W}" height="${H}" style="display:block">
        <defs>
          <linearGradient id="dvc-line" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0" stop-color="#38bdf8"/><stop offset=".55" stop-color="#6d8bff"/><stop offset="1" stop-color="#a855f7"/>
          </linearGradient>
          <linearGradient id="dvc-area" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stop-color="#6d8bff" stop-opacity=".30"/>
            <stop offset=".65" stop-color="#6d8bff" stop-opacity=".07"/>
            <stop offset="1" stop-color="#6d8bff" stop-opacity="0"/>
          </linearGradient>
          <filter id="dvc-glow" x="-30%" y="-30%" width="160%" height="160%">
            <feDropShadow dx="0" dy="2" stdDeviation="2.5" flood-color="#6d8bff" flood-opacity=".35"/>
          </filter>
        </defs>
        ${grid}${ticks}
        ${area ? `<path d="${area}" fill="url(#dvc-area)"/>` : ''}
        <path d="${line}" fill="none" stroke="url(#dvc-line)" stroke-width="2.25" stroke-linecap="round" stroke-linejoin="round" filter="url(#dvc-glow)"/>
        ${peak > 0 && last ? `<circle cx="${last.x}" cy="${last.y}" r="3.4" fill="#fff" stroke="#6d8bff" stroke-width="2.2"/>` : ''}
        ${peak === 0 ? `<text x="${P.l + iw / 2}" y="${P.t + ih / 2}" text-anchor="middle" font-size="11" fill="#b7c1cf">该时段暂无访问</text>` : ''}
        <line id="dvc-guide" y1="${P.t}" y2="${P.t + ih}" stroke="#6d8bff" stroke-width="1.2" stroke-dasharray="4 3" opacity="0"/>
        <circle id="dvc-cursor" r="4.2" fill="#6d8bff" stroke="#fff" stroke-width="1.6" opacity="0"/>
        <rect id="dvc-hit" x="${P.l}" y="${P.t}" width="${iw}" height="${ih}" fill="transparent" style="cursor:crosshair"/>
      </svg>
      <div class="tf-tip" id="dvc-tip" style="display:none"></div>`;

    // 悬浮交互：最近点吸附 + 十字引导线 + 深色气泡提示
    const svg = host.querySelector('svg');
    const guide = host.querySelector('#dvc-guide');
    const cursor = host.querySelector('#dvc-cursor');
    const tip = host.querySelector('#dvc-tip');
    const move = e => {
        const mx = e.clientX - svg.getBoundingClientRect().left;
        let best = 0, dist = Infinity;
        pts.forEach((p, i) => { const dd = Math.abs(p.x - mx); if (dd < dist) { dist = dd; best = i; } });
        const p = pts[best];
        guide.setAttribute('x1', p.x); guide.setAttribute('x2', p.x); guide.setAttribute('opacity', '.55');
        cursor.setAttribute('cx', p.x); cursor.setAttribute('cy', p.y); cursor.setAttribute('opacity', '1');
        tip.style.display = '';
        tip.innerHTML = `${esc(p.day)}<br><b>${fmtCount(p.hits)} 次</b>`;
        const half = tip.offsetWidth / 2 || 40; // 靠近左右边缘时钳制，防气泡溢出
        tip.style.left = Math.max(half + 2, Math.min(W - half - 2, p.x)) + 'px';
        tip.style.top = Math.max(p.y - 10, 30) + 'px';
    };
    const leave = () => {
        guide.setAttribute('opacity', '0'); cursor.setAttribute('opacity', '0'); tip.style.display = 'none';
    };
    const hit = host.querySelector('#dvc-hit');
    hit.addEventListener('mousemove', move);
    hit.addEventListener('mouseleave', leave);
}

async function renderDashboard() {
    let d;
    try { d = await api('GET', '/api/dashboard'); }
    catch (e) { $('#pageBody').innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; return; }
    const sys = d.system || {}, ddns = d.ddns || {}, stun = d.stun || {}, cert = d.cert || {};
    const mon = d.monitor || {}, docker = d.docker || {}, proxy = d.proxy || {}, visits = d.visits || {};

    // 顶部关键指标卡：健康项绿色、告警项红色/橙色
    const card = (icon, val, label, tone, onclick) => `
      <div class="dash-stat${tone ? ' ' + tone : ''}"${onclick ? ` onclick="setPage('${onclick}')" style="cursor:pointer"` : ''}>
        <div class="dash-stat-icon">${icon}</div>
        <div class="dash-stat-body"><div class="v">${val}</div><div class="l">${label}</div></div>
      </div>`;

    const monDown = mon.down || 0, ddnsFail = ddns.failed || 0, stunFail = stun.failed || 0, certSoon = cert.expiringSoon || 0;
    let stats = '<div class="dash-stats">';
    stats += card('🌐', `${ddns.enabled ?? 0}<span class="muted" style="font-size:13px"> / ${ddns.total ?? 0}</span>`,
        'DDNS 启用/总数' + (ddnsFail ? ` · ${ddnsFail} 失败` : ''), ddnsFail ? 'warn' : 'ok', 'ddns');
    stats += card('🔓', `${stun.running ?? 0}<span class="muted" style="font-size:13px"> / ${stun.total ?? 0}</span>`,
        'STUN 运行/总数' + (stunFail ? ` · ${stunFail} 异常` : ''), stunFail ? 'warn' : 'ok', 'stun');
    stats += card('📡', monDown ? `${mon.up ?? 0}<span class="muted" style="font-size:13px"> UP · ${monDown} DOWN</span>`
        : `${mon.up ?? 0}<span class="muted" style="font-size:13px"> / ${mon.total ?? 0}</span>`,
        '可用性监控', monDown ? 'err' : (mon.total ? 'ok' : ''), 'monitor');
    stats += card('🔐', `${cert.issued ?? 0}<span class="muted" style="font-size:13px"> / ${cert.total ?? 0}</span>`,
        '证书 已签发/总数' + (certSoon ? ` · ${certSoon} 临期` : ''), certSoon ? 'warn' : 'ok', 'cert');
    const proxyTotal = proxy.total ?? 0, proxyOn = proxy.enabled ?? 0;
    stats += card('🔀', `${proxyOn}<span class="muted" style="font-size:13px"> / ${proxyTotal}</span>`,
        proxyTotal > 0 && !proxy.listening ? '代理站点 · 未监听' : '代理站点 启用/总数',
        proxyTotal > 0 && !proxy.listening ? 'warn' : (proxyTotal > 0 ? 'ok' : ''), 'proxy');
    stats += card('🐳', docker.connected
        ? `${docker.running ?? 0}<span class="muted" style="font-size:13px"> / ${docker.containers ?? 0}</span>`
        : '<span class="muted" style="font-size:15px">未连接</span>',
        'Docker 运行/总容器', docker.connected ? ((docker.stopped ?? 0) > 0 ? 'warn' : 'ok') : '', 'docker');
    stats += card('⏱️', fmtUptime(sys.uptimeSec), `端口 ${sys.port || '-'}${sys.httpsActive ? ' · HTTPS' : ''}`, '', '');
    stats += '</div>';

    // 证书临期明细
    const certList = (cert.expiringList || []).map(c => `
      <tr><td>${esc(c.name)}</td><td class="small muted">${esc((c.not_after || '').slice(0, 10))}</td>
        <td>${badge(c.daysLeft <= 7 ? `仅剩 ${c.daysLeft} 天` : `${c.daysLeft} 天后到期`, c.daysLeft <= 7 ? 'err' : 'warn')}</td></tr>`).join('');

    // 代理访问统计：每日总访问折线 + 网站/地区 TOP10（横向条形）
    const visitDays = visits.days || [];

    const topList = items => (items || []).length ? items.map((it, i) => {
        const top = items[0].hits || 1;
        return `<div class="dash-top-item">
          <span class="dash-top-rank">${i + 1}</span>
          <span class="dash-top-name" title="${esc(it.name)}">${esc(it.name)}</span>
          <span class="dash-top-bar"><i style="width:${(it.hits / top * 100).toFixed(1)}%"></i></span>
          <span class="dash-top-hits">${fmtCount(it.hits)}</span>
        </div>`;
    }).join('') : '<p class="muted small">暂无访问数据</p>';

    $('#pageBody').innerHTML = `
      ${stats}
      ${certSoon ? `
      <div class="panel">
        <h3 class="dash-panel-title">🔐 证书临期提醒（≤ ${cert.warnDays} 天）</h3>
        <table><thead><tr><th>任务</th><th>到期日</th><th>剩余</th></tr></thead><tbody>${certList}</tbody></table>
      </div>` : ''}
      <div class="panel">
        <h3 class="dash-panel-title">📈 代理访问统计
          <span class="muted small" style="font-weight:400">（最近 7 天 · 共 ${fmtCount(visits.total)} 次）</span></h3>
        <div class="dash-visit-grid">
          <div class="dash-visit-col">
            <div class="dash-visit-sub">每日总访问次数</div>
            <div class="dash-visit-chart" id="dashVisitChart"></div>
          </div>
          <div class="dash-visit-top dash-top-sites">
            <div class="dash-visit-sub">网站访问 TOP10</div>
            ${topList(visits.topSites)}
          </div>
          <div class="dash-visit-top dash-top-regions">
            <div class="dash-visit-sub">来源地区 TOP10</div>
            ${topList(visits.topRegions)}
          </div>
        </div>
      </div>
      <div class="panel">
        <h3 class="dash-panel-title">⚡ 网络测速
          <span class="muted small" style="font-weight:400">（浏览器 ↔ 本系统链路，不经外部测速服务器）</span></h3>
        <div class="dash-speed-grid">
          <div class="dash-speed-tile"><div class="v" id="st-ping">${speedState.ping || '--'}</div><div class="l">延迟（中位往返）</div><div class="s" id="st-ping-sub">${speedState.pingSub || ''}</div></div>
          <div class="dash-speed-tile"><div class="v" id="st-jitter">${speedState.jitter || '--'}</div><div class="l">抖动（P95 − 中位）</div><div class="s" id="st-jitter-sub">${speedState.jitterSub || ''}</div></div>
          <div class="dash-speed-tile"><div class="v" id="st-loss">${speedState.loss || '--'}</div><div class="l">丢包率（${Math.round(SPEED_TEST_MS / 1000)} 秒探测）</div><div class="s"></div></div>
          <div class="dash-speed-tile"><div class="v" id="st-down">${speedState.down || '--'}</div><div class="l">下载速率</div><div class="s" id="st-down-sub">${speedState.downSub || ''}</div></div>
          <div class="dash-speed-tile"><div class="v" id="st-up">${speedState.up || '--'}</div><div class="l">上传速率</div><div class="s"></div></div>
        </div>
        <div class="dash-speed-prog${speedState.running ? '' : ' hidden'}">
          <div class="st-prog-steps" id="stProgSteps">${speedStepsHtml(speedState.running, speedState.progIdx)}</div>
          <div class="st-prog-bar"><i id="stProgBar" style="width:${speedState.running ? speedState.progPct : 0}%"></i></div>
          <span class="st-prog-txt" id="stProgTxt">${speedState.progText || '准备中…'}</span>
        </div>
        <div class="dash-speed-actions">
          <button class="btn primary" id="stBtn" onclick="runSpeedTest()"${speedState.running ? ' disabled' : ''}>
            ${speedState.running ? '测速中 ' + speedState.progPct + '%' : '开始测速'}</button>
        </div>
      </div>
      <div class="tip">数据每 15 秒自动刷新一次；点击顶部指标卡可跳转到对应模块查看详情。</div>`;
    drawVisitChart($('#dashVisitChart'), visitDays);
    // TOP10 名称等宽：两列各自独立测量对齐——网站域名长、地区城市名短，
    // 各按本列最长名称定宽（受 .dash-top-sites / .dash-top-regions 的 max-width 约束），互不牵制
    // （scrollWidth 含被 ellipsis 截断的完整文本宽；超出 max-width 时本列全体一致截断，仍保持对齐）
    $$('.dash-visit-top').forEach(col => {
        const nameEls = Array.from(col.querySelectorAll('.dash-top-name'));
        if (!nameEls.length) return;
        let maxW = 0;
        nameEls.forEach(el => { maxW = Math.max(maxW, el.scrollWidth); });
        nameEls.forEach(el => { el.style.width = maxW + 1 + 'px'; });  // +1 防亚像素取整误差溢出省略号
    });
    setRefresh(renderDashboard, 15000);
}

/**
 * 网络测速：延迟/丢包、下载、上传三个阶段各测 10 秒（延迟阶段还给出抖动 = P95 − P50 往返）。
 * 速率阶段多路并发拉/推流；测量前先短时预热全部并发连接（按时间封顶，小带宽链路不拖总时长），
 * 避免新建连接的握手与 TCP 慢启动计入测量窗口；下载读流放在每连接各自的 Worker 里，
 * 上传优先流式推流（fetch duplex），
 * 让连接全程满载而非整片上传后空等响应往返；测速期间暂停仪表盘自动刷新与顶栏监控轮询，
 * 避免额外请求抢占浏览器同源连接数与服务端 CPU 干扰测量；三阶段按权重计入顶部进度条。
 */
async function runSpeedTest() {
    if (speedState.running) return;
    speedState.running = true;
    const syncBtn = () => {
        const b = document.getElementById('stBtn');
        if (b) {
            b.disabled = speedState.running;
            b.textContent = speedState.running ? '测速中 ' + speedState.progPct + '%' : '开始测速';
        }
    };
    // 驼峰键映射到带连字符的元素 id（pingSub -> st-ping-sub），附属小字不必另写一套取元素逻辑
    const setV = (k, v) => {
        speedState[k] = v;
        const el = document.getElementById('st-' + k.replace(/[A-Z]/g, m => '-' + m.toLowerCase()));
        if (el) el.textContent = v;
    };
    ['ping', 'loss', 'down', 'up', 'jitter'].forEach(k => setV(k, '--'));
    ['pingSub', 'jitterSub', 'downSub'].forEach(k => setV(k, ''));
    syncBtn();
    setRefresh(null);    // 停掉 15 秒整页重绘（其聚合请求会抢连接与 CPU）
    stopSysMetrics();    // 停掉顶栏 5 秒监控轮询

    // ---------- 整体进度 ----------
    // 三个阶段等权（各占 1/3）。阶段内部：预热段按渐近曲线推进且最多只吃掉本阶段 12%
    // ——慢链路下光 6 路预热就能跑几十秒，拿窗口时长去估会把进度顶穿甚至倒挂；
    // 测量段按测量窗口时长线性推进，但封顶在本阶段 97%，留下的 3% 属于
    // “窗口已结束、还在等各路收尾排空/兜底中断”的尾巴（这段真实耗时无法预估）。
    // 进入下一阶段时才把本阶段补满，done 又只增不减：进度条因而单调不回退，
    // 也不会出现“已到 100% 但测速还在跑”。
    const tAll = performance.now();
    const prog = { idx: -1, warm: true, t0: 0, done: 0 };
    const progPaint = () => {
        const pct = Math.round(prog.done * 100);
        speedState.progPct = pct;
        speedState.progIdx = prog.idx;
        const nm = prog.idx < 0 ? '准备中'
            : prog.idx >= SPEED_PHASES.length ? '已完成'
            : SPEED_PHASES[prog.idx] + (prog.warm ? ' · 预热' : ' · 测量');
        speedState.progText = nm + ' · ' + pct + '% · 已用 ' + Math.round((performance.now() - tAll) / 1000) + ' 秒';
        // 测速中途切走页面时这些元素已不在 DOM：只更新缓存，回到总览重绘时据缓存复原
        const bar = document.getElementById('stProgBar');
        if (bar) bar.style.width = pct + '%';
        const txt = document.getElementById('stProgTxt');
        if (txt) txt.textContent = speedState.progText;
        $$('.st-prog-step').forEach((el, i) => {
            el.className = 'st-prog-step' + (i < prog.idx ? ' done' : i === prog.idx ? ' cur' : '');
        });
        syncBtn();
    };
    const progTick = () => {
        if (prog.idx >= 0 && prog.idx < SPEED_PHASES.length) {
            const per = 1 / SPEED_PHASES.length, e = performance.now() - prog.t0;
            const f = prog.idx * per + (prog.warm
                ? per * SPEED_PROG_WARM * (e / (e + 1500))
                : per * (SPEED_PROG_WARM + (1 - SPEED_PROG_WARM) * Math.min(e / SPEED_TEST_MS, 1) * (1 - SPEED_PROG_TAIL)));
            if (f > prog.done) prog.done = Math.min(f, 1);
        }
        progPaint();
    };
    const progEnter = i => { prog.idx = i; prog.warm = true; prog.t0 = performance.now(); progTick(); };
    const progMeasure = () => { prog.warm = false; prog.t0 = performance.now(); progTick(); };
    const progFinish = () => { prog.idx = SPEED_PHASES.length; prog.done = 1; progPaint(); };
    progTick();
    // 500ms 兜底心跳：测量循环里的进度刷新只在该阶段真有数据回传时才跑，
    // 慢链路下可能几秒才一块，进度条不能跟着停住
    const progTimer = setInterval(progTick, 500);
    let seq = 0, lastUi = 0;
    const tick = () => { // 高频回包按 200ms 节流刷新，避免 DOM 写入拖慢测量本身
        const t = performance.now();
        if (t - lastUi < 200) return false;
        lastUi = t;
        return true;
    };
    const rate = (bytes, since) => fmtMbps(bytes / ((performance.now() - since) / 1000));
    try {
        // 1) 延迟与丢包：小载荷连续往返，5 秒未回计一次丢失
        const probe = async () => {
            const t0 = performance.now();
            const ctrl = new AbortController();
            const timer = setTimeout(() => ctrl.abort(), 5000);
            try {
                const r = await fetch(API_BASE + '/api/system/speedtest/ping?n=' + Date.now() + '_' + (++seq),
                    { headers: { 'X-Token': TOKEN }, cache: 'no-store', signal: ctrl.signal });
                clearTimeout(timer);
                if (!r.ok) throw new Error('HTTP ' + r.status);
                await r.arrayBuffer();
                return performance.now() - t0;
            } catch (e) {
                clearTimeout(timer);
                return null;
            }
        };
        // 预热两次不计入：首请求含连接建立/TLS 握手与冷启动路径，会显著抬高结果
        progEnter(0);
        await probe();
        await probe();
        // 取中位数而非平均值：少量尖峰（NAS 掉频/GC/Docker 抖动）会把均值大幅拉高，
        // 中位数才代表链路的典型往返（LibreSpeed 等也只报低分位/最小值）
        // 抖动取“P95 − P50”（即 ITU-T G.114 的网络性抖动 ipdv，主流测速站同算法）：
        // 中位数掩盖链路稳定性，往返散布才反映网页卡顿体感（无线中继信号抖动、NAS 掉频、
        // GC 停顿都先在这里现形）；而“最高 − 最低”会把一次偶然毛刺直接算进结果——
        // 单个 1 秒尖峰就能把抖动报成 1000ms，与链路典型质量无关。分位法放过最极端的 5%，
        // 在小带宽/高延迟链路上也更有可比性（下面小字仍给出最低~最高全区间，便于对照离群值）
        const samples = [];
        let lost = 0;
        // 分位取样：排序后按比例取位置（样本极少时自然退化为最值，仍是有效估计）
        const quant = (a, p) => a[Math.min(a.length - 1, Math.floor(p * a.length))];
        const stat = () => {
            if (!samples.length) return null;
            const a = samples.slice().sort((x, y) => x - y);
            const p50 = quant(a, 0.5), p95 = quant(a, 0.95);
            return { med: p50, lo: a[0], hi: a[a.length - 1], jit: p95 - p50 };
        };
        const showPing = s => {
            setV('ping', Math.round(s.med) + ' ms');
            setV('pingSub', '最低 ' + Math.round(s.lo) + ' · 最高 ' + Math.round(s.hi) + ' ms');
            setV('jitter', Math.round(s.jit) + ' ms');
            // 样本不足时标一句“偏少”：二几个样本里的 P95 基本就是最大值，这一轮的抖动
            // 只能当“单次毛刺幅度”看，不能与样本几百的局域网那轮拉同一把尺子
            setV('jitterSub', 'P95−P50 · 样本 ' + samples.length
                + (samples.length < SPEED_PING_MIN_SAMPLES ? '（偏少）' : '')
                + (lost ? ' · 丢失 ' + lost : ''));
        };
        progMeasure();
        const tP = performance.now();
        // 至少测满 10 秒；样本不够且未到上限则接着探（高延迟链路下保证抖动的样本量）
        for (;;) {
            const e = performance.now() - tP;
            if (e >= SPEED_PING_MAX_MS || (e >= SPEED_TEST_MS && samples.length >= SPEED_PING_MIN_SAMPLES)) break;
            const dt = await probe();
            if (dt === null) lost++;
            else samples.push(dt);
            if (tick()) {
                const s = stat();
                if (s) showPing(s);
                setV('loss', Math.round(lost * 100 / (samples.length + lost)) + ' %');
            }
            await new Promise(r => setTimeout(r, 10)); // 小间隙：避免连续自压抬高 RTT，又不至于让 CPU 掉频
        }
        const sp = stat();
        if (sp) showPing(sp);
        else { setV('ping', '失败'); setV('jitter', '失败'); }
        setV('loss', Math.round(lost * 100 / (samples.length + lost)) + ' %');

        // 2) 下载速率：先预热全部并发连接（延迟阶段只用过 1 条连接，其余 5 条的
        //    TLS 建连与慢启动开销不应计入测量窗口），再计时多路并发拉流。
        //    测量窗口由浏览器控制：到点统一中断请求，服务端写出时踩到断连即静默收尾。
        //    切勿改成让服务端“按时长跑完再收尾”——远程访问时服务端与浏览器之间隔着反向代理
        //    与大内核缓冲，写出不会被真实链路背压阻塞：服务端几百毫秒就灌完几 MB，
        //    浏览器还要按链路速率慢慢收几十秒，测速既不结束、算出的速率还严重偏低。
        const DOWN_URL = API_BASE + '/api/system/speedtest/down';
        progEnter(1);
        try {
            // 预热：每路只拉定长小块（?bytes= 走 Content-Length 精确收尾），跑通握手与慢启动即止。
            // 预热必须按时间封顶：小带宽链路（1~2Mbps）下 6 路各拉几百 KB 要十几秒，
            // 不封顶的话预热会把整轮测速拖成分钟级并一直卡在进度条的“预热”段；
            // 到点就中断，连接能跑通多少算多少，正式窗口照样按时开始。
            const warm = new AbortController();
            const warmGuard = setTimeout(() => warm.abort(), 4000);
            try {
                await Promise.all(Array.from({ length: SPEED_STREAMS }, () =>
                    fetch(DOWN_URL + '?bytes=' + (128 * 1024),
                        { headers: { 'X-Token': TOKEN }, cache: 'no-store', signal: warm.signal })
                        .then(async r => {
                            if (!r.ok) throw new Error('下载测速请求失败: HTTP ' + r.status);
                            await r.arrayBuffer();
                        })));
            } finally {
                clearTimeout(warmGuard);
            }
        } catch (e) {
            if (e.name !== 'AbortError') throw e;
        }
        // ms 只是服务端单请求最长存活时间的兜底，取得比窗口长一些，确保正常收尾由浏览器中断触发
        const downUrl = DOWN_URL + '?ms=' + (SPEED_TEST_MS + 5000);
        let got = 0;
        progMeasure();
        const tD = performance.now();
        const paintDown = () => { if (tick()) setV('down', rate(got, tD)); };
        // 首选：每连接一个 Worker 读流并在线程内计数（见 DOWN_WORKER_SRC 说明）
        let downPartial = '';
        const downWorkers = async () => {
            const ws = [];
            let objUrl = '';
            try {
                objUrl = URL.createObjectURL(new Blob([DOWN_WORKER_SRC], { type: 'text/javascript' }));
                for (let i = 0; i < SPEED_STREAMS; i++) ws.push(new Worker(objUrl));
            } catch (e) {
                // 环境不支持（file:// 打开、blob: 脚本被 CSP 拦住、老浏览器）：回退主线程读流
                ws.forEach(w => w.terminate());
                if (objUrl) URL.revokeObjectURL(objUrl);
                return null;
            }
            // 必须传绝对地址：Worker 脚本由 blob: 创建，没有文档基址，根路径访问时 API_BASE 为空串，
            // 形如 /api/... 的相对地址在 Worker 里直接 “Failed to parse URL” 全部失败，
            // 于是静默回退主线程读流，千兆链路的下载仍被主线程卡住（上下行悬殊依旧）
            const workerUrl = new URL(downUrl, location.href).href;
            try {
                const per = new Array(ws.length).fill(0);
                let err = '';
                const settled = ws.map((w, i) => new Promise(resolve => {
                    w.onmessage = ev => {
                        const d = ev.data || {};
                        per[i] = d.b || 0;
                        if (d.t === 'e' && !err) err = d.m || '读取失败';
                        got = per.reduce((a, b) => a + b, 0);
                        paintDown();
                        if (d.t === 'd') resolve(); // 本路已结束（中断生效且流关闭）
                    };
                }));
                ws.forEach(w => w.postMessage({
                    cmd: 'start', url: workerUrl, token: TOKEN,
                    iv: 200,                          // 每路 200ms 报一次累计值，供实时速率显示
                    hardMs: SPEED_TEST_MS + 15000     // 链路彻底卡死也要收场
                }));
                const downStop = setTimeout(() => ws.forEach(w => w.postMessage({ cmd: 'stop' })), SPEED_TEST_MS);
                await Promise.all(settled);
                clearTimeout(downStop);
                if (err && !got) throw new Error('下载测速请求失败: ' + err);
                // 某路中途失败/未收到数据时，各路字节之和不再代表链路能力（只是下限）：
                // 与其悄悄给出一个偏低的数字，不如在卡片小字里标出有效路数
                const alive = per.filter(b => b > 0).length;
                if (alive < ws.length) downPartial = '仅 ' + alive + '/' + ws.length + ' 路有数据（结果偏低）';
                return got;
            } finally {
                ws.forEach(w => w.terminate());   // 不终止会跨轮累积线程，下一轮测速连接数与 CPU 都被干扰
                URL.revokeObjectURL(objUrl);
            }
        };
        // 回退：主线程读流，语义与 Worker 版一致（到点统一中断，服务端踩到断连即静默收尾）
        const downMain = async () => {
            const downAbort = new AbortController();
            const downStop = setTimeout(() => downAbort.abort(), SPEED_TEST_MS);          // 窗口到点：中断即测完
            const downGuard = setTimeout(() => downAbort.abort(), SPEED_TEST_MS + 15000); // 链路彻底卡死也要收场
            const pull = async () => {
                try {
                    const resp = await fetch(downUrl,
                        { headers: { 'X-Token': TOKEN }, cache: 'no-store', signal: downAbort.signal });
                    if (!resp.ok) throw new Error('下载测速请求失败: HTTP ' + resp.status);
                    const reader = resp.body.getReader();
                    for (;;) {
                        const { done, value } = await reader.read();
                        if (done) break;
                        got += value.length;
                        paintDown();
                    }
                } catch (e) {
                    if (e.name === 'AbortError') return; // 窗口到点中断：正常收尾，不是失败
                    throw e;
                }
            };
            try {
                await Promise.all(Array.from({ length: SPEED_STREAMS }, pull));
            } finally {
                clearTimeout(downStop);
                clearTimeout(downGuard);
            }
            return got;
        };
        if ((await downWorkers().catch(() => null)) === null) await downMain();
        if (!got) throw new Error('下载测速未收到数据');
        if (downPartial) setV('downSub', downPartial);
        // 下载阶段的带宽（字节/秒）作为上传阶段分片与入块的种子：先量一下链路再推流，
        // 比从固定 128KB 逐轮往上爬更快（本地万兆链路要爬好几轮才能到顶，而慢速上行并不需要从128KB 再往上走）
        const downBps = got / Math.max((performance.now() - tD) / 1000, 0.2);
        setV('down', rate(got, tD));

        // 3) 上传速率：https 页面优先流式推流（fetch + duplex:'half'）——整条连接 10 秒连续满载。
        //    旧“整片 POST 等响应再发下一片”的模式，每片之间连接空转一个往返周期，
        //    千兆链路实测只能压出约 1/3 带宽；流式模式由浏览器按网络节奏回调 pull 入块
        //    （默认高水位 1 块，天然背压，推流节奏即网络真实吞吐节奏），到时 close() 结束，
        //    服务端读到 EOF 返回实收字节数作为权威计量。
        //    注意：浏览器的流式请求体只在 HTTP/2、HTTP/3 上可用，而这两种协议只跑在 TLS
        //    之上——明文 http:// 页面里发流式 POST，浏览器会对同端口发起 TLS/h2 协商，
        //    失败即整路 "Failed to fetch"（net::ERR_ALPN_NEGOTIATION_FAILED）。
        //    因此 http:// 下走自适应定长分片 POST；https 下若流式实际不可用
        //    （如服务端未启用 h2）同样降级到分片模式。
        const UP_URL = API_BASE + '/api/system/speedtest/up';
        progEnter(2); // 负载池生成（8MB 随机器）也算本阶段开销，先进预热段顶着
        const UP_POOL = 8 * 1024 * 1024;
        // 单片上限 32MB：10Gbps 链路下 8MB 一片只要 6ms，每片的请求建立、响应解析与主线程收尾
        // 会反复插在数据流里，速率既上不去也稳不住（同一链路用 Node 六路 8MB 片只跑到 11Gbps）。
        // 上限放大不会拖慢链：慢链路下分片由下面的“约 2 秒一片”自适应缩到几百 KB，碰不到上限。
        const UP_CHUNK_MAX = 32 * 1024 * 1024;
        // 流式入块取约 50ms 的链路量（按刚测出的下载带宽折算），夹在 64KB~1MB：
        // 块太小则每块一次 JS 入块回调，快链路被这个开销卡住；块太大则窗口结束时
        // 每路还压着一整块待排空（2Mbps 链路上 1MB 块就是 4 秒尾巴），慢链路反而被尾巴拖死
        const UP_BLOCK = stClamp(Math.round(downBps * 0.05) || 256 * 1024, 64 * 1024, 1024 * 1024);
        // 高熵负载池：随机数据不可压缩，只生成一次（慢设备上生成几十 MB 随机数本身就要几百毫秒）
        const upPool = new Uint8Array(UP_POOL); // getRandomValues 单次上限 65536 字节，需分片填充
        for (let off = 0; off < UP_POOL; off += 65536) {
            crypto.getRandomValues(upPool.subarray(off, off + 65536));
        }
        const upBlock = upPool.subarray(0, UP_BLOCK);
        // 分片体一律包成 Blob（哪怕只有一个片段）：本机六路实测，同一份 8MiB 数据做成视图体
        // 一片要 7 秒（54Mbps），包成 Blob 只要 39ms（1709Mbps）；1MiB 分片同样是
        // 视图 87Mbps 对 Blob 1320Mbps —— 与分片大小无关，只与体类型有关。
        // 因为 ArrayBuffer/TypedArray 请求体需由渲染进程主线程逐块投递给网络层（多路并发时
        // 每块都要等事件循环），而 Blob 请求体由浏览器侧直接从 blob 数据流读，不占主线程。
        // 旧实现只在分片超过负载池（8MB）时才用 Blob，慢启动阶段那些几 MB 的视图体会把
        // 分片尺寸“爬级”拖成十几秒一轮：放大因子被慢片压到 1 以下，整轮上传速率因此偏低。
        // 用 Blob 拼接同一份高熵池：不额外生成随机数，六路共享同一个不变对象。
        // 同一尺寸的分片体复用同一个 Blob：new Blob([...]) 会把数据整份复制进 blob 存储，
        // 每片都新建会在并发下明显拖速（本机六路实测：纯复用同一 Blob 2.7~2.9Gbps，
        // 每片新建 1.5~2.0Gbps）；自适应分片稳定后尺寸不再变，一项缓存即可覆盖窗口的
        // 主要部分，又不像预先拼好 32MB 那样在小带宽链路上白占内存
        let upBodySize = 0, upBodyBlob = null;
        const upBody = size => {
            if (size !== upBodySize || !upBodyBlob) {
                const parts = [];
                for (let left = size; left > 0; left -= UP_POOL) parts.push(upPool.subarray(0, Math.min(UP_POOL, left)));
                upBodySize = size;
                upBodyBlob = new Blob(parts);
            }
            return upBodyBlob;
        };
        // 流式上传能力探测：除浏览器需支持 duplex 外，还要求页面本身是 https——
        // 不满足时直接走定长分片，避免流式请求在明文端口上触发注定失败的 TLS 协商；
        // 不支持流式请求体的浏览器 Request 构造器会直接抛 TypeError
        const canStreamUp = location.protocol === 'https:' && (() => {
            try { new Request('', { method: 'POST', body: new ReadableStream(), duplex: 'half' }); return true; }
            catch (e) { return false; }
        })();
        // 每个阶段独立的 AbortController + 兜底超时：既防单路卡死把测速永久挂起，
        // 也避免兜底中止后复用同一个已 abort 的 signal 让降级路径注定失败（旧实现的真实缺陷）
        const phaseRun = async (limitMs, fn) => {
            const ctrl = new AbortController();
            const guard = setTimeout(() => ctrl.abort(), limitMs);
            try { return await fn(ctrl.signal); } finally { clearTimeout(guard); }
        };
        let sent = 0;
        let tU = performance.now();
        const streamUp = (ms, signal) => { // 单路流式推流 ms 毫秒，返回该路服务端实收字节数
            const end = performance.now() + ms;
            return fetch(UP_URL, {
                method: 'POST',
                headers: { 'X-Token': TOKEN, 'Content-Type': 'application/octet-stream' },
                body: new ReadableStream({
                    pull(controller) {
                        if (performance.now() >= end) controller.close();
                        else {
                            controller.enqueue(upBlock);
                            sent += UP_BLOCK;
                            if (tick()) setV('up', rate(sent, tU));
                        }
                    }
                }),
                duplex: 'half',
                signal
            }).then(async r => {
                if (!r.ok) throw new Error('上传测速请求失败: HTTP ' + r.status);
                const j = await r.json();
                return (j.data && j.data.bytes) || 0;
            });
        };
        // 流式轮：先预热再正式测量，各自独立兜底（预热卡死不致命，不能把正式窗口一起带走）
        const streamRound = async () => {
            // 预热：下载阶段的连接对发送方向未经考验，先让全部连接度过 TCP 慢启动（不计入测量）；
            // 兜底按时间封顶，小带宽链路上六路各推几百 KB 就能跑十几秒，不能把整轮测速拖长
            await phaseRun(8000, s =>
                Promise.all(Array.from({ length: SPEED_STREAMS }, () => streamUp(600, s)))).catch(() => { });
            progMeasure();
            sent = 0;
            tU = performance.now();
            // 窗口外再留 15 秒排空尾巴：每路 close() 时最多还压着一块待发送
            const ups = await phaseRun(SPEED_TEST_MS + 15000, s =>
                Promise.all(Array.from({ length: SPEED_STREAMS }, () => streamUp(SPEED_TEST_MS, s))));
            const upTotal = ups.reduce((a, b) => a + b, 0);
            if (!upTotal) throw new Error('上传测速未发出数据');
            setV('up', rate(upTotal, tU));
        };
        // 定长分片轮：http:// 下的唯一上传通道，也是 https 下流式不可用时的降级路径。
        // 分片大小自适应到约 2 秒一片：固定大分片在慢速上行（远程/4G）下单片要跑几十秒，
        // 窗口结束后还得干等它跑完，这正是“测速一分多钟不结束”的另一个来源。
        // 首片取 128KB：慢链路下首片也能几秒内跑完，自适应立即收敛，而不是六路各自卡在首片。
        const chunkRound = async () => {
            const tC = performance.now();
            progMeasure(); // 分片轮无独立预热（首片兼任），直接从测量段起算
            // 首片大小由下载阶段的带宽与中位往返算带宽延迟积（每路一片刚好填满约一个往返）：
            // 千兆/万兆本地链路因此第一步就落到 MB 级，不必从 128KB 一轮轮往上爬——
            // 爬级期间的低速率会把整轮平均拉低，同一链路两次上传跑出数倍差距主要就源于此；
            // 小带宽链路算出来仍是最小 128KB，行为与原来一致（上行不对称时由 2 秒目标修正）
            const rttMs = sp ? sp.med : 30;
            const seed = stClamp(Math.round(downBps * rttMs / 1000 / SPEED_STREAMS), 128 * 1024, UP_CHUNK_MAX);
            let total = 0, size = seed;
            try {
                await phaseRun(SPEED_TEST_MS + 30000, async signal => {
                    const push = async () => {
                        try {
                            while (performance.now() - tC < SPEED_TEST_MS) {
                                const body = upBody(size);
                                const t0 = performance.now();
                                const r = await fetch(UP_URL, {
                                    method: 'POST',
                                    headers: { 'X-Token': TOKEN, 'Content-Type': 'application/octet-stream' },
                                    body,
                                    signal
                                });
                                if (!r.ok) throw new Error('上传测速请求失败: HTTP ' + r.status);
                                const j = await r.json();
                                total += (j.data && j.data.bytes) || size;
                                // 用这一片的实际耗时把下一片缩放到约 2 秒，单轮最多放缩 4 倍：
                                // 不限步长时快链路上首几片就能顶到上限，窗口结束后还得等它跑完
                                const dt = Math.max(performance.now() - t0, 50);
                                size = stClamp(Math.round(size * stClamp(2000 / dt, 0.25, 4)), 128 * 1024, UP_CHUNK_MAX);
                                if (tick()) setV('up', rate(total, tC));
                            }
                        } catch (e) {
                            // 单路异常（链路抖动、服务端兜底断开）：该路收工即可，
                            // 已有其他路确认的计量就不该把整个测速报成失败
                            if (e.name === 'AbortError' || !total) throw e;
                        }
                    };
                    await Promise.all(Array.from({ length: SPEED_STREAMS }, push));
                });
            } catch (e) {
                // 兜底超时打断：慢链路上最后一片可能还在路上拿不到服务端确认，
                // 但已确认的字节数仍是有效测量结果，不能因此把整个测速报成失败
                if (e.name !== 'AbortError' || !total) throw e;
            }
            if (!total) throw new Error('上传测速未发出数据');
            setV('up', rate(total, tC));
        };
        if (canStreamUp) {
            try {
                await streamRound();
            } catch (se) {
                // 流式实际不可用（如 https 站点未启用 HTTP/2）或彻底卡死：降级为定长分片重测
                setV('up', '--');
                await chunkRound();
            }
        } else {
            await chunkRound();
        }
        progFinish();
        toast('测速完成');
    } catch (e) {
        toast('测速失败: ' + e.message, 'err');
    } finally {
        clearInterval(progTimer);
        speedState.running = false;
        // 仍处于已登录的主视图才恢复轮询与重绘（测速中途退出登录时不应把请求重新拉起）
        if (!$('#mainView').classList.contains('hidden')) {
            startSysMetrics();
            if (currentPage === 'dashboard') {
                // 测速耗时 30 秒且期间未刷新，回到总览重绘各面板并恢复自动刷新（按钮状态由模板按 running 渲染）
                renderDashboard().catch(() => { });
            } else {
                syncBtn(); // 已切走页面：仅同步按钮状态，不覆盖当前页内容
            }
        }
    }
}
