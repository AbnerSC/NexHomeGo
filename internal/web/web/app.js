/* ============ NexHome 前端逻辑（原生 JS，无框架） ============ */
/* 主入口：通用工具、登录鉴权、页面路由。
   各菜单模块的逻辑拆分到 js/ 目录（须在 index.html 中先于本文件加载）：
   dashboard=仪表盘 home=网站导航 ddns=DDNS stun=STUN monitor=可用性监控 notify=通知中心
   wol=WOL cert=SSL证书 proxy=反向代理 docker=Docker logs=日志 diag=内存诊断 settings=设置 */
'use strict';

const $ = s => document.querySelector(s);
const $$ = s => document.querySelectorAll(s);

let TOKEN = localStorage.getItem('nx_token') || '';
/** API 基础前缀：启用安全入口后面板挂在 /{入口} 下，所有模块请求需带上该前缀（根路径访问时为空串） */
const API_BASE = (() => {
    const p = location.pathname.replace(/\/+$/, '');
    return p.length > 1 ? p : '';
})();
let currentPage = 'dashboard';
let refreshTimer = null;          // 状态实时刷新定时器

/* ---------------- 基础工具 ---------------- */

function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function toast(msg, type = 'ok') {
    const t = $('#toast');
    t.textContent = msg;
    t.className = 'toast ' + type;
    setTimeout(() => t.classList.add('hidden'), 2600);
}

/** 统一 API 调用：携带 token，统一错误处理 */
async function api(method, path, body) {
    const opt = { method, headers: { 'X-Token': TOKEN } };
    if (body !== undefined) {
        opt.headers['Content-Type'] = 'application/json';
        opt.body = JSON.stringify(body);
    }
    const resp = await fetch(API_BASE + path, opt);
    let data = {};
    try { data = await resp.json(); } catch (e) { /* 非 JSON 响应 */ }
    if (resp.status === 401 && !path.endsWith('/login') && !path.endsWith('/check')) {
        TOKEN = '';
        localStorage.removeItem('nx_token');
        showLogin();
        throw new Error('登录已过期，请重新登录');
    }
    if (!data.ok) throw new Error(data.error || ('请求失败 ' + resp.status));
    return data.data;
}

/** 模态框栈：嵌套打开新模态框时保存上一层的标题/内容/宽度类，关闭时逐层回退 */
const modalStack = [];

/**
 * 打开模态框；若当前已有模态框打开则自动入栈，关闭时回退到上一层
 * （如从 Compose 项目容器列表下钻容器详情，关闭详情后回到项目列表）。
 * @param {string} cls 可选宽度样式类，如 'wide'
 */
function modal(title, bodyHtml, cls) {
    const mask = $('#modalMask');
    if (mask.classList.contains('hidden')) modalStack.length = 0;
    else modalStack.push({
        title: $('#modalTitle').textContent,
        body: $('#modalBody').innerHTML,
        cls: $('#modalBox').className.replace('modal', '').trim()
    });
    $('#modalTitle').textContent = title;
    $('#modalBody').innerHTML = bodyHtml;
    $('#modalBox').className = 'modal' + (cls ? ' ' + cls : '');
    mask.classList.remove('hidden');
}

function closeModal() {
    if (modalStack.length) {
        const prev = modalStack.pop();
        $('#modalTitle').textContent = prev.title;
        $('#modalBody').innerHTML = prev.body;
        $('#modalBox').className = 'modal' + (prev.cls ? ' ' + prev.cls : '');
        return;
    }
    $('#modalMask').classList.add('hidden');
}

/**
 * 全局确认弹窗，替代原生 confirm，风格与主题一致。
 * 后续所有需要“确定/取消”交互的场景都应使用本方法。
 * @param {string|Object} opts 传字符串时视为提示内容；或配置对象
 *   { title, message, html, confirmText, cancelText, danger, boxWidth }
 *   html：传入时以富文本渲染确认内容（如镜像预览表），优先级高于 message；
 *   boxWidth：需要展示表格等宽内容时放宽弹窗宽度（如 '560px'）。
 * @returns {Promise<boolean>} 点击确认或按 Enter 返回 true；点击取消或按 Esc 返回 false（点击遮罩不关闭）
 * 用法：if (!(await confirmBox({ message: '确定删除？', danger: true }))) return;
 */
function confirmBox(opts) {
    if (typeof opts === 'string') opts = { message: opts };
    const {
        title = '操作确认',
        message = '',
        html = '',
        confirmText = '确定',
        cancelText = '取消',
        danger = false,
        boxWidth = '',
    } = opts;

    const mask = $('#confirmMask');
    const box = mask.querySelector('.confirm-box');
    const okBtn = $('#confirmOk');
    const cancelBtn = $('#confirmCancel');

    $('#confirmTitle').textContent = title;
    if (html) $('#confirmMsg').innerHTML = html;
    else $('#confirmMsg').textContent = message;
    $('#confirmIcon').textContent = danger ? '⚠️' : '❔';
    okBtn.textContent = confirmText;
    cancelBtn.textContent = cancelText;
    box.classList.toggle('danger', danger);
    box.style.width = boxWidth || '';

    mask.classList.remove('hidden');
    okBtn.focus();

    return new Promise(resolve => {
        const done = result => {
            mask.classList.add('hidden');
            okBtn.removeEventListener('click', onOk);
            cancelBtn.removeEventListener('click', onCancel);
            mask.removeEventListener('mousedown', onMask);
            document.removeEventListener('keydown', onKey, true);
            resolve(result);
        };
        const onOk = () => done(true);
        const onCancel = () => done(false);
        const onMask = () => {}; // 不再点击遮罩关闭，需主动点击按钮
        const onKey = e => {
            if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); done(false); }
            else if (e.key === 'Enter') { e.preventDefault(); e.stopPropagation(); done(true); }
        };
        okBtn.addEventListener('click', onOk);
        cancelBtn.addEventListener('click', onCancel);
        mask.addEventListener('mousedown', onMask);
        document.addEventListener('keydown', onKey, true);
    });
}

function badge(text, cls) { return `<span class="badge ${cls}">${esc(text)}</span>`; }

function statusBadge(status) {
    if (!status) return badge('-', 'gray');
    if (status.startsWith('SUCCESS') || status === 'RUNNING' || status === 'ISSUED') return badge(status, 'ok');
    if (status.startsWith('FAIL') || status === 'ERROR' || status === 'STOPPED') return badge(status, 'err');
    return badge(status, 'warn');
}

function setRefresh(fn, ms) {
    if (refreshTimer) clearInterval(refreshTimer);
    refreshTimer = null;
    if (fn) refreshTimer = setInterval(() => fn().catch(() => { }), ms);
}

/* ---------------- 登录鉴权 ---------------- */

async function checkLogin() {
    try {
        const r = await api('GET', '/api/auth/check');
        if (r.loggedIn) enterApp(); else showLogin();
    } catch (e) { showLogin(); }
}

function showLogin() {
    $('#mainView').classList.add('hidden');
    $('#loginView').classList.remove('hidden');
    stopSysMetrics();
}

async function enterApp() {
    $('#loginView').classList.add('hidden');
    $('#mainView').classList.remove('hidden');
    setPage('dashboard');
    loadSysInfo();
    startSysMetrics();
}

$('#loginForm').addEventListener('submit', async e => {
    e.preventDefault();
    try {
        const r = await api('POST', '/api/auth/login', { password: $('#loginPwd').value });
        TOKEN = r.token;
        localStorage.setItem('nx_token', TOKEN);
        $('#loginPwd').value = '';
        enterApp();
    } catch (err) { toast(err.message, 'err'); }
});

$('#btnLogout').addEventListener('click', async () => {
    try { await api('POST', '/api/auth/logout'); } catch (e) { /* ignore */ }
    TOKEN = '';
    localStorage.removeItem('nx_token');
    showLogin();
});

$('#modalClose').addEventListener('click', closeModal);

async function loadSysInfo() {
    try {
        const i = await api('GET', '/api/system/info');
        $('#sysInfo').textContent = `v${i.version} · ${i.javaVersion}`;
    } catch (e) { /* ignore */ }
}

/* ---------------- 顶栏系统监控（CPU / 内存 / 虚拟内存） ---------------- */

let metricsTimer = null;      // 独立定时器：不受页面切换 setRefresh 影响

/** MB -> 人类可读（≥1GB 显示一位小数 GB，否则取整 MB） */
function fmtMB(mb) {
    return mb >= 1024 ? (mb / 1024).toFixed(1) + ' GB' : Math.round(mb) + ' MB';
}

/** 负载着色：≥85% 红、≥60% 橙、其余默认蓝 */
function loadClass(p) { return p >= 85 ? 'err' : p >= 60 ? 'warn' : ''; }

async function loadSysMetrics() {
    try {
        const m = await api('GET', '/api/system/metrics');
        const memPct = m.memTotalMB > 0 ? Math.round(m.memUsedMB * 100 / m.memTotalMB) : 0;
        const swapPct = m.swapTotalMB > 0 ? Math.round(m.swapUsedMB * 100 / m.swapTotalMB) : 0;
        const cpuTxt = m.cpuLoad >= 0 ? m.cpuLoad + '%' : '--';
        const cpuBar = m.cpuLoad >= 0 ? m.cpuLoad : 0;
        $('#sysMetrics').innerHTML = `
            <div class="metric" title="CPU 使用率 ${cpuTxt}，共 ${m.cores} 核">
                <span class="metric-icon">⚙️</span>
                <span class="metric-name">CPU</span>
                <span class="metric-value">${cpuTxt}</span>
                <span class="metric-bar ${loadClass(m.cpuLoad)}"><i style="width:${cpuBar}%"></i></span>
                <span class="metric-sub">${m.cores} 核</span>
            </div>
            <div class="metric" title="内存：${fmtMB(m.memUsedMB)} / ${fmtMB(m.memTotalMB)}（使用率 ${memPct}%）">
                <span class="metric-icon">🧠</span>
                <span class="metric-name">内存</span>
                <span class="metric-value">${memPct}%</span>
                <span class="metric-bar ${loadClass(memPct)}"><i style="width:${memPct}%"></i></span>
                <span class="metric-sub">${fmtMB(m.memUsedMB)}/${fmtMB(m.memTotalMB)}</span>
            </div>
            <div class="metric" title="${m.swapTotalMB > 0
                ? `虚拟内存：${fmtMB(m.swapUsedMB)} / ${fmtMB(m.swapTotalMB)}（使用率 ${swapPct}%）`
                : '系统未启用虚拟内存（Swap）'}">
                <span class="metric-icon">💾</span>
                <span class="metric-name">虚拟内存</span>
                ${m.swapTotalMB > 0 ? `
                <span class="metric-value">${swapPct}%</span>
                <span class="metric-bar ${loadClass(swapPct)}"><i style="width:${swapPct}%"></i></span>
                <span class="metric-sub">${fmtMB(m.swapUsedMB)}/${fmtMB(m.swapTotalMB)}</span>`
                : '<span class="metric-sub">未启用</span>'}
            </div>`;
    } catch (e) { /* 静默失败，不影响主功能 */ }
}

/** 启动顶栏系统监控：立即加载一次，之后每 5 秒刷新 */
function startSysMetrics() {
    loadSysMetrics();
    if (!metricsTimer) metricsTimer = setInterval(loadSysMetrics, 5000);
}

function stopSysMetrics() {
    if (metricsTimer) { clearInterval(metricsTimer); metricsTimer = null; }
}

/* ---------------- 页面路由 ---------------- */

const PAGE_TITLES = {
    dashboard: '总览', home: '网站导航', ddns: 'DDNS 域名同步', stun: 'STUN 端口穿透',
    monitor: '可用性监控', notify: '通知中心',
    wol: 'WOL 网络唤醒', cert: 'SSL 证书管理', proxy: '反向代理中心', docker: 'Docker 容器', logs: '操作日志', diag: '内存诊断', settings: '系统设置'
};

const RENDER = {
    dashboard: renderDashboard, home: renderHome, ddns: renderDdns, stun: renderStun,
    monitor: renderMonitor, notify: renderNotify,
    wol: renderWol, cert: renderCert, proxy: renderProxy, docker: renderDocker, logs: renderLogs, diag: renderDiag, settings: renderSettings
};

function setPage(page) {
    currentPage = page;
    setRefresh(null);
    $$('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.page === page));
    $('#pageTitle').textContent = PAGE_TITLES[page];
    $('#pageBody').innerHTML = '<p class="muted">加载中...</p>';
    RENDER[page]().catch(e => { $('#pageBody').innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; });
}

$$('.nav-item').forEach(n => n.addEventListener('click', () => setPage(n.dataset.page)));

/* ---------------- 启动 ---------------- */
checkLogin();
