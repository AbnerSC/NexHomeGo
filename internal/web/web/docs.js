/* ======================================================================
   NexHome 使用文档页交互脚本（纯前端，不发送任何 API 请求）
   职责：
     1. 依据正文结构（section.doc-sec > h2 / details.doc-sub-sec > summary h3）
        自动生成左侧两级目录，并为每个小节补生锚点 id；
     2. 关键词搜索：隐藏未命中章节 + 正文命中处高亮，回车跳至首个命中；
     3. 全部展开 / 收起；打印前自动清空搜索并展开全部，打印后还原；
     4. 滚动定位：当前章/节高亮、自动展开所在章节目录、顶栏面包屑同步；
     5. 窄屏目录抽屉（☰ + 遮罩）。
   依赖 docs.css 中的类名：.toc-l1 / .toc-l2-wrap(.open) / .toc-l2 / .on /
   .dim / .hidden / .doc-mask(.show) / .toc-empty / mark.hit
   ====================================================================== */
'use strict';

(function () {
    const $ = (sel, root) => (root || document).querySelector(sel);
    const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

    const tocEl = $('#docToc');
    const searchEl = $('#docSearch');
    const crumbEl = $('#docCrumb');
    const sideEl = $('#docSide');
    const article = $('.doc-article');
    if (!tocEl || !article) return;

    // sticky 顶栏高度 + 余量：滚动定位判定基准线
    const TOP_LINE = 70;

    const esc = s => String(s == null ? '' : s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const textOf = el => (el && el.textContent ? el.textContent : '').replace(/\s+/g, ' ').trim();
    const docTop = el => el.getBoundingClientRect().top + window.scrollY;

    /* ---------------- 1. 生成两级目录 ---------------- */
    const toc = [];

    $$('section.doc-sec').forEach(sec => {
        const title = textOf($('h2', sec)) || sec.id;
        const l1 = document.createElement('a');
        l1.className = 'toc-l1';
        l1.href = '#' + sec.id;
        l1.textContent = title;

        const wrap = document.createElement('div');
        wrap.className = 'toc-l2-wrap';

        const entry = { sec, title, l1, wrap, subs: [] };

        $$('details.doc-sub-sec', sec).forEach((d, di) => {
            if (!d.id) d.id = sec.id + '-s' + (di + 1);
            const st = textOf($('summary h3', d)) || (di + 1) + '. 未命名小节';
            const l2 = document.createElement('a');
            l2.className = 'toc-l2';
            l2.href = '#' + d.id;
            l2.textContent = st;
            // 点小节目录：先展开再跳转，避免锚点落在折叠标题上；窄屏同时收起抽屉
            l2.addEventListener('click', () => { d.open = true; syncExpandBtn(); closeDrawer(); });
            wrap.appendChild(l2);
            entry.subs.push({ node: d, l2, title: st, body: textOf(d) });
        });

        // 点章目录：展开本章全部小节（正文里指向 #sec-xxx 的交叉链接同理）
        l1.addEventListener('click', () => {
            entry.subs.forEach(s => { s.node.open = true; });
            wrap.classList.add('open');
            syncExpandBtn();
            closeDrawer();
        });
        $$('a[href^="#sec-"]', article).forEach(a => a.addEventListener('click', () => {
            const t = document.getElementById(a.getAttribute('href').slice(1));
            if (t && t.matches('section.doc-sec')) $$('details.doc-sub-sec', t).forEach(d => { d.open = true; });
            syncExpandBtn();
        }));

        tocEl.appendChild(l1);
        tocEl.appendChild(wrap);
        toc.push(entry);
    });

    /* ---------------- 2. 移动端目录抽屉 ---------------- */
    const mask = document.createElement('div');
    mask.className = 'doc-mask';
    document.body.appendChild(mask);

    function openDrawer() { sideEl.classList.add('show'); mask.classList.add('show'); }
    function closeDrawer() { sideEl.classList.remove('show'); mask.classList.remove('show'); }

    const btnMenu = $('#btnMenu');
    if (btnMenu) btnMenu.addEventListener('click', () => {
        sideEl.classList.contains('show') ? closeDrawer() : openDrawer();
    });
    mask.addEventListener('click', closeDrawer);
    window.addEventListener('resize', () => { if (innerWidth > 860) closeDrawer(); });

    /* ---------------- 3. 展开 / 收起全部 ---------------- */
    const btnExpand = $('#btnExpandAll');
    const subsAll = () => $$('details.doc-sub-sec');
    function syncExpandBtn() {
        if (!btnExpand) return;
        const list = subsAll();
        btnExpand.textContent = list.every(d => d.open) ? '全部收起' : '全部展开';
    }
    if (btnExpand) btnExpand.addEventListener('click', () => {
        const open = !subsAll().every(d => d.open);
        subsAll().forEach(d => { d.open = open; });
        syncExpandBtn();
    });

    /* ---------------- 4. 搜索过滤与命中高亮 ---------------- */
    const foundEl = document.createElement('div');
    foundEl.className = 'doc-found hidden';
    searchEl.parentNode.appendChild(foundEl);

    const escReg = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

    function clearHits() {
        $$('mark.hit', article).forEach(m => m.replaceWith(document.createTextNode(m.textContent)));
        article.normalize();
    }

    /** 在容器内的文本节点上包裹命中片段，返回命中次数（跳过 script/style） */
    function markIn(root, re) {
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
            acceptNode(n) {
                if (!n.nodeValue || !n.nodeValue.trim()) return NodeFilter.FILTER_REJECT;
                return n.parentElement && n.parentElement.closest('script,style')
                    ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT;
            }
        });
        const nodes = [];
        while (walker.nextNode()) nodes.push(walker.currentNode);
        let count = 0;
        nodes.forEach(t => {
            const v = t.nodeValue;
            re.lastIndex = 0;
            if (!re.test(v)) return;
            re.lastIndex = 0;
            const frag = document.createDocumentFragment();
            let last = 0, m;
            while ((m = re.exec(v))) {
                if (m.index > last) frag.appendChild(document.createTextNode(v.slice(last, m.index)));
                const mk = document.createElement('mark');
                mk.className = 'hit';
                mk.textContent = m[0];
                frag.appendChild(mk);
                last = m.index + m[0].length;
                count++;
                if (!m[0].length) re.lastIndex++;
            }
            if (last < v.length) frag.appendChild(document.createTextNode(v.slice(last)));
            t.parentNode.replaceChild(frag, t);
        });
        return count;
    }

    let searching = false;

    function applySearch(raw) {
        const q = raw.trim();
        clearHits();
        $$('.toc-empty', tocEl).forEach(e => e.remove());

        if (!q) {
            searching = false;
            toc.forEach(e => {
                e.sec.classList.remove('dim');
                e.l1.classList.remove('hidden', 'on');
                e.wrap.classList.remove('open');
                e.subs.forEach(s => { s.node.classList.remove('dim'); s.l2.classList.remove('hidden', 'on'); });
            });
            foundEl.classList.add('hidden');
            crumbEl.textContent = '使用文档';
            spy();
            return;
        }

        searching = true;
        const ql = q.toLowerCase();
        const re = new RegExp(escReg(q), 'gi');
        let total = 0, secsHit = 0;

        toc.forEach(e => {
            const titleHit = e.title.toLowerCase().includes(ql);
            let subHit = 0;
            e.subs.forEach(s => {
                const ok = titleHit || s.title.toLowerCase().includes(ql) || s.body.toLowerCase().includes(ql);
                s.node.classList.toggle('dim', !ok);
                s.l2.classList.toggle('hidden', !ok);
                if (!ok) return;
                subHit++;
                s.node.open = true;
                total += markIn(s.node, re);
            });
            const secOk = titleHit || subHit > 0;
            e.sec.classList.toggle('dim', !secOk);
            e.l1.classList.toggle('hidden', !secOk);
            e.wrap.classList.toggle('open', secOk);
            e.l1.classList.remove('on');
            e.subs.forEach(s => s.l2.classList.remove('on'));
            if (secOk) secsHit++;
        });

        syncExpandBtn();
        foundEl.classList.remove('hidden');
        foundEl.textContent = secsHit
            ? `匹配 ${secsHit} 章 / ${total} 处命中（回车跳到第一处）`
            : '没有匹配的章节';
        crumbEl.textContent = secsHit ? '搜索结果：' + q : '未找到：' + q;

        if (!secsHit) {
            const tip = document.createElement('div');
            tip.className = 'toc-empty';
            tip.textContent = '没有匹配的章节，换个关键词试试（支持功能名、字段名、端口号等）';
            tocEl.appendChild(tip);
        }
    }

    let timer = null;
    searchEl.addEventListener('input', () => {
        clearTimeout(timer);
        const v = searchEl.value;
        timer = setTimeout(() => applySearch(v), 220);
    });
    // 回车定位首个命中小节；Esc 清空
    searchEl.addEventListener('keydown', e => {
        if (e.key === 'Enter') {
            e.preventDefault();
            const first = toc.find(x => !x.sec.classList.contains('dim'));
            if (!first) return;
            const sub = first.subs.find(s => !s.node.classList.contains('dim')) || first;
            const target = sub.node || sub.sec;
            target.open = true;
            scrollTo(target);
        } else if (e.key === 'Escape') {
            searchEl.value = '';
            applySearch('');
        }
    });

    /* ---------------- 5. 滚动定位（目录高亮 + 面包屑） ---------------- */
    function scrollTo(el) {
        window.scrollTo({ top: Math.max(0, docTop(el) - TOP_LINE + 6), behavior: 'smooth' });
    }

    function keepTocInView(link) {
        const r = link.getBoundingClientRect(), c = tocEl.getBoundingClientRect();
        if (r.top < c.top) tocEl.scrollTop -= (c.top - r.top) + 20;
        else if (r.bottom > c.bottom) tocEl.scrollTop += (r.bottom - c.bottom) + 20;
    }

    let lastKey = '';

    function spy() {
        if (searching) return;
        const line = window.scrollY + TOP_LINE + 12;
        let secEntry = null;
        for (const e of toc) {
            if (e.sec.classList.contains('dim')) continue;
            if (docTop(e.sec) <= line) secEntry = e; else break;
        }
        if (!secEntry) secEntry = toc.find(e => !e.sec.classList.contains('dim')) || null;
        if (!secEntry) return;

        let cur = null;
        secEntry.subs.forEach(s => {
            if (s.node.classList.contains('dim')) return;
            if (docTop(s.node) <= line) cur = s;
        });
        cur = cur || secEntry.subs[0] || null;

        const key = secEntry.sec.id + '|' + (cur ? cur.node.id : '');
        if (key === lastKey) return;
        lastKey = key;

        toc.forEach(e => {
            e.l1.classList.toggle('on', e === secEntry);
            e.wrap.classList.toggle('open', e === secEntry);
            e.subs.forEach(s => s.l2.classList.toggle('on', !!cur && s === cur));
        });
        crumbEl.innerHTML = '使用文档 · <b>' + esc(secEntry.title) + '</b>'
            + (cur ? ' › ' + esc(cur.title) : '');
        keepTocInView(secEntry.l1);
    }

    let ticking = false;
    window.addEventListener('scroll', () => {
        if (ticking) return;
        ticking = true;
        requestAnimationFrame(() => { ticking = false; spy(); });
    }, { passive: true });

    /* ---------------- 6. 打印 / 存 PDF ---------------- */
    const btnPrint = $('#btnPrint');
    let backup = null;
    if (btnPrint) btnPrint.addEventListener('click', () => {
        backup = subsAll().map(d => d.open);
        if (searchEl.value) { searchEl.value = ''; applySearch(''); }
        subsAll().forEach(d => { d.open = true; });
        syncExpandBtn();
        window.print();
    });
    window.addEventListener('afterprint', () => {
        if (!backup) return;
        subsAll().forEach((d, i) => { if (backup[i] != null) d.open = backup[i]; });
        backup = null;
        syncExpandBtn();
    });

    /* ---------------- 7. 初始定位 ---------------- */
    function revealHash() {
        const id = decodeURIComponent((location.hash || '').replace(/^#/, ''));
        if (!id) return;
        const el = document.getElementById(id);
        if (!el) return;
        if (el.matches('details.doc-sub-sec')) { el.open = true; syncExpandBtn(); }
        if (el.matches('section.doc-sec')) {
            const first = $('details.doc-sub-sec', el);
            if (first) { first.open = true; syncExpandBtn(); }
        }
    }

    // 「/」快速聚焦搜索框（输入态不拦截）
    document.addEventListener('keydown', e => {
        if (e.key === '/' && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName)) {
            e.preventDefault();
            searchEl.focus();
        }
    });

    window.addEventListener('hashchange', () => { revealHash(); spy(); });

    revealHash();
    syncExpandBtn();
    spy();
    if (location.hash) {
        const el = document.getElementById(decodeURIComponent(location.hash.slice(1)));
        if (el) setTimeout(() => scrollTo(el), 30);
    }
})();
