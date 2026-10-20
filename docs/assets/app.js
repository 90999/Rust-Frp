/* ===========================================================================
   NFrp 文档 · 应用逻辑
   ---------------------------------------------------------------------------
   零依赖。负责：
   - 把 PAGES 注入 #dynamicPages
   - 哈希路由 + 侧栏高亮 + 上下页
   - 主题切换（记忆到 localStorage）
   - 代码块复制按钮
   - 滚动进场动画（IntersectionObserver）
   - 移动端抽屉导航
   =========================================================================== */

(function () {
  'use strict';

  /* ---------- 页面顺序（用于上下页导航） ---------- */
  const ORDER = [
    { id: 'home',            title: '概览' },
    { id: 'install',         title: '安装' },
    { id: 'quickstart',      title: '快速开始' },
    { id: 'config-server',   title: '服务端配置' },
    { id: 'config-client',   title: '客户端配置' },
    { id: 'proxies',         title: '代理类型' },
    { id: 'plugins',         title: '插件' },
    { id: 'transports',      title: '传输层' },
    { id: 'protocol',        title: '线协议总览' },
    { id: 'protocol-v1',     title: 'v1 与加密' },
    { id: 'protocol-v2',     title: 'v2 与 AEAD' },
    { id: 'messages',        title: '消息类型' },
    { id: 'security',        title: '安全模型' },
    { id: 'acl-rbac',        title: 'ACL 与 RBAC' },
    { id: 'audit',           title: '审计日志' },
    { id: 'changes',         title: '安全修复史' },
    { id: 'api',             title: 'HTTP API' },
    { id: 'library',         title: '作为库使用' },
    { id: 'compat',          title: '与官方 frp 互通' },
  ];

  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));

  /* ---------- 注入动态页面 ---------- */
  function injectPages() {
    const host = $('#dynamicPages');
    if (!host || typeof PAGES === 'undefined') return;
    const frag = document.createDocumentFragment();
    Object.keys(PAGES).forEach(function (id) {
      const sec = document.createElement('section');
      sec.className = 'page';
      sec.id = 'page-' + id;
      sec.hidden = true;
      sec.innerHTML = PAGES[id];
      frag.appendChild(sec);
    });
    host.appendChild(frag);
  }

  /* ---------- 路由 ---------- */
  function currentRoute() {
    const h = (location.hash || '').replace(/^#\/?/, '').trim();
    if (!h) return 'home';
    return h.replace(/\/$/, '') || 'home';
  }

  function activate(id) {
    // 找不到就退回首页
    let target = $('#page-' + id);
    if (!target) {
      id = 'home';
      target = $('#page-home');
    }

    $$('.page').forEach(function (p) {
      p.hidden = p !== target;
    });

    // 重新触发进场动画
    target.classList.remove('page');
    void target.offsetWidth;
    target.classList.add('page');

    // 侧栏高亮
    $$('.nav-link').forEach(function (a) {
      const href = (a.getAttribute('href') || '').replace(/^#\/?/, '') || 'home';
      a.classList.toggle('active', href === id);
    });

    buildPager(target, id);
    decorateCodeBlocks(target);
    observeReveals(target);
    closeDrawer();

    // 滚动到顶部（除非是页内锚点）
    if (!location.hash.includes('#', 2)) {
      window.scrollTo({ top: 0, behavior: 'auto' });
    }

    document.title =
      (ORDER.find(function (o) { return o.id === id; }) || { title: '文档' }).title +
      ' · NFrp 文档';
  }

  /* ---------- 上下页 ---------- */
  function buildPager(host, id) {
    const idx = ORDER.findIndex(function (o) { return o.id === id; });
    if (idx < 0) return;

    const prev = ORDER[idx - 1];
    const next = ORDER[idx + 1];
    const old = $('.pager', host);
    if (old) old.remove();

    if (!prev && !next) return;

    const nav = document.createElement('nav');
    nav.className = 'pager';

    if (prev) {
      nav.insertAdjacentHTML(
        'beforeend',
        '<a href="#/' + prev.id + '">' +
          '<span class="dir">' +
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" ' +
          'stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>' +
          '上一页</span>' +
          '<span class="name">' + prev.title + '</span></a>'
      );
    } else {
      nav.insertAdjacentHTML('beforeend', '<span class="spacer"></span>');
    }

    if (next) {
      nav.insertAdjacentHTML(
        'beforeend',
        '<a class="next" href="#/' + next.id + '">' +
          '<span class="dir">下一页' +
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" ' +
          'stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M12 5l7 7-7 7"/></svg>' +
          '</span>' +
          '<span class="name">' + next.title + '</span></a>'
      );
    }

    host.appendChild(nav);
  }

  /* ---------- 代码块复制 ---------- */
  const COPY_ICON =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" ' +
    'stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/>' +
    '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
  const CHECK_ICON =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" ' +
    'stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>';

  function decorateCodeBlocks(host) {
    $$('pre', host).forEach(function (pre) {
      if (pre.dataset.decorated) return;
      pre.dataset.decorated = '1';

      const btn = document.createElement('button');
      btn.className = 'copy-btn';
      btn.type = 'button';
      btn.setAttribute('aria-label', '复制代码');
      btn.innerHTML = COPY_ICON;
      btn.addEventListener('click', function () {
        const code = pre.querySelector('code');
        const text = code ? code.textContent : pre.textContent;
        const done = function () {
          btn.innerHTML = CHECK_ICON;
          btn.classList.add('copied');
          setTimeout(function () {
            btn.innerHTML = COPY_ICON;
            btn.classList.remove('copied');
          }, 1500);
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(done).catch(function () {
            legacyCopy(text) && done();
          });
        } else if (legacyCopy(text)) {
          done();
        }
      });
      pre.appendChild(btn);
    });
  }

  function legacyCopy(text) {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.cssText = 'position:fixed;top:-9999px;opacity:0';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      return ok;
    } catch (e) {
      return false;
    }
  }

  /* ---------- 滚动进场 ---------- */
  let io = null;
  function observeReveals(host) {
    const items = $$('.reveal', host).filter(function (el) {
      return !el.classList.contains('in');
    });
    if (!items.length) return;

    if (!('IntersectionObserver' in window)) {
      items.forEach(function (el) { el.classList.add('in'); });
      return;
    }

    if (!io) {
      io = new IntersectionObserver(
        function (entries) {
          entries.forEach(function (e) {
            if (e.isIntersecting) {
              e.target.classList.add('in');
              io.unobserve(e.target);
            }
          });
        },
        { rootMargin: '0px 0px -8% 0px', threshold: 0.06 }
      );
    }
    items.forEach(function (el, i) {
      el.style.transitionDelay = Math.min(i * 45, 260) + 'ms';
      io.observe(el);
    });
  }

  /* ---------- 主题 ---------- */
  const THEME_KEY = 'nfrp-doc-theme';

  function applyTheme(t) {
    document.documentElement.setAttribute('data-theme', t);
    const moon = $('.ico-moon');
    const sun = $('.ico-sun');
    if (moon && sun) {
      const light = t === 'light';
      moon.style.display = light ? 'none' : '';
      sun.style.display = light ? '' : 'none';
    }
    const meta = document.querySelector('meta[name="color-scheme"]');
    if (meta) meta.setAttribute('content', t === 'light' ? 'light dark' : 'dark light');
  }

  function initTheme() {
    let saved = null;
    try { saved = localStorage.getItem(THEME_KEY); } catch (e) {}
    // 默认深色 —— 不跟随系统。
    // 这套配色是按深色设计的（B 站粉在深底上才够亮），
    // 跟随系统会让浅色用户看到一个"次选"的观感。
    // 想换浅色点右上角的图标，选择会被记住。
    applyTheme(saved || 'dark');

    const btn = $('#themeBtn');
    if (btn) {
      btn.addEventListener('click', function () {
        const cur = document.documentElement.getAttribute('data-theme');
        const next = cur === 'light' ? 'dark' : 'light';
        applyTheme(next);
        try { localStorage.setItem(THEME_KEY, next); } catch (e) {}
      });
    }
  }

  /* ---------- 移动端抽屉 ---------- */
  function openDrawer() {
    const sb = $('#sidebar');
    const scrim = $('#scrim');
    const btn = $('#menuBtn');
    if (!sb) return;
    sb.classList.add('open');
    scrim && scrim.classList.add('show');
    btn && btn.setAttribute('aria-expanded', 'true');
  }

  function closeDrawer() {
    const sb = $('#sidebar');
    const scrim = $('#scrim');
    const btn = $('#menuBtn');
    if (!sb) return;
    sb.classList.remove('open');
    scrim && scrim.classList.remove('show');
    btn && btn.setAttribute('aria-expanded', 'false');
  }

  function initDrawer() {
    const btn = $('#menuBtn');
    const scrim = $('#scrim');
    btn && btn.addEventListener('click', function () {
      $('#sidebar').classList.contains('open') ? closeDrawer() : openDrawer();
    });
    scrim && scrim.addEventListener('click', closeDrawer);
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') closeDrawer();
    });
  }

  /* ---------- 启动 ---------- */
  function boot() {
    injectPages();
    initTheme();
    initDrawer();

    window.addEventListener('hashchange', function () {
      activate(currentRoute());
    });

    activate(currentRoute());
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
