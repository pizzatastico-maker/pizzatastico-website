/**
 * Pizzatastico Hybrid Web Analytics & Consent Engine (v2.4.1)
 *
 * Layer 1 (100% Cookieless First-Party Telemetry — § 25 TDDDG exempt):
 *   - Zero cookies, zero localStorage/sessionStorage/IndexedDB identifiers, zero IP storage, zero fingerprinting.
 *   - Ephemeral single-event random v4 UUID written via Firestore REST API (write-only, schema-validated).
 *
 * Layer 2 (Optional Google Analytics 4 — Strict Two-Stage Opt-In under § 25(1) TDDDG, Art. 6(1)(a) & Art. 7(3) GDPR):
 *   - Zero requests to googletagmanager.com / google-analytics.com prior to explicit user opt-in.
 *   - Symmetric, zero-nudging equal-contrast buttons (OLG Köln 6 U 80/23 & DSK OH Telemedien compliant).
 *   - Explicit Layer-1 provider/third-country & revocation notice + direct Privacy & Imprint links (§ 5 DDG).
 *   - Instant 1-click revocation & _ga cookie purge via footer "Cookie Settings" button.
 */
(function () {
  'use strict';

  var GA_MEASUREMENT_ID = 'G-NCF8XS4LF5';
  var CONSENT_KEY = 'pz_cookie_consent_v1';
  var FIRESTORE_BASE =
    'https://firestore.googleapis.com/v1/projects/pizzatastico-40234/databases/(default)/documents/web_telemetry_events';

  var VALID_LANGS = {
    en: 1, de: 1, it: 1, es: 1, fr: 1, pl: 1, zh: 1, ja: 1, ko: 1, vi: 1,
    pt: 1, el: 1, hu: 1, fi: 1, nl: 1, sv: 1, da: 1, no: 1, cs: 1, sk: 1,
    ro: 1, hr: 1, tr: 1, bg: 1, uk: 1
  };

  var gaLoaded = false;
  var scroll75Fired = false;
  var trackingBound = false;

  function isConsentDenied() {
    try {
      return localStorage.getItem(CONSENT_KEY) === 'denied';
    } catch (_) {
      return false;
    }
  }

  function isLocalOrBot() {
    try {
      var h = (window.location.hostname || '').toLowerCase();
      if (!h || h === 'localhost' || h === '127.0.0.1' || window.location.protocol === 'file:') {
        return true;
      }
      if (navigator.webdriver) return true;
      var ua = (navigator.userAgent || '').toLowerCase();
      if (/bot|crawl|spider|slurp|lighthouse|headless|prerender|whatsapp|facebookexternalhit|discordbot|telegrambot|slackbot|applebot|bingpreview/i.test(ua)) {
        return true;
      }
    } catch (_) {}
    return false;
  }

  function ephemeralUuidV4() {
    if (window.crypto && typeof window.crypto.randomUUID === 'function') {
      return window.crypto.randomUUID().toLowerCase();
    }
    var bytes = new Uint8Array(16);
    if (window.crypto && window.crypto.getRandomValues) {
      window.crypto.getRandomValues(bytes);
    } else {
      for (var i = 0; i < 16; i++) bytes[i] = Math.floor(Math.random() * 256);
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    var hex = [];
    for (var j = 0; j < 16; j++) {
      hex.push((bytes[j] + 0x100).toString(16).slice(1));
    }
    return (
      hex[0] + hex[1] + hex[2] + hex[3] + '-' +
      hex[4] + hex[5] + '-' +
      hex[6] + hex[7] + '-' +
      hex[8] + hex[9] + '-' +
      hex[10] + hex[11] + hex[12] + hex[13] + hex[14] + hex[15]
    );
  }

  function detectPageAndLang() {
    var cfg = window.__PZ_PAGE__ || {};
    var lang = (cfg.lang || document.documentElement.lang || 'en').toLowerCase().slice(0, 2);
    if (!VALID_LANGS[lang]) lang = 'en';

    var page = cfg.page || '';
    if (!page) {
      var p = (window.location.pathname || '/').toLowerCase();
      if (p.indexOf('formula') !== -1) page = 'formula';
      else if (p.indexOf('pde') !== -1) page = 'pde';
      else if (p.indexOf('guide') !== -1) page = 'guide';
      else if (p.indexOf('stats') !== -1) page = 'stats';
      else if (p.indexOf('privacy') !== -1) page = 'privacy';
      else if (p.indexOf('imprint') !== -1) page = 'imprint';
      else page = 'home';
    }
    return { page: page, lang: lang };
  }

  function detectDevice() {
    var ua = (navigator.userAgent || '').toLowerCase();
    if (/iphone|ipad|ipod/.test(ua) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1)) {
      return 'ios';
    }
    if (/android/.test(ua)) {
      return 'android';
    }
    return 'desktop';
  }

  function sanitizeRegex(val, maxLen, rx) {
    if (!val || typeof val !== 'string') return '';
    var trimmed = val.trim().slice(0, maxLen);
    return rx.test(trimmed) ? trimmed : trimmed.replace(/[^a-zA-Z0-9._-]/g, '').slice(0, maxLen);
  }

  function detectAttribution() {
    var params;
    try {
      params = new URLSearchParams(window.location.search || '');
    } catch (_) {
      params = null;
    }
    var rawUtmSrc = params ? (params.get('utm_source') || params.get('ref') || '') : '';
    var rawUtmCmp = params ? (params.get('utm_campaign') || '') : '';
    var utmSrc = sanitizeRegex(rawUtmSrc, 40, /^[a-zA-Z0-9._-]*$/);
    var utmCmp = sanitizeRegex(rawUtmCmp, 40, /^[a-zA-Z0-9._-]*$/);

    var refHost = '';
    try {
      if (document.referrer) {
        refHost = new URL(document.referrer).hostname.toLowerCase().replace(/^www\./, '');
      }
    } catch (_) {}

    var signal = (refHost + ' ' + utmSrc.toLowerCase()).trim();
    var refCat = 'direct';

    if (refHost && (refHost === 'pizzatastico.com' || refHost.endsWith('.pizzatastico.com'))) {
      refCat = 'internal';
      refHost = '';
    } else if (/chatgpt\.com|openai\.com/.test(signal)) {
      refCat = 'ai_chatgpt';
    } else if (/perplexity\.ai/.test(signal)) {
      refCat = 'ai_perplexity';
    } else if (/gemini\.google\.com/.test(signal)) {
      refCat = 'ai_gemini';
    } else if (/claude\.ai|anthropic\.com/.test(signal)) {
      refCat = 'ai_claude';
    } else if (/copilot\.microsoft\.com/.test(signal)) {
      refCat = 'ai_copilot';
    } else if (/(^|\.)google\.[a-z.]+$/.test(refHost) || utmSrc.toLowerCase() === 'google') {
      refCat = 'search_google';
    } else if (/bing\.com|duckduckgo\.com|ecosia\.org|yahoo\.|yandex\.|baidu\.com|qwant\.com|search\.brave\.com/.test(signal)) {
      refCat = 'search_other';
    } else if (/youtube\.com|youtu\.be/.test(signal)) {
      refCat = 'social_youtube';
    } else if (/reddit\.com/.test(signal)) {
      refCat = 'social_reddit';
    } else if (/tiktok\.com/.test(signal)) {
      refCat = 'social_tiktok';
    } else if (/instagram\.com/.test(signal)) {
      refCat = 'social_instagram';
    } else if (/facebook\.com|fb\.com|t\.co|x\.com|twitter\.com|threads\.net|linkedin\.com|pinterest\./.test(signal)) {
      refCat = 'social_other';
    } else if (refHost || utmSrc) {
      refCat = 'referral';
    }

    var cleanHost = refHost.replace(/[^a-z0-9.-]/g, '').slice(0, 64);
    return {
      refCat: refCat,
      refHost: cleanHost,
      utmSrc: utmSrc,
      utmCmp: utmCmp
    };
  }

  function detectTzRegion() {
    try {
      var tz = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
      tz = tz.replace(/[^a-zA-Z0-9/_+-]/g, '').slice(0, 40);
      return tz;
    } catch (_) {
      return '';
    }
  }

  var meta = detectPageAndLang();
  var device = detectDevice();
  var attr = detectAttribution();
  var tzRegion = detectTzRegion();

  function sendCookielessEvent(eventType, targetLabel) {
    if (isLocalOrBot() || isConsentDenied()) return;
    try {
      var now = new Date();
      var iso = now.toISOString();
      var day = iso.slice(0, 10);
      var fields = {
        ts: { timestampValue: iso },
        day: { stringValue: day },
        type: { stringValue: eventType },
        page: { stringValue: meta.page },
        lang: { stringValue: meta.lang },
        ref_cat: { stringValue: attr.refCat },
        device: { stringValue: device }
      };
      if (attr.refHost) fields.ref_host = { stringValue: attr.refHost };
      if (attr.utmSrc) fields.utm_src = { stringValue: attr.utmSrc };
      if (attr.utmCmp) fields.utm_cmp = { stringValue: attr.utmCmp };
      if (tzRegion) fields.tz_region = { stringValue: tzRegion };
      if (targetLabel) {
        var cleanTarget = String(targetLabel).replace(/[^a-zA-Z0-9./:_-]/g, '').slice(0, 64);
        if (cleanTarget) fields.target = { stringValue: cleanTarget };
      }

      var docId = ephemeralUuidV4();
      fetch(FIRESTORE_BASE + '?documentId=' + encodeURIComponent(docId), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: fields }),
        keepalive: true,
        credentials: 'omit'
      }).catch(function () {});
    } catch (_) {}
  }

  function bootGoogleAnalytics() {
    if (gaLoaded || isLocalOrBot()) return;
    gaLoaded = true;

    window.dataLayer = window.dataLayer || [];
    window.gtag = window.gtag || function () { window.dataLayer.push(arguments); };

    window.gtag('consent', 'default', {
      ad_storage: 'denied',
      ad_user_data: 'denied',
      ad_personalization: 'denied',
      analytics_storage: 'granted'
    });
    window.gtag('js', new Date());
    window.gtag('config', GA_MEASUREMENT_ID, {
      anonymize_ip: true,
      allow_google_signals: false,
      allow_ad_personalization_signals: false
    });

    var script = document.createElement('script');
    script.async = true;
    script.src = 'https://www.googletagmanager.com/gtag/js?id=' + GA_MEASUREMENT_ID;
    document.head.appendChild(script);
  }

  function purgeGaCookies() {
    try {
      if (typeof window.gtag === 'function') {
        window.gtag('consent', 'update', { analytics_storage: 'denied' });
      }
      window['ga-disable-' + GA_MEASUREMENT_ID] = true;
      var cookies = (document.cookie || '').split(';');
      var host = window.location.hostname;
      var domains = [host, '.' + host, '.pizzatastico.com', 'pizzatastico.com'];
      for (var i = 0; i < cookies.length; i++) {
        var name = cookies[i].split('=')[0].trim();
        if (name.indexOf('_ga') === 0 || name.indexOf('_gid') === 0 || name.indexOf('_gat') === 0) {
          document.cookie = name + '=; Max-Age=0; path=/; SameSite=Lax';
          for (var d = 0; d < domains.length; d++) {
            document.cookie = name + '=; Max-Age=0; path=/; domain=' + domains[d] + '; SameSite=Lax';
          }
        }
      }
    } catch (_) {}
  }

  function trackEvent(cookielessType, gaEventName, targetLabel) {
    sendCookielessEvent(cookielessType, targetLabel);
    if (gaLoaded && typeof window.gtag === 'function' && !window['ga-disable-' + GA_MEASUREMENT_ID]) {
      window.gtag('event', gaEventName, {
        page_type: meta.page,
        page_lang: meta.lang,
        event_label: targetLabel || ''
      });
    }
  }

  function getI18n() {
    var d = window.__PZ_I18N__ || {};
    var prefix = meta.lang === 'en' ? '/' : '/' + meta.lang + '/';
    return {
      text:
        d.consent_banner_text ||
        'We use optional analytics cookies (Google Analytics 4, Google Ireland / USA) only with your consent to analyze website usage. You can revoke your choice at any time via "Cookie Settings" in the footer.',
      privacyLabel: d.nav_privacy || 'Privacy Policy',
      privacyHref: d.privacy_href || prefix + 'privacy.html',
      imprintLabel: d.nav_imprint || 'Legal Notice',
      imprintHref: d.imprint_href || prefix + 'imprint.html',
      accept: d.consent_accept || 'Allow Analytics',
      decline: d.consent_decline || 'Decline'
    };
  }

  function removeBanner() {
    var existing = document.getElementById('pz-consent-banner');
    if (existing && existing.parentNode) {
      existing.parentNode.removeChild(existing);
    }
  }

  function renderConsentBanner() {
    removeBanner();
    var t = getI18n();
    var bar = document.createElement('div');
    bar.id = 'pz-consent-banner';
    bar.setAttribute('role', 'region');
    bar.setAttribute('aria-label', 'Cookie Consent');
    bar.className =
      'fixed bottom-3 left-3 right-3 z-50 max-w-4xl mx-auto bg-white text-slate-800 border border-slate-300 rounded-2xl shadow-2xl px-4 py-3.5 sm:px-5 sm:py-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3.5 text-xs';

    var textWrap = document.createElement('div');
    textWrap.className = 'text-slate-700 leading-relaxed pr-1';
    textWrap.appendChild(document.createTextNode(t.text + ' '));

    var pLink = document.createElement('a');
    pLink.href = t.privacyHref;
    pLink.className = 'underline text-slate-900 hover:text-slate-600 font-semibold whitespace-nowrap';
    pLink.textContent = t.privacyLabel;
    textWrap.appendChild(pLink);

    textWrap.appendChild(document.createTextNode(' · '));

    var iLink = document.createElement('a');
    iLink.href = t.imprintHref;
    iLink.className = 'underline text-slate-900 hover:text-slate-600 font-semibold whitespace-nowrap';
    iLink.textContent = t.imprintLabel;
    textWrap.appendChild(iLink);

    var btnWrap = document.createElement('div');
    btnWrap.className = 'flex items-center gap-2.5 w-full sm:w-auto shrink-0';

    // Strict visual symmetry (identical color, border, font-weight, size) — zero visual nudging (OLG Köln 6 U 80/23)
    var symmetricBtnClass =
      'flex-1 sm:flex-initial px-4 py-2 rounded-xl border border-slate-300 bg-slate-100 hover:bg-slate-200 text-slate-900 font-semibold transition cursor-pointer text-xs text-center';

    var btnDecline = document.createElement('button');
    btnDecline.type = 'button';
    btnDecline.className = symmetricBtnClass;
    btnDecline.textContent = t.decline;
    btnDecline.onclick = function () {
      try { localStorage.setItem(CONSENT_KEY, 'denied'); } catch (_) {}
      purgeGaCookies();
      removeBanner();
    };

    var btnAccept = document.createElement('button');
    btnAccept.type = 'button';
    btnAccept.className = symmetricBtnClass;
    btnAccept.textContent = t.accept;
    btnAccept.onclick = function () {
      try { localStorage.setItem(CONSENT_KEY, 'granted'); } catch (_) {}
      window['ga-disable-' + GA_MEASUREMENT_ID] = false;
      removeBanner();
      bindClickAndScrollTracking();
      bootGoogleAnalytics();
      sendCookielessEvent('consent_accept');
    };

    btnWrap.appendChild(btnDecline);
    btnWrap.appendChild(btnAccept);
    bar.appendChild(textWrap);
    bar.appendChild(btnWrap);
    document.body.appendChild(bar);
  }

  window.pzOpenCookieSettings = function () {
    purgeGaCookies();
    try { localStorage.removeItem(CONSENT_KEY); } catch (_) {}
    renderConsentBanner();
  };

  function bindClickAndScrollTracking() {
    if (trackingBound) return;
    trackingBound = true;

    document.addEventListener('click', function (e) {
      var anchor = e.target && e.target.closest ? e.target.closest('a') : null;
      if (!anchor || !anchor.href) return;
      var href = anchor.href;

      if (href.indexOf('apps.apple.com') !== -1) {
        trackEvent('click_appstore', 'app_store_click', meta.page);
      } else if (href.indexOf('play.google.com') !== -1) {
        trackEvent('click_playstore', 'play_store_click', meta.page);
      } else if (href.indexOf('doi.org/') !== -1) {
        var doiKey = href.split('doi.org/')[1] || 'doi';
        trackEvent('click_doi', 'doi_click', doiKey);
      } else if (meta.page !== 'pde' && href.indexOf('pde.html') !== -1) {
        trackEvent('click_pde', 'pde_paper_click', meta.page);
      } else if (meta.page !== 'guide' && href.indexOf('guide.html') !== -1) {
        trackEvent('click_guide', 'guide_click', meta.page);
      }
    }, { capture: true });

    if (meta.page === 'formula' || meta.page === 'pde' || meta.page === 'guide' || meta.page === 'home' || meta.page === 'stats') {
      window.addEventListener('scroll', function () {
        if (scroll75Fired) return;
        var docEl = document.documentElement;
        var scrollTop = window.pageYOffset || docEl.scrollTop || 0;
        var winH = window.innerHeight || docEl.clientHeight || 0;
        var fullH = Math.max(docEl.scrollHeight || 0, document.body ? document.body.scrollHeight : 0);
        if (fullH > winH * 1.3 && (scrollTop + winH) / fullH >= 0.75) {
          scroll75Fired = true;
          trackEvent('scroll_75', 'scroll_75', meta.page);
        }
      }, { passive: true });
    }
  }

  function init() {
    var saved = null;
    try { saved = localStorage.getItem(CONSENT_KEY); } catch (_) {}

    if (saved !== 'denied') {
      sendCookielessEvent('pageview');
      bindClickAndScrollTracking();
    }

    // Do not auto-pop banner while visitor is reading Legal Notice or Privacy Policy itself (§ 5 DDG / BayLDA)
    if (meta.page === 'imprint' || meta.page === 'privacy') {
      if (saved === 'granted') bootGoogleAnalytics();
      return;
    }

    if (saved === 'granted') {
      bootGoogleAnalytics();
    } else if (saved !== 'denied') {
      renderConsentBanner();
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
