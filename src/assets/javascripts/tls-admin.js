(function () {
  // follow the Morpheus user theme (html data-mode): paint from the remembered value at once, then confirm it from a
  // Morpheus page so a theme change shows up without clearing caches; without any answer the OS setting applies
  function setMode(m) { if (m === 'dark' || m === 'light') document.documentElement.setAttribute('data-mode', m); }
  try { setMode(localStorage.getItem('tls-theme-mode')); } catch (e) { /* ignore */ }
  fetch('/', {credentials: 'same-origin', cache: 'no-store'}).then(function (r) { return r.text(); }).then(function (t) {
    var x = /<html[^>]*data-mode="(light|dark)"/i.exec(t);
    if (x) { setMode(x[1]); try { localStorage.setItem('tls-theme-mode', x[1]); } catch (e) { /* ignore */ } }
  }).catch(function () { /* keep what we have */ });

  var API = '/plugin/tls/api/';
  var app = document.getElementById('app');
  var state = null, formDirty = false, timer = null;

  function h(tag, attrs, kids) {
    var e = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === 'class') e.className = attrs[k];
      else if (k === 'text') e.textContent = attrs[k];
      else if (k.indexOf('on') === 0) e.addEventListener(k.slice(2), attrs[k]);
      else if (attrs[k] !== undefined && attrs[k] !== null && attrs[k] !== false) e.setAttribute(k, attrs[k] === true ? '' : attrs[k]);
    });
    (kids || []).forEach(function (c) { if (c != null) e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });
    return e;
  }
  // Morpheus protects POSTs with a session CSRF token. This page is standalone, so read the token from a
  // regular Morpheus page (the same token is valid for the whole session).
  var csrf = null;
  function getCsrf() {
    if (csrf) return Promise.resolve(csrf);
    return fetch('/operations/dashboard', {credentials: 'same-origin'}).then(function (r) { return r.text(); }).then(function (html) {
      var doc = new DOMParser().parseFromString(html, 'text/html');
      var tok = doc.querySelector("meta[name='_csrf']"), hdr = doc.querySelector("meta[name='_csrf_header']");
      if (!tok) throw new Error('could not find the Morpheus CSRF token');
      csrf = {token: tok.getAttribute('content'), header: hdr ? hdr.getAttribute('content') : 'X-CSRF-TOKEN'};
      return csrf;
    });
  }
  function api(path, body) {
    var opt = {credentials: 'same-origin', headers: {'X-Requested-With': 'XMLHttpRequest'}};
    var pre = Promise.resolve();
    if (body) {
      opt.method = 'POST'; opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body);
      pre = getCsrf().then(function (c) { opt.headers[c.header] = c.token; });
    }
    return pre.then(function () { return fetch(API + path, opt); }).then(function (r) {
      return r.json().catch(function () { return {error: 'HTTP ' + r.status}; }).then(function (j) { if (!r.ok && !j.error) j.error = 'HTTP ' + r.status; return j; });
    }).catch(function (e) { return {error: String(e.message || e), network: true}; });
  }
  function fmt(iso) { if (!iso) return '-'; var d = new Date(iso); return isNaN(d) ? iso : d.toLocaleString(); }
  function cls(st) { return st === 'OK' ? 'ok' : (st === 'RENEWAL_DUE' || st === 'STAGING') ? 'warn' : 'bad'; }
  var TEXT = {OK: 'Certificate is valid', RENEWAL_DUE: 'Renewal is due', STAGING: 'Staging certificate (not trusted by browsers)',
    SELF_SIGNED: 'Self-signed certificate (Morpheus default)', EXPIRED: 'Certificate has expired',
    DOES_NOT_COVER_DOMAINS: 'Certificate does not cover the configured domains', UNREACHABLE: 'Could not read the served certificate'};

  // Prominent status banner (sticky, persistent node): shown while a run is in progress and while nginx restarts.
  var noticeBox = h('div', {id: 'notice', class: 'hidden', role: 'status', 'aria-live': 'polite'});
  var noticeKind = null, noticeTimer = null, downCount = 0;
  function isStaging() { return !!(state && state.settings && state.settings.useStaging !== 'false'); }
  function showNotice(kind, autoHideMs) {
    if (noticeTimer) { clearTimeout(noticeTimer); noticeTimer = null; }
    var stg = isStaging() ? ' A staging certificate is not trusted by browsers, so the page may not reconnect until you reload it and accept the warning.' : '';
    var T = {
      restart: ['warn', true, 'The appliance web server is restarting', 'This page reconnects by itself \u2013 please wait, nothing is wrong. It usually takes a few seconds.' + stg],
      running: ['info', true, 'Renewal in progress', 'The web server restarts at the end of a renewal, so this page may be unreachable for a few seconds.' + stg],
      stuck: ['bad', false, 'Cannot reach the appliance', 'The page has not reconnected after several tries. Most likely the browser does not trust the new certificate (a staging certificate was installed): reload the page and accept the warning, or switch the authority to production and renew again. If it is not that, check that the appliance is up.'],
      back: ['ok', false, 'Reconnected', 'The web server is back.']
    }[kind];
    noticeKind = kind;
    noticeBox.className = 'notice ' + T[0];
    noticeBox.replaceChildren.apply(noticeBox, [T[1] ? h('span', {class: 'spin', 'aria-hidden': 'true'}) : null,
      h('div', {class: 'grow'}, [h('div', {class: 'big', text: T[2]}), h('div', {text: T[3]})]),
      kind === 'stuck' ? h('button', {class: 'primary', text: 'Reload page', onclick: function () { window.location.reload(); }}) : null].filter(Boolean));
    if (autoHideMs) noticeTimer = setTimeout(hideNotice, autoHideMs);
  }
  function hideNotice() {
    if (noticeTimer) { clearTimeout(noticeTimer); noticeTimer = null; }
    noticeKind = null; noticeBox.className = 'hidden';
  }

  function load() {
    return api('status').then(function (d) {
      if (timer) clearTimeout(timer);
      if (d.network && state) {
        // nginx restarts during a renewal and drops connections: keep the page and retry
        downCount++;
        showNotice(downCount >= 5 ? 'stuck' : 'restart');
        timer = setTimeout(load, 3000);
        return;
      }
      if (d.error) { app.replaceChildren(h('div', {class: 'card'}, [h('b', {text: 'Error: '}), d.error])); return; }
      var wasDown = noticeKind === 'restart' || noticeKind === 'stuck';
      downCount = 0;
      state = d; render();
      if (d.running) { showNotice('running'); timer = setTimeout(load, 3000); }
      else if (wasDown) showNotice('back', 6000);
      else if (noticeKind === 'running') hideNotice();
    });
  }

  function field(label, input) { return h('div', {}, [h('label', {text: label}), input]); }
  function sel(id, opts, val) {
    var s = h('select', {id: id}, opts.map(function (o) { return h('option', {value: o[0], text: o[1], selected: o[0] === val}); }));
    return s;
  }


  // ---- one-time root-side setup: checklist + one-line command -------------------------------------------------
  var setup = null, setupTimer = null, setupSig = null;
  // one persistent node: render() re-attaches it, so an opened script view survives page refreshes and polling
  var setupBox = h('div', {id: 'setup-card'});
  function loadSetup() {
    if (setupTimer) { clearTimeout(setupTimer); setupTimer = null; }
    return api('setup').then(function (d) {
      if (!d.error) setup = d;
      renderSetup();
      // while something is missing, keep checking so the list turns green by itself after the command was run
      if (setup && !setup.ready) setupTimer = setTimeout(loadSetup, 5000);
    });
  }
  function copyText(text, done) {
    function fallback() {
      var t = h('textarea', {style: 'position:fixed;opacity:0'}); t.value = text; document.body.appendChild(t); t.select();
      try { document.execCommand('copy'); done(true); } catch (e) { done(false); }
      document.body.removeChild(t);
    }
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(function () { done(true); }, fallback);
    else fallback();
  }
  function renderSetup() {
    var box = setupBox;
    if (!setup) return;
    // only rebuild when something changed, otherwise the 5 s polling would close the script view
    var sig = JSON.stringify([setup.ready, setup.checks, setup.command]);
    if (sig === setupSig && box.firstChild) return;
    setupSig = sig;
    var items = (setup.checks || []).map(function (c) {
      return h('div', {class: 'check-row'}, [h('span', {class: 'pill ' + (c.ok ? 'ok' : 'bad'), text: c.ok ? 'OK' : 'MISSING'}),
        h('span', {text: ' ' + c.label}), h('span', {class: 'muted', text: ' \u2013 ' + (c.detail || '')})]);
    });
    if (setup.ready) {
      box.className = 'card';
      box.replaceChildren(h('details', {}, [h('summary', {}, [h('b', {text: 'Setup complete'}), h('span', {class: 'muted', text: ' \u2013 all checks passed (click for details)'})])].concat(items)));
      return;
    }
    var msg = h('span', {class: 'muted', id: 'setupmsg'});
    var ta = h('textarea', {id: 'setup-cmd', readonly: true, rows: 4, class: 'cmd'}); ta.value = setup.command || '';
    var pre = h('pre', {id: 'setup-script', class: 'hidden'});
    box.className = 'card banner warn';
    box.replaceChildren(h('div', {class: 'grow'}, [
      h('h2', {text: 'One-time setup needed'}),
      h('p', {class: 'muted', text: 'The plugin runs without root, so a few root-side pieces have to be put in place once. Open a root-capable shell on the appliance (console or SSH), paste the command below and press Enter. This page turns green by itself afterwards.'})
    ].concat(items, [
      setup.command ? h('div', {}, [ta,
        h('div', {class: 'actions'}, [
          h('button', {class: 'primary', text: 'Copy command', onclick: function () { copyText(setup.command, function (ok) { msg.textContent = ok ? 'Copied.' : 'Copy failed - select the text and copy it manually.'; }); }}),
          h('button', {text: 'View script', onclick: function () {
            if (!pre.classList.contains('hidden')) { pre.classList.add('hidden'); return; }
            api('setup?script=1').then(function (d) { pre.textContent = d.script || d.error || '(not available)'; pre.classList.remove('hidden'); });
          }}),
          h('button', {text: 'Check again', onclick: function () { msg.textContent = 'Checking\u2026'; loadSetup().then(function () { var m = document.getElementById('setupmsg'); if (m) m.textContent = ''; }); }}),
          msg]),
        h('p', {class: 'muted', text: 'The command carries the full script (' + (setup.scriptBytes || '?') + ' bytes, SHA-256 ' + (setup.sha256 || '?') + '). It backs up /etc/morpheus first and skips whatever is already in place. Add --dry-run after "install" to see what it would do.'}),
        pre]) : h('p', {class: 'muted', text: 'The setup script is not available in this build.'})
    ])));
  }

  function render() {
    var c = state.cert || {}, s = state.settings || {}, st = c.state || 'UNREACHABLE', run = state.running;
    var kids = [noticeBox, setupBox];

    var btn = function (text, mode, kind) {
      return h('button', {class: kind || '', disabled: run, text: text, onclick: function () { start(mode); }});
    };
    kids.push(h('div', {class: 'card banner ' + cls(st)}, [
      h('div', {class: 'grow'}, [
        h('div', {class: 'big', text: TEXT[st] || st}),
        h('div', {class: 'muted', text: (c.daysRemaining != null ? c.daysRemaining + ' days remaining, expires ' + fmt(c.notAfter) : (c.error || '')) +
          (run ? ' \u2022 a run is in progress\u2026' : '')})]),
      btn('Check now', 'check'), btn('Renew if due', 'renew', 'primary'), btn('Force renew', 'force', 'danger')]));
    kids.push(h('div', {id: 'runmsg', class: 'msg muted'}));

    var rows = [['Subject', c.subject], ['Issuer', c.issuer], ['Valid until', fmt(c.notAfter)], ['Covers', c.sans], ['SHA-256', c.fingerprint], ['Checked', fmt(c.checkedAt)]];
    kids.push(h('div', {class: 'card'}, [h('h2', {text: 'Installed certificate (served by nginx)'}),
      h('table', {}, rows.map(function (r) { return h('tr', {}, [h('th', {text: r[0]}), h('td', {text: r[1] == null ? '-' : String(r[1])})]); }))]));

    var tokenPh = s.tokenSet ? 'saved \u2013 leave blank to keep' : 'Cloudflare API token (Zone:DNS:Edit)';
    var form = h('div', {class: 'card'}, [h('h2', {text: 'Settings'}),
      h('div', {class: 'grid'}, [
        field('Domains (comma separated, wildcard allowed with DNS-01)', h('input', {type: 'text', id: 'f-domains', value: s.domains || ''})),
        field('Contact e-mail', h('input', {type: 'text', id: 'f-contactEmail', value: s.contactEmail || ''})),
        field('Certificate authority', sel('f-useStaging', [['true', 'Let\'s Encrypt STAGING (test, not trusted)'], ['false', 'Let\'s Encrypt production']], s.useStaging === 'false' ? 'false' : 'true')),
        field('Challenge type', sel('f-challengeType', [['dns-01', 'DNS-01 (no open port needed)'], ['http-01', 'HTTP-01 (needs port 80 from the internet)']], s.challengeType)),
        field('DNS provider', sel('f-dnsProvider', [['cloudflare', 'Cloudflare'], ['hook', 'Custom hook script']], s.dnsProvider)),
        field('Cloudflare API token', h('input', {type: 'password', id: 'f-cloudflareApiToken', placeholder: tokenPh, autocomplete: 'off'})),
        field('Cloudflare zone id (optional, auto-detected)', h('input', {type: 'text', id: 'f-cloudflareZoneId', value: s.cloudflareZoneId || ''})),
        field('DNS hook script (absolute path, for provider "hook")', h('input', {type: 'text', id: 'f-dnsHookScript', value: s.dnsHookScript || ''})),
        field('Renew when fewer than N days remain', h('input', {type: 'number', id: 'f-renewBeforeDays', min: 1, max: 89, value: s.renewBeforeDays || '30'})),
        h('div', {class: 'check'}, [h('input', {type: 'checkbox', id: 'f-autoRenew', checked: s.autoRenew === 'true'}),
          h('label', {for: 'f-autoRenew', text: 'Renew automatically (checked once a day)'})])]),
      h('div', {class: 'actions'}, [h('button', {class: 'primary', text: 'Save settings', onclick: save}), h('span', {id: 'savemsg', class: 'muted'})])]);
    kids.push(form);

    var l = state.last;
    var lastKids = [h('h2', {text: 'Last run'})];
    if (!l || !l.startedAt) lastKids.push(h('p', {class: 'muted', text: 'No run yet.'}));
    else {
      lastKids.push(h('p', {}, [h('span', {class: 'pill ' + (l.status === 'RENEWED' || l.status === 'UP_TO_DATE' ? 'ok' : l.status === 'RENEWAL_DUE' ? 'warn' : 'bad'), text: l.status || (l.success ? 'OK' : 'FAILED')}), ' ',
        l.mode + ' (' + l.trigger + ') ' + fmt(l.startedAt) + ' \u2192 ' + fmt(l.finishedAt) + ' \u2013 ' + (l.message || '')]));
      if (l.log) lastKids.push(h('pre', {text: l.log}));
    }
    kids.push(h('div', {class: 'card'}, lastKids));
    app.replaceChildren.apply(app, kids);
    renderSetup();
  }

  function val(id) { return document.getElementById(id).value; }
  function save() {
    var body = {domains: val('f-domains'), contactEmail: val('f-contactEmail'), useStaging: val('f-useStaging'),
      challengeType: val('f-challengeType'), dnsProvider: val('f-dnsProvider'), cloudflareApiToken: val('f-cloudflareApiToken'),
      cloudflareZoneId: val('f-cloudflareZoneId'), dnsHookScript: val('f-dnsHookScript'), renewBeforeDays: val('f-renewBeforeDays'),
      autoRenew: document.getElementById('f-autoRenew').checked ? 'true' : 'false'};
    var m = document.getElementById('savemsg'); m.textContent = 'Saving\u2026';
    api('settings', body).then(function (d) {
      if (d.error) { m.textContent = 'Error: ' + d.error; return; }
      m.textContent = d.warning ? 'Saved, but: ' + d.warning : 'Saved.';
      return load().then(function () { var n = document.getElementById('savemsg'); if (n) n.textContent = d.warning ? 'Saved, but: ' + d.warning : 'Saved.'; });
    });
  }
  function start(mode) {
    if (mode === 'force' && !window.confirm('Force a new certificate now? This replaces the installed certificate and restarts nginx.')) return;
    var m = document.getElementById('runmsg'); m.textContent = 'Starting\u2026';
    api('run', {mode: mode}).then(function (d) {
      if (d.network) { m.textContent = ''; showNotice('restart'); load(); return; }
      if (d.error) { m.textContent = 'Error: ' + d.error; return; }
      m.textContent = d.message;
      load();
    });
  }
  load();
  loadSetup();
})();
