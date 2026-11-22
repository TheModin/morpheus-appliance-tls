(function () {
  // remember the user's Morpheus theme mode so the standalone admin page can follow it (same origin)
  try { var m = document.documentElement.getAttribute('data-mode'); if (m) localStorage.setItem('tls-theme-mode', m); } catch (e) { /* ignore */ }
  var a = document.getElementById('tls-badge');
  if (!a) return;
  var KEY = 'tls-badge', TTL = 5 * 60 * 1000;
  function show(c) {
    var st = c.state || 'UNREACHABLE';
    a.textContent = 'Certificate: ' + (st === 'OK' || st === 'RENEWAL_DUE' ? c.daysRemaining + ' days' : st.replace(/_/g, ' ').toLowerCase());
    a.className = 'tls-badge ' + (st === 'OK' ? 'ok' : st === 'RENEWAL_DUE' || st === 'STAGING' ? 'warn' : 'bad');
    a.style.display = 'block';
  }
  // reuse the last answer for a few minutes so ordinary page navigation costs no request at all
  try {
    var c = JSON.parse(sessionStorage.getItem(KEY) || 'null');
    if (c && Date.now() - c.t < TTL) { if (c.d) show(c.d); return; }
  } catch (e) { /* ignore */ }
  fetch('/plugin/tls/api/badge', {credentials: 'same-origin', headers: {'X-Requested-With': 'XMLHttpRequest'}})
    .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
    .then(function (d) { try { sessionStorage.setItem(KEY, JSON.stringify({t: Date.now(), d: d})); } catch (e) { /* ignore */ } show(d); })
    .catch(function () {
      // not allowed (or unavailable): stay hidden, and do not ask again for a while
      try { sessionStorage.setItem(KEY, JSON.stringify({t: Date.now(), d: null})); } catch (e) { /* ignore */ }
    });
})();
