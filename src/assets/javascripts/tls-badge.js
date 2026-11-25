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
    avoid();
    // other floating widgets (e.g. the Morpheus Copilot button) may load later
    [800, 2500, 6000].forEach(function (ms) { setTimeout(avoid, ms); });
    window.addEventListener('resize', avoid);
  }
  // Keep the badge clear of whatever floats above it in the same corner: move it left of the widget that covers it.
  function avoid() {
    a.style.right = '12px';
    var r = a.getBoundingClientRect();
    if (!r.width || !document.elementsFromPoint) return;
    var left = null, xs = [], ys = [r.top + 3, (r.top + r.bottom) / 2, r.bottom - 3];
    for (var x = r.left + 2; x < r.right; x += 6) xs.push(x);
    xs.forEach(function (x) {
      ys.forEach(function (y) {
        var stack = document.elementsFromPoint(x, y);
        for (var i = 0; i < stack.length && stack[i] !== a; i++) {
          var b = stack[i].getBoundingClientRect();
          // a small floating widget (not a page-wide layer) that covers part of the badge
          if (b.width > 0 && b.width < 220 && b.height < 220) left = left === null ? b.left : Math.min(left, b.left);
        }
      });
    });
    if (left !== null) a.style.right = Math.max(12, Math.round(window.innerWidth - left + 8)) + 'px';
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
