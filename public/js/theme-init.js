// Runs before the page paints so the saved theme does not flash. (A separate file, because inline scripts are blocked by our CSP.)
(function () {
  var t = null;
  try { t = localStorage.getItem('securenotes-theme'); } catch (e) { /* storage blocked */ }
  if (t !== 'light' && t !== 'dark') t = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', t);
})();
