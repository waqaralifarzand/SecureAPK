// Poll /api/analysis/<id>/status every 2 seconds while the analysis is running.
(function () {
  const id = window.SECUREAPK_ANALYSIS_ID;
  if (!id) return;
  const bar = document.getElementById('progress-bar');
  const phase = document.getElementById('current-phase');
  const pill = document.getElementById('status-pill');

  function tick() {
    fetch('/api/analysis/' + encodeURIComponent(id) + '/status')
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (!data) return;
        if (bar) bar.style.width = (data.progress_pct || 0) + '%';
        if (phase) phase.textContent = data.current_phase || '-';
        if (pill) {
          pill.className = 'pill pill-' + data.status;
          pill.textContent = data.status;
        }
        if (data.status !== 'running') {
          window.location.reload();
        }
      })
      .catch(function () { /* swallow transient errors; next tick retries */ });
  }

  setInterval(tick, 2000);
})();
