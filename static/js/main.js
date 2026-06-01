// Upload-card behaviour: drag-and-drop, selected-file preview, and the
// "Start Analysis" button stays disabled until an APK has been chosen.
// Presentation only — no analysis logic here (Phase 10 redesign).
(function () {
  const dz = document.getElementById('dropzone');
  const input = document.getElementById('apk_file');
  const preview = document.getElementById('dropzone-file');
  const startBtn = document.getElementById('start-analysis');
  if (!dz || !input) return;

  function humanSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  }

  function refresh() {
    const hasFile = !!(input.files && input.files[0]);
    if (hasFile && preview) {
      preview.textContent = input.files[0].name + ' (' + humanSize(input.files[0].size) + ')';
      preview.hidden = false;
    } else if (preview) {
      preview.textContent = '';
      preview.hidden = true;
    }
    if (startBtn) startBtn.disabled = !hasFile;
  }

  input.addEventListener('change', refresh);

  ['dragenter', 'dragover'].forEach(function (evt) {
    dz.addEventListener(evt, function (e) { e.preventDefault(); dz.classList.add('dragover'); });
  });
  ['dragleave', 'drop'].forEach(function (evt) {
    dz.addEventListener(evt, function (e) { e.preventDefault(); dz.classList.remove('dragover'); });
  });
  dz.addEventListener('drop', function (e) {
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) {
      input.files = e.dataTransfer.files;
      refresh();
    }
  });

  // Initialise on load (covers browser form-restore re-populating the input).
  refresh();
})();
