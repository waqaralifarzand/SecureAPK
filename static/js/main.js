// Upload-card behaviour: drag-and-drop, selected-file preview, ADB health
// check, upload loading state, and double-submit prevention.
(function () {
  var dz = document.getElementById('dropzone');
  var input = document.getElementById('apk_file');
  var preview = document.getElementById('dropzone-file');
  var startBtn = document.getElementById('start-analysis');
  var form = document.getElementById('upload-form');
  var dynamicToggle = document.getElementById('dynamic-toggle');
  var adbStatus = document.getElementById('adb-status');
  if (!dz || !input) return;

  function humanSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  }

  function refresh() {
    var hasFile = !!(input.files && input.files[0]);
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

  // ADB health check when dynamic toggle is activated
  if (dynamicToggle && adbStatus) {
    dynamicToggle.addEventListener('change', function () {
      if (!dynamicToggle.checked) {
        adbStatus.hidden = true;
        return;
      }
      adbStatus.hidden = false;
      adbStatus.className = 'adb-status adb-checking';
      adbStatus.textContent = 'Checking emulator availability...';

      fetch('/api/health/adb')
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (data) {
          if (!data) {
            adbStatus.className = 'adb-status adb-warn';
            adbStatus.textContent = 'Could not check ADB status.';
            return;
          }
          if (!data.adb_installed) {
            adbStatus.className = 'adb-status adb-warn';
            adbStatus.textContent = 'ADB is not installed — dynamic analysis will be skipped.';
          } else if (!data.emulator_running) {
            adbStatus.className = 'adb-status adb-warn';
            adbStatus.textContent = 'No emulator detected — dynamic analysis will be skipped. Start an emulator via Android Studio → Device Manager.';
          } else {
            adbStatus.className = 'adb-status adb-ok';
            adbStatus.textContent = 'Emulator detected: ' + data.emulator_serial;
          }
        })
        .catch(function () {
          adbStatus.className = 'adb-status adb-warn';
          adbStatus.textContent = 'Could not check ADB status.';
        });
    });
  }

  // Upload loading state + double-submit prevention
  if (form && startBtn) {
    var submitted = false;
    form.addEventListener('submit', function () {
      if (submitted) { return false; }
      submitted = true;
      startBtn.disabled = true;
      startBtn.innerHTML = '<span class="spinner"></span> Uploading…';
    });
  }

  refresh();
})();
