// Drag-and-drop upload helper.
(function () {
  const dz = document.getElementById('dropzone');
  const input = document.getElementById('apk_file');
  const label = document.getElementById('dropzone-file');
  if (!dz || !input) return;

  function showName() {
    if (input.files && input.files[0]) {
      label.textContent = input.files[0].name + ' (' + input.files[0].size + ' bytes)';
    }
  }

  input.addEventListener('change', showName);

  ['dragenter', 'dragover'].forEach(function (evt) {
    dz.addEventListener(evt, function (e) { e.preventDefault(); dz.classList.add('dragover'); });
  });
  ['dragleave', 'drop'].forEach(function (evt) {
    dz.addEventListener(evt, function (e) { e.preventDefault(); dz.classList.remove('dragover'); });
  });
  dz.addEventListener('drop', function (e) {
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) {
      input.files = e.dataTransfer.files;
      showName();
    }
  });
})();
