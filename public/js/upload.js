/* Upload page logic — drag & drop, progress, automatic encryption notice */
'use strict';

initApp('upload', 'Upload File', 'Files are automatically encrypted before they are stored', async (user) => {
  const content = document.getElementById('content');

  content.innerHTML = `
    <div class="card" style="max-width:640px">
      <h3>Upload a new file</h3>
      <div class="alert alert-info show">
        ${icon('lock')} <strong>Automatic encryption:</strong> your file is encrypted with <strong>AES-256-GCM</strong>
        before any data is written to disk on the server.
        Only authorised users can decrypt and download it.
      </div>

      <div class="drop-zone" id="drop-zone">
        <div class="big">${icon('upload')}</div>
        <p><strong>Drag and drop</strong> a file here, or <strong>click to browse</strong></p>
        <p class="text-muted" style="font-size:12.5px">Maximum size: 25 MB · Allowed: PDF, Word, Excel, TXT, CSV, PNG/JPG/WEBP</p>
      </div>
      <input type="file" id="file-input" accept=".pdf,.doc,.docx,.xls,.xlsx,.txt,.csv,.png,.jpg,.jpeg,.webp" style="display:none">

      <div id="file-preview" class="file-row mt-2" style="display:none">
        <span class="file-icon" id="preview-icon">${icon('file')}</span>
        <div class="meta">
          <div class="name" id="preview-name"></div>
          <div class="sub" id="preview-size"></div>
        </div>
        <button class="btn btn-ghost btn-sm" id="preview-clear" title="Remove file">${icon('x')}</button>
      </div>

      <div class="progress" id="progress"><div id="progress-bar"></div></div>
      <div id="upload-message"></div>

      <div class="modal-foot" style="margin-top:18px">
        <a href="/files.html" class="btn btn-ghost">Cancel</a>
        <button class="btn btn-primary" id="upload-btn" disabled>${icon('upload')} Upload and Encrypt</button>
      </div>
    </div>
  `;

  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');
  const preview = document.getElementById('file-preview');
  const previewName = document.getElementById('preview-name');
  const previewSize = document.getElementById('preview-size');
  const previewIcon = document.getElementById('preview-icon');
  const uploadBtn = document.getElementById('upload-btn');
  const progress = document.getElementById('progress');
  const progressBar = document.getElementById('progress-bar');
  const message = document.getElementById('upload-message');
  let selectedFile = null;

  function setFile(file) {
    if (!file) return;
    const allowed = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt', 'csv', 'png', 'jpg', 'jpeg', 'webp'];
    const ext = (file.name.split('.').pop() || '').toLowerCase();
    if (!allowed.includes(ext)) {
      toastError('Unsupported file type. Upload PDF, Word, Excel, TXT, CSV, PNG/JPG or WEBP only.');
      return;
    }
    if (file.size > 25 * 1024 * 1024) {
      toastError('File exceeds the maximum upload size of 25 MB.');
      return;
    }
    selectedFile = file;
    previewName.textContent = file.name;
    previewSize.textContent = formatBytes(file.size);
    previewIcon.className = 'file-icon ' + fileIconClass(file.name);
    previewIcon.innerHTML = icon(fileGlyph(file.name));
    preview.style.display = 'flex';
    uploadBtn.disabled = false;
  }

  dropZone.addEventListener('click', () => fileInput.click());
  dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('drag'); });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag'));
  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag');
    if (e.dataTransfer.files.length) setFile(e.dataTransfer.files[0]);
  });
  fileInput.addEventListener('change', () => { if (fileInput.files.length) setFile(fileInput.files[0]); });
  document.getElementById('preview-clear').addEventListener('click', () => {
    selectedFile = null;
    preview.style.display = 'none';
    fileInput.value = '';
    uploadBtn.disabled = true;
  });

  uploadBtn.addEventListener('click', async () => {
    if (!selectedFile) return;
    uploadBtn.disabled = true;
    progress.classList.add('show');
    progressBar.style.width = '15%';
    message.innerHTML = '';

    const form = new FormData();
    form.append('file', selectedFile);

    try {
      // Upload via XMLHttpRequest so we can show real upload progress.
      const xhr = new XMLHttpRequest();
      const result = await new Promise((resolve, reject) => {
        xhr.open('POST', '/api/files');
        xhr.setRequestHeader('X-CSRF-Token', API.csrfToken || '');
        xhr.upload.addEventListener('progress', (ev) => {
          if (ev.lengthComputable) progressBar.style.width = Math.round((ev.loaded / ev.total) * 80) + '%';
        });
        xhr.addEventListener('load', () => {
          progressBar.style.width = '100%';
          let data = null;
          try { data = JSON.parse(xhr.responseText); } catch {}
          if (xhr.status >= 200 && xhr.status < 300) resolve(data);
          else reject(new Error((data && data.error) || 'Upload failed (' + xhr.status + ')'));
        });
        xhr.addEventListener('error', () => reject(new Error('Network error during upload.')));
        xhr.send(form);
      });

      message.innerHTML = `<div class="alert alert-success show mt-2">${icon('check')} ${escapeHtml(result.message)}</div>`;
      toast('File uploaded and encrypted.', 'success');
      setTimeout(() => (window.location.href = '/files.html'), 1400);
    } catch (err) {
      message.innerHTML = `<div class="alert alert-error show mt-2">${escapeHtml(err.message)}</div>`;
      uploadBtn.disabled = false;
      progress.classList.remove('show');
    }
  });
});
