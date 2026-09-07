/* My Files page logic — share expiry, view-once access, history, preview, download, revoke */
'use strict';

let currentPage = 1;
let currentSearch = '';

initApp('files', 'My Files', 'Manage encrypted documents, sharing permissions, expiry and access history', async (user) => {
  const content = document.getElementById('content');

  content.innerHTML = `
    <div class="toolbar">
      <div class="search-box">
        <span class="icon">${icon('search')}</span>
        <input type="search" id="search-input" placeholder="Search encrypted files by name…" value="">
      </div>
      <a href="/upload.html" class="btn btn-primary">${icon('upload')} Upload File</a>
    </div>

    <div class="permission-guide mb-2">
      <div class="guide-card compact">
        <div class="guide-icon">${icon('eye')}</div>
        <div><strong>View only</strong><span>Preview allowed, download blocked.</span></div>
      </div>
      <div class="guide-card compact">
        <div class="guide-icon">${icon('clock')}</div>
        <div><strong>Expiry</strong><span>Access can expire automatically.</span></div>
      </div>
      <div class="guide-card compact">
        <div class="guide-icon">${icon('shield')}</div>
        <div><strong>View once</strong><span>Single preview, then access is consumed.</span></div>
      </div>
    </div>

    <div class="card" id="files-card">
      <div class="empty"><div class="big">${icon('clock')}</div><p>Loading files…</p></div>
    </div>
    <div class="pagination" id="pagination"></div>
  `;

  const searchInput = document.getElementById('search-input');
  let debounce;
  searchInput.addEventListener('input', () => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      currentSearch = searchInput.value.trim();
      currentPage = 1;
      loadFiles();
    }, 350);
  });

  async function loadFiles() {
    const card = document.getElementById('files-card');
    let data;
    try {
      data = await API.get(`/api/files?page=${currentPage}&per_page=10&search=${encodeURIComponent(currentSearch)}`);
    } catch (err) {
      card.innerHTML = `<div class="empty">${escapeHtml(err.message)}</div>`;
      return;
    }

    if (!data.files.length) {
      card.innerHTML = `<div class="empty">
        <div class="big">${icon('folder')}</div>
        <p>${currentSearch ? 'No files match your search.' : 'You have no files yet.'}<br>
        ${currentSearch ? '' : '<a href="/upload.html">Upload your first file</a> — it will be AES-256 encrypted before storage.'}</p>
      </div>`;
      document.getElementById('pagination').innerHTML = '';
      return;
    }

    card.innerHTML = `<div class="table-wrap"><table>
      <thead><tr>
        <th>File</th><th>Size</th><th>Uploaded</th><th>Shared With</th><th style="text-align:right">Actions</th>
      </tr></thead><tbody>
      ${data.files.map(fileTableRow).join('')}
      </tbody></table></div>`;

    renderPagination(document.getElementById('pagination'), {
      page: data.page, total: data.total, per_page: data.per_page, onPage: (p) => { currentPage = p; loadFiles(); },
    });
  }

  function fileTableRow(f) {
    const shared = f.shared_with_names ? '@' + f.shared_with_names : (f.share_count ? `${f.share_count} user(s)` : '—');
    return `<tr>
      <td>
        <div class="flex gap-1" style="align-items:center">
          <span class="file-icon ${fileIconClass(f.original_name)}">${icon(fileGlyph(f.original_name))}</span>
          <div>
            <div class="cell-main">${escapeHtml(f.original_name)}</div>
            <div class="cell-sub">${escapeHtml(f.mime_type || 'unknown type')} · encrypted at rest</div>
          </div>
        </div>
      </td>
      <td class="cell-sub">${f.size_formatted}</td>
      <td class="cell-sub">${formatDate(f.created_at)}</td>
      <td class="cell-sub">${shared}</td>
      <td>
        <div class="flex gap-1" style="justify-content:flex-end; flex-wrap:wrap">
          <a class="btn btn-outline btn-sm" href="/api/files/${f.id}/preview" target="_blank" title="Open secure preview">${icon('eye')} Preview</a>
          <button class="btn btn-outline btn-sm" data-action="share" data-id="${f.id}" title="Share file">${icon('share')} Share</button>
          <button class="btn btn-outline btn-sm" data-action="info" data-id="${f.id}" title="Details, access and history">${icon('info')} Info</button>
          <a class="btn btn-outline btn-sm" href="/api/files/${f.id}/download" title="Download decrypted copy">${icon('download')}</a>
          <button class="btn btn-danger-outline btn-sm" data-action="delete" data-id="${f.id}" title="Delete">${icon('trash')}</button>
        </div>
      </td>
    </tr>`;
  }

  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-action]');
    if (!btn || !document.body.contains(btn)) return;
    const id = btn.dataset.id;
    const action = btn.dataset.action;
    if (action === 'share') return openShareModal(id);
    if (action === 'info') return openInfoModal(id);
    if (action === 'delete') return confirmDelete(id);
  });

  async function openShareModal(fileId) {
    const modal = document.createElement('div');
    modal.className = 'modal-overlay show';
    modal.innerHTML = `
      <div class="modal modal-wide">
        <div class="modal-head">
          <h3>${icon('share')} Share File Securely</h3>
          <button class="modal-close" data-close>${icon('x')}</button>
        </div>
        <div class="share-options-grid">
          <div class="share-panel">
            <div class="field">
              <label for="share-username">Recipient (username or email)</label>
              <input type="text" id="share-username" placeholder="e.g. employee" autocomplete="off">
            </div>
            <div class="field">
              <label for="share-permission">Permission</label>
              <select id="share-permission">
                <option value="download">Download — preview + download decrypted copy</option>
                <option value="view">View only — preview in browser, no download</option>
              </select>
            </div>
            <div class="field">
              <label for="share-expiry">Access expiry</label>
              <select id="share-expiry">
                <option value="0">No expiry</option>
                <option value="1">Expires in 1 day</option>
                <option value="3">Expires in 3 days</option>
                <option value="7" selected>Expires in 7 days</option>
                <option value="14">Expires in 14 days</option>
                <option value="30">Expires in 30 days</option>
              </select>
            </div>
            <label class="check-row">
              <input type="checkbox" id="share-view-once">
              <span><strong>View once</strong><small>Recipient can preview the file one time only. Download is disabled automatically.</small></span>
            </label>
            <div class="alert alert-error" id="share-error"></div>
            <div class="modal-foot">
              <button class="btn btn-ghost" data-close>Cancel</button>
              <button class="btn btn-primary" id="share-submit">Share Securely</button>
            </div>
          </div>
          <div class="share-explain">
            <h4>Permission rules</h4>
            <div class="rule-row"><span class="badge badge-view">VIEW</span><p>Can open secure preview. Cannot download decrypted copy.</p></div>
            <div class="rule-row"><span class="badge badge-download">DOWNLOAD</span><p>Can preview and download after server permission check.</p></div>
            <div class="rule-row"><span class="badge badge-once">VIEW ONCE</span><p>One successful preview consumes the share.</p></div>
            <div class="rule-row"><span class="badge">AUDIT</span><p>Share, preview, download, revoke and denied attempts are logged.</p></div>
          </div>
        </div>
      </div>`;
    document.body.appendChild(modal);

    modal.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', () => modal.remove()));
    modal.addEventListener('click', (e) => { if (e.target === modal) modal.remove(); });

    const permissionSelect = document.getElementById('share-permission');
    const viewOnce = document.getElementById('share-view-once');
    viewOnce.addEventListener('change', () => {
      if (viewOnce.checked) permissionSelect.value = 'view';
      permissionSelect.disabled = viewOnce.checked;
    });

    const errorBox = document.getElementById('share-error');
    document.getElementById('share-submit').addEventListener('click', async () => {
      const username = document.getElementById('share-username').value.trim();
      const permission = permissionSelect.value;
      const expiry_days = Number(document.getElementById('share-expiry').value);
      const view_once = viewOnce.checked;
      if (!username) { errorBox.textContent = 'Please enter the recipient username or email.'; errorBox.classList.add('show'); return; }
      try {
        await API.post(`/api/files/${fileId}/share`, { username, permission, expiry_days, view_once });
        modal.remove();
        toast('Secure share created successfully.', 'success');
        loadFiles();
      } catch (err) {
        errorBox.textContent = err.message;
        errorBox.classList.add('show');
      }
    });
  }

  async function openInfoModal(fileId) {
    let data;
    try { data = await API.get(`/api/files/${fileId}`); }
    catch (err) { toastError(err.message); return; }

    const f = data.file;
    const modal = document.createElement('div');
    modal.className = 'modal-overlay show';
    modal.innerHTML = `
      <div class="modal modal-wide">
        <div class="modal-head">
          <h3>${icon('info')} File Details & Access History</h3>
          <button class="modal-close" data-close>${icon('x')}</button>
        </div>
        <div class="detail-grid">
          <div class="detail-item"><div class="k">File name</div><div class="v">${escapeHtml(f.original_name)}</div></div>
          <div class="detail-item"><div class="k">Size</div><div class="v">${f.size_formatted}</div></div>
          <div class="detail-item"><div class="k">Type</div><div class="v">${escapeHtml(f.mime_type)}</div></div>
          <div class="detail-item"><div class="k">Encryption</div><div class="v">AES-256-GCM</div></div>
          <div class="detail-item"><div class="k">Uploaded</div><div class="v">${formatDate(f.created_at)}</div></div>
          <div class="detail-item"><div class="k">File ID</div><div class="v mono">#${f.id}</div></div>
        </div>

        ${data.is_owner ? `
        <div class="section-title-row"><h3>People with access</h3><span class="text-muted">Owner can revoke anytime</span></div>
        <div id="access-list">${renderAccessList(data.shares, fileId)}</div>
        <div class="field mt-2">
          <label for="info-share-username">Grant access to another user</label>
          <div class="flex gap-1 responsive-stack">
            <input type="text" id="info-share-username" placeholder="username or email">
            <select id="info-share-permission" style="max-width:160px">
              <option value="download">Download</option>
              <option value="view">View only</option>
            </select>
            <select id="info-share-expiry" style="max-width:145px">
              <option value="0">No expiry</option>
              <option value="1">1 day</option>
              <option value="7" selected>7 days</option>
              <option value="30">30 days</option>
            </select>
            <label class="mini-check"><input type="checkbox" id="info-share-once"> View once</label>
            <button class="btn btn-primary btn-sm" id="info-share-btn">Share</button>
          </div>
          <div class="alert alert-error mt-1" id="info-share-error"></div>
        </div>` : `<div class="alert alert-info show mb-0">You have <strong>${f.can_download ? 'download' : 'view'}</strong> access to this file.</div>`}

        <div class="section-title-row mt-2"><h3>Recent access history</h3><span class="text-muted">Preview, download, share and denied actions</span></div>
        <div id="file-history">${renderHistory(data.access_history)}</div>

        <div class="modal-foot">
          <a class="btn btn-outline" href="/api/files/${fileId}/preview" target="_blank">${icon('eye')} Preview</a>
          ${data.is_owner ? `<a class="btn btn-outline" href="/api/files/${fileId}/download">${icon('download')} Download</a>` : ''}
          <button class="btn btn-ghost" data-close>Close</button>
        </div>
      </div>`;
    document.body.appendChild(modal);

    modal.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', () => modal.remove()));
    modal.addEventListener('click', async (e) => {
      if (e.target === modal) modal.remove();
      const revoke = e.target.closest('[data-revoke]');
      if (revoke) {
        const shareId = revoke.dataset.revoke;
        try {
          await API.del(`/api/files/${fileId}/shares/${shareId}`);
          toast('Access revoked.', 'success');
          const fresh = await API.get(`/api/files/${fileId}`);
          document.getElementById('access-list').innerHTML = renderAccessList(fresh.shares, fileId);
          document.getElementById('file-history').innerHTML = renderHistory(fresh.access_history);
        } catch (err) { toastError(err.message); }
      }
    });

    if (data.is_owner) {
      const pSelect = document.getElementById('info-share-permission');
      const once = document.getElementById('info-share-once');
      once.addEventListener('change', () => { if (once.checked) pSelect.value = 'view'; pSelect.disabled = once.checked; });
      document.getElementById('info-share-btn').addEventListener('click', async () => {
        const username = document.getElementById('info-share-username').value.trim();
        const permission = pSelect.value;
        const expiry_days = Number(document.getElementById('info-share-expiry').value);
        const view_once = once.checked;
        const errBox = document.getElementById('info-share-error');
        errBox.classList.remove('show');
        if (!username) { errBox.textContent = 'Enter a username.'; errBox.classList.add('show'); return; }
        try {
          await API.post(`/api/files/${fileId}/share`, { username, permission, expiry_days, view_once });
          toast('Access granted.', 'success');
          const fresh = await API.get(`/api/files/${fileId}`);
          document.getElementById('access-list').innerHTML = renderAccessList(fresh.shares, fileId);
          document.getElementById('file-history').innerHTML = renderHistory(fresh.access_history);
        } catch (err) {
          errBox.textContent = err.message;
          errBox.classList.add('show');
        }
      });
    }
  }

  function permissionBadge(s) {
    if (s.view_once) return '<span class="badge badge-once">VIEW ONCE</span>';
    if (s.permission === 'download') return '<span class="badge badge-download">DOWNLOAD</span>';
    return '<span class="badge badge-view">VIEW ONLY</span>';
  }

  function statusBadge(s) {
    if (!s.access_active && s.access_state === 'expired') return '<span class="badge badge-expired">EXPIRED</span>';
    if (!s.access_active && s.access_state === 'view_once_used') return '<span class="badge badge-expired">USED</span>';
    return '<span class="badge badge-active">ACTIVE</span>';
  }

  function renderAccessList(shares, fileId) {
    if (!shares || !shares.length) return `<p class="text-muted">No one has access yet. Use the form below to share this file.</p>`;
    return `<div class="table-wrap"><table>
      <thead><tr><th>User</th><th>Permission</th><th>Status</th><th>Expires</th><th>Last Access</th><th></th></tr></thead>
      <tbody>${shares.map((s) => `
        <tr>
          <td><b>${escapeHtml(s.full_name)}</b> <span class="cell-sub">(@${escapeHtml(s.username)})</span></td>
          <td>${permissionBadge(s)}</td>
          <td>${statusBadge(s)}</td>
          <td class="cell-sub">${s.expires_at ? formatDate(s.expires_at) : 'Never'}</td>
          <td class="cell-sub">${s.last_accessed_at ? formatDate(s.last_accessed_at) : 'Not yet'}</td>
          <td class="text-right"><button class="btn btn-danger-outline btn-sm" data-revoke="${s.id}">Revoke</button></td>
        </tr>`).join('')}
      </tbody></table></div>`;
  }

  function renderHistory(items) {
    if (!items || !items.length) return `<div class="empty compact-empty">No access history yet for this file.</div>`;
    return `<div class="history-list">${items.map((l) => `
      <div class="history-item">
        <span class="badge">${escapeHtml(actionLabel(l.action))}</span>
        <div><strong>${escapeHtml(l.username || '(system)')}</strong><p>${escapeHtml(l.details || '—')}</p></div>
        <time>${formatDate(l.created_at)}</time>
      </div>`).join('')}</div>`;
  }

  async function confirmDelete(fileId) {
    if (!confirm('Delete this file permanently? Encrypted data and all shares will be removed.')) return;
    try {
      await API.del(`/api/files/${fileId}`);
      toast('File deleted.', 'success');
      loadFiles();
    } catch (err) {
      toastError(err.message);
    }
  }

  loadFiles();
});
