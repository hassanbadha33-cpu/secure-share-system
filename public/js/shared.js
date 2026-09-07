/* Shared with Me page logic — secure preview, view-once, expiry, download permission */
'use strict';

initApp('shared', 'Shared with Me', 'Open secure previews and download only when permission allows', async (user) => {
  const content = document.getElementById('content');
  content.innerHTML = `<div class="card">
    <div class="empty"><div class="big">${icon('clock')}</div><p>Loading files shared with you…</p></div>
  </div>`;

  let data;
  try { data = await API.get('/api/files/shared'); }
  catch (err) { toastError(err.message); return; }

  if (!data.files.length) {
    content.innerHTML = `<div class="card"><div class="empty">
      <div class="big">${icon('share')}</div>
      <p>No files have been shared with you yet.<br>
      When a colleague shares a file with you, it will appear here.</p>
    </div></div>`;
    return;
  }

  const active = data.files.filter((f) => f.access_active).length;
  const viewOnly = data.files.filter((f) => f.access_active && !f.can_download).length;
  const downloads = data.files.filter((f) => f.can_download).length;
  const inactive = data.files.length - active;

  content.innerHTML = `
    <div class="shared-hero">
      <div>
        <div class="hero-kicker-mini">Shared Access Control</div>
        <h3>Preview, download, expiry and view-once are enforced by the server.</h3>
        <p>Buttons are not only visual. Every preview and download request is checked against the file permission record before decryption.</p>
      </div>
      <div class="shared-stats">
        <div><strong>${active}</strong><span>Active</span></div>
        <div><strong>${viewOnly}</strong><span>View only</span></div>
        <div><strong>${downloads}</strong><span>Download</span></div>
        <div><strong>${inactive}</strong><span>Expired/used</span></div>
      </div>
    </div>

    <div class="permission-guide">
      <div class="guide-card">
        <div class="guide-icon">${icon('eye')}</div>
        <div><strong>View permission</strong><span>opens a secure in-browser preview. The file stays encrypted at rest and no download button is provided.</span></div>
      </div>
      <div class="guide-card">
        <div class="guide-icon">${icon('download')}</div>
        <div><strong>Download permission</strong><span>allows preview and a decrypted download after the server checks access permission.</span></div>
      </div>
      <div class="guide-card">
        <div class="guide-icon">${icon('clock')}</div>
        <div><strong>Expiry / View once</strong><span>access can expire by date or be consumed after one successful preview.</span></div>
      </div>
    </div>

    <div class="card">
      <div class="card-head"><h3>Files shared with you (${data.files.length})</h3></div>
      <div class="table-wrap"><table>
        <thead><tr>
          <th>File</th><th>Shared By</th><th>Permission</th><th>Status</th><th>Expires</th><th style="text-align:right">Actions</th>
        </tr></thead><tbody>
        ${data.files.map(row).join('')}
        </tbody></table></div>
    </div>`;

  function permissionBadge(f) {
    if (f.view_once) return '<span class="badge badge-once">VIEW ONCE</span>';
    return f.can_download ? '<span class="badge badge-download">DOWNLOAD</span>' : '<span class="badge badge-view">VIEW ONLY</span>';
  }

  function statusBadge(f) {
    if (f.access_active) return '<span class="badge badge-active">ACTIVE</span>';
    if (f.access_state === 'expired') return '<span class="badge badge-expired">EXPIRED</span>';
    if (f.access_state === 'view_once_used') return '<span class="badge badge-expired">USED</span>';
    return '<span class="badge badge-expired">BLOCKED</span>';
  }

  function row(f) {
    const actionButtons = f.access_active
      ? `<a class="btn btn-outline btn-sm" href="/api/files/${f.id}/preview" target="_blank" title="Open secure preview">${icon('eye')} Preview</a>
         ${f.can_download
          ? `<a class="btn btn-primary btn-sm" href="/api/files/${f.id}/download" title="Download decrypted copy">${icon('download')} Download</a>`
          : `<span class="text-muted view-note">Download blocked</span>`}`
      : `<span class="text-muted view-note">Access ${f.access_state === 'view_once_used' ? 'used' : 'expired'}</span>`;

    return `<tr>
      <td>
        <div class="flex gap-1" style="align-items:center">
          <span class="file-icon ${fileIconClass(f.original_name)}">${icon(fileGlyph(f.original_name))}</span>
          <div>
            <div class="cell-main">${escapeHtml(f.original_name)}</div>
            <div class="cell-sub">${f.size_formatted} · ${escapeHtml(f.mime_type || 'unknown type')}</div>
          </div>
        </div>
      </td>
      <td>${escapeHtml(f.shared_by_name || 'Unknown')}</td>
      <td>${permissionBadge(f)}</td>
      <td>${statusBadge(f)}</td>
      <td class="cell-sub">${f.expires_at ? formatDate(f.expires_at) : 'Never'}</td>
      <td><div class="flex gap-1" style="justify-content:flex-end; flex-wrap:wrap">${actionButtons}</div></td>
    </tr>`;
  }
});
