/* Dashboard page logic */
'use strict';

initApp('dashboard', 'Dashboard', 'Overview of your secure file vault', async (user) => {
  const content = document.getElementById('content');

  function statCard(iconName, value, label) {
    return `<div class="stat">
      <div class="icon">${icon(iconName)}</div>
      <div><div class="value">${value}</div><div class="label">${label}</div></div>
    </div>`;
  }

  function fileRow(f) {
    return `<div class="file-row">
      <div class="file-icon ${fileIconClass(f.original_name)}">${icon(fileGlyph(f.original_name))}</div>
      <div class="meta">
        <div class="name">${escapeHtml(f.original_name)}</div>
        <div class="sub">${formatBytes(f.size)} · ${formatDate(f.created_at)}${f.share_count ? ' · shared with ' + f.share_count + ' user(s)' : ''}</div>
      </div>
      <div class="actions">
        <a class="btn btn-outline btn-sm" href="/files.html">Manage</a>
      </div>
    </div>`;
  }

  function logRow(l) {
    return `<tr>
      <td><span class="badge">${escapeHtml(actionLabel(l.action))}</span></td>
      <td>${escapeHtml(l.details || '—')}</td>
      <td class="cell-sub">${formatDate(l.created_at)}</td>
    </tr>`;
  }

  let data;
  try {
    data = await API.get('/api/dashboard');
  } catch (err) {
    toastError(err.message);
    content.innerHTML = `<div class="card"><div class="empty">Could not load dashboard: ${escapeHtml(err.message)}</div></div>`;
    return;
  }

  const s = data.stats;
  let html = '';

  html += `<div class="dashboard-hero">
    <div class="dashboard-banner">
      <h3>Welcome, ${escapeHtml(user.full_name)}</h3>
      <p>Your workspace combines encrypted file storage, controlled sharing, role-based permissions, and activity monitoring in one system.</p>
      <div class="workflow-mini">
        <div>1. Upload</div>
        <div>2. Encrypt</div>
        <div>3. Share</div>
        <div>4. Audit</div>
      </div>
    </div>
    <div class="dashboard-side-card executive-card">
      <div class="executive-top">
        ${userAvatarHtml(user, 'executive-avatar')}
        <div>
          <h3>${user.role === 'admin' ? 'System Administrator' : 'Active User'}</h3>
          <p class="text-muted">${escapeHtml(user.full_name)} · <strong>${escapeHtml(user.role)}</strong></p>
        </div>
      </div>
      <div class="admin-trust-strip">
        <span>Verified session</span><span>Extended RBAC</span><span>Hash audit</span>
      </div>
      <div class="rbac-list">
        <div><strong>Admin</strong> · full users, files, logs and settings control</div>
        <div><strong>Security/Auditor</strong> · security center, reports and audit review</div>
        <div><strong>Manager/Employee</strong> · controlled upload, share and file access</div>
      </div>
    </div>
  </div>`;

  /* ---- Stats grid ---- */
  html += `<div class="stats-grid">
    ${statCard('folder', s.my_files, 'My Files')}
    ${statCard('database', s.my_storage_formatted, 'Storage Used')}
    ${statCard('share', s.shared_with_me, 'Active Shares For Me')}
    ${statCard('eye', s.my_preview_events || 0, 'My Preview Events')}
    ${statCard('shield', s.my_blocked_events || 0, 'Blocked Attempts')}
    ${statCard('layers', s.quota_formatted, 'Storage Quota')}
  </div>`;

  /* ---- Admin-only stats ---- */
  if (user.role === 'admin' && s.total_users !== undefined) {
    html += `<div class="card">
      <div class="card-head"><h3>Organization Overview</h3></div>
      <div class="stats-grid mb-0">
        ${statCard('users', s.total_users, 'Total Users')}
        ${statCard('folder', s.total_files, 'Total Files')}
        ${statCard('database', s.total_storage, 'Total Storage')}
        ${statCard('activity', s.total_logs, 'Logged Activities')}
      </div>
      <div class="mt-2">
        ${(s.users_by_role || []).map((r) => `<span class="badge" style="margin-right:6px">${escapeHtml(r.role)}: ${r.c}</span>`).join('')}
      </div>
    </div>
    <div class="card">
      <div class="card-head"><h3>Security Metrics</h3><a class="btn btn-outline btn-sm" href="/security.html">Open Security Center</a></div>
      <div class="stats-grid mb-0">
        ${statCard('eye', s.view_only_shares || 0, 'View-Only Shares')}
        ${statCard('download', s.download_shares || 0, 'Download Shares')}
        ${statCard('clock', s.view_once_shares || 0, 'View-Once Shares')}
        ${statCard('activity', s.blocked_access || 0, 'Blocked Attempts')}
      </div>
    </div>`;
  }

  /* ---- Recent files ---- */
  html += `<div class="card">
    <div class="card-head">
      <h3>Recent Files</h3>
      <a class="btn btn-outline btn-sm" href="/files.html">View all</a>
    </div>
    ${data.recent_files && data.recent_files.length
      ? data.recent_files.map(fileRow).join('')
      : `<div class="empty"><div class="big">${icon('folder')}</div><p>No files uploaded yet.<br><a href="/upload.html">Upload your first file</a> — it will be encrypted automatically.</p></div>`}
  </div>`;

  /* ---- Recent activity ---- */
  html += `<div class="card">
    <div class="card-head">
      <h3>Recent Activity</h3>
      <a class="btn btn-outline btn-sm" href="/logs.html">Full log</a>
    </div>
    ${data.recent_activity && data.recent_activity.length
      ? `<div class="table-wrap"><table><thead><tr><th>Action</th><th>Details</th><th>Time</th></tr></thead><tbody>${data.recent_activity.map(logRow).join('')}</tbody></table></div>`
      : `<div class="empty"><div class="big">${icon('activity')}</div><p>No activity recorded yet.</p></div>`}
  </div>`;

  content.innerHTML = html;
});
