/* Security Center — live security status, permission matrix and audit evidence */
'use strict';

initApp('security', 'Security Center', 'Live security posture, permission model and audit evidence', async (user) => {
  const content = document.getElementById('content');
  content.innerHTML = `<div class="card"><div class="empty"><div class="big">${icon('clock')}</div><p>Loading security center…</p></div></div>`;

  let data;
  try { data = await API.get('/api/security/overview'); }
  catch (err) {
    toastError(err.message);
    content.innerHTML = `<div class="card"><div class="empty">Could not load security overview: ${escapeHtml(err.message)}</div></div>`;
    return;
  }

  const m = data.metrics;
  content.innerHTML = `
    <div class="security-hero-card pro-security-hero">
      <div>
        <div class="hero-kicker-mini">Project Defense Ready</div>
        <h3>Secure Share proves encryption, permission enforcement, and auditability.</h3>
        <p>The system does not only hide buttons. The backend checks each preview, download, share, revoke, denied request, and admin verification before granting access.</p>
        <div class="flex gap-1 mt-2 responsive-stack"><a class="btn btn-primary btn-sm" href="/api/security/report">${icon('download')} Export Security Report</a><button class="btn btn-outline btn-sm" id="refresh-security">${icon('activity')} Refresh</button></div>
      </div>
      <div class="security-score">
        <strong>${data.controls.length}</strong><span>active controls</span>
      </div>
    </div>

    <div class="stats-grid">
      ${stat('lock', m.encrypted_files, 'Encrypted Files')}
      ${stat('database', m.encrypted_storage, 'Encrypted Storage')}
      ${stat('share', m.active_shares, 'Active Shares')}
      ${stat('eye', m.view_only_shares, 'View Shares')}
      ${stat('download', m.download_shares, 'Download Shares')}
      ${stat('clock', m.view_once_shares, 'View Once Shares')}
      ${stat('activity', m.blocked_attempts, 'Blocked Attempts')}
      ${stat('shield', m.preview_events, 'Preview Events')}
      ${stat('key', m.admin_2fa_success, 'Admin 2FA Success')}
      ${stat('lock', m.admin_2fa_failed, 'Admin 2FA Failed')}
      ${stat('mail', m.admin_2fa_delivery, '2FA Delivery')}
      ${stat('hash', m.audit_integrity, 'Audit Integrity')}
      ${stat('shield', m.open_alerts, 'Open Alerts')}
    </div>

    <div class="security-grid">
      ${data.controls.map((c) => controlCard(c)).join('')}
    </div>

    <div class="card">
      <div class="card-head"><h3>Permission Model</h3></div>
      <div class="table-wrap"><table>
        <thead><tr><th>Permission</th><th>Allowed</th><th>Blocked</th><th>Server-side result</th></tr></thead>
        <tbody>
          <tr><td><span class="badge badge-view">VIEW ONLY</span></td><td>Secure browser preview</td><td>Decrypted download</td><td>Preview logged; download denied and logged</td></tr>
          <tr><td><span class="badge badge-download">DOWNLOAD</span></td><td>Preview and download</td><td>Unauthorized users</td><td>Both requests checked and logged</td></tr>
          <tr><td><span class="badge badge-once">VIEW ONCE</span></td><td>One successful preview</td><td>Second preview/download</td><td>Opened time saved; future preview blocked</td></tr>
          <tr><td><span class="badge badge-expired">EXPIRED</span></td><td>Nothing after expiry</td><td>Preview/download</td><td>Access denied with reason</td></tr>
          <tr><td><span class="badge badge-active">ADMIN 2FA</span></td><td>Password + 6-digit code</td><td>Password-only admin access</td><td>Challenge generated, delivered, verified, and logged</td></tr>
          <tr><td><span class="badge badge-active">EMAIL OTP</span></td><td>SMTP email delivery when configured</td><td>Browser-exposed codes in production</td><td>Uses masked destination and terminal fallback for local demo</td></tr>
        </tbody>
      </table></div>
    </div>

    <div class="card">
      <div class="card-head"><h3>Security Workflow</h3></div>
      <div class="workflow-track">
        <div><span>1</span><strong>Login</strong><em>Session created</em></div>
        <div><span>2</span><strong>Upload</strong><em>File validated</em></div>
        <div><span>3</span><strong>Encrypt</strong><em>AES-256-GCM</em></div>
        <div><span>4</span><strong>Share</strong><em>Permission + expiry</em></div>
        <div><span>5</span><strong>Preview/Download</strong><em>Server check</em></div>
        <div><span>6</span><strong>Audit</strong><em>Action recorded</em></div>
      </div>
    </div>

    <div class="card">
      <div class="card-head"><h3>Tamper-Resistant Audit Integrity</h3></div>
      <div class="permission-guide mb-0">
        <div class="guide-card compact"><div class="guide-icon">${icon('hash')}</div><div><strong>${escapeHtml(data.audit_integrity.ok ? 'Audit chain intact' : 'Audit chain broken')}</strong><span>${escapeHtml(data.audit_integrity.reason)} · checked ${escapeHtml(data.audit_integrity.checked)} log entries.</span></div></div>
        <div class="guide-card compact"><div class="guide-icon">${icon('activity')}</div><div><strong>Hash-linked records</strong><span>Every log entry stores previous hash + entry hash, so later editing can be detected.</span></div></div>
      </div>
    </div>

    <div class="card">
      <div class="card-head"><h3>Security Alerts</h3><span class="text-muted">High-risk activity becomes reviewable alerts</span></div>
      ${renderAlerts(data.recent_alerts)}
    </div>

    <div class="card">
      <div class="card-head"><h3>Recent Security Events</h3><a class="btn btn-outline btn-sm" href="/logs.html">Open full logs</a></div>
      ${renderEvents(data.recent_security_events)}
    </div>
  `;

  document.getElementById('refresh-security')?.addEventListener('click', () => window.location.reload());

  function stat(iconName, value, label) {
    return `<div class="stat"><div class="icon">${icon(iconName)}</div><div><div class="value">${escapeHtml(value)}</div><div class="label">${escapeHtml(label)}</div></div></div>`;
  }

  function controlCard(c) {
    return `<div class="security-control-card">
      <div class="control-icon">${icon('shield')}</div>
      <h3>${escapeHtml(c.name)}</h3>
      <span class="badge badge-active">${escapeHtml(c.status)}</span>
      <p>${escapeHtml(c.detail)}</p>
    </div>`;
  }

  function renderAlerts(items) {
    if (!items || !items.length) return `<div class="empty compact-empty">No security alerts recorded yet.</div>`;
    return `<div class="history-list">${items.map((a) => `
      <div class="history-item">
        <span class="badge ${a.severity === 'high' ? 'badge-expired' : 'badge-active'}">${escapeHtml(a.severity || 'medium')}</span>
        <div><strong>${escapeHtml(a.title || 'Security alert')}</strong><p>${escapeHtml(a.details || '—')}</p></div>
        <time>${formatDate(a.created_at)}</time>
      </div>`).join('')}</div>`;
  }

  function renderEvents(items) {
    if (!items || !items.length) return `<div class="empty compact-empty">No security events recorded yet.</div>`;
    return `<div class="history-list">${items.map((l) => `
      <div class="history-item">
        <span class="badge">${escapeHtml(actionLabel(l.action))}</span>
        <div><strong>${escapeHtml(l.username || '(system)')}</strong><p>${escapeHtml(l.details || '—')}</p></div>
        <time>${formatDate(l.created_at)}</time>
      </div>`).join('')}</div>`;
  }
});
