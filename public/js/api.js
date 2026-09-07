/* ============================================================
   Secure Share System — shared API client & icon system
   Vanilla JS: JSON requests, CSRF tokens, session state,
   SVG icon set (feather-style line icons, single colour).
   ============================================================ */

'use strict';

/* ------------------------- SVG icon set ------------------------- */

const ICONS = {
  home: '<path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/>',
  folder: '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>',
  upload: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>',
  share: '<circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>',
  file: '<path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/>',
  fileText: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>',
  activity: '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
  users: '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
  user: '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
  search: '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
  download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>',
  trash: '<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/>',
  info: '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
  x: '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
  plus: '<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
  edit: '<path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>',
  key: '<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>',
  inbox: '<polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>',
  database: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>',
  layers: '<polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  check: '<polyline points="20 6 9 17 4 12"/>',
  clock: '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>',
  lock: '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  eye: '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
  mail: '<path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/>',
  hash: '<line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/>',
};

/**
 * Render an SVG icon.
 * @param {string} name - key of ICONS
 * @returns {string} SVG markup (sized by CSS, inherits currentColor)
 */
function icon(name) {
  const body = ICONS[name] || ICONS.file;
  return '<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" ' +
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + body + '</svg>';
}

/* ------------------------- API client ------------------------- */

const API = {
  user: null,
  csrfToken: null,

  /** Low-level fetch wrapper. */
  async request(method, path, body) {
    const opts = { method, credentials: 'same-origin', headers: {} };
    let isForm = false;
    if (body instanceof FormData) {
      opts.body = body;
      isForm = true;
    } else if (body !== undefined && body !== null) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    if (['POST', 'PATCH', 'PUT', 'DELETE'].includes(method) && this.csrfToken) {
      opts.headers['X-CSRF-Token'] = this.csrfToken;
    }
    const res = await fetch(path, opts);
    let data = null;
    try { data = await res.json(); } catch (e) { /* empty body */ }
    if (!res.ok) {
      const err = new Error((data && data.error) || 'Request failed (' + res.status + ')');
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  },

  get(path) { return this.request('GET', path); },
  post(path, body) { return this.request('POST', path, body); },
  patch(path, body) { return this.request('PATCH', path, body); },
  del(path) { return this.request('DELETE', path); },

  /** Load the current session; returns user or null. */
  async loadSession() {
    try {
      const data = await this.get('/api/session');
      this.user = data.user;
      this.csrfToken = data.csrf_token;
      return data.user;
    } catch (e) {
      this.user = null;
      this.csrfToken = null;
      return null;
    }
  },

  async login(username, password) {
    const data = await this.post('/api/auth/login', { username, password });
    if (data.two_factor_required) return data;
    this.user = data.user;
    this.csrfToken = data.csrf_token;
    return data;
  },

  async verifyTwoFactor(challengeToken, code) {
    const data = await this.post('/api/auth/verify-2fa', { challenge_token: challengeToken, code });
    this.user = data.user;
    this.csrfToken = data.csrf_token;
    return data;
  },

  async resendTwoFactor(challengeToken) {
    return this.post('/api/auth/resend-2fa', { challenge_token: challengeToken });
  },

  async forgotPassword(identifier) {
    return this.post('/api/auth/forgot-password', { identifier });
  },

  async resetPassword(resetToken, code, newPassword) {
    return this.post('/api/auth/reset-password', { reset_token: resetToken, code, new_password: newPassword });
  },

  async logout() {
    try { await this.post('/api/auth/logout'); } catch (e) { /* ignore */ }
    this.user = null;
    this.csrfToken = null;
  },
};

/* ------------------------- Toast notifications ------------------------- */

function toast(message, type = 'info') {
  let wrap = document.querySelector('.toast-wrap');
  if (!wrap) {
    wrap = document.createElement('div');
    wrap.className = 'toast-wrap';
    document.body.appendChild(wrap);
  }
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.textContent = message;
  wrap.appendChild(el);
  setTimeout(() => {
    el.style.opacity = '0';
    el.style.transition = 'opacity .3s';
    setTimeout(() => el.remove(), 320);
  }, 4200);
}

function toastError(message) {
  toast(message || 'Something went wrong.', 'error');
}

/* ------------------------- Formatting helpers ------------------------- */

function formatBytes(bytes) {
  if (!bytes && bytes !== 0) return '—';
  if (bytes < 1024) return bytes + ' B';
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = bytes;
  let i = -1;
  do { v /= 1024; i++; } while (v >= 1024 && i < units.length - 1);
  return v.toFixed(1) + ' ' + units[i];
}

function formatDate(sqliteDate) {
  if (!sqliteDate) return '—';
  const s = String(sqliteDate).replace(' ', 'T') + 'Z';
  const d = new Date(s);
  if (isNaN(d.getTime())) return sqliteDate;
  return d.toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  });
}

function escapeHtml(str) {
  return String(str == null ? '' : str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/** CSS class for the file-type icon tile (all grey in the light theme). */
function fileIconClass(name) {
  const ext = (name.split('.').pop() || '').toLowerCase();
  const map = { txt: 'fi-txt', pdf: 'fi-pdf', doc: 'fi-doc', docx: 'fi-doc', xls: 'fi-xls', xlsx: 'fi-xls', png: 'fi-img', jpg: 'fi-img', jpeg: 'fi-img', gif: 'fi-img', webp: 'fi-img', zip: 'fi-zip', rar: 'fi-zip', '7z': 'fi-zip' };
  return map[ext] || 'fi-default';
}

/** SVG icon name for a file type. */
function fileGlyph(name) {
  const ext = (name.split('.').pop() || '').toLowerCase();
  const map = { txt: 'fileText', pdf: 'file', doc: 'fileText', docx: 'fileText', xls: 'fileText', xlsx: 'fileText' };
  return map[ext] || 'file';
}

function initials(name) {
  return String(name || '?').split(/\s+/).map((w) => w[0] || '').slice(0, 2).join('').toUpperCase();
}

function isAdminUser(user) {
  return user && user.role === 'admin' && (user.username === 'admin' || /admin/i.test(user.email || ''));
}

function userAvatarHtml(user, extraClass = '') {
  const cls = `avatar ${extraClass}`.trim();
  if (isAdminUser(user)) {
    return `<div class="${cls} avatar-photo" title="System Administrator"><img src="/assets/admin-profile.png" alt="${escapeHtml(user.full_name)} profile photo"></div>`;
  }
  return `<div class="${cls}">${initials(user && user.full_name)}</div>`;
}

function actionLabel(action) {
  const map = {
    login: 'Log In', login_failed: 'Failed Login', login_locked: 'Login Locked', login_denied: 'Login Denied',
    logout: 'Log Out', register: 'Registration', upload: 'File Upload', download: 'File Download',
    download_failed: 'Download Failed', preview: 'Secure Preview', preview_failed: 'Preview Failed', view_once_consumed: 'View Once Used', share: 'File Shared', revoke_share: 'Access Revoked',
    delete_file: 'File Deleted', access_denied: 'Access Denied', user_created: 'User Created',
    user_updated: 'User Updated', user_deleted: 'User Deleted', password_reset: 'Password Reset',
    password_changed: 'Password Changed', password_change_failed: 'Password Change Failed',
    profile_updated: 'Profile Updated',
    password_reset_requested: 'Reset Requested', password_reset_failed: 'Reset Failed', password_reset_completed: 'Password Reset',
    security_report_exported: 'Report Exported', security_alert_resolved: 'Alert Resolved',
    upload_blocked: 'Upload Blocked', view_once_consumed: 'View Once Used',
  };
  return map[action] || action;
}

/* ------------------------- App shell (sidebar + topbar) ------------------------- */

function renderShell(activePage) {
  const user = API.user;
  if (!user) return;
  const isAdmin = user.role === 'admin';

  const navItems = [
    { href: '/dashboard.html', icon: 'home', label: 'Dashboard', key: 'dashboard' },
    { href: '/files.html', icon: 'folder', label: 'My Files', key: 'files' },
    { href: '/upload.html', icon: 'upload', label: 'Upload File', key: 'upload' },
    { href: '/shared.html', icon: 'share', label: 'Shared with Me', key: 'shared' },
    { href: '/security.html', icon: 'shield', label: 'Security Center', key: 'security' },
    { href: '/logs.html', icon: 'activity', label: 'Activity Log', key: 'logs' },
  ];
  if (isAdmin) {
    navItems.push({ href: '/users.html', icon: 'users', label: 'Manage Users', key: 'users' });
  }
  navItems.push({ href: '/profile.html', icon: 'user', label: 'My Profile', key: 'profile' });

  const navHtml = navItems.map((n) =>
    `<li><a href="${n.href}" class="${n.key === activePage ? 'active' : ''}">
       <span class="icon">${icon(n.icon)}</span><span class="txt">${n.label}</span></a></li>`
  ).join('');

  const roleBadge = user.role === 'admin' ? 'badge-admin' : user.role === 'manager' ? 'badge-manager' : user.role === 'security_officer' ? 'badge-admin' : user.role === 'auditor' ? 'badge-manager' : 'badge-employee';

  const shell = `
  <div class="sidebar">
    <div class="brand">
      <div class="brand-logo">${icon('lock')}</div>
      <h1>Secure Share<small>Corporate Data Protection</small></h1>
    </div>
    <ul class="nav">${navHtml}</ul>
    <div class="sidebar-profile-card">
      ${userAvatarHtml(user, 'sidebar-avatar')}
      <div>
        <strong>${escapeHtml(user.full_name)}</strong>
        <span>${escapeHtml(user.role)} · active session</span>
      </div>
    </div>
    <div class="sidebar-footer">
      AES-256-GCM encryption<br>SQL database · RBAC access control
    </div>
  </div>
  <div class="main">
    <div class="topbar">
      <div>
        <h2 id="page-title"></h2>
        <div class="sub" id="page-sub"></div>
      </div>
      <div class="topbar-right">
        <span class="badge ${roleBadge}">${user.role}</span>
        <div class="user-chip">
          ${userAvatarHtml(user)}
          <div class="who">
            <b>${escapeHtml(user.full_name)}</b>
            <span>@${escapeHtml(user.username)}</span>
          </div>
        </div>
        <button class="btn btn-ghost btn-sm" id="logout-btn" title="Log out">${icon('logout')}</button>
      </div>
    </div>
    <div class="content" id="content">
      <!-- page content injected here -->
    </div>
  </div>`;

  const app = document.createElement('div');
  app.className = 'app';
  app.innerHTML = shell;
  document.body.innerHTML = '';
  document.body.appendChild(app);

  const logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      await API.logout();
      window.location.href = '/login.html';
    });
  }
}

/** Guard for authenticated pages: load session, render shell, run page init. */
async function initApp(activePage, title, sub, pageInit) {
  const user = await API.loadSession();
  if (!user) {
    window.location.href = '/login.html';
    return;
  }
  renderShell(activePage);
  document.getElementById('page-title').textContent = title;
  document.getElementById('page-sub').textContent = sub;
  if (typeof pageInit === 'function') pageInit(user);
}

/* ------------------------- Pagination builder ------------------------- */

function renderPagination(container, { page, total, per_page, onPage }) {
  const pages = Math.max(1, Math.ceil(total / per_page));
  if (pages <= 1) return;
  container.innerHTML = `
    <button class="btn btn-outline btn-sm" ${page <= 1 ? 'disabled' : ''} data-p="${page - 1}">Prev</button>
    <span class="page-info">Page ${page} of ${pages} · ${total} total</span>
    <button class="btn btn-outline btn-sm" ${page >= pages ? 'disabled' : ''} data-p="${page + 1}">Next</button>`;
  container.querySelectorAll('button[data-p]').forEach((b) => {
    b.addEventListener('click', () => onPage(Number(b.dataset.p)));
  });
}
