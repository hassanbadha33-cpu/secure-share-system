/* Admin — Manage Users page logic */
'use strict';

initApp('users', 'Manage Users', 'Administrator — user accounts, roles and access control (RBAC)', async (user) => {
  if (user.role !== 'admin') {
    window.location.href = '/dashboard.html';
    return;
  }

  const content = document.getElementById('content');
  const ROLE_OPTIONS = [
    ['employee', 'Employee — normal upload and shared access'],
    ['manager', 'Manager — collaboration and team oversight'],
    ['security_officer', 'Security Officer — security center and alerts'],
    ['auditor', 'Auditor — read-only audit review'],
    ['hr_officer', 'HR Officer — HR document workspace'],
    ['finance_officer', 'Finance Officer — finance document workspace'],
    ['external_partner', 'External Partner — temporary shared-file access only'],
    ['admin', 'Administrator — full system control'],
  ];
  const roleOptions = (selected) => ROLE_OPTIONS.map(([value, label]) => `<option value="${value}" ${selected === value ? 'selected' : ''}>${label}</option>`).join('');
  content.innerHTML = `
    <div class="toolbar">
      <div class="search-box">
        <span class="icon">${icon('search')}</span>
        <input type="search" id="user-search" placeholder="Search users…">
      </div>
      <button class="btn btn-primary" id="add-user-btn">${icon('plus')} New User</button>
    </div>
    <div class="card" id="users-card"><div class="empty"><div class="big">${icon('clock')}</div><p>Loading users…</p></div></div>
  `;

  let search = '';
  document.getElementById('user-search').addEventListener('input', (e) => {
    clearTimeout(window.__userSearchT);
    window.__userSearchT = setTimeout(() => { search = e.target.value.trim(); loadUsers(); }, 300);
  });

  async function loadUsers() {
    const card = document.getElementById('users-card');
    let data;
    try {
      data = await API.get('/api/admin/users?search=' + encodeURIComponent(search));
    } catch (err) {
      card.innerHTML = `<div class="empty">${escapeHtml(err.message)}</div>`;
      return;
    }

    if (!data.users.length) {
      card.innerHTML = `<div class="empty"><div class="big">${icon('users')}</div><p>No users found.</p></div>`;
      return;
    }

    card.innerHTML = `<div class="table-wrap"><table>
      <thead><tr>
        <th>User</th><th>Role</th><th>Status</th><th>Files</th><th>Storage</th><th>Joined</th><th style="text-align:right">Actions</th>
      </tr></thead><tbody>
      ${data.users.map((u) => `
        <tr>
          <td>
            <div class="flex gap-1" style="align-items:center">
              ${userAvatarHtml(u, 'user-table-avatar')}
              <div>
                <div class="cell-main">${escapeHtml(u.full_name)}</div>
                <div class="cell-sub">@${escapeHtml(u.username)} · ${escapeHtml(u.email)}</div>
              </div>
            </div>
          </td>
          <td><span class="badge">${escapeHtml(u.role.replace(/_/g, ' '))}</span></td>
          <td><span class="badge">${escapeHtml(u.status)}</span></td>
          <td class="cell-sub">${u.file_count}</td>
          <td class="cell-sub">${u.storage_formatted}</td>
          <td class="cell-sub">${formatDate(u.created_at)}</td>
          <td>
            <div class="flex gap-1" style="justify-content:flex-end; flex-wrap:wrap">
              <button class="btn btn-outline btn-sm" data-user-edit="${u.id}">${icon('edit')} Edit</button>
              <button class="btn btn-outline btn-sm" data-user-reset="${u.id}">${icon('key')} Reset PW</button>
              ${u.id !== user.id ? `<button class="btn btn-danger-outline btn-sm" data-user-delete="${u.id}" title="Delete user">${icon('trash')}</button>` : ''}
            </div>
          </td>
        </tr>`).join('')}
      </tbody></table></div>`;
  }

  /* ---- Open edit modal ---- */
  async function openEditModal(userId) {
    let users;
    try { users = (await API.get('/api/admin/users')).users; } catch (err) { toastError(err.message); return; }
    const u = users.find((x) => x.id === userId);
    if (!u) return;

    const modal = document.createElement('div');
    modal.className = 'modal-overlay show';
    modal.innerHTML = `
      <div class="modal">
        <div class="modal-head"><h3>${icon('edit')} Edit ${escapeHtml(u.full_name)}</h3><button class="modal-close" data-close>${icon('x')}</button></div>
        <div class="field">
          <label>Role (Role-Based Access Control)</label>
          <select id="edit-role">${roleOptions(u.role)}</select>
        </div>
        <div class="field">
          <label>Account Status</label>
          <select id="edit-status">
            <option value="active" ${u.status === 'active' ? 'selected' : ''}>Active</option>
            <option value="suspended" ${u.status === 'suspended' ? 'selected' : ''}>Suspended (blocks login and access)</option>
          </select>
        </div>
        <div class="alert alert-error" id="edit-error"></div>
        <div class="modal-foot">
          <button class="btn btn-ghost" data-close>Cancel</button>
          <button class="btn btn-primary" id="edit-save">Save Changes</button>
        </div>
      </div>`;
    document.body.appendChild(modal);
    modal.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', () => modal.remove()));
    modal.addEventListener('click', (e) => { if (e.target === modal) modal.remove(); });

    document.getElementById('edit-save').addEventListener('click', async () => {
      const errBox = document.getElementById('edit-error');
      errBox.classList.remove('show');
      const body = {
        role: document.getElementById('edit-role').value,
        status: document.getElementById('edit-status').value,
      };
      try {
        await API.patch(`/api/admin/users/${userId}`, body);
        modal.remove();
        toast('User updated.', 'success');
        loadUsers();
      } catch (err) {
        errBox.textContent = err.message;
        errBox.classList.add('show');
      }
    });
  }

  /* ---- Reset password ---- */
  async function resetPassword(userId) {
    if (!confirm('Reset this user\'s password? They will receive a new temporary password and be signed out of all sessions.')) return;
    try {
      const data = await API.post(`/api/admin/users/${userId}/reset-password`, {});
      alert('Password reset successful.\n\nTemporary password for this user:\n' + data.temporary_password +
        '\n\nShare it securely with the user — they will be prompted to change it.');
      loadUsers();
    } catch (err) {
      toastError(err.message);
    }
  }

  /* ---- Delete user ---- */
  async function deleteUser(userId) {
    if (!confirm('Delete this user permanently? Their files and shares will also be removed. This cannot be undone.')) return;
    try {
      await API.del(`/api/admin/users/${userId}`);
      toast('User deleted.', 'success');
      loadUsers();
    } catch (err) {
      toastError(err.message);
    }
  }

  /* ---- Create user modal ---- */
  function openCreateModal() {
    const modal = document.createElement('div');
    modal.className = 'modal-overlay show';
    modal.innerHTML = `
      <div class="modal">
        <div class="modal-head"><h3>${icon('plus')} Create User Account</h3><button class="modal-close" data-close>${icon('x')}</button></div>
        <div class="field"><label>Full Name</label><input type="text" id="new-full-name" placeholder="Full name"></div>
        <div class="field"><label>Username</label><input type="text" id="new-username" placeholder="3-30 chars, letters/numbers/._-"></div>
        <div class="field"><label>Email</label><input type="email" id="new-email" placeholder="user@company.com"></div>
        <div class="field"><label>Password</label><input type="text" id="new-password" placeholder="Min 8 chars, upper, lower and number"></div>
        <div class="field"><label>Role</label>
          <select id="new-role">${roleOptions('employee')}</select>
        </div>
        <div class="alert alert-error" id="create-error"></div>
        <div class="modal-foot">
          <button class="btn btn-ghost" data-close>Cancel</button>
          <button class="btn btn-primary" id="create-save">Create User</button>
        </div>
      </div>`;
    document.body.appendChild(modal);
    modal.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', () => modal.remove()));
    modal.addEventListener('click', (e) => { if (e.target === modal) modal.remove(); });

    document.getElementById('create-save').addEventListener('click', async () => {
      const errBox = document.getElementById('create-error');
      errBox.classList.remove('show');
      const body = {
        full_name: document.getElementById('new-full-name').value.trim(),
        username: document.getElementById('new-username').value.trim(),
        email: document.getElementById('new-email').value.trim(),
        password: document.getElementById('new-password').value,
        role: document.getElementById('new-role').value,
      };
      try {
        await API.post('/api/admin/users', body);
        modal.remove();
        toast('User account created.', 'success');
        loadUsers();
      } catch (err) {
        errBox.textContent = err.message;
        errBox.classList.add('show');
      }
    });
  }

  document.getElementById('add-user-btn').addEventListener('click', openCreateModal);

  document.addEventListener('click', (e) => {
    const edit = e.target.closest('[data-user-edit]');
    const reset = e.target.closest('[data-user-reset]');
    const del = e.target.closest('[data-user-delete]');
    if (edit) openEditModal(Number(edit.dataset.userEdit));
    else if (reset) resetPassword(Number(reset.dataset.userReset));
    else if (del) deleteUser(Number(del.dataset.userDelete));
  });

  loadUsers();
});
