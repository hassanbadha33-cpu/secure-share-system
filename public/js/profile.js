/* Profile page logic — update details + change password */
'use strict';

initApp('profile', 'My Profile', 'Update your account information and password', async (user) => {
  const content = document.getElementById('content');
  content.innerHTML = `
    <div class="profile-hero-card">
      <div class="profile-hero-left">
        ${userAvatarHtml(user, 'profile-avatar-large')}
        <div>
          <div class="hero-kicker-mini">Account Identity</div>
          <h3>${escapeHtml(user.full_name)}</h3>
          <p>@${escapeHtml(user.username)} · ${escapeHtml(user.email)}</p>
        </div>
      </div>
      <div class="profile-hero-badges">
        <span class="badge ${user.role === 'admin' ? 'badge-admin' : user.role === 'manager' ? 'badge-manager' : 'badge-employee'}">${escapeHtml(user.role)}</span>
        <span class="badge badge-active">Active</span>
        <span class="badge badge-info">Session protected</span>
      </div>
    </div>

    <div class="flex wrap gap-2" style="align-items:flex-start">
      <div class="card" style="flex:1;min-width:300px">
        <h3>Account Information</h3>
        <div class="alert alert-error" id="info-error"></div>
        <div class="alert alert-success" id="info-success"></div>
        <div class="field"><label>Full Name</label><input type="text" id="p-full-name" value="${escapeHtml(user.full_name)}"></div>
        <div class="field"><label>Email Address</label><input type="email" id="p-email" value="${escapeHtml(user.email)}"></div>
        <div class="field"><label>Username</label><input type="text" id="p-username" value="${escapeHtml(user.username)}" disabled>
          <div class="hint">Username cannot be changed.</div></div>
        <div class="field"><label>Role</label>
          <input type="text" id="p-role" value="${escapeHtml(user.role)}" disabled>
          <div class="hint">Role-Based Access Control (RBAC) determines your permissions.</div></div>
        <div class="modal-foot" style="margin-top:8px">
          <button class="btn btn-primary" id="save-info">Save Changes</button>
        </div>
      </div>

      <div class="card" style="flex:1;min-width:300px">
        <h3>Change Password</h3>
        <p class="text-muted" style="font-size:13px;margin-bottom:14px">Passwords are hashed with scrypt. Changing your password signs out your other sessions.</p>
        <div class="alert alert-error" id="pw-error"></div>
        <div class="alert alert-success" id="pw-success"></div>
        <div class="field"><label>Current Password</label><input type="password" id="pw-current" autocomplete="current-password"></div>
        <div class="field"><label>New Password</label><input type="password" id="pw-new" autocomplete="new-password">
          <div class="hint">At least 8 characters with an uppercase letter, a lowercase letter and a number.</div></div>
        <div class="field"><label>Confirm New Password</label><input type="password" id="pw-confirm" autocomplete="new-password"></div>
        <div class="modal-foot" style="margin-top:8px">
          <button class="btn btn-primary" id="save-pw">Update Password</button>
        </div>
      </div>
    </div>
  `;

  const infoError = document.getElementById('info-error');
  const infoSuccess = document.getElementById('info-success');
  document.getElementById('save-info').addEventListener('click', async () => {
    infoError.style.display = 'none';
    infoSuccess.style.display = 'none';
    try {
      const data = await API.patch('/api/profile', {
        full_name: document.getElementById('p-full-name').value.trim(),
        email: document.getElementById('p-email').value.trim(),
      });
      infoSuccess.textContent = data.message;
      infoSuccess.style.display = 'block';
      API.user = data.user;
      toast('Profile updated.', 'success');
    } catch (err) {
      infoError.textContent = err.message;
      infoError.style.display = 'block';
    }
  });

  const pwError = document.getElementById('pw-error');
  const pwSuccess = document.getElementById('pw-success');
  document.getElementById('save-pw').addEventListener('click', async () => {
    pwError.style.display = 'none';
    pwSuccess.style.display = 'none';
    const current = document.getElementById('pw-current').value;
    const next = document.getElementById('pw-new').value;
    const confirm = document.getElementById('pw-confirm').value;
    if (next !== confirm) {
      pwError.textContent = 'New passwords do not match.';
      pwError.style.display = 'block';
      return;
    }
    try {
      const data = await API.post('/api/profile/password', { current_password: current, new_password: next });
      pwSuccess.textContent = data.message;
      pwSuccess.style.display = 'block';
      document.getElementById('pw-current').value = '';
      document.getElementById('pw-new').value = '';
      document.getElementById('pw-confirm').value = '';
      toast('Password updated.', 'success');
    } catch (err) {
      pwError.textContent = err.message;
      pwError.style.display = 'block';
    }
  });
});
