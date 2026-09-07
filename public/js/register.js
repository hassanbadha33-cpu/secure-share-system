/* Registration page logic */
'use strict';

(async function initRegister() {
  const user = await API.loadSession();
  if (user) {
    window.location.href = '/dashboard.html';
    return;
  }

  const form = document.getElementById('register-form');
  const alertBox = document.getElementById('alert');
  const btn = document.getElementById('register-btn');
  const fullName = document.getElementById('full_name');
  const username = document.getElementById('username');
  const password = document.getElementById('password');
  const confirm = document.getElementById('confirm');
  const policyCheck = document.getElementById('policy-check');
  const meterBar = document.getElementById('meter-bar');
  const togglePassword = document.getElementById('toggle-register-password');
  const passwordChecks = document.getElementById('password-checks');

  function showError(msg) {
    alertBox.className = 'alert alert-error show';
    alertBox.textContent = msg;
  }

  function showSuccess(msg) {
    alertBox.className = 'alert alert-success show';
    alertBox.textContent = msg;
  }

  function usernameSuggestion(value) {
    return String(value || '')
      .toLowerCase()
      .replace(/[^a-z0-9\s._-]/g, '')
      .trim()
      .replace(/\s+/g, '.')
      .slice(0, 30);
  }

  fullName.addEventListener('blur', () => {
    if (!username.value.trim()) {
      username.value = usernameSuggestion(fullName.value);
    }
  });

  if (togglePassword) {
    togglePassword.addEventListener('click', () => {
      const showing = password.type === 'text';
      password.type = showing ? 'password' : 'text';
      confirm.type = showing ? 'password' : 'text';
      togglePassword.textContent = showing ? 'Show' : 'Hide';
    });
  }

  function updatePasswordMeter() {
    const v = password.value;
    const checks = {
      length: v.length >= 8,
      upper: /[A-Z]/.test(v),
      lower: /[a-z]/.test(v),
      number: /[0-9]/.test(v),
    };
    const score = Object.values(checks).filter(Boolean).length;
    const pct = score * 25;
    meterBar.style.width = pct + '%';
    meterBar.style.background = pct <= 25 ? '#ef4444' : pct <= 75 ? '#f59e0b' : '#10b981';

    if (passwordChecks) {
      Object.entries(checks).forEach(([key, ok]) => {
        const el = passwordChecks.querySelector(`[data-check="${key}"]`);
        if (el) el.classList.toggle('ok', ok);
      });
    }
  }

  password.addEventListener('input', updatePasswordMeter);

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    alertBox.classList.remove('show');
    alertBox.className = 'alert alert-error';

    const data = {
      full_name: fullName.value.trim(),
      username: username.value.trim(),
      email: document.getElementById('email').value.trim(),
      password: password.value,
    };

    if (!data.full_name || !data.username || !data.email || !data.password) {
      showError('Please fill in all fields.');
      return;
    }
    if (data.password !== confirm.value) {
      showError('Passwords do not match.');
      return;
    }
    if (policyCheck && !policyCheck.checked) {
      showError('Please confirm that you understand the secure access policy.');
      return;
    }

    btn.disabled = true;
    btn.textContent = 'Creating secure account…';
    try {
      await API.post('/api/auth/register', data);
      showSuccess('Account created successfully. Redirecting to login…');
      setTimeout(() => (window.location.href = '/login.html'), 1400);
    } catch (err) {
      showError(err.message);
      btn.disabled = false;
      btn.textContent = 'Create secure account';
    }
  });
})();
