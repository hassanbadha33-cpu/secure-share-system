/* Professional login page logic with admin 2FA, reset-code recovery and polished UX */
'use strict';

(async function initLogin() {
  const user = await API.loadSession();
  if (user) { window.location.href = '/dashboard.html'; return; }

  const form = document.getElementById('login-form');
  const alertBox = document.getElementById('alert');
  const btn = document.getElementById('login-btn');
  const usernameInput = document.getElementById('username');
  const passwordInput = document.getElementById('password');
  const togglePassword = document.getElementById('toggle-password');
  const forgotLink = document.getElementById('forgot-link');
  const capsWarning = document.getElementById('caps-warning');
  const twoFactorPanel = document.getElementById('two-factor-panel');
  const twoFactorForm = document.getElementById('two-factor-form');
  const codeInput = document.getElementById('two-factor-code');
  const codeHint = document.getElementById('two-factor-hint');
  const verifyBtn = document.getElementById('verify-2fa-btn');
  const resendBtn = document.getElementById('resend-2fa-btn');
  const backBtn = document.getElementById('back-login-btn');
  let challengeToken = null;

  function friendlyError(err, fallback = 'Something went wrong. Please try again.') {
    const msg = (err && err.message) ? String(err.message) : fallback;
    if (/invalid login|invalid credentials|username|password/i.test(msg)) {
      return 'The username or password is incorrect. Please check your credentials and try again.';
    }
    if (/too many|locked/i.test(msg)) {
      return 'Too many failed attempts. This account has been temporarily protected. Try again later or contact the administrator.';
    }
    if (/csrf/i.test(msg)) {
      return 'Your secure session expired. Refresh the page and try again.';
    }
    if (/expired/i.test(msg) && /code|token/i.test(msg)) {
      return 'The code has expired. Request a new code and try again.';
    }
    if (/invalid/i.test(msg) && /code|token/i.test(msg)) {
      return 'The code is invalid. Enter the latest 6-digit code from your email.';
    }
    return msg;
  }

  function showError(msg) {
    alertBox.className = 'alert alert-error show';
    alertBox.textContent = msg;
  }

  function showInfo(msg) {
    alertBox.className = 'alert alert-info show';
    alertBox.textContent = msg;
  }

  function setCapsWarning(event) {
    if (!capsWarning || !event || typeof event.getModifierState !== 'function') return;
    capsWarning.classList.toggle('show', event.getModifierState('CapsLock'));
  }

  function showTwoFactor(data) {
    challengeToken = data.challenge_token;
    form.style.display = 'none';
    document.querySelector('.demo-grid')?.classList.add('muted-section');
    document.querySelector('.auth-security-hint')?.classList.add('muted-section');
    twoFactorPanel.style.display = 'block';
    codeInput.value = '';
    codeInput.focus();

    if (data.delivery_method === 'email') {
      codeHint.innerHTML = `A 6-digit verification code was sent to <strong>${escapeHtml(data.destination_hint || 'your admin email')}</strong>.<br><span>Enter it within 5 minutes. The code is never exposed in the browser.</span>`;
    } else if (data.demo_code) {
      codeHint.innerHTML = 'Email delivery is not available yet. Check the server terminal for the fallback verification code.';
    } else {
      codeHint.innerHTML = 'Check the server terminal for the generated 6-digit admin verification code.';
    }
    showInfo(data.message || 'Admin verification required.');
  }

  function resetToPasswordStep() {
    challengeToken = null;
    form.style.display = 'block';
    twoFactorPanel.style.display = 'none';
    document.querySelector('.demo-grid')?.classList.remove('muted-section');
    document.querySelector('.auth-security-hint')?.classList.remove('muted-section');
    btn.disabled = false;
    btn.textContent = 'Sign in securely';
    passwordInput.focus();
  }

  document.querySelectorAll('[data-username][data-password]').forEach((card) => {
    card.addEventListener('click', () => {
      usernameInput.value = card.dataset.username;
      passwordInput.value = card.dataset.password;
      document.querySelectorAll('.demo-card').forEach((el) => el.classList.remove('selected'));
      card.classList.add('selected');
      showInfo(`${card.dataset.label || card.dataset.username} demo account is ready. Click “Sign in securely”.`);
      btn.focus();
    });
  });

  togglePassword?.addEventListener('click', () => {
    const showing = passwordInput.type === 'text';
    passwordInput.type = showing ? 'password' : 'text';
    togglePassword.textContent = showing ? 'Show' : 'Hide';
    togglePassword.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
    passwordInput.focus();
  });

  passwordInput?.addEventListener('keydown', setCapsWarning);
  passwordInput?.addEventListener('keyup', setCapsWarning);
  passwordInput?.addEventListener('blur', () => capsWarning?.classList.remove('show'));
  forgotLink?.addEventListener('click', openForgotPasswordModal);

  function openForgotPasswordModal() {
    let resetToken = null;
    const modal = document.createElement('div');
    modal.className = 'modal-overlay show';
    modal.innerHTML = `
      <div class="modal modal-recovery" role="dialog" aria-modal="true" aria-label="Password recovery">
        <div class="modal-head recovery-head">
          <h3>${icon('key')} Password Recovery</h3>
          <button class="modal-close" data-close aria-label="Close password recovery">${icon('x')}</button>
        </div>
        <div class="recovery-stepper" aria-label="Password recovery steps">
          <div class="step active" data-step="1"><strong>1</strong><span>Identify</span></div>
          <div class="step" data-step="2"><strong>2</strong><span>Verify</span></div>
          <div class="step" data-step="3"><strong>3</strong><span>Reset</span></div>
        </div>
        <p class="auth-sub recovery-copy">Enter a registered username or email. The system sends a 6-digit reset code using the configured email service.</p>
        <div id="forgot-step-one">
          <div class="field"><label for="forgot-identifier">Username or email</label><input type="text" id="forgot-identifier" placeholder="admin or admin@securefiles.local" autocomplete="username"></div>
          <div class="alert alert-error" id="forgot-error"></div>
          <button class="btn btn-primary btn-block" id="forgot-send">Send reset code</button>
          <p class="modal-helper">For security, the same confirmation may appear even when an account does not exist.</p>
        </div>
        <div id="forgot-step-two" style="display:none">
          <div class="alert alert-info show" id="forgot-hint"></div>
          <div class="field"><label for="reset-code">6-digit reset code</label><input type="text" id="reset-code" inputmode="numeric" maxlength="6" placeholder="123456" autocomplete="one-time-code" class="code-input"></div>
          <div class="field"><label for="reset-password">New password</label><input type="password" id="reset-password" placeholder="Min 8 chars, uppercase, lowercase and number" autocomplete="new-password"></div>
          <div class="field"><label for="reset-password-confirm">Confirm new password</label><input type="password" id="reset-password-confirm" placeholder="Repeat new password" autocomplete="new-password"></div>
          <div class="password-policy-line">Password policy: 8+ characters, uppercase, lowercase and number.</div>
          <div class="alert alert-error" id="reset-error"></div>
          <button class="btn btn-primary btn-block" id="reset-submit">Reset password</button>
        </div>
        <div class="modal-foot"><button class="btn btn-ghost" data-close>Close</button></div>
      </div>`;
    document.body.appendChild(modal);

    const identifierInput = modal.querySelector('#forgot-identifier');
    const forgotErr = modal.querySelector('#forgot-error');
    const resetErr = modal.querySelector('#reset-error');
    const sendBtn = modal.querySelector('#forgot-send');
    const resetBtn = modal.querySelector('#reset-submit');
    const code = modal.querySelector('#reset-code');
    const resetPasswordInput = modal.querySelector('#reset-password');
    const resetPasswordConfirmInput = modal.querySelector('#reset-password-confirm');

    identifierInput.value = usernameInput.value.trim();
    setTimeout(() => identifierInput.focus(), 30);

    function closeModal() { modal.remove(); }
    function setRecoveryStep(step) {
      modal.querySelectorAll('.recovery-stepper .step').forEach((el) => {
        const current = Number(el.dataset.step);
        el.classList.toggle('active', current === step);
        el.classList.toggle('done', current < step);
      });
    }
    function showForgotError(message, type = 'error') {
      forgotErr.className = `alert alert-${type} show`;
      forgotErr.textContent = message;
    }
    function showResetError(message) {
      resetErr.className = 'alert alert-error show';
      resetErr.textContent = message;
    }

    modal.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', closeModal));
    modal.addEventListener('click', (e) => { if (e.target === modal) closeModal(); });
    modal.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });
    identifierInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') sendBtn.click(); });
    [code, resetPasswordInput, resetPasswordConfirmInput].forEach((input) => {
      input.addEventListener('keydown', (e) => { if (e.key === 'Enter') resetBtn.click(); });
    });
    code.addEventListener('input', () => { code.value = code.value.replace(/\D/g, '').slice(0, 6); });

    sendBtn.addEventListener('click', async () => {
      forgotErr.classList.remove('show');
      const identifier = identifierInput.value.trim();
      if (!identifier) { showForgotError('Enter your username or email.'); return; }
      sendBtn.disabled = true; sendBtn.textContent = 'Sending reset code…';
      try {
        const data = await API.forgotPassword(identifier);
        if (!data.reset_token) {
          showForgotError(data.message || 'If the account exists and is active, a reset code has been sent.', 'info');
          sendBtn.disabled = false; sendBtn.textContent = 'Send reset code';
          return;
        }
        resetToken = data.reset_token;
        modal.querySelector('#forgot-step-one').style.display = 'none';
        modal.querySelector('#forgot-step-two').style.display = 'block';
        modal.querySelector('#forgot-hint').textContent = data.message || 'Reset code sent. Enter it below within 5 minutes.';
        setRecoveryStep(2);
        code.focus();
      } catch (err) {
        showForgotError(friendlyError(err, 'Password recovery failed. Try again.'));
        sendBtn.disabled = false; sendBtn.textContent = 'Send reset code';
      }
    });

    resetBtn.addEventListener('click', async () => {
      resetErr.classList.remove('show');
      const resetCode = code.value.trim();
      const pass = resetPasswordInput.value;
      const confirm = resetPasswordConfirmInput.value;
      if (!/^\d{6}$/.test(resetCode)) { showResetError('Enter the 6-digit reset code.'); return; }
      if (!pass || !confirm) { showResetError('Enter and confirm the new password.'); return; }
      if (pass !== confirm) { showResetError('Passwords do not match.'); return; }
      resetBtn.disabled = true; resetBtn.textContent = 'Resetting password…';
      try {
        const data = await API.resetPassword(resetToken, resetCode, pass);
        setRecoveryStep(3);
        closeModal();
        showInfo(data.message || 'Password reset successful. Sign in with the new password.');
        passwordInput.value = '';
        passwordInput.focus();
      } catch (err) {
        showResetError(friendlyError(err, 'Password reset failed. Try again.'));
        resetBtn.disabled = false; resetBtn.textContent = 'Reset password';
      }
    });
  }

  codeInput?.addEventListener('input', () => { codeInput.value = codeInput.value.replace(/\D/g, '').slice(0, 6); });
  backBtn?.addEventListener('click', resetToPasswordStep);

  resendBtn?.addEventListener('click', async () => {
    if (!challengeToken) return showError('Verification session missing. Please sign in again.');
    resendBtn.disabled = true; resendBtn.textContent = 'Sending…';
    try {
      const data = await API.resendTwoFactor(challengeToken);
      codeInput.value = '';
      if (data.delivery_method === 'email') {
        codeHint.innerHTML = `New verification code sent to <strong>${escapeHtml(data.destination_hint || 'your admin email')}</strong>.<br><span>Use the latest code; older codes are invalid.</span>`;
      } else if (data.demo_code) {
        codeHint.innerHTML = 'Email delivery is not available yet. A new fallback code was printed in the server terminal.';
      } else {
        codeHint.innerHTML = 'A new code was generated. Check the server terminal.';
      }
      showInfo(data.message || 'New verification code sent.');
    } catch (err) { showError(friendlyError(err, 'Could not resend the verification code.')); }
    finally { resendBtn.disabled = false; resendBtn.textContent = 'Resend code'; }
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    alertBox.classList.remove('show');
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    if (!username || !password) return showError('Please enter your username/email and password.');
    btn.disabled = true; btn.textContent = 'Checking credentials…';
    try {
      const data = await API.login(username, password);
      if (data.two_factor_required) {
        btn.disabled = false; btn.textContent = 'Sign in securely';
        showTwoFactor(data); return;
      }
      btn.textContent = 'Opening secure workspace…';
      window.location.href = '/dashboard.html';
    } catch (err) {
      showError(friendlyError(err));
      btn.disabled = false; btn.textContent = 'Sign in securely';
    }
  });

  twoFactorForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!challengeToken) return showError('Verification session missing. Please sign in again.');
    const code = codeInput.value.trim();
    if (!/^\d{6}$/.test(code)) return showError('Enter the 6-digit verification code.');
    verifyBtn.disabled = true; verifyBtn.textContent = 'Verifying…';
    try {
      await API.verifyTwoFactor(challengeToken, code);
      verifyBtn.textContent = 'Opening admin workspace…';
      window.location.href = '/dashboard.html';
    } catch (err) {
      showError(friendlyError(err));
      verifyBtn.disabled = false; verifyBtn.textContent = 'Verify and open dashboard';
    }
  });
})();
