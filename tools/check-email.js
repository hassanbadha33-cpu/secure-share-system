'use strict';

/** Test Gmail SMTP config without starting the full system. */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function loadEnvFile() {
  const envPath = path.join(__dirname, '..', '.env');
  if (!fs.existsSync(envPath)) {
    throw new Error('.env not found. Run: npm run setup:email');
  }
  const lines = fs.readFileSync(envPath, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    process.env[key] = value;
  }
}

function hasPlaceholder(value) {
  return !value || /PASTE_|your_|example\.com|replace_with/i.test(String(value));
}

(async () => {
  try {
    loadEnvFile();
    const nodemailer = require('nodemailer');
    const missing = [];
    for (const key of ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASS', 'OTP_FROM', 'OTP_TO_EMAIL', 'OTP_SECRET']) {
      if (hasPlaceholder(process.env[key])) missing.push(key);
    }
    if (missing.length) {
      console.error('Email setup is incomplete. Fix these values in .env: ' + missing.join(', '));
      process.exit(1);
    }

    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 465),
      secure: String(process.env.SMTP_SECURE).toLowerCase() === 'true' || Number(process.env.SMTP_PORT) === 465,
      auth: {
        user: process.env.SMTP_USER,
        pass: String(process.env.SMTP_PASS).replace(/\s+/g, ''),
      },
      tls: { minVersion: 'TLSv1.2' },
    });

    const testCode = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    await transporter.sendMail({
      from: process.env.OTP_FROM,
      to: process.env.OTP_TO_EMAIL,
      subject: 'Secure Share email OTP test',
      text: `Secure Share test code: ${testCode}. If you received this email, SMTP is working.`,
      html: `<div style="font-family:Arial,sans-serif"><h2>Secure Share Email Test</h2><p>Your test code is:</p><div style="font-size:30px;font-weight:800;letter-spacing:8px;color:#24A673">${testCode}</div><p>If you received this, Gmail SMTP is working.</p></div>`,
    });
    console.log('Success. Test email sent to ' + process.env.OTP_TO_EMAIL);
  } catch (err) {
    console.error('\nEmail test failed:');
    console.error(err && err.message ? err.message : err);
    console.error('\nCheck: App Password, 2-Step Verification, sender email, internet connection.');
    process.exit(1);
  }
})();
