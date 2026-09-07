'use strict';

/**
 * Secure Share System — HTTP server.
 *
 * An Automated File Encryption and Secure Sharing System for Corporate Data
 * Protection. Plain Node.js http server (no external dependencies) with an
 * SQL database (SQLite via node:sqlite) and a native HTML/CSS/JS frontend.
 *
 * Core features (mapped to the research objectives):
 *   1. Secure web platform to upload, store and manage corporate files.
 *   2. Automated AES-256-GCM encryption of every file before it is stored.
 *   3. User authentication (scrypt password hashing + session tokens) and
 *      authorization (only approved users may access specific files).
 *   4. Secure file sharing with Role-Based Access Control (admin / manager /
 *      employee) and per-share permissions (view / download).
 *   5. Activity logging of uploads, downloads, sharing and access attempts.
 *   6. Tested end-to-end (see README for credentials).
 *
 * Run:  node server.js   (or: npm start)
 */

const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { URL } = require('url');

const { initDatabase, getDb, logActivity, createSecurityAlert, verifyAuditChain, STORAGE_DIR } = require('./lib/db');
const {
  hashPassword, verifyPassword, randomToken, passwordPolicyError,
  isValidEmail, isValidUsername, encryptBuffer, decryptBuffer, createDecryptStream,
} = require('./lib/security');
const { parseMultipart } = require('./lib/multipart');

/* ------------------------------------------------------------------ *
 * Environment configuration loader
 * ------------------------------------------------------------------ */

function loadEnvFile() {
  const envPath = path.join(__dirname, '.env');
  if (!fs.existsSync(envPath)) return;
  const lines = fs.readFileSync(envPath, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (key && process.env[key] === undefined) process.env[key] = value;
  }
}

loadEnvFile();

/* Optional email transport. The system still runs without npm install;
 * email delivery activates after installing/configuring nodemailer. */
let nodemailer = null;
try {
  nodemailer = require('nodemailer');
} catch (e) {
  nodemailer = null;
}

/* ------------------------------------------------------------------ *
 * Configuration
 * ------------------------------------------------------------------ */

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const PUBLIC_DIR = path.join(__dirname, 'public');
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;        // 8 hours
const SESSION_RENEW_MS = 1 * 60 * 60 * 1000;       // sliding renewal after 1h
const MAX_UPLOAD_SIZE = 25 * 1024 * 1024;          // 25 MB per file
const STORAGE_QUOTA = 250 * 1024 * 1024;           // 250 MB per user
const ALLOWED_UPLOAD_EXTENSIONS = new Set([
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.txt', '.csv',
  '.png', '.jpg', '.jpeg', '.webp'
]);
const LOGIN_MAX_ATTEMPTS = 5;                      // lockout threshold
const LOGIN_LOCKOUT_MS = 15 * 60 * 1000;           // 15 minutes
const ADMIN_2FA_TTL_MS = Number(process.env.ADMIN_2FA_TTL_SECONDS || 300) * 1000;  // default 5 minutes
const ADMIN_2FA_MAX_ATTEMPTS = Number(process.env.ADMIN_2FA_MAX_ATTEMPTS || 5);         // failed code limit per challenge
const OTP_DELIVERY_MODE = String(process.env.OTP_DELIVERY_MODE || 'terminal').toLowerCase(); // terminal | email
const OTP_SECRET = process.env.OTP_SECRET || crypto.randomBytes(32).toString('hex');
const SMTP_HOST = process.env.SMTP_HOST || '';
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_SECURE = String(process.env.SMTP_SECURE || '').toLowerCase() === 'true' || SMTP_PORT === 465;
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const OTP_FROM = process.env.OTP_FROM || (SMTP_USER ? `Secure Share <${SMTP_USER}>` : 'Secure Share <no-reply@secure-share.local>');
const OTP_TO_EMAIL = process.env.OTP_TO_EMAIL || ''; // optional local override for testing with demo accounts

const ROLES = ['admin', 'security_officer', 'auditor', 'manager', 'employee', 'hr_officer', 'finance_officer', 'external_partner'];
const ROLE_LABELS = {
  admin: 'Administrator',
  security_officer: 'Security Officer',
  auditor: 'Auditor',
  manager: 'Manager',
  employee: 'Employee',
  hr_officer: 'HR Officer',
  finance_officer: 'Finance Officer',
  external_partner: 'External Partner'
};
const READ_ONLY_ROLES = new Set(['auditor', 'security_officer']);
const PASSWORD_RESET_TTL_MS = 5 * 60 * 1000;
const PASSWORD_RESET_MAX_ATTEMPTS = 5;
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8', '.htm': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.gif': 'image/gif', '.ico': 'image/x-icon', '.webp': 'image/webp',
  '.txt': 'text/plain; charset=utf-8', '.pdf': 'application/pdf',
  '.woff2': 'font/woff2', '.woff': 'font/woff', '.map': 'application/json',
};

/* ------------------------------------------------------------------ *
 * Small helpers
 * ------------------------------------------------------------------ */

function sendJSON(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function sendError(res, status, message) {
  sendJSON(res, status, { error: message });
}

/** Read the whole request body (with a size cap). Returns a Buffer. */
function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(Object.assign(new Error('Request body too large.'), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function getClientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return String(fwd).split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

function sanitizeFilename(name) {
  let base = path.basename(String(name || '').replace(/[\\/]/g, '/'));
  base = base.replace(/[\u0000-\u001f\u007f]/g, '').trim();
  return base || 'file';
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = bytes;
  let i = -1;
  do { v /= 1024; i++; } while (v >= 1024 && i < units.length - 1);
  return v.toFixed(1) + ' ' + units[i];
}

function escapeHtml(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function nowSql() {
  return new Date().toISOString().slice(0, 19).replace('T', ' ');
}

function isShareExpired(share) {
  return Boolean(share && share.expires_at && new Date(share.expires_at.replace(' ', 'T') + 'Z') <= new Date());
}

function isViewOnceConsumed(share) {
  return Boolean(share && Number(share.view_once) === 1 && share.opened_at);
}

function getShareForUser(db, fileId, userId) {
  return db.prepare('SELECT * FROM shares WHERE file_id = ? AND shared_with = ?').get(fileId, userId);
}

function shareAccessState(share) {
  if (!share) return { active: false, reason: 'not_shared' };
  if (isShareExpired(share)) return { active: false, reason: 'expired' };
  if (isViewOnceConsumed(share)) return { active: false, reason: 'view_once_used' };
  return { active: true, reason: 'active' };
}

function canReadFile(db, file, user) {
  if (file.owner_id === user.id || user.role === 'admin') return true;
  const share = getShareForUser(db, file.id, user.id);
  return shareAccessState(share).active;
}

function canDownloadFile(db, file, user) {
  if (file.owner_id === user.id || user.role === 'admin') return true;
  const share = getShareForUser(db, file.id, user.id);
  const state = shareAccessState(share);
  return state.active && share.permission === 'download';
}

function getAccessDenialMessage(share, fallback = 'You do not have permission to access this file.') {
  const state = shareAccessState(share);
  if (state.reason === 'expired') return 'This shared access has expired. Ask the owner to share the file again.';
  if (state.reason === 'view_once_used') return 'This was a view-once file and it has already been opened. Ask the owner to grant access again.';
  return fallback;
}

function previewableText(file) {
  const ext = path.extname(file.original_name || '').toLowerCase();
  const mime = String(file.mime_type || '').toLowerCase();
  return mime.startsWith('text/') || ['.txt', '.csv', '.json', '.md', '.log'].includes(ext);
}

function previewableInline(file) {
  const ext = path.extname(file.original_name || '').toLowerCase();
  const mime = String(file.mime_type || '').toLowerCase();
  return mime === 'application/pdf' || mime.startsWith('image/') || ['.pdf', '.png', '.jpg', '.jpeg', '.webp'].includes(ext);
}

function sendPreviewHtml(res, title, bodyHtml, status = 200) {
  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)} — Secure Preview</title>
<style>
:root{--navy:#11203F;--green:#24A673;--bg:#f3f6f9;--text:#1f2937;--muted:#5b6778;--border:#dbe4ee;}
*{box-sizing:border-box}body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.55}
.header{background:var(--navy);color:#fff;padding:22px 28px;display:flex;align-items:center;justify-content:space-between;gap:16px}
.header h1{font-size:19px;margin:0}.header span{color:#b9c7d6;font-size:13px}.header-actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.back-link{background:rgba(255,255,255,.12);color:#fff;border:1px solid rgba(255,255,255,.25);border-radius:999px;padding:7px 11px;text-decoration:none;font-weight:800;font-size:12px}.back-link:hover{background:rgba(255,255,255,.2);text-decoration:none}.badge{background:#dff8ee;color:#08724f;border:1px solid #abebd0;border-radius:999px;padding:7px 10px;font-weight:800;font-size:12px;letter-spacing:.04em;cursor:default;user-select:none}
.wrap{max-width:1100px;margin:28px auto;padding:0 18px}.card{background:#fff;border:1px solid var(--border);border-radius:18px;box-shadow:0 18px 50px rgba(17,32,63,.08);padding:24px}.notice{background:#ecfdf5;border:1px solid #bbf7d0;color:#065f46;border-radius:14px;padding:14px 16px;margin-bottom:18px;font-size:14px}.muted{color:var(--muted)}pre{white-space:pre-wrap;word-wrap:break-word;background:#0f172a;color:#e5e7eb;border-radius:14px;padding:20px;overflow:auto;max-height:70vh}.meta{display:grid;grid-template-columns:160px 1fr;gap:10px;margin:16px 0}.k{font-weight:800;color:var(--navy)}.actions{margin-top:16px}.btn{display:inline-block;background:var(--navy);color:#fff;text-decoration:none;border-radius:10px;padding:10px 14px;font-weight:700}.btn:hover{text-decoration:none}.preview-frame{position:relative;min-height:520px}.watermark{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;pointer-events:none;z-index:999;color:rgba(17,32,63,.08);font-weight:900;font-size:58px;transform:rotate(-24deg);letter-spacing:.08em;text-align:center}.doc-frame{width:100%;height:72vh;border:1px solid var(--border);border-radius:14px;background:#fff}.img-preview{max-width:100%;border-radius:14px;border:1px solid var(--border);display:block;margin:auto;background:#fff}@media(max-width:700px){.header{padding:16px;display:grid;gap:12px}.header h1{font-size:17px}.header-actions{width:100%;justify-content:space-between}.back-link,.badge{font-size:11px;padding:7px 9px}.wrap{margin:12px auto;padding:0 10px}.card{padding:14px;border-radius:14px}.meta{grid-template-columns:1fr;gap:4px}.doc-frame{height:68vh}.watermark{font-size:28px;letter-spacing:.04em}}
</style></head><body>
<div class="header"><div><h1>Secure Share Preview</h1><span>Temporary in-browser decryption for authorized viewing only</span></div><div class="header-actions"><a class="back-link" href="/dashboard.html">Back to Dashboard</a><div class="badge">Secure View Active</div></div></div>
<div class="watermark">VIEW ONLY · SECURE PREVIEW</div><div class="wrap"><div class="card">${bodyHtml}</div></div></body></html>`;
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': Buffer.byteLength(html),
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-src data:; object-src data:; frame-ancestors 'self';",
  });
  res.end(html);
}

function publicUser(u) {
  return {
    id: u.id,
    full_name: u.full_name,
    username: u.username,
    email: u.email,
    role: u.role,
    status: u.status,
    created_at: u.created_at,
  };
}

/* ------------------------------------------------------------------ *
 * Authentication middleware
 * ------------------------------------------------------------------ */

const COOKIE_NAME = 'sss_session';

function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie;
  if (!raw) return out;
  for (const part of raw.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

function setSessionCookie(res, token) {
  res.setHeader('Set-Cookie',
    `${COOKIE_NAME}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_MS / 1000}`);
}

function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`);
}

/** Load the current user from the session cookie. Returns user row or null. */
function getCurrentUser(req) {
  const token = parseCookies(req)[COOKIE_NAME];
  if (!token) return null;
  const db = getDb();
  const session = db.prepare(
    `SELECT s.token, s.csrf_token, s.expires_at, s.user_id, u.*
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token = ?`
  ).get(token);
  if (!session) return null;
  if (new Date(session.expires_at + 'Z') < new Date()) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    return null;
  }
  // Sliding renewal
  if (Date.now() - new Date(session.created_at + 'Z').getTime() > SESSION_RENEW_MS) {
    const newExpiry = new Date(Date.now() + SESSION_TTL_MS).toISOString().slice(0, 19).replace('T', ' ');
    db.prepare('UPDATE sessions SET expires_at = ? WHERE token = ?').run(newExpiry, token);
  }
  if (session.status !== 'active') return null; // suspended users lose access
  return {
    id: session.user_id, full_name: session.full_name, username: session.username,
    email: session.email, role: session.role, status: session.status,
    created_at: session.created_at, csrf_token: session.csrf_token,
  };
}

function requireAuth(req, res) {
  const user = getCurrentUser(req);
  if (!user) {
    sendError(res, 401, 'Authentication required. Please log in.');
    return null;
  }
  return user;
}

function requireRole(user, roles) {
  return roles.includes(user.role);
}
function requireAdminOrSecurity(user) {
  return user.role === 'admin' || user.role === 'security_officer' || user.role === 'auditor';
}

function canUploadFiles(user) {
  return !READ_ONLY_ROLES.has(user.role) && user.role !== 'external_partner';
}

function canShareOwnedFiles(user) {
  return !READ_ONLY_ROLES.has(user.role) && user.role !== 'external_partner';
}

function canManageUsers(user) {
  return user.role === 'admin';
}

function roleLabel(role) {
  return ROLE_LABELS[role] || role;
}


/** Validate the CSRF token on mutating requests (defends against CSRF attacks). */
function checkCsrf(req, res, user) {
  const header = req.headers['x-csrf-token'];
  const expected = user && user.csrf_token;
  if (!expected || !header || header !== expected) {
    sendError(res, 403, 'Invalid or missing CSRF token. Refresh the page and try again.');
    return false;
  }
  return true;
}

/* ------------------------------------------------------------------ *
 * Login rate limiting (in-memory)
 * ------------------------------------------------------------------ */

const loginAttempts = new Map(); // username -> { count, until }

function isLockedOut(username) {
  const rec = loginAttempts.get(username);
  if (!rec) return false;
  // Only a real lockout window (until > 0) blocks the user. until = 0 simply
  // means "failed attempts recorded but not yet locked out".
  if (rec.until > 0 && Date.now() > rec.until) {
    loginAttempts.delete(username);
    return false;
  }
  return rec.until > 0;
}

function recordFailure(username) {
  const rec = loginAttempts.get(username) || { count: 0, until: 0 };
  rec.count += 1;
  if (rec.count >= LOGIN_MAX_ATTEMPTS) {
    rec.until = Date.now() + LOGIN_LOCKOUT_MS;
    rec.count = 0;
  }
  loginAttempts.set(username, rec);
}

function clearFailures(username) {
  loginAttempts.delete(username);
}


/* ------------------------------------------------------------------ *
 * Admin two-factor verification (email-ready production mode)
 * ------------------------------------------------------------------ */

// challengeToken -> { userId, codeHash, expiresAt, attempts, ip, deliveryMethod, destinationHint }
const twoFactorChallenges = new Map();

function generateSixDigitCode() {
  return String(crypto.randomInt(100000, 1000000));
}

function hashOtpCode(challengeToken, code) {
  return crypto
    .createHmac('sha256', OTP_SECRET)
    .update(`${challengeToken}:${String(code)}`)
    .digest('hex');
}

function verifyOtpCode(challengeToken, submittedCode, expectedHash) {
  const actual = Buffer.from(hashOtpCode(challengeToken, submittedCode), 'hex');
  const expected = Buffer.from(String(expectedHash || ''), 'hex');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function maskEmail(email) {
  const value = String(email || '').trim();
  const at = value.indexOf('@');
  if (at <= 1) return value || 'configured admin email';
  const name = value.slice(0, at);
  const domain = value.slice(at + 1);
  return `${name[0]}${'*'.repeat(Math.max(2, Math.min(name.length - 1, 6)))}@${domain}`;
}

function otpDestinationFor(user) {
  return OTP_TO_EMAIL || user.email;
}

function terminalOtpNotice(user, code, reason) {
  console.log('\n[Secure Share Admin 2FA]');
  console.log(`Delivery: terminal fallback${reason ? ' (' + reason + ')' : ''}`);
  console.log(`Admin: ${user.username} <${user.email}>`);
  console.log(`Verification code: ${code}`);
  console.log(`Expires in: ${Math.floor(ADMIN_2FA_TTL_MS / 1000)} seconds\n`);
}

function emailHtmlTemplate(user, code) {
  const safeName = escapeHtml(user.full_name || user.username || 'Administrator');
  const safeCode = escapeHtml(code);
  return `<!doctype html><html><body style="margin:0;background:#f5f8fb;font-family:Arial,sans-serif;color:#11203F">
  <div style="max-width:620px;margin:0 auto;padding:28px">
    <div style="background:#11203F;color:white;border-radius:18px 18px 0 0;padding:22px 26px">
      <div style="font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:#94f0ce;font-weight:700">Secure Share Admin Verification</div>
      <h1 style="margin:8px 0 0;font-size:24px">Your 6-digit sign-in code</h1>
    </div>
    <div style="background:white;border:1px solid #dbe4ee;border-top:0;border-radius:0 0 18px 18px;padding:26px">
      <p style="font-size:15px;line-height:1.6">Hello ${safeName},</p>
      <p style="font-size:15px;line-height:1.6">A sign-in attempt for the Secure Share administrator workspace requires this verification code:</p>
      <div style="font-size:34px;letter-spacing:10px;font-weight:800;color:#24A673;background:#ecfdf5;border:1px solid #bbf7d0;border-radius:14px;text-align:center;padding:18px;margin:22px 0">${safeCode}</div>
      <p style="font-size:14px;line-height:1.6;color:#5B6778">This code expires in 5 minutes. If you did not try to sign in, ignore this email and review the activity log.</p>
      <p style="font-size:13px;color:#5B6778;margin-top:22px">Secure Share System<br>Automated File Encryption & Secure Sharing</p>
    </div>
  </div></body></html>`;
}

async function deliverOtpCode(user, code) {
  const destination = otpDestinationFor(user);

  if (OTP_DELIVERY_MODE !== 'email') {
    terminalOtpNotice(user, code, 'OTP_DELIVERY_MODE is terminal');
    return { method: 'terminal', sent: false, destinationHint: 'server terminal', demoCode: code, note: 'Code generated in terminal demo mode.' };
  }

  if (!nodemailer) {
    terminalOtpNotice(user, code, 'nodemailer is not installed');
    return { method: 'terminal', sent: false, destinationHint: 'server terminal', demoCode: null, note: 'Email mode requested, but nodemailer is not installed. Run npm install.' };
  }

  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS || !destination || !isValidEmail(destination)) {
    terminalOtpNotice(user, code, 'missing or invalid SMTP/email configuration');
    return { method: 'terminal', sent: false, destinationHint: 'server terminal', demoCode: null, note: 'Email settings are incomplete, so the system used terminal fallback.' };
  }

  try {
    const normalizedSmtpPass = SMTP_HOST.includes('gmail.com') ? String(SMTP_PASS).replace(/\s+/g, '') : SMTP_PASS;

    const transporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_SECURE,
      auth: { user: SMTP_USER, pass: normalizedSmtpPass },
      tls: { minVersion: 'TLSv1.2' },
    });

    await transporter.sendMail({
      from: OTP_FROM,
      to: destination,
      subject: 'Secure Share administrator verification code',
      text: `Your Secure Share admin verification code is ${code}. It expires in 5 minutes. If you did not try to sign in, ignore this email and review the activity log.`,
      html: emailHtmlTemplate(user, code),
    });

    return { method: 'email', sent: true, destinationHint: maskEmail(destination), demoCode: null, note: 'Verification code sent by email.' };
  } catch (err) {
    console.error('Email OTP delivery failed:', err && err.message ? err.message : err);
    terminalOtpNotice(user, code, 'email delivery failed; terminal fallback used');
    return {
      method: 'terminal',
      sent: false,
      destinationHint: 'server terminal',
      demoCode: null,
      note: 'Email delivery failed, so the system used terminal fallback. Check SMTP settings in .env.'
    };
  }
}

async function createAdminTwoFactorChallenge(user, req) {
  const challengeToken = randomToken(24);
  const code = generateSixDigitCode();
  const expiresAt = Date.now() + ADMIN_2FA_TTL_MS;
  const delivery = await deliverOtpCode(user, code);

  twoFactorChallenges.set(challengeToken, {
    userId: user.id,
    codeHash: hashOtpCode(challengeToken, code),
    expiresAt,
    attempts: 0,
    ip: getClientIp(req),
    deliveryMethod: delivery.method,
    destinationHint: delivery.destinationHint,
  });

  const detail = delivery.method === 'email'
    ? `Admin password accepted; verification code sent to ${delivery.destinationHint}`
    : `Admin password accepted; verification code generated using terminal fallback`;
  logActivity(user.id, 'admin_2fa_challenge', detail, getClientIp(req));

  return { challengeToken, expiresAt, delivery };
}

function completeLoginSession(req, res, user, detail) {
  const db = getDb();
  clearFailures(user.username);
  clearFailures(user.email);

  const token = randomToken(32);
  const csrfToken = randomToken(24);
  const expiry = new Date(Date.now() + SESSION_TTL_MS).toISOString().slice(0, 19).replace('T', ' ');
  db.prepare('INSERT INTO sessions (token, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)')
    .run(token, user.id, csrfToken, expiry);

  logActivity(user.id, 'login', detail || 'User logged in successfully', getClientIp(req));
  setSessionCookie(res, token);
  return sendJSON(res, 200, { ok: true, user: publicUser(user), csrf_token: csrfToken });
}

async function handleVerifyTwoFactor(req, res, bodyBuffer) {
  let data;
  try { data = JSON.parse(bodyBuffer.toString('utf8') || '{}'); }
  catch { return sendError(res, 400, 'Invalid JSON body.'); }

  const challengeToken = String(data.challenge_token || '').trim();
  const submittedCode = String(data.code || '').replace(/\D/g, '').slice(0, 6);
  if (!challengeToken || submittedCode.length !== 6) {
    return sendError(res, 400, 'Enter the 6-digit verification code.');
  }

  const challenge = twoFactorChallenges.get(challengeToken);
  if (!challenge) return sendError(res, 400, 'Verification session not found. Please sign in again.');
  if (Date.now() > challenge.expiresAt) {
    twoFactorChallenges.delete(challengeToken);
    logActivity(challenge.userId, 'admin_2fa_expired', 'Admin 2FA code expired before verification', getClientIp(req));
    return sendError(res, 410, 'Verification code expired. Please sign in again.');
  }

  const db = getDb();
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(challenge.userId);
  if (!user || user.status !== 'active') {
    twoFactorChallenges.delete(challengeToken);
    return sendError(res, 403, 'Admin account is not active.');
  }

  if (!verifyOtpCode(challengeToken, submittedCode, challenge.codeHash)) {
    challenge.attempts += 1;
    logActivity(user.id, 'admin_2fa_failed', `Invalid admin 2FA code attempt ${challenge.attempts}`, getClientIp(req));
    if (challenge.attempts >= ADMIN_2FA_MAX_ATTEMPTS) {
      twoFactorChallenges.delete(challengeToken);
      recordFailure(user.username);
      return sendError(res, 429, 'Too many incorrect verification codes. Please sign in again.');
    }
    return sendError(res, 401, `Invalid verification code. ${ADMIN_2FA_MAX_ATTEMPTS - challenge.attempts} attempt(s) remaining.`);
  }

  twoFactorChallenges.delete(challengeToken);
  logActivity(user.id, 'admin_2fa_success', 'Admin 2FA verification completed successfully', getClientIp(req));
  return completeLoginSession(req, res, user, 'Admin logged in successfully after 2FA verification');
}

async function handleResendTwoFactor(req, res, bodyBuffer) {
  let data;
  try { data = JSON.parse(bodyBuffer.toString('utf8') || '{}'); }
  catch { return sendError(res, 400, 'Invalid JSON body.'); }

  const challengeToken = String(data.challenge_token || '').trim();
  const challenge = twoFactorChallenges.get(challengeToken);
  if (!challenge) return sendError(res, 400, 'Verification session not found. Please sign in again.');

  const db = getDb();
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(challenge.userId);
  if (!user || user.status !== 'active') return sendError(res, 403, 'Admin account is not active.');

  const code = generateSixDigitCode();
  challenge.codeHash = hashOtpCode(challengeToken, code);
  challenge.expiresAt = Date.now() + ADMIN_2FA_TTL_MS;
  challenge.attempts = 0;
  const delivery = await deliverOtpCode(user, code);
  challenge.deliveryMethod = delivery.method;
  challenge.destinationHint = delivery.destinationHint;
  twoFactorChallenges.set(challengeToken, challenge);

  logActivity(user.id, 'admin_2fa_resend', delivery.method === 'email'
    ? `Admin requested a new verification code sent to ${delivery.destinationHint}`
    : 'Admin requested a new verification code using terminal fallback', getClientIp(req));
  return sendJSON(res, 200, {
    ok: true,
    message: delivery.method === 'email'
      ? `A new verification code was sent to ${delivery.destinationHint}.`
      : 'A new verification code was generated in the server terminal.',
    delivery_method: delivery.method,
    destination_hint: delivery.destinationHint,
    demo_code: delivery.demoCode,
    expires_in_seconds: Math.floor(ADMIN_2FA_TTL_MS / 1000),
  });
}


/* ------------------------------------------------------------------ *
 * Password reset by email verification code
 * ------------------------------------------------------------------ */

function passwordResetDestinationFor(user) {
  return process.env.PASSWORD_RESET_TO_EMAIL || OTP_TO_EMAIL || user.email;
}

function passwordResetEmailHtml(user, code) {
  const safeName = escapeHtml(user.full_name || user.username || 'User');
  const safeCode = escapeHtml(code);
  return `<!doctype html><html><body style="margin:0;background:#f5f8fb;font-family:Arial,sans-serif;color:#11203F">
  <div style="max-width:620px;margin:0 auto;padding:28px">
    <div style="background:#11203F;color:white;border-radius:18px 18px 0 0;padding:22px 26px">
      <div style="font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:#94f0ce;font-weight:700">Secure Share Password Recovery</div>
      <h1 style="margin:8px 0 0;font-size:24px">Your password reset code</h1>
    </div>
    <div style="background:white;border:1px solid #dbe4ee;border-top:0;border-radius:0 0 18px 18px;padding:26px">
      <p style="font-size:15px;line-height:1.6">Hello ${safeName},</p>
      <p style="font-size:15px;line-height:1.6">Use this verification code to reset your Secure Share password:</p>
      <div style="font-size:34px;letter-spacing:10px;font-weight:800;color:#24A673;background:#ecfdf5;border:1px solid #bbf7d0;border-radius:14px;text-align:center;padding:18px;margin:22px 0">${safeCode}</div>
      <p style="font-size:14px;line-height:1.6;color:#5B6778">This code expires in 5 minutes. If you did not request this reset, ignore this email and contact the system administrator.</p>
      <p style="font-size:13px;color:#5B6778;margin-top:22px">Secure Share System<br>Automated File Encryption & Secure Sharing</p>
    </div>
  </div></body></html>`;
}

async function deliverPasswordResetCode(user, code) {
  const destination = passwordResetDestinationFor(user);

  if (OTP_DELIVERY_MODE !== 'email') {
    terminalOtpNotice(user, code, 'password reset terminal fallback');
    return { method: 'terminal', sent: false, destinationHint: 'server terminal', note: 'Password reset code generated in terminal demo mode.' };
  }
  if (!nodemailer) {
    terminalOtpNotice(user, code, 'password reset fallback; nodemailer missing');
    return { method: 'terminal', sent: false, destinationHint: 'server terminal', note: 'Email mode requested, but nodemailer is not installed.' };
  }
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS || !destination || !isValidEmail(destination)) {
    terminalOtpNotice(user, code, 'password reset fallback; SMTP incomplete');
    return { method: 'terminal', sent: false, destinationHint: 'server terminal', note: 'Email settings are incomplete, so the reset code was printed in terminal.' };
  }

  try {
    const normalizedSmtpPass = SMTP_HOST.includes('gmail.com') ? String(SMTP_PASS).replace(/\s+/g, '') : SMTP_PASS;
    const transporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_SECURE,
      auth: { user: SMTP_USER, pass: normalizedSmtpPass },
      tls: { minVersion: 'TLSv1.2' },
    });
    await transporter.sendMail({
      from: OTP_FROM,
      to: destination,
      subject: 'Secure Share password reset code',
      text: `Your Secure Share password reset code is ${code}. It expires in 5 minutes. If you did not request this reset, ignore this email.`,
      html: passwordResetEmailHtml(user, code),
    });
    return { method: 'email', sent: true, destinationHint: maskEmail(destination), note: 'Password reset code sent by email.' };
  } catch (err) {
    console.error('Password reset email delivery failed:', err && err.message ? err.message : err);
    terminalOtpNotice(user, code, 'password reset email failed; terminal fallback used');
    return { method: 'terminal', sent: false, destinationHint: 'server terminal', note: 'Email delivery failed, so the reset code was printed in terminal.' };
  }
}

async function handleForgotPassword(req, res, bodyBuffer) {
  let data;
  try { data = JSON.parse(bodyBuffer.toString('utf8') || '{}'); }
  catch { return sendError(res, 400, 'Invalid JSON body.'); }
  const identifier = String(data.identifier || '').trim();
  if (!identifier) return sendError(res, 400, 'Enter your username or email address.');

  const db = getDb();
  const user = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?').get(identifier, identifier.toLowerCase());
  // Production-safe message avoids account enumeration.
  if (!user || user.status !== 'active') {
    logActivity(user ? user.id : null, 'password_reset_requested', `Password reset requested for "${identifier}"`, getClientIp(req));
    return sendJSON(res, 200, { ok: true, message: 'If the account exists and is active, a reset code has been sent.' });
  }

  const resetToken = randomToken(24);
  const code = generateSixDigitCode();
  const codeHash = hashOtpCode(resetToken, code);
  const expiresAt = Date.now() + PASSWORD_RESET_TTL_MS;
  db.prepare('DELETE FROM password_resets WHERE user_id = ?').run(user.id);
  db.prepare('INSERT INTO password_resets (token, user_id, code_hash, expires_at, ip_address) VALUES (?, ?, ?, ?, ?)')
    .run(resetToken, user.id, codeHash, expiresAt, getClientIp(req));
  const delivery = await deliverPasswordResetCode(user, code);
  logActivity(user.id, 'password_reset_requested', delivery.method === 'email'
    ? `Password reset code sent to ${delivery.destinationHint}`
    : 'Password reset code generated using terminal fallback', getClientIp(req));
  return sendJSON(res, 200, {
    ok: true,
    reset_token: resetToken,
    message: delivery.method === 'email'
      ? `A password reset code was sent to ${delivery.destinationHint}.`
      : 'A password reset code was generated in the server terminal.',
    delivery_method: delivery.method,
    destination_hint: delivery.destinationHint,
    expires_in_seconds: Math.floor(PASSWORD_RESET_TTL_MS / 1000),
  });
}

async function handleResetPassword(req, res, bodyBuffer) {
  let data;
  try { data = JSON.parse(bodyBuffer.toString('utf8') || '{}'); }
  catch { return sendError(res, 400, 'Invalid JSON body.'); }
  const token = String(data.reset_token || '').trim();
  const code = String(data.code || '').replace(/\D/g, '').slice(0, 6);
  const newPassword = String(data.new_password || '');
  if (!token || code.length !== 6) return sendError(res, 400, 'Enter the 6-digit reset code.');
  const policyError = passwordPolicyError(newPassword);
  if (policyError) return sendError(res, 400, policyError);

  const db = getDb();
  const reset = db.prepare('SELECT * FROM password_resets WHERE token = ?').get(token);
  if (!reset) return sendError(res, 400, 'Password reset session not found. Start again.');
  if (Date.now() > Number(reset.expires_at)) {
    db.prepare('DELETE FROM password_resets WHERE token = ?').run(token);
    logActivity(reset.user_id, 'password_reset_failed', 'Password reset code expired', getClientIp(req));
    return sendError(res, 410, 'Reset code expired. Start again.');
  }
  if (!verifyOtpCode(token, code, reset.code_hash)) {
    const attempts = Number(reset.attempts || 0) + 1;
    db.prepare('UPDATE password_resets SET attempts = ? WHERE token = ?').run(attempts, token);
    logActivity(reset.user_id, 'password_reset_failed', `Invalid password reset code attempt ${attempts}`, getClientIp(req));
    if (attempts >= PASSWORD_RESET_MAX_ATTEMPTS) {
      db.prepare('DELETE FROM password_resets WHERE token = ?').run(token);
      return sendError(res, 429, 'Too many incorrect reset codes. Start again.');
    }
    return sendError(res, 401, `Invalid reset code. ${PASSWORD_RESET_MAX_ATTEMPTS - attempts} attempt(s) remaining.`);
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(reset.user_id);
  if (!user || user.status !== 'active') {
    db.prepare('DELETE FROM password_resets WHERE token = ?').run(token);
    return sendError(res, 403, 'Account is not active. Contact the administrator.');
  }
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(newPassword), user.id);
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(user.id);
  db.prepare('DELETE FROM password_resets WHERE user_id = ?').run(user.id);
  logActivity(user.id, 'password_reset_completed', 'Password reset completed using email verification code', getClientIp(req));
  return sendJSON(res, 200, { ok: true, message: 'Password reset successful. Sign in with your new password.' });
}

/* ------------------------------------------------------------------ *
 * API routing
 * ------------------------------------------------------------------ */

async function handleApi(req, res, url, bodyBuffer) {
  const method = req.method;
  const segments = url.pathname.split('/').filter(Boolean); // e.g. ['api','files','3','download']

  if (segments.length < 2 || segments[0] !== 'api') {
    return sendError(res, 404, 'Not found.');
  }
  const resource = segments[1];

  /* ---------------- Public auth endpoints ---------------- */

  if (resource === 'auth' && segments[2] === 'register' && method === 'POST') {
    return handleRegister(req, res, bodyBuffer);
  }
  if (resource === 'auth' && segments[2] === 'login' && method === 'POST') {
    return handleLogin(req, res, bodyBuffer);
  }
  if (resource === 'auth' && segments[2] === 'verify-2fa' && method === 'POST') {
    return handleVerifyTwoFactor(req, res, bodyBuffer);
  }
  if (resource === 'auth' && segments[2] === 'resend-2fa' && method === 'POST') {
    return handleResendTwoFactor(req, res, bodyBuffer);
  }
  if (resource === 'auth' && segments[2] === 'forgot-password' && method === 'POST') {
    return handleForgotPassword(req, res, bodyBuffer);
  }
  if (resource === 'auth' && segments[2] === 'reset-password' && method === 'POST') {
    return handleResetPassword(req, res, bodyBuffer);
  }

  /* ---------------- Everything below requires auth ---------------- */

  const user = requireAuth(req, res);
  if (!user) return;

  if (resource === 'auth' && segments[2] === 'logout' && method === 'POST') {
    if (!checkCsrf(req, res, user)) return;
    const db = getDb();
    const token = parseCookies(req)[COOKIE_NAME];
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    logActivity(user.id, 'logout', 'User logged out', getClientIp(req));
    clearSessionCookie(res);
    return sendJSON(res, 200, { ok: true });
  }

  if (resource === 'session' && method === 'GET') {
    return sendJSON(res, 200, { user: publicUser(user), csrf_token: user.csrf_token });
  }

  /* ---- guard: every mutating endpoint below needs a valid CSRF token ---- */
  if (['POST', 'PATCH', 'PUT', 'DELETE'].includes(method) && !checkCsrf(req, res, user)) {
    return;
  }

  switch (resource) {
    case 'dashboard':
      return handleDashboard(req, res, user);

    case 'security':
      return handleSecurity(req, res, url, segments, method, bodyBuffer, user);

    case 'files':
      return handleFiles(req, res, url, segments, method, bodyBuffer, user);

    case 'logs':
      return handleLogs(req, res, url, user);

    case 'admin':
      return handleAdmin(req, res, url, segments, method, bodyBuffer, user);

    case 'profile':
      return handleProfile(req, res, segments, method, bodyBuffer, user);

    default:
      return sendError(res, 404, 'Unknown API endpoint.');
  }
}

/* ------------------------- Registration ------------------------- */

async function handleRegister(req, res, bodyBuffer) {
  let data;
  try {
    data = JSON.parse(bodyBuffer.toString('utf8') || '{}');
  } catch {
    return sendError(res, 400, 'Invalid JSON body.');
  }
  const { full_name, username, email, password } = data;

  if (!full_name || typeof full_name !== 'string' || full_name.trim().length < 3) {
    return sendError(res, 400, 'Please provide your full name (at least 3 characters).');
  }
  if (!isValidUsername(username)) {
    return sendError(res, 400, 'Username must be 3-30 characters (letters, numbers, . _ -).');
  }
  if (!isValidEmail(email)) {
    return sendError(res, 400, 'Please provide a valid email address.');
  }
  const policyError = passwordPolicyError(password);
  if (policyError) return sendError(res, 400, policyError);

  const db = getDb();
  const usernameTaken = db.prepare('SELECT id FROM users WHERE username = ?').get(username.trim());
  if (usernameTaken) return sendError(res, 409, 'That username is already taken.');
  const emailTaken = db.prepare('SELECT id FROM users WHERE email = ?').get(email.trim().toLowerCase());
  if (emailTaken) return sendError(res, 409, 'That email address is already registered.');

  const info = db.prepare(
    'INSERT INTO users (full_name, username, email, password_hash, role) VALUES (?, ?, ?, ?, ?)'
  ).run(full_name.trim(), username.trim(), email.trim().toLowerCase(), hashPassword(password), 'employee');

  logActivity(Number(info.lastInsertRowid), 'register', 'New account created', getClientIp(req));
  return sendJSON(res, 201, { ok: true, message: 'Account created. You can now log in.' });
}

/* ----------------------------- Login ----------------------------- */

async function handleLogin(req, res, bodyBuffer) {
  let data;
  try {
    data = JSON.parse(bodyBuffer.toString('utf8') || '{}');
  } catch {
    return sendError(res, 400, 'Invalid JSON body.');
  }
  const { username, password } = data;
  const identifier = String(username || '').trim();
  if (!identifier || !password) {
    return sendError(res, 400, 'Please enter your username and password.');
  }
  if (isLockedOut(identifier)) {
    logActivity(null, 'login_locked', `Login blocked for "${identifier}" (too many failed attempts)`, getClientIp(req));
    return sendError(res, 429, 'Too many failed attempts. Account temporarily locked for 15 minutes.');
  }

  const db = getDb();
  const user = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?').get(identifier, identifier);

  if (!user || !verifyPassword(password, user.password_hash)) {
    recordFailure(identifier);
    logActivity(user ? user.id : null, 'login_failed',
      `Failed login attempt for "${identifier}"`, getClientIp(req));
    return sendError(res, 401, 'Invalid username or password.');
  }
  if (user.status !== 'active') {
    logActivity(user.id, 'login_denied', 'Login denied: account is suspended', getClientIp(req));
    return sendError(res, 403, 'Your account has been suspended. Contact the administrator.');
  }

  clearFailures(identifier);

  if (user.role === 'admin') {
    const challenge = await createAdminTwoFactorChallenge(user, req);
    return sendJSON(res, 200, {
      ok: false,
      two_factor_required: true,
      challenge_token: challenge.challengeToken,
      message: challenge.delivery.method === 'email'
        ? `Admin verification required. A 6-digit code was sent to ${challenge.delivery.destinationHint}.`
        : 'Admin verification required. Enter the 6-digit code generated by the server terminal.',
      delivery_method: challenge.delivery.method,
      destination_hint: challenge.delivery.destinationHint,
      expires_in_seconds: Math.floor(ADMIN_2FA_TTL_MS / 1000),
      demo_code: challenge.delivery.demoCode,
    });
  }

  return completeLoginSession(req, res, user, 'User logged in successfully');
}

/* --------------------------- Dashboard --------------------------- */

function handleDashboard(req, res, user) {
  const db = getDb();
  const ownFiles = db.prepare(
    'SELECT COUNT(*) AS c, COALESCE(SUM(size),0) AS s FROM files WHERE owner_id = ?'
  ).get(user.id);
  const sharedWithMe = db.prepare(
    `SELECT COUNT(*) AS c FROM shares
     WHERE shared_with = ?
       AND (expires_at IS NULL OR expires_at > datetime('now'))
       AND NOT (view_once = 1 AND opened_at IS NOT NULL)`
  ).get(user.id);
  const recentActivity = db.prepare(
    'SELECT * FROM activity_logs WHERE user_id = ? ORDER BY id DESC LIMIT 6'
  ).all(user.id);
  const recentFiles = db.prepare(
    `SELECT f.*, (SELECT COUNT(*) FROM shares s WHERE s.file_id = f.id) AS share_count
     FROM files f WHERE f.owner_id = ? ORDER BY f.id DESC LIMIT 5`
  ).all(user.id);

  const stats = {
    my_files: ownFiles.c,
    my_storage_bytes: ownFiles.s,
    my_storage_formatted: formatBytes(ownFiles.s),
    shared_with_me: sharedWithMe.c,
    quota_bytes: STORAGE_QUOTA,
    quota_formatted: formatBytes(STORAGE_QUOTA),
    my_preview_events: db.prepare("SELECT COUNT(*) AS c FROM activity_logs WHERE user_id = ? AND action = 'preview'").get(user.id).c,
    my_blocked_events: db.prepare("SELECT COUNT(*) AS c FROM activity_logs WHERE user_id = ? AND action = 'access_denied'").get(user.id).c,
  };

  if (user.role === 'admin') {
    stats.total_users = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
    stats.total_files = db.prepare('SELECT COUNT(*) AS c FROM files').get().c;
    stats.total_logs = db.prepare('SELECT COUNT(*) AS c FROM activity_logs').get().c;
    stats.total_storage = formatBytes(db.prepare('SELECT COALESCE(SUM(size),0) AS s FROM files').get().s);
    stats.users_by_role = db.prepare('SELECT role, COUNT(*) AS c FROM users GROUP BY role').all();
    stats.view_only_shares = db.prepare("SELECT COUNT(*) AS c FROM shares WHERE permission = 'view' AND (expires_at IS NULL OR expires_at > datetime('now')) AND NOT (view_once = 1 AND opened_at IS NOT NULL)").get().c;
    stats.download_shares = db.prepare("SELECT COUNT(*) AS c FROM shares WHERE permission = 'download' AND (expires_at IS NULL OR expires_at > datetime('now'))").get().c;
    stats.view_once_shares = db.prepare("SELECT COUNT(*) AS c FROM shares WHERE view_once = 1").get().c;
    stats.expired_shares = db.prepare("SELECT COUNT(*) AS c FROM shares WHERE expires_at IS NOT NULL AND expires_at <= datetime('now')").get().c;
    stats.blocked_access = db.prepare("SELECT COUNT(*) AS c FROM activity_logs WHERE action = 'access_denied'").get().c;
    stats.preview_events = db.prepare("SELECT COUNT(*) AS c FROM activity_logs WHERE action = 'preview'").get().c;
    stats.recent_all_activity = db.prepare(
      `SELECT a.*, u.username FROM activity_logs a LEFT JOIN users u ON u.id = a.user_id
       ORDER BY a.id DESC LIMIT 8`
    ).all();
  }

  return sendJSON(res, 200, {
    stats,
    recent_activity: recentActivity.map(formatLog),
    recent_files: recentFiles.map((f) => formatFile(f, user)),
  });
}


function handleSecurity(req, res, url, segments, method, bodyBuffer, user) {
  if (segments[2] === 'overview' && method === 'GET') return handleSecurityOverview(req, res, user);
  if (segments[2] === 'report' && method === 'GET') return handleSecurityReport(req, res, user);
  if (segments[2] === 'alerts' && method === 'GET') return handleSecurityAlerts(req, res, url, user);
  if (segments[2] === 'alerts' && segments[3] && segments[4] === 'resolve' && method === 'POST') {
    if (!checkCsrf(req, res, user)) return;
    return handleResolveSecurityAlert(req, res, Number(segments[3]), user);
  }
  return sendError(res, 404, 'Unknown security endpoint.');
}

function securityReportPayload(user) {
  const db = getDb();
  const auditIntegrity = verifyAuditChain();
  const counts = {
    users: db.prepare('SELECT COUNT(*) AS c FROM users').get().c,
    active_users: db.prepare("SELECT COUNT(*) AS c FROM users WHERE status = 'active'").get().c,
    files: db.prepare('SELECT COUNT(*) AS c FROM files').get().c,
    shares: db.prepare('SELECT COUNT(*) AS c FROM shares').get().c,
    open_alerts: db.prepare("SELECT COUNT(*) AS c FROM security_alerts WHERE status = 'open'").get().c,
    logs: db.prepare('SELECT COUNT(*) AS c FROM activity_logs').get().c,
  };
  const recentAlerts = db.prepare(
    `SELECT sa.*, u.username FROM security_alerts sa LEFT JOIN users u ON u.id = sa.user_id
     ORDER BY sa.id DESC LIMIT 20`
  ).all();
  const recentLogs = db.prepare(
    `SELECT a.*, u.username FROM activity_logs a LEFT JOIN users u ON u.id = a.user_id
     ORDER BY a.id DESC LIMIT 30`
  ).all().map(formatLog);
  return {
    generated_at: new Date().toISOString(),
    generated_by: publicUser(user),
    system: {
      app: 'Secure Share System',
      encryption: 'AES-256-GCM',
      password_hashing: 'scrypt',
      database: 'SQLite',
      admin_2fa_delivery: OTP_DELIVERY_MODE === 'email' ? 'Email mode' : 'Terminal mode',
    },
    counts,
    audit_integrity: auditIntegrity,
    alerts: recentAlerts,
    recent_logs: recentLogs,
  };
}

function handleSecurityReport(req, res, user) {
  if (!requireAdminOrSecurity(user)) return sendError(res, 403, 'Security report access requires admin, security officer or auditor role.');
  const report = securityReportPayload(user);
  logActivity(user.id, 'security_report_exported', 'Exported security report JSON', getClientIp(req));
  res.writeHead(200, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Disposition': 'attachment; filename="secure-share-security-report.json"',
    'Cache-Control': 'no-store',
  });
  res.end(JSON.stringify(report, null, 2));
}

function handleSecurityAlerts(req, res, url, user) {
  if (!requireAdminOrSecurity(user)) return sendError(res, 403, 'Security alerts require admin, security officer or auditor role.');
  const db = getDb();
  const status = (url.searchParams.get('status') || '').trim();
  let where = '1=1';
  const params = [];
  if (status && ['open', 'resolved'].includes(status)) { where += ' AND sa.status = ?'; params.push(status); }
  const alerts = db.prepare(
    `SELECT sa.*, u.username FROM security_alerts sa LEFT JOIN users u ON u.id = sa.user_id
     WHERE ${where} ORDER BY sa.id DESC LIMIT 100`
  ).all(...params);
  return sendJSON(res, 200, { alerts });
}

function handleResolveSecurityAlert(req, res, alertId, user) {
  if (user.role !== 'admin' && user.role !== 'security_officer') return sendError(res, 403, 'Only admin or security officer can resolve alerts.');
  const db = getDb();
  const alert = db.prepare('SELECT * FROM security_alerts WHERE id = ?').get(alertId);
  if (!alert) return sendError(res, 404, 'Security alert not found.');
  db.prepare("UPDATE security_alerts SET status = 'resolved', resolved_at = datetime('now') WHERE id = ?").run(alertId);
  logActivity(user.id, 'security_alert_resolved', `Resolved security alert #${alertId}: ${alert.title}`, getClientIp(req));
  return sendJSON(res, 200, { ok: true, message: 'Security alert resolved.' });
}

function handleSecurityOverview(req, res, user) {
  const db = getDb();
  const activeShares = db.prepare("SELECT COUNT(*) AS c FROM shares WHERE (expires_at IS NULL OR expires_at > datetime('now')) AND NOT (view_once = 1 AND opened_at IS NOT NULL)").get().c;
  const viewShares = db.prepare("SELECT COUNT(*) AS c FROM shares WHERE permission = 'view'").get().c;
  const downloadShares = db.prepare("SELECT COUNT(*) AS c FROM shares WHERE permission = 'download'").get().c;
  const viewOnce = db.prepare("SELECT COUNT(*) AS c FROM shares WHERE view_once = 1").get().c;
  const consumedOnce = db.prepare("SELECT COUNT(*) AS c FROM shares WHERE view_once = 1 AND opened_at IS NOT NULL").get().c;
  const denied = db.prepare("SELECT COUNT(*) AS c FROM activity_logs WHERE action = 'access_denied'").get().c;
  const previews = db.prepare("SELECT COUNT(*) AS c FROM activity_logs WHERE action = 'preview'").get().c;
  const downloads = db.prepare("SELECT COUNT(*) AS c FROM activity_logs WHERE action = 'download'").get().c;
  const admin2faSuccess = db.prepare("SELECT COUNT(*) AS c FROM activity_logs WHERE action = 'admin_2fa_success'").get().c;
  const admin2faFailed = db.prepare("SELECT COUNT(*) AS c FROM activity_logs WHERE action = 'admin_2fa_failed'").get().c;
  const files = db.prepare('SELECT COUNT(*) AS c, COALESCE(SUM(size),0) AS s FROM files').get();
  const auditIntegrity = verifyAuditChain();
  const openAlerts = db.prepare("SELECT COUNT(*) AS c FROM security_alerts WHERE status = 'open'").get().c;
  const highAlerts = db.prepare("SELECT COUNT(*) AS c FROM security_alerts WHERE status = 'open' AND severity = 'high'").get().c;
  const recentAlerts = db.prepare(`SELECT sa.*, u.username FROM security_alerts sa LEFT JOIN users u ON u.id = sa.user_id ORDER BY sa.id DESC LIMIT 8`).all();
  const recentSecurityEvents = db.prepare(
    `SELECT a.*, u.username FROM activity_logs a LEFT JOIN users u ON u.id = a.user_id
     WHERE a.action IN ('preview','download','access_denied','share','revoke_share','login_failed','login_locked','admin_2fa_challenge','admin_2fa_success','admin_2fa_failed','admin_2fa_expired','admin_2fa_resend')
     ORDER BY a.id DESC LIMIT 8`
  ).all().map(formatLog);

  return sendJSON(res, 200, {
    user: publicUser(user),
    controls: [
      { name: 'AES-256-GCM File Encryption', status: 'Enabled', detail: 'Uploaded files are encrypted before storage.' },
      { name: 'scrypt Password Hashing', status: 'Enabled', detail: 'Passwords are stored as salted scrypt hashes.' },
      { name: 'Session Authentication', status: 'Enabled', detail: 'Authenticated users receive secure server-side sessions.' },
      { name: 'Admin 6-Digit Verification', status: 'Enabled', detail: 'Administrator login requires password plus a temporary 6-digit verification code.' },
      { name: 'Email OTP Delivery', status: OTP_DELIVERY_MODE === 'email' ? 'Configured' : 'Terminal Fallback', detail: OTP_DELIVERY_MODE === 'email' ? 'Admin verification codes are delivered through SMTP email when credentials are valid.' : 'Local fallback prints verification codes in the server terminal until SMTP is configured.' },
      { name: 'CSRF Protection', status: 'Enabled', detail: 'Mutating requests require a CSRF token.' },
      { name: 'Role-Based Access Control', status: 'Extended', detail: 'Admin, security officer, auditor, manager, employee, HR, finance and external partner roles are supported.' },
      { name: 'View-only Secure Preview', status: 'Enabled', detail: 'View users preview in-browser without download permission.' },
      { name: 'Share Expiry and View Once', status: 'Enabled', detail: 'Owners can create expiring and one-time preview shares.' },
      { name: 'Tamper-resistant Audit Logging', status: auditIntegrity.ok ? 'Intact' : 'Broken', detail: auditIntegrity.ok ? `Hash chain verified across ${auditIntegrity.checked} log entries.` : `Audit chain break detected at log #${auditIntegrity.broken_at}.` },
      { name: 'Security Alerts', status: openAlerts ? `${openAlerts} Open` : 'Clear', detail: 'High-risk events create security alerts for administrator review.' },
    ],
    metrics: {
      encrypted_files: files.c,
      encrypted_storage: formatBytes(files.s),
      active_shares: activeShares,
      view_only_shares: viewShares,
      download_shares: downloadShares,
      view_once_shares: viewOnce,
      consumed_view_once: consumedOnce,
      preview_events: previews,
      download_events: downloads,
      admin_2fa_success: admin2faSuccess,
      admin_2fa_failed: admin2faFailed,
      admin_2fa_delivery: OTP_DELIVERY_MODE === 'email' ? 'Email Mode' : 'Terminal Mode',
      blocked_attempts: denied,
      audit_integrity: auditIntegrity.ok ? 'Intact' : 'Broken',
      audit_checked: auditIntegrity.checked,
      open_alerts: openAlerts,
      high_alerts: highAlerts,
    },
    audit_integrity: auditIntegrity,
    recent_alerts: recentAlerts,
    recent_security_events: recentSecurityEvents,
  });
}

/* ----------------------------- Files ----------------------------- */

function handleFiles(req, res, url, segments, method, bodyBuffer, user) {
  const db = getDb();
  const id = segments[2] ? Number(segments[2]) : null;

  // GET /api/files  — list my files (with search + pagination)
  if (method === 'GET' && id === null) {
    const search = (url.searchParams.get('search') || '').trim();
    const page = Math.max(1, Number(url.searchParams.get('page')) || 1);
    const perPage = Math.min(50, Math.max(1, Number(url.searchParams.get('per_page')) || 10));
    const offset = (page - 1) * perPage;

    let where = 'f.owner_id = ?';
    const params = [user.id];
    if (search) {
      where += ' AND f.original_name LIKE ?';
      params.push('%' + search + '%');
    }
    const total = db.prepare(`SELECT COUNT(*) AS c FROM files f WHERE ${where}`).get(...params).c;
    const rows = db.prepare(
      `SELECT f.*, (SELECT COUNT(*) FROM shares s WHERE s.file_id = f.id) AS share_count,
              (SELECT GROUP_CONCAT(u2.username) FROM shares s2 JOIN users u2 ON u2.id = s2.shared_with WHERE s2.file_id = f.id) AS shared_with_names
       FROM files f WHERE ${where}
       ORDER BY f.id DESC LIMIT ? OFFSET ?`
    ).all(...params, perPage, offset);

    return sendJSON(res, 200, {
      files: rows.map((f) => formatFile(f, user)),
      total, page, per_page: perPage,
    });
  }

  // GET /api/files/shared  — files shared with me
  if (method === 'GET' && segments[2] === 'shared') {
    const rows = db.prepare(
      `SELECT f.*, sh.id AS share_id, sh.permission, sh.expires_at, sh.view_once, sh.opened_at, sh.last_accessed_at,
              sh.created_at AS shared_at, u.username AS shared_by_name
       FROM shares sh
       JOIN files f ON f.id = sh.file_id
       JOIN users u ON u.id = sh.shared_by
       WHERE sh.shared_with = ?
       ORDER BY sh.id DESC`
    ).all(user.id);
    return sendJSON(res, 200, { files: rows.map((f) => formatFile(f, user, true)) });
  }

  // POST /api/files  — upload (multipart)
  if (method === 'POST' && id === null) {
    if (!canUploadFiles(user)) {
      logActivity(user.id, 'access_denied', `Upload denied for role ${user.role}`, getClientIp(req));
      return sendError(res, 403, 'Your role is read-only and cannot upload files.');
    }
    return handleUpload(req, res, bodyBuffer, user);
  }

  if (id) {
    const file = db.prepare('SELECT * FROM files WHERE id = ?').get(id);
    if (!file) return sendError(res, 404, 'File not found.');

    // GET /api/files/:id/preview  — decrypt only for an authorized in-browser preview.
    // View-only users can preview but cannot download the decrypted file.
    if (method === 'GET' && segments[3] === 'preview') {
      const share = getShareForUser(db, id, user.id);
      if (!canReadFile(db, file, user)) {
        const message = getAccessDenialMessage(share, 'You do not have permission to preview this file.');
        logActivity(user.id, 'access_denied',
          `Preview denied on file #${id} ("${file.original_name}") — ${message}`, getClientIp(req));
        return sendPreviewHtml(res, 'Preview blocked', `
          <div class="notice" style="background:#fef2f2;border-color:#fecaca;color:#991b1b"><strong>Preview blocked:</strong> ${escapeHtml(message)}</div>
          <div class="meta"><div class="k">File name</div><div>${escapeHtml(file.original_name)}</div><div class="k">Reason</div><div>${escapeHtml(shareAccessState(share).reason)}</div></div>
          <p class="muted">This proves the system is enforcing access control instead of simply hiding buttons in the user interface.</p>
        `, 403);
      }
      const blobPath = path.join(STORAGE_DIR, file.stored_name);
      if (!fs.existsSync(blobPath)) {
        logActivity(user.id, 'preview_failed', `File #${id} missing on disk`, getClientIp(req));
        return sendError(res, 500, 'Encrypted file is missing on the server.');
      }
      try {
        const key = Buffer.from(file.key_b64, 'base64');
        const iv = Buffer.from(file.iv_b64, 'base64');
        const ownerOrAdmin = file.owner_id === user.id || user.role === 'admin';
        const permissionLabel = ownerOrAdmin ? 'Owner/Admin' : (share.permission === 'download' ? 'Download' : (share.view_once ? 'View once' : 'View only'));
        logActivity(user.id, 'preview', `Previewed "${file.original_name}" (id #${id}, decrypted temporarily)`, getClientIp(req));
        if (share && !ownerOrAdmin) {
          db.prepare('UPDATE shares SET last_accessed_at = datetime(\'now\') WHERE id = ?').run(share.id);
        }

        const plain = decryptBuffer(fs.readFileSync(blobPath), key, iv);

        // A view-once share is consumed only after successful decryption.
        if (share && !ownerOrAdmin && Number(share.view_once) === 1 && !share.opened_at) {
          db.prepare('UPDATE shares SET opened_at = datetime(\'now\'), last_accessed_at = datetime(\'now\') WHERE id = ?').run(share.id);
          logActivity(user.id, 'view_once_consumed', `View-once access consumed for "${file.original_name}"`, getClientIp(req));
        }

        if (previewableText(file)) {
          const text = plain.toString('utf8');
          return sendPreviewHtml(res, file.original_name, `
            <div class="notice"><strong>Secure preview:</strong> this file remains encrypted at rest. The system decrypted it temporarily for authorized viewing only.</div>
            <div class="meta"><div class="k">File name</div><div>${escapeHtml(file.original_name)}</div><div class="k">Size</div><div>${formatBytes(file.size)}</div><div class="k">Permission</div><div>${escapeHtml(permissionLabel)}</div></div>
            <pre>${escapeHtml(text)}</pre>
          `);
        }

        if (previewableInline(file)) {
          const b64 = plain.toString('base64');
          const mime = file.mime_type || 'application/octet-stream';
          const src = `data:${mime};base64,${b64}`;
          const isImage = String(mime).startsWith('image/');
          return sendPreviewHtml(res, file.original_name, `
            <div class="notice"><strong>Secure preview:</strong> preview was decrypted temporarily in-browser. Download permission is still checked separately.</div>
            <div class="meta"><div class="k">File name</div><div>${escapeHtml(file.original_name)}</div><div class="k">Size</div><div>${formatBytes(file.size)}</div><div class="k">Permission</div><div>${escapeHtml(permissionLabel)}</div></div>
            <div class="preview-frame">
              ${isImage
                ? `<img class="img-preview" alt="Secure preview" src="${src}">`
                : `<iframe class="doc-frame" title="Secure document preview" src="${src}"></iframe>`}
            </div>
          `);
        }

        return sendPreviewHtml(res, file.original_name, `
          <div class="notice"><strong>View-only access is active.</strong> This file type cannot be safely rendered inside the browser without triggering a download.</div>
          <div class="meta"><div class="k">File name</div><div>${escapeHtml(file.original_name)}</div><div class="k">File type</div><div>${escapeHtml(file.mime_type || 'unknown')}</div><div class="k">Size</div><div>${formatBytes(file.size)}</div><div class="k">Security reason</div><div>Download is disabled because the owner granted view-only permission.</div></div>
          <p class="muted">For full document reading, the owner should share the file with <strong>Download</strong> permission or convert the document to PDF/TXT before sharing as view-only.</p>
        `);
      } catch (e) {
        return sendError(res, 500, 'Could not create secure preview: ' + e.message);
      }
    }

    // GET /api/files/:id/download  — decrypt & stream (check BEFORE the
    // generic GET handler so /files/:id/download is not shadowed)
    if (method === 'GET' && segments[3] === 'download') {
      const share = getShareForUser(db, id, user.id);
      const canDownload = canDownloadFile(db, file, user);
      if (!canDownload) {
        const message = getAccessDenialMessage(share, 'You do not have download permission for this file.');
        logActivity(user.id, 'access_denied',
          `Download denied on file #${id} ("${file.original_name}") — ${message}`, getClientIp(req));
        return sendError(res, 403, message);
      }
      const blobPath = path.join(STORAGE_DIR, file.stored_name);
      if (!fs.existsSync(blobPath)) {
        logActivity(user.id, 'download_failed', `File #${id} missing on disk`, getClientIp(req));
        return sendError(res, 500, 'Encrypted file is missing on the server.');
      }
      try {
        const stream = createDecryptStream(blobPath, Buffer.from(file.key_b64, 'base64'), Buffer.from(file.iv_b64, 'base64'));
        if (share && file.owner_id !== user.id && user.role !== 'admin') {
          db.prepare('UPDATE shares SET last_accessed_at = datetime(\'now\') WHERE id = ?').run(share.id);
        }
        logActivity(user.id, 'download', `Downloaded "${file.original_name}" (id #${id}, decrypted on the fly)`, getClientIp(req));
        const asciiName = file.original_name.replace(/[^\x20-\x7e]/g, '_').replace(/"/g, "'");
        res.writeHead(200, {
          'Content-Type': file.mime_type || 'application/octet-stream',
          'Content-Disposition': `attachment; filename="${asciiName}"; filename*=UTF-8''${encodeURIComponent(file.original_name)}`,
          'Content-Length': file.size,
          'X-Content-Type-Options': 'nosniff',
        });
        stream.on('error', () => { try { res.destroy(); } catch {} });
        stream.pipe(res);
        return;
      } catch (e) {
        return sendError(res, 500, 'Could not decrypt file: ' + e.message);
      }
    }

    // GET /api/files/:id  — file details + access list
    if (method === 'GET') {
      const canAccess = canReadFile(db, file, user);
      if (!canAccess) {
        logActivity(user.id, 'access_denied', `Access denied to file #${id} ("${file.original_name}")`, getClientIp(req));
        return sendError(res, 403, 'You do not have permission to access this file.');
      }
      const shares = db.prepare(
        `SELECT sh.id, sh.permission, sh.expires_at, sh.view_once, sh.opened_at, sh.last_accessed_at, sh.created_at,
                u.id AS user_id, u.username, u.full_name
         FROM shares sh JOIN users u ON u.id = sh.shared_with
         WHERE sh.file_id = ? ORDER BY sh.id DESC`
      ).all(id).map(formatShare);
      const history = db.prepare(
        `SELECT a.*, u.username FROM activity_logs a LEFT JOIN users u ON u.id = a.user_id
         WHERE a.details LIKE ? OR a.details LIKE ?
         ORDER BY a.id DESC LIMIT 12`
      ).all(`%#${id}%`, `%${file.original_name}%`).map(formatLog);
      return sendJSON(res, 200, { file: formatFile(file, user), shares, access_history: history, is_owner: file.owner_id === user.id || user.role === 'admin' });
    }

    // POST /api/files/:id/share  — grant access to another user
    if (method === 'POST' && segments[3] === 'share') {
      if (!canShareOwnedFiles(user) || (file.owner_id !== user.id && user.role !== 'admin')) {
        logActivity(user.id, 'access_denied', `Sharing denied on file #${id}`, getClientIp(req));
        return sendError(res, 403, 'Only the file owner with share permission (or an administrator) can share this file.');
      }
      let data;
      try { data = JSON.parse(bodyBuffer.toString('utf8') || '{}'); } catch {
        return sendError(res, 400, 'Invalid JSON body.');
      }
      const target = String(data.username || '').trim();
      let permission = data.permission === 'view' ? 'view' : 'download';
      const viewOnce = Boolean(data.view_once);
      if (viewOnce) permission = 'view';
      const expiryDays = Number(data.expiry_days || 0);
      const allowedExpiry = new Set([0, 1, 3, 7, 14, 30]);
      if (!allowedExpiry.has(expiryDays)) return sendError(res, 400, 'Invalid expiry period.');
      const expiresAt = expiryDays > 0
        ? new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000).toISOString().slice(0, 19).replace('T', ' ')
        : null;
      if (!target) return sendError(res, 400, 'Please specify the username of the recipient.');
      const recipient = db.prepare('SELECT id, username, status FROM users WHERE username = ? OR email = ?')
        .get(target, target);
      if (!recipient) return sendError(res, 404, 'No user found with that username/email.');
      if (recipient.status !== 'active') return sendError(res, 400, 'That account is suspended and cannot receive shares.');
      if (recipient.id === file.owner_id) return sendError(res, 400, 'This file already belongs to that user.');
      db.prepare(
        `INSERT INTO shares (file_id, shared_by, shared_with, permission, expires_at, view_once, opened_at, last_accessed_at)
         VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)
         ON CONFLICT(file_id, shared_with) DO UPDATE SET
           permission = excluded.permission,
           expires_at = excluded.expires_at,
           view_once = excluded.view_once,
           opened_at = NULL,
           last_accessed_at = NULL,
           created_at = datetime('now')`
      ).run(id, user.id, recipient.id, permission, expiresAt, viewOnce ? 1 : 0);
      const shareMode = viewOnce ? 'view-once' : permission;
      const expiryNote = expiresAt ? `, expires: ${expiresAt}` : ', no expiry';
      logActivity(user.id, 'share',
        `Shared "${file.original_name}" with @${recipient.username} (permission: ${shareMode}${expiryNote})`, getClientIp(req));
      return sendJSON(res, 200, { ok: true, message: `File shared with @${recipient.username} (${shareMode}).` });
    }

    // DELETE /api/files/:id/shares/:shareId  — revoke access
    if (method === 'DELETE' && segments[3] === 'shares' && segments[4]) {
      const shareId = Number(segments[4]);
      const share = db.prepare('SELECT * FROM shares WHERE id = ? AND file_id = ?').get(shareId, id);
      if (!share) return sendError(res, 404, 'Share record not found.');
      if (file.owner_id !== user.id && user.role !== 'admin') {
        return sendError(res, 403, 'Only the file owner (or an administrator) can revoke access.');
      }
      db.prepare('DELETE FROM shares WHERE id = ?').run(shareId);
      logActivity(user.id, 'revoke_share', `Revoked access to "${file.original_name}"`, getClientIp(req));
      return sendJSON(res, 200, { ok: true, message: 'Access revoked.' });
    }

    // DELETE /api/files/:id  — delete file permanently (must come AFTER the
    // share-revoke route above so /files/:id/shares/:shareId is not matched)
    if (method === 'DELETE') {
      if (file.owner_id !== user.id && user.role !== 'admin') {
        logActivity(user.id, 'access_denied', `Delete denied on file #${id}`, getClientIp(req));
        return sendError(res, 403, 'Only the file owner (or an administrator) can delete this file.');
      }
      db.prepare('DELETE FROM files WHERE id = ?').run(id);
      const blobPath = path.join(STORAGE_DIR, file.stored_name);
      fs.rm(blobPath, { force: true }, () => {});
      logActivity(user.id, 'delete_file', `Deleted file "${file.original_name}" (id #${id})`, getClientIp(req));
      return sendJSON(res, 200, { ok: true, message: 'File deleted successfully.' });
    }
  }

  return sendError(res, 404, 'Unknown files endpoint.');
}

/* ---------------------------- Upload ----------------------------- */

async function handleUpload(req, res, bodyBuffer, user) {
  const contentType = req.headers['content-type'] || '';
  const boundaryMatch = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType);
  if (!boundaryMatch) return sendError(res, 400, 'Expected multipart/form-data upload.');

  const db = getDb();
  // Enforce per-user storage quota
  const used = db.prepare('SELECT COALESCE(SUM(size),0) AS s FROM files WHERE owner_id = ?').get(user.id).s;
  const parts = parseMultipart(bodyBuffer, boundaryMatch[1] || boundaryMatch[2]);

  const filePart = parts.find((p) => p.name === 'file' && p.filename);
  if (!filePart || filePart.value.length === 0) {
    return sendError(res, 400, 'Please choose a file to upload.');
  }
  if (filePart.value.length > MAX_UPLOAD_SIZE) {
    return sendError(res, 413, 'File exceeds the maximum upload size of 25 MB.');
  }
  if (used + filePart.value.length > STORAGE_QUOTA) {
    return sendError(res, 413, 'Uploading this file would exceed your storage quota (250 MB).');
  }

  const originalName = sanitizeFilename(filePart.filename);
  const extension = path.extname(originalName).toLowerCase();
  if (!ALLOWED_UPLOAD_EXTENSIONS.has(extension)) {
    logActivity(user.id, 'upload_blocked', `Blocked unsupported upload "${originalName}"`, getClientIp(req));
    return sendError(res, 400,
      'Unsupported file type. Allowed: PDF, Word, Excel, TXT, CSV, PNG, JPG and WEBP.');
  }
  const mimeType = String(filePart.contentType || 'application/octet-stream').split(';')[0].trim();
  const dangerousMime = new Set(['application/x-msdownload','application/x-sh','application/x-bat','application/x-msdos-program','text/x-php','application/x-php']);
  if (dangerousMime.has(mimeType)) {
    logActivity(user.id, 'upload_blocked', `Blocked dangerous MIME type for "${originalName}" (${mimeType})`, getClientIp(req));
    return sendError(res, 400, 'This upload type is blocked for security reasons.');
  }

  // ---- Automated encryption: encrypt BEFORE anything is written to disk ----
  const { ciphertext, key, iv } = encryptBuffer(filePart.value);
  const storedName = randomToken(16) + '.bin';
  fs.writeFileSync(path.join(STORAGE_DIR, storedName), ciphertext);

  const info = db.prepare(
    `INSERT INTO files (owner_id, original_name, stored_name, size, mime_type, key_b64, iv_b64)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(user.id, originalName, storedName, filePart.value.length, mimeType,
    key.toString('base64'), iv.toString('base64'));

  logActivity(user.id, 'upload',
    `Uploaded "${originalName}" (${formatBytes(filePart.value.length)}) — AES-256-GCM encrypted before storage`,
    getClientIp(req));

  return sendJSON(res, 201, {
    ok: true, message: 'File uploaded and automatically encrypted.',
    file: { id: Number(info.lastInsertRowid), original_name: originalName, size: filePart.value.length },
  });
}

/* ----------------------------- Logs ------------------------------ */

function handleLogs(req, res, url, user) {
  const db = getDb();
  const isAdmin = user.role === 'admin';
  const search = (url.searchParams.get('search') || '').trim();
  const page = Math.max(1, Number(url.searchParams.get('page')) || 1);
  const perPage = Math.min(100, Math.max(1, Number(url.searchParams.get('per_page')) || 20));
  const offset = (page - 1) * perPage;

  let where = isAdmin ? '1=1' : 'a.user_id = ?';
  const params = isAdmin ? [] : [user.id];
  if (search) {
    where += ' AND (a.action LIKE ? OR a.details LIKE ? OR COALESCE(u.username,"") LIKE ?)';
    params.push('%' + search + '%', '%' + search + '%', '%' + search + '%');
  }
  const total = db.prepare(
    `SELECT COUNT(*) AS c FROM activity_logs a LEFT JOIN users u ON u.id = a.user_id WHERE ${where}`
  ).get(...params).c;
  const rows = db.prepare(
    `SELECT a.*, u.username FROM activity_logs a
     LEFT JOIN users u ON u.id = a.user_id
     WHERE ${where} ORDER BY a.id DESC LIMIT ? OFFSET ?`
  ).all(...params, perPage, offset);

  return sendJSON(res, 200, { logs: rows.map(formatLog), total, page, per_page: perPage });
}

/* ------------------------- Admin endpoints ------------------------ */

function handleAdmin(req, res, url, segments, method, bodyBuffer, user) {
  if (user.role !== 'admin') {
    logActivity(user.id, 'access_denied', 'Attempted to access administrator area', getClientIp(req));
    return sendError(res, 403, 'Administrator access required.');
  }
  const db = getDb();
  if (segments[2] !== 'users') return sendError(res, 404, 'Unknown admin endpoint.');

  // GET /api/admin/users
  if (method === 'GET') {
    const search = (url.searchParams.get('search') || '').trim();
    let where = '1=1';
    const params = [];
    if (search) {
      where = '(u.username LIKE ? OR u.full_name LIKE ? OR u.email LIKE ?)';
      params.push('%' + search + '%', '%' + search + '%', '%' + search + '%');
    }
    const rows = db.prepare(
      `SELECT u.*, (SELECT COUNT(*) FROM files f WHERE f.owner_id = u.id) AS file_count,
              (SELECT COALESCE(SUM(f.size),0) FROM files f WHERE f.owner_id = u.id) AS storage_used
       FROM users u WHERE ${where} ORDER BY u.id ASC`
    ).all(...params);
    return sendJSON(res, 200, { users: rows.map(publicUserWithStats) });
  }

  // POST /api/admin/users  — create a user (only when there is NO :id segment,
  // otherwise POST /api/admin/users/:id/reset-password would be shadowed)
  if (method === 'POST' && segments.length === 3) {
    let data;
    try { data = JSON.parse(bodyBuffer.toString('utf8') || '{}'); } catch {
      return sendError(res, 400, 'Invalid JSON body.');
    }
    const { full_name, username, email, password, role } = data;
    if (!full_name || full_name.trim().length < 3) return sendError(res, 400, 'Full name is required (min 3 characters).');
    if (!isValidUsername(username)) return sendError(res, 400, 'Username must be 3-30 characters (letters, numbers, . _ -).');
    if (!isValidEmail(email)) return sendError(res, 400, 'Please provide a valid email address.');
    const policyError = passwordPolicyError(password);
    if (policyError) return sendError(res, 400, policyError);
    const finalRole = ROLES.includes(role) ? role : 'employee';
    if (db.prepare('SELECT id FROM users WHERE username = ?').get(username.trim())) {
      return sendError(res, 409, 'That username is already taken.');
    }
    if (db.prepare('SELECT id FROM users WHERE email = ?').get(email.trim().toLowerCase())) {
      return sendError(res, 409, 'That email address is already registered.');
    }
    const info = db.prepare(
      'INSERT INTO users (full_name, username, email, password_hash, role) VALUES (?, ?, ?, ?, ?)'
    ).run(full_name.trim(), username.trim(), email.trim().toLowerCase(), hashPassword(password), finalRole);
    logActivity(user.id, 'user_created', `Created account for @${username.trim()} (role: ${finalRole})`, getClientIp(req));
    return sendJSON(res, 201, { ok: true, message: 'User account created.' });
  }

  const userId = segments[3] ? Number(segments[3]) : null;
  if (!userId) return sendError(res, 400, 'User id is required.');
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!target) return sendError(res, 404, 'User not found.');

  // PATCH /api/admin/users/:id  — update role / status
  if (method === 'PATCH') {
    let data;
    try { data = JSON.parse(bodyBuffer.toString('utf8') || '{}'); } catch {
      return sendError(res, 400, 'Invalid JSON body.');
    }
    const changes = [];
    const params = [];
    if (data.role !== undefined) {
      if (!ROLES.includes(data.role)) return sendError(res, 400, 'Invalid role.');
      if (target.id === user.id && data.role !== 'admin') {
        return sendError(res, 400, 'You cannot demote your own administrator role.');
      }
      changes.push('role = ?'); params.push(data.role);
    }
    if (data.status !== undefined) {
      if (!['active', 'suspended'].includes(data.status)) return sendError(res, 400, 'Invalid status.');
      if (target.id === user.id && data.status === 'suspended') {
        return sendError(res, 400, 'You cannot suspend your own account.');
      }
      changes.push('status = ?'); params.push(data.status);
      if (data.status === 'suspended') {
        db.prepare('DELETE FROM sessions WHERE user_id = ?').run(target.id);
      }
    }
    if (changes.length === 0) return sendError(res, 400, 'Nothing to update.');
    params.push(target.id);
    db.prepare(`UPDATE users SET ${changes.join(', ')} WHERE id = ?`).run(...params);
    logActivity(user.id, 'user_updated',
      `Updated account @${target.username}: ${changes.join(', ')}`, getClientIp(req));
    return sendJSON(res, 200, { ok: true, message: 'User updated.' });
  }

  // POST /api/admin/users/:id/reset-password
  if (method === 'POST' && segments[4] === 'reset-password') {
    // Generate a policy-compliant temporary password:
    const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    const lower = 'abcdefghijkmnopqrstuvwxyz';
    const digits = '23456789';
    const pick = (set) => set[crypto.randomInt(set.length)];
    const temp = pick(upper) + pick(lower) + pick(digits) +
      Array.from({ length: 9 }, () => pick(upper + lower + digits)).join('');
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(temp), target.id);
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(target.id);
    logActivity(user.id, 'password_reset', `Reset password for @${target.username}`, getClientIp(req));
    return sendJSON(res, 200, { ok: true, message: 'Password reset.', temporary_password: temp });
  }

  // DELETE /api/admin/users/:id
  if (method === 'DELETE') {
    if (target.id === user.id) return sendError(res, 400, 'You cannot delete your own account.');
    const files = db.prepare('SELECT stored_name FROM files WHERE owner_id = ?').all(target.id);
    db.prepare('DELETE FROM users WHERE id = ?').run(target.id); // cascades sessions/shares/files rows
    for (const f of files) {
      fs.rm(path.join(STORAGE_DIR, f.stored_name), { force: true }, () => {});
    }
    logActivity(user.id, 'user_deleted', `Deleted account @${target.username} and their files`, getClientIp(req));
    return sendJSON(res, 200, { ok: true, message: 'User and their files deleted.' });
  }

  return sendError(res, 404, 'Unknown admin endpoint.');
}

/* ---------------------------- Profile ----------------------------- */

function handleProfile(req, res, segments, method, bodyBuffer, user) {
  const db = getDb();
  if (method === 'GET') {
    const row = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
    return sendJSON(res, 200, { user: publicUser(row) });
  }
  if (method === 'PATCH' && !segments[2]) {
    let data;
    try { data = JSON.parse(bodyBuffer.toString('utf8') || '{}'); } catch {
      return sendError(res, 400, 'Invalid JSON body.');
    }
    const updates = [];
    const params = [];
    if (data.full_name !== undefined) {
      if (String(data.full_name).trim().length < 3) return sendError(res, 400, 'Full name must be at least 3 characters.');
      updates.push('full_name = ?'); params.push(String(data.full_name).trim());
    }
    if (data.email !== undefined) {
      const email = String(data.email).trim().toLowerCase();
      if (!isValidEmail(email)) return sendError(res, 400, 'Please provide a valid email address.');
      const clash = db.prepare('SELECT id FROM users WHERE email = ? AND id != ?').get(email, user.id);
      if (clash) return sendError(res, 409, 'That email address is already in use.');
      updates.push('email = ?'); params.push(email);
    }
    if (updates.length === 0) return sendError(res, 400, 'Nothing to update.');
    params.push(user.id);
    db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...params);
    logActivity(user.id, 'profile_updated', 'Updated profile information', getClientIp(req));
    const fresh = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
    return sendJSON(res, 200, { ok: true, user: publicUser(fresh), message: 'Profile updated.' });
  }
  if (method === 'POST' && segments[2] === 'password') {
    let data;
    try { data = JSON.parse(bodyBuffer.toString('utf8') || '{}'); } catch {
      return sendError(res, 400, 'Invalid JSON body.');
    }
    const row = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
    if (!verifyPassword(String(data.current_password || ''), row.password_hash)) {
      logActivity(user.id, 'password_change_failed', 'Wrong current password provided', getClientIp(req));
      return sendError(res, 400, 'Your current password is incorrect.');
    }
    const policyError = passwordPolicyError(data.new_password);
    if (policyError) return sendError(res, 400, policyError);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(data.new_password), user.id);
    db.prepare('DELETE FROM sessions WHERE user_id = ? AND token != ?')
      .run(user.id, parseCookies(req)[COOKIE_NAME]);
    logActivity(user.id, 'password_changed', 'Password changed successfully', getClientIp(req));
    return sendJSON(res, 200, { ok: true, message: 'Password changed. Other sessions were signed out.' });
  }
  return sendError(res, 404, 'Unknown profile endpoint.');
}

/* ------------------------- Formatters ----------------------------- */

function formatFile(f, user, isShared = false) {
  const ownerOrAdmin = f.owner_id === user.id || user.role === 'admin';
  const pseudoShare = isShared ? {
    id: f.share_id,
    permission: f.permission,
    expires_at: f.expires_at,
    view_once: f.view_once,
    opened_at: f.opened_at,
    last_accessed_at: f.last_accessed_at,
  } : null;
  const state = isShared ? shareAccessState(pseudoShare) : { active: true, reason: 'owner' };
  const out = {
    id: f.id,
    original_name: f.original_name,
    size: f.size,
    size_formatted: formatBytes(f.size),
    mime_type: f.mime_type,
    created_at: f.created_at,
    is_owner: ownerOrAdmin,
    can_preview: ownerOrAdmin || state.active,
    can_download: ownerOrAdmin || (state.active && f.permission === 'download'),
    share_count: f.share_count !== undefined ? f.share_count : 0,
  };
  if (f.shared_with_names) out.shared_with_names = String(f.shared_with_names).split(',').join(', @');
  if (isShared) {
    out.share_id = f.share_id;
    out.permission = f.permission;
    out.expires_at = f.expires_at;
    out.view_once = Number(f.view_once) === 1;
    out.opened_at = f.opened_at;
    out.last_accessed_at = f.last_accessed_at;
    out.shared_at = f.shared_at;
    out.shared_by_name = f.shared_by_name;
    out.access_state = state.reason;
    out.access_active = state.active;
    out.can_download = state.active && f.permission === 'download';
    out.can_preview = state.active;
  }
  return out;
}

function formatShare(s) {
  const state = shareAccessState(s);
  return {
    id: s.id,
    user_id: s.user_id,
    username: s.username,
    full_name: s.full_name,
    permission: s.permission,
    expires_at: s.expires_at,
    view_once: Number(s.view_once) === 1,
    opened_at: s.opened_at,
    last_accessed_at: s.last_accessed_at,
    created_at: s.created_at,
    access_state: state.reason,
    access_active: state.active,
  };
}

function formatLog(l) {
  return {
    id: l.id,
    user_id: l.user_id,
    username: l.username || '(system)',
    action: l.action,
    details: l.details,
    ip_address: l.ip_address,
    created_at: l.created_at,
  };
}

function publicUserWithStats(u) {
  return {
    id: u.id, full_name: u.full_name, username: u.username, email: u.email,
    role: u.role, status: u.status, created_at: u.created_at,
    file_count: u.file_count, storage_used: u.storage_used,
    storage_formatted: formatBytes(u.storage_used),
  };
}

/* ------------------------------------------------------------------ *
 * Static file serving
 * ------------------------------------------------------------------ */

function serveStatic(req, res, url) {
  let pathname = decodeURIComponent(url.pathname);
  if (pathname === '/') pathname = '/login.html';

  // Prevent path traversal
  const resolved = path.resolve(PUBLIC_DIR, '.' + pathname);
  if (!resolved.startsWith(path.resolve(PUBLIC_DIR))) {
    return sendError(res, 403, 'Forbidden.');
  }

  fs.readFile(resolved, (err, data) => {
    if (err) {
      if (err.code === 'ENOENT' || err.code === 'EISDIR') {
        return serve404(res);
      }
      return sendError(res, 500, 'Server error reading file.');
    }
    const ext = path.extname(resolved).toLowerCase();
    res.writeHead(200, {
      'Content-Type': MIME_TYPES[ext] || 'application/octet-stream',
      'Content-Length': data.length,
      'Cache-Control': 'no-cache',
    });
    res.end(data);
  });
}

function serve404(res) {
  const html = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>404 — Page Not Found | Secure Share</title><link rel="stylesheet" href="/css/style.css"></head>
<body class="auth-body"><div class="auth-card center-card">
<h1>404</h1><p>The page you are looking for does not exist.</p>
<a class="btn btn-primary" href="/">Go to login</a></div></body></html>`;
  res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': Buffer.byteLength(html) });
  res.end(html);
}

/* ------------------------------------------------------------------ *
 * Security headers for every response
 * ------------------------------------------------------------------ */

function applySecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'");
}

/* ------------------------------------------------------------------ *
 * HTTP server
 * ------------------------------------------------------------------ */

const server = http.createServer(async (req, res) => {
  try {
    applySecurityHeaders(res);
    const url = new URL(req.url, 'http://' + (req.headers.host || 'localhost'));

    // API routes
    if (url.pathname.startsWith('/api/') || url.pathname === '/api') {
      const isMutating = ['POST', 'PATCH', 'PUT', 'DELETE'].includes(req.method);
      const maxBody = isMutating
        ? (req.headers['content-type'] || '').includes('multipart/form-data')
          ? MAX_UPLOAD_SIZE + 1024 * 1024
          : 1024 * 1024
        : 0;
      const body = maxBody > 0 ? await readBody(req, maxBody) : Buffer.alloc(0);
      await handleApi(req, res, url, body);
      return;
    }

    // Everything else: static assets
    serveStatic(req, res, url);
  } catch (err) {
    const status = (err.status && err.status < 500) ? err.status : 500;
    if (status >= 500) console.error('Request error:', err);
    if (!res.headersSent) {
      try { sendError(res, status, status >= 500 ? 'Internal server error.' : err.message); } catch {}
    } else {
      try { res.end(); } catch {}
    }
  }
});

server.on('clientError', (_err, socket) => {
  socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
});

initDatabase();

// Friendly message instead of a raw stack trace when the port is already in use
server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error('');
    console.error('  [!] Port ' + PORT + ' is already in use.');
    console.error('      The Secure Share System is probably already running.');
    console.error('      -> Open http://' + HOST + ':' + PORT + ' in your browser, or');
    console.error('      -> stop the other instance first, or');
    console.error('      -> run on another port:  PORT=3001 node server.js');
    console.error('');
  } else {
    console.error('Server error:', err);
  }
  process.exit(1);
});

server.listen(PORT, HOST, () => {
  console.log('============================================================');
  console.log('  Secure Share System - Automated File Encryption & Sharing');
  console.log('============================================================');
  console.log('  URL       : http://' + HOST + ':' + PORT);
  console.log('  Database  : SQLite (secure-share.db)');
  console.log('  Encryption: AES-256-GCM (automated, before storage)');
  console.log('');
  console.log('  Demo accounts:');
  console.log('    admin    / Admin@123   (System Administrator)');
  console.log('    manager  / Manager@123 (Manager)');
  console.log('    employee / Employee@123 (Employee)');
  console.log('    auditor  / Auditor@123  (Auditor - read-only audit)');
  console.log('    security / Security@123 (Security Officer)');
  console.log('============================================================');
});
