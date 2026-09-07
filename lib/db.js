'use strict';

/**
 * SQLite database layer for the Secure Share System.
 *
 * Uses Node's built-in `node:sqlite` module (available since Node 22.5).
 * Creates the schema and seeds demo data on first run.
 */

const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { hashPassword } = require('./security');

const DB_PATH = path.join(__dirname, '..', 'secure-share.db');
const STORAGE_DIR = path.join(__dirname, '..', 'storage');

let db = null;

/** Full SQL schema for the system. */
const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name     TEXT    NOT NULL,
  username      TEXT    NOT NULL UNIQUE,
  email         TEXT    NOT NULL UNIQUE,
  password_hash TEXT    NOT NULL,
  role          TEXT    NOT NULL DEFAULT 'employee',   -- admin | security_officer | auditor | manager | employee | hr_officer | finance_officer | external_partner
  status        TEXT    NOT NULL DEFAULT 'active',     -- active | suspended
  created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  token       TEXT    NOT NULL UNIQUE,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token  TEXT    NOT NULL,
  expires_at  TEXT    NOT NULL,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS files (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  original_name TEXT    NOT NULL,
  stored_name   TEXT    NOT NULL UNIQUE,   -- random file name of the ciphertext blob
  size          INTEGER NOT NULL,          -- original (plaintext) size in bytes
  mime_type     TEXT    NOT NULL,
  key_b64       TEXT    NOT NULL,          -- AES-256 key, base64
  iv_b64        TEXT    NOT NULL,          -- AES-GCM 12-byte IV, base64
  created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS shares (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id     INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  shared_by   INTEGER NOT NULL REFERENCES users(id),
  shared_with INTEGER NOT NULL REFERENCES users(id),
  permission  TEXT    NOT NULL DEFAULT 'download',   -- view | download
  expires_at  TEXT,                                    -- optional share expiry
  view_once   INTEGER NOT NULL DEFAULT 0,               -- 1 = single-use secure preview
  opened_at   TEXT,                                    -- set after first view-once preview
  last_accessed_at TEXT,                               -- preview/download tracking
  created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  UNIQUE(file_id, shared_with)
);

CREATE TABLE IF NOT EXISTS activity_logs (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
  action     TEXT NOT NULL,
  details    TEXT,
  ip_address TEXT,
  prev_hash  TEXT,
  entry_hash TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS password_resets (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  token        TEXT NOT NULL UNIQUE,
  user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash    TEXT NOT NULL,
  expires_at   INTEGER NOT NULL,
  attempts     INTEGER NOT NULL DEFAULT 0,
  ip_address   TEXT,
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS security_alerts (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
  severity    TEXT NOT NULL DEFAULT 'medium',
  title       TEXT NOT NULL,
  details     TEXT,
  status      TEXT NOT NULL DEFAULT 'open',
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  resolved_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_files_owner    ON files(owner_id);
CREATE INDEX IF NOT EXISTS idx_shares_file    ON shares(file_id);
CREATE INDEX IF NOT EXISTS idx_shares_with    ON shares(shared_with);
CREATE INDEX IF NOT EXISTS idx_logs_user      ON activity_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_logs_created   ON activity_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_resets_token   ON password_resets(token);
CREATE INDEX IF NOT EXISTS idx_alerts_status  ON security_alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON security_alerts(created_at);
`;

/** Add a column safely for users opening older copies of the project database. */
function ensureColumn(table, column, definition) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name);
  if (!cols.includes(column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition};`);
  }
}

/** Lightweight migrations so earlier demo databases still work after upgrades. */
function runMigrations() {
  ensureColumn('shares', 'expires_at', 'TEXT');
  ensureColumn('shares', 'view_once', 'INTEGER NOT NULL DEFAULT 0');
  ensureColumn('shares', 'opened_at', 'TEXT');
  ensureColumn('shares', 'last_accessed_at', 'TEXT');
  ensureColumn('activity_logs', 'prev_hash', 'TEXT');
  ensureColumn('activity_logs', 'entry_hash', 'TEXT');
  db.exec(`CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    ip_address TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );`);
  db.exec(`CREATE TABLE IF NOT EXISTS security_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    title TEXT NOT NULL,
    details TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    resolved_at TEXT
  );`);
  backfillMissingAuditHashes();
}

function backfillMissingAuditHashes() {
  try {
    const missing = db.prepare("SELECT COUNT(*) AS c FROM activity_logs WHERE entry_hash IS NULL OR entry_hash = '' OR entry_hash = 'PENDING'").get().c;
    if (!missing) return;
    const rows = db.prepare('SELECT * FROM activity_logs ORDER BY id ASC').all();
    let prevHash = 'GENESIS';
    const update = db.prepare('UPDATE activity_logs SET prev_hash = ?, entry_hash = ? WHERE id = ?');
    for (const row of rows) {
      const entryHash = makeLogHash({
        id: row.id, userId: row.user_id, action: row.action, details: row.details,
        ip: row.ip_address, createdAt: row.created_at, prevHash,
      });
      update.run(prevHash, entryHash, row.id);
      prevHash = entryHash;
    }
  } catch (e) {
    console.error('audit hash backfill failed:', e.message);
  }
}

/** Statements that run after the schema is created (used for idempotent seeds). */
function seedUsers() {
  const existing = db.prepare('SELECT COUNT(*) AS c FROM users').get();
  if (existing.c > 0) return;

  const insert = db.prepare(
    'INSERT INTO users (full_name, username, email, password_hash, role) VALUES (?, ?, ?, ?, ?)'
  );
  const tx = db.exec('BEGIN');
  try {
    insert.run('Mohamed Ahmed', 'admin', 'admin@securefiles.local', hashPassword('Admin@123'), 'admin');
    insert.run('Jane Manager', 'manager', 'manager@securefiles.local', hashPassword('Manager@123'), 'manager');
    insert.run('John Employee', 'employee', 'employee@securefiles.local', hashPassword('Employee@123'), 'employee');
    insert.run('Aisha Auditor', 'auditor', 'auditor@securefiles.local', hashPassword('Auditor@123'), 'auditor');
    insert.run('David Security', 'security', 'security@securefiles.local', hashPassword('Security@123'), 'security_officer');
    insert.run('Helen HR', 'hr', 'hr@securefiles.local', hashPassword('Hr@12345'), 'hr_officer');
    insert.run('Farah Finance', 'finance', 'finance@securefiles.local', hashPassword('Finance@123'), 'finance_officer');
    insert.run('External Partner', 'partner', 'partner@securefiles.local', hashPassword('Partner@123'), 'external_partner');
    db.exec('COMMIT');
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
}

/** Create a few demo files owned by admin and shared with the employee. */
function seedDemoFiles() {
  const { encryptBuffer } = require('./security');
  const count = db.prepare('SELECT COUNT(*) AS c FROM files').get();
  if (count.c > 0) return;

  const admin = db.prepare("SELECT * FROM users WHERE username = 'admin'").get();
  const employee = db.prepare("SELECT * FROM users WHERE username = 'employee'").get();
  const manager = db.prepare("SELECT * FROM users WHERE username = 'manager'").get();
  if (!admin || !employee || !manager) return;

  const demos = [
    {
      name: 'Company-Security-Policy-2026.txt',
      mime: 'text/plain',
      content: 'CORPORATE SECURITY POLICY (SAMPLE)\n\n' +
        'Classification: INTERNAL SECURITY\n\n' +
        '1. All confidential files must be encrypted before storage or sharing.\n' +
        '2. View-only documents may be previewed in the browser but cannot be downloaded.\n' +
        '3. View-once access expires immediately after the first successful preview.\n' +
        '4. All file operations are logged for accountability.\n' +
        '5. Report suspected data exposure to the system administrator immediately.\n'
    },
    {
      name: 'Quarterly-Financial-Report-Q3.txt',
      mime: 'text/plain',
      content: 'QUARTERLY FINANCIAL REPORT - Q3 (SAMPLE)\n\n' +
        'Revenue: KES 12,450,000\n' +
        'Expenses: KES 8,210,000\n' +
        'Net Profit: KES 4,240,000\n' +
        'Classification: CONFIDENTIAL - download permission required for offline use.\n'
    },
    {
      name: 'HR-Employee-Salary-Summary.txt',
      mime: 'text/plain',
      content: 'HR EMPLOYEE SALARY SUMMARY (SAMPLE)\n\n' +
        'This file demonstrates view-only sharing. The recipient can preview the document securely inside the system, but the download button is not available.\n\n' +
        'Sample Rows:\n- Employee A: KES 85,000\n- Employee B: KES 72,000\n- Employee C: KES 91,000\n'
    },
    {
      name: 'Board-Meeting-Minutes-Preview-Once.txt',
      mime: 'text/plain',
      content: 'BOARD MEETING MINUTES - VIEW ONCE SAMPLE\n\n' +
        'This file demonstrates one-time preview access. After the first preview, the system records the opening time and blocks further view-only access unless the owner shares it again.\n'
    }
  ];

  const insertFile = db.prepare(
    `INSERT INTO files (owner_id, original_name, stored_name, size, mime_type, key_b64, iv_b64)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  );
  const insertShare = db.prepare(
    `INSERT INTO shares (file_id, shared_by, shared_with, permission, expires_at, view_once) VALUES (?, ?, ?, ?, ?, ?)`
  );

  db.exec('BEGIN');
  try {
    for (const demo of demos) {
      const plain = Buffer.from(demo.content, 'utf8');
      const { ciphertext, key, iv } = encryptBuffer(plain);
      const storedName = cryptoRandomName() + '.bin';
      fs.writeFileSync(path.join(STORAGE_DIR, storedName), ciphertext);
      const info = insertFile.run(
        admin.id, demo.name, storedName, plain.length, demo.mime,
        key.toString('base64'), iv.toString('base64')
      );
      const fileId = Number(info.lastInsertRowid);
      // Demo permissions intentionally include all important presentation cases:
      // view-only preview, normal download, expiring share, and view-once share.
      const tomorrow = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString().slice(0, 19).replace('T', ' ');
      const nextWeek = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 19).replace('T', ' ');
      if (demo.name.includes('Security-Policy')) {
        insertShare.run(fileId, admin.id, employee.id, 'view', nextWeek, 0);
        insertShare.run(fileId, admin.id, manager.id, 'download', nextWeek, 0);
      } else if (demo.name.includes('Financial')) {
        insertShare.run(fileId, admin.id, employee.id, 'download', nextWeek, 0);
        insertShare.run(fileId, admin.id, manager.id, 'view', tomorrow, 0);
      } else if (demo.name.includes('Salary')) {
        insertShare.run(fileId, admin.id, employee.id, 'view', tomorrow, 0);
        insertShare.run(fileId, admin.id, manager.id, 'download', nextWeek, 0);
      } else {
        insertShare.run(fileId, admin.id, employee.id, 'view', tomorrow, 1);
        insertShare.run(fileId, admin.id, manager.id, 'view', tomorrow, 1);
      }
      logActivity(admin.id, 'upload', `Demo file "${demo.name}" encrypted and stored (automated encryption)`);
    }
    db.exec('COMMIT');
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
}

/** Small random hex name generator (mirrors server helper, kept local to avoid circular deps). */
function cryptoRandomName() {
  const crypto = require('crypto');
  return crypto.randomBytes(16).toString('hex');
}

/**
 * Insert an activity log row. Safe to call from anywhere.
 * @param {number|null} userId
 * @param {string} action
 * @param {string|null} details
 * @param {string|null} ip
 */
function makeLogHash({ id, userId, action, details, ip, createdAt, prevHash }) {
  return crypto
    .createHash('sha256')
    .update([id, userId || '', action || '', details || '', ip || '', createdAt || '', prevHash || 'GENESIS'].join('|'))
    .digest('hex');
}

function createSecurityAlert(userId, severity, title, details) {
  try {
    const dbc = getDb();
    dbc.prepare(
      'INSERT INTO security_alerts (user_id, severity, title, details) VALUES (?, ?, ?, ?)'
    ).run(userId || null, severity || 'medium', title || 'Security alert', details || null);
  } catch (e) {
    console.error('createSecurityAlert failed:', e.message);
  }
}

/**
 * Insert an activity log row. Every entry is hash-chained to the previous one.
 * If a previous row is edited later, the audit integrity check can detect it.
 */
function logActivity(userId, action, details, ip) {
  try {
    const dbc = getDb();
    const prev = dbc.prepare('SELECT entry_hash FROM activity_logs ORDER BY id DESC LIMIT 1').get();
    const prevHash = prev && prev.entry_hash ? prev.entry_hash : 'GENESIS';
    const info = dbc.prepare(
      'INSERT INTO activity_logs (user_id, action, details, ip_address, prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(userId || null, action, details || null, ip || null, prevHash, 'PENDING');
    const row = dbc.prepare('SELECT * FROM activity_logs WHERE id = ?').get(Number(info.lastInsertRowid));
    const entryHash = makeLogHash({
      id: row.id, userId: row.user_id, action: row.action, details: row.details,
      ip: row.ip_address, createdAt: row.created_at, prevHash: row.prev_hash,
    });
    dbc.prepare('UPDATE activity_logs SET entry_hash = ? WHERE id = ?').run(entryHash, row.id);

    const highRisk = new Set(['access_denied', 'login_locked', 'admin_2fa_failed', 'admin_2fa_expired', 'password_reset_failed', 'password_reset_completed', 'upload_blocked']);
    if (highRisk.has(action)) {
      const severity = action === 'access_denied' || action === 'login_locked' ? 'high' : 'medium';
      createSecurityAlert(userId || null, severity, action.replace(/_/g, ' '), details || 'Security event recorded.');
    }
  } catch (e) {
    // Logging must never break a request.
    console.error('logActivity failed:', e.message);
  }
}

function verifyAuditChain() {
  const dbc = getDb();
  const rows = dbc.prepare('SELECT * FROM activity_logs ORDER BY id ASC').all();
  let prevHash = 'GENESIS';
  let checked = 0;
  for (const row of rows) {
    const expectedPrev = row.prev_hash || 'GENESIS';
    if (expectedPrev !== prevHash) {
      return { ok: false, checked, broken_at: row.id, reason: 'Previous hash mismatch' };
    }
    const expectedHash = makeLogHash({
      id: row.id, userId: row.user_id, action: row.action, details: row.details,
      ip: row.ip_address, createdAt: row.created_at, prevHash: row.prev_hash,
    });
    if (row.entry_hash !== expectedHash) {
      return { ok: false, checked, broken_at: row.id, reason: 'Entry hash mismatch' };
    }
    prevHash = row.entry_hash;
    checked += 1;
  }
  return { ok: true, checked, broken_at: null, reason: 'Audit chain intact' };
}

/** Open (and initialize) the database. */
function initDatabase() {
  if (db) return db;
  if (!fs.existsSync(STORAGE_DIR)) {
    fs.mkdirSync(STORAGE_DIR, { recursive: true });
  }
  db = new DatabaseSync(DB_PATH);
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec(SCHEMA);
  runMigrations();
  seedUsers();
  seedDemoFiles();
  return db;
}

/** Drop everything and recreate (used by `npm run db:reset`). */
function resetDatabase() {
  if (db) db.close();
  if (fs.existsSync(DB_PATH)) fs.unlinkSync(DB_PATH);
  if (fs.existsSync(STORAGE_DIR)) {
    for (const f of fs.readdirSync(STORAGE_DIR)) {
      fs.unlinkSync(path.join(STORAGE_DIR, f));
    }
  } else {
    fs.mkdirSync(STORAGE_DIR, { recursive: true });
  }
  db = null;
  return initDatabase();
}

/** Return the open database handle (initializing if needed). */
function getDb() {
  return initDatabase();
}

module.exports = { initDatabase, getDb, resetDatabase, logActivity, createSecurityAlert, verifyAuditChain, DB_PATH, STORAGE_DIR };
