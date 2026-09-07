-- ============================================================================
--  Secure Share System — SQL Database Schema
--  Automated File Encryption and Secure Sharing System for Corporate Data
--  Protection  (Kenya Methodist University — CISY 401 Research Project)
--
--  The application (server.js) creates this schema automatically on first run
--  using SQLite (node:sqlite). This file is the canonical, portable copy of
--  the schema and seed data for documentation and manual setup.
--
--  Compatible with SQLite. (For MySQL, replace AUTOINCREMENT with
--  AUTO_INCREMENT and datetime('now') with NOW().)
-- ============================================================================

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------
-- 1. USERS — accounts and roles (Role-Based Access Control)
--    role:   admin | manager | employee
--    status: active | suspended
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name     TEXT    NOT NULL,
  username      TEXT    NOT NULL UNIQUE,
  email         TEXT    NOT NULL UNIQUE,
  password_hash TEXT    NOT NULL,          -- scrypt hash (salt embedded)
  role          TEXT    NOT NULL DEFAULT 'employee',
  status        TEXT    NOT NULL DEFAULT 'active',
  created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ---------------------------------------------------------------------------
-- 2. SESSIONS — login sessions + per-session CSRF token
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  token       TEXT    NOT NULL UNIQUE,     -- random 256-bit session token
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token  TEXT    NOT NULL,            -- anti-CSRF token for this session
  expires_at  TEXT    NOT NULL,            -- sliding expiry (8 hours)
  created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ---------------------------------------------------------------------------
-- 3. FILES — metadata of encrypted files
--    The actual ciphertext blob lives in /storage/<stored_name> and is
--    encrypted with AES-256-GCM using a random per-file key (key_b64) and
--    IV (iv_b64). Blob layout: [16-byte auth tag | ciphertext].
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS files (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  original_name TEXT    NOT NULL,          -- sanitized original file name
  stored_name   TEXT    NOT NULL UNIQUE,   -- random name of the encrypted blob
  size          INTEGER NOT NULL,          -- original plaintext size in bytes
  mime_type     TEXT    NOT NULL,
  key_b64       TEXT    NOT NULL,          -- AES-256 key (base64)
  iv_b64        TEXT    NOT NULL,          -- AES-GCM 12-byte IV (base64)
  created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ---------------------------------------------------------------------------
-- 4. SHARES — secure file sharing with permissions
--    permission: view (secure browser preview only) | download (preview + decrypted download)
--    expires_at: optional access expiry timestamp
--    view_once: one successful preview consumes the share
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS shares (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id     INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  shared_by   INTEGER NOT NULL REFERENCES users(id),
  shared_with INTEGER NOT NULL REFERENCES users(id),
  permission  TEXT    NOT NULL DEFAULT 'download',
  expires_at  TEXT,
  view_once   INTEGER NOT NULL DEFAULT 0,
  opened_at   TEXT,
  last_accessed_at TEXT,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  UNIQUE(file_id, shared_with)
);

-- ---------------------------------------------------------------------------
-- 5. ACTIVITY_LOGS — audit trail of file operations and access attempts
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS activity_logs (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
  action     TEXT NOT NULL,                -- login, upload, download, share, ...
  details    TEXT,
  ip_address TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ---------------------------------------------------------------------------
-- Indexes for common queries
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_files_owner  ON files(owner_id);
CREATE INDEX IF NOT EXISTS idx_shares_file  ON shares(file_id);
CREATE INDEX IF NOT EXISTS idx_shares_with  ON shares(shared_with);
CREATE INDEX IF NOT EXISTS idx_logs_user    ON activity_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_logs_created ON activity_logs(created_at);

-- ============================================================================
-- SEED DATA (demo accounts — passwords are scrypt hashes of the values below)
--   admin    / Admin@123      -> Mohamed Ahmed
--   manager  / Manager@123    -> Manager
--   employee / Employee@123   -> Employee
-- ============================================================================
INSERT OR IGNORE INTO users (id, full_name, username, email, password_hash, role)
VALUES
  (1, 'Mohamed Ahmed', 'admin',    'admin@securefiles.local',    '$placeholder_admin_hash',    'admin'),
  (2, 'Jane Manager',         'manager',  'manager@securefiles.local',  '$placeholder_manager_hash',  'manager'),
  (3, 'John Employee',        'employee', 'employee@securefiles.local', '$placeholder_employee_hash', 'employee');

-- NOTE: the placeholder hashes above are replaced at application startup with
-- real scrypt hashes of Admin@123 / Manager@123 / Employee@123. If you create
-- the schema manually, generate hashes with the application (see lib/security.js)
-- or reset the database with:  npm run db:reset
