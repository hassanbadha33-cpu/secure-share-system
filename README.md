# 🔐 Secure Share System

**Development of an Automated File Encryption and Secure Sharing System for Corporate Data Protection**

A complete, working web application built for the *Kenya Methodist University — CISY 401: Research Project I* proposal (see `research.pdf`). It provides a secure corporate platform where authorised users can upload documents, have them **automatically encrypted before storage**, securely share files with approved users under **role-based access control**, and keep a full **audit log** of every file operation.

---

## ✅ Features (mapped to the research objectives)

| # | Specific Objective (from the proposal) | Implemented |
|---|----------------------------------------|-------------|
| 1 | Design a secure web-based platform for uploading, storing and managing corporate files | ✅ Full web app: upload, list, search, details, delete, storage quota |
| 2 | Implement an automated file encryption mechanism that protects files **before** they are stored or shared | ✅ Every file is encrypted with **AES-256-GCM** (random key + IV per file) before anything touches disk; ciphertext blobs contain no plaintext |
| 3 | Develop user authentication & authorization so only authorised users access specific files | ✅ Registration/login with **scrypt** password hashing, HttpOnly session cookies, CSRF protection, login lockout; per-file access checks |
| 4 | Secure file-sharing with Role-Based Access Control and permission management | ✅ Roles **admin / manager / employee**; share files with any user at **view** or **download** permission; revoke access anytime |
| 5 | Activity logging of uploads, downloads, sharing and access attempts | ✅ Full audit trail (logins, uploads, downloads, shares, revokes, deletes, failed attempts, access denials) with IP addresses |
| 6 | Test and evaluate the effectiveness, usability and security of the system | ✅ 58 end-to-end API tests pass; browser rendering verified (see *Testing* below) |

## 🗂️ Pages

| Page | URL | Description |
|------|-----|-------------|
| Login | `/login.html` | Sign in (username or email + password) |
| Register | `/register.html` | Self-registration (Employee role) |
| Dashboard | `/dashboard.html` | Stats, storage usage, recent files & activity (admin sees org-wide stats) |
| My Files | `/files.html` | List/search/delete files, download, share, revoke, view access list |
| Upload | `/upload.html` | Drag & drop upload with progress bar — encrypted automatically |
| Shared with Me | `/shared.html` | Files others shared with you (respects view/download permission) |
| Activity Log | `/logs.html` | Full audit trail (admin sees all users, others see their own) |
| Manage Users | `/users.html` | **Admin only** — create users, change roles, suspend, reset passwords, delete |
| My Profile | `/profile.html` | Update details, change password (signs out other sessions) |

## 🔑 Demo Accounts

| Username | Password | Role |
|----------|----------|------|
| `admin` or `admin@securefiles.local` | `Admin@123` | System Administrator |
| `manager` or `manager@securefiles.local` | `Manager@123` | Manager |
| `employee` or `employee@securefiles.local` | `Employee@123` | Employee |

Two demo files are pre-seeded (owned by admin, already shared with `employee` and `manager`) so the "Shared with Me" page and dashboard are populated on first login.

## 🛠️ Technology Stack

- **Frontend:** Native **HTML + CSS + vanilla JavaScript** (no frameworks, no CDNs — works offline)
- **Backend:** Node.js (built-in `http` server, zero external dependencies)
- **Database:** **SQL** — SQLite via Node's built-in `node:sqlite` (schema also provided in `database.sql`)
- **Encryption:** AES-256-GCM via Node's built-in `crypto` (per-file random key/IV; key & IV stored in DB, ciphertext stored on disk as `[auth tag | ciphertext]`)
- **Password hashing:** scrypt (memory-hard KDF, same purpose as bcrypt)
- **Security headers:** CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, Referrer-Policy

## 🚀 How to Run

Requires **Node.js 22.5+** (uses the built-in `node:sqlite` module — no `npm install` needed).

**Easiest way — double-click the launcher for your computer:**

| Your computer | File to double-click | What happens |
|---------------|----------------------|--------------|
| Windows | `start.bat` | Opens the site in your browser automatically |
| Mac | `start.command` | Same — opens the site in your browser automatically |

Both launchers check that Node.js is installed (with a friendly message + link if not), skip startup if the site is already running, and print the demo logins.

**Manual way:**

```bash
node server.js          # or: npm start
```

Then open **http://127.0.0.1:3000** in your browser.

> The database (`secure-share.db`) and encrypted file store (`storage/`) are created automatically on first run. To reset to pristine demo data (while the server is stopped):

```bash
npm run db:reset
```

## 📦 Sending the project to someone else

1. Zip the whole `secure-share-system` folder (or send the ready-made `Secure-Share-System.zip`).
2. The person receiving it just needs to:
   - Install **Node.js 22 or newer** (free, from https://nodejs.org — 2 minutes)
   - Unzip the folder
   - **Double-click `start.bat` (Windows) or `start.command` (Mac)**
3. The site opens in their browser. Demo accounts: `admin / Admin@123`, `manager / Manager@123`, `employee / Employee@123`.

Everything is included in the zip — the database with demo files is pre-seeded, and no internet connection or `npm install` is required while running.

## 📁 Project Structure

```
secure-share-system/
├── server.js            # HTTP server: API routes, auth, RBAC, encryption, logging
├── database.sql         # Canonical SQL schema + seed (documentation/manual setup)
├── package.json
├── lib/
│   ├── db.js            # SQLite schema, seed data, activity logging
│   ├── security.js      # scrypt hashing, AES-256-GCM encrypt/decrypt
│   └── multipart.js     # dependency-free multipart/form-data parser
├── public/              # Native HTML/CSS/JS frontend
│   ├── css/style.css
│   ├── js/  (api.js, login, register, dashboard, files, upload, shared, logs, users, profile)
│   └── *.html  (all 9 pages)
├── storage/             # Encrypted file blobs (never served directly)
└── secure-share.db      # SQLite database (created at runtime)
```

## 🔒 Security Measures Implemented

- **Automated encryption:** files are encrypted with AES-256-GCM *before* they are written to disk; ciphertext is never stored as plaintext
- **Authenticated encryption:** AES-GCM detects any tampering — corrupted blobs fail to decrypt
- **Password security:** scrypt hashing with per-user salt; policy requires 8+ chars with upper/lower/number
- **Session security:** 256-bit random tokens, HttpOnly + SameSite cookies, 8-hour sliding expiry, session invalidation on password change
- **Admin 2FA demo:** Administrator login requires password plus a temporary 6-digit verification code before a session is created
- **CSRF protection:** per-session token required on every mutating request
- **Login lockout:** 5 failed attempts → 15-minute lockout
- **RBAC:** admin / manager / employee roles enforced on every endpoint (non-admins get 403 on admin APIs)
- **Per-file authorization:** owners, admins and named sharees only; view-only shares cannot download
- **Input validation:** SQL injection prevented via prepared statements; path traversal blocked on static serving; upload size + storage quota enforced
- **Audit trail:** every significant action logged with user, details and IP

## 🧪 Testing

The suite in this repo's development process (`/tmp/test_api.sh`) exercises **58 end-to-end checks** — all passing:

- Login (success, wrong password, lockout, suspended accounts) and registration (duplicates, weak passwords)
- Upload → **ciphertext verified to contain no plaintext** → encrypted blob layout
- Search, share, view-only enforcement, revoke, delete, permission denials (403s)
- Admin user management (create, role change, suspend, reset password) with non-admin blocked
- Log visibility by role, profile updates, password changes
- Static serving of every page + path-traversal blocking
- Real-browser checks via headless Chrome: all 9 pages render; unauthenticated users are redirected to login

---

*Built for the CISY 401 Research Project — Automated File Encryption and Secure Sharing System for Corporate Data Protection.*

## Premium UI Update

This build includes a presentation-ready authentication experience:

- Two-column login screen with professional security illustration.
- Demo role cards for Admin, Manager, and Employee quick filling.
- Working Register page link from the login page.
- Improved registration screen with password visibility toggle, password checks, and policy confirmation.
- Improved dashboard introduction panel showing the security workflow: Upload → Encrypt → Share → Audit.
- Maintains the same working backend, SQLite database, AES-256-GCM encryption, session cookies, CSRF protection, RBAC, and audit logging.

Demo login remains:

- Admin: `admin` / `Admin@123` + 6-digit verification code
- Manager: `manager` / `Manager@123`
- Employee: `employee` / `Employee@123`

## View-Only Preview Improvement

This upgraded build fixes the issue where a file shared with **View** permission only showed “View only” without allowing the receiver to open anything.

The new behavior is:

| Permission | What the receiver can do | What is blocked |
|---|---|---|
| View only | Open a secure browser preview using `/api/files/:id/preview` | Downloading the decrypted file |
| Download | Preview the file and download a decrypted copy | Access by unrelated users |

Important note for project defense: files remain encrypted at rest. The preview endpoint decrypts the file temporarily only after authentication and permission checks. Preview and download actions are recorded in the activity log.

A new **Security Center** page was also added to explain AES-256-GCM encryption, RBAC, sessions, CSRF protection, secure preview, controlled download, and audit logs in a presentation-friendly way.

## Final Professional Upgrade

This build includes the final defense-focused improvements:

- View-only shared files now use a real secure preview route instead of only displaying "View only".
- Download remains blocked for view-only users.
- Download users can preview and download.
- Owners can share files with expiry periods and optional view-once access.
- View-once shares are consumed after the first successful preview.
- File details include access history.
- The Security Center includes live metrics, permission model, and recent security events.
- The dashboard includes stronger security metrics for presentation.

Key endpoint added:

```text
GET /api/files/:id/preview
GET /api/security/overview
```

This makes the project clearer for marking because it demonstrates backend permission enforcement, not only frontend button hiding.

## Professional Identity Upgrade

This build includes a more professional administrator identity presentation:

- Admin profile photo in the topbar and sidebar.
- Executive-style dashboard account card.
- Improved profile page with role, status, and protected-session badges.
- Login page administrator showcase for a more polished demo impression.
- User table displays the administrator photo while other roles continue to use initials.

Security note: the profile image is a visual/profile feature only. Real access is still controlled by authentication, server-side RBAC, file permissions, and audit logging.

## Email-Based Admin 2FA Upgrade

This build includes an email-ready administrator 2FA workflow.

Admin login now works as:

1. Admin enters username/email and password.
2. The backend verifies the password.
3. A temporary 6-digit code is generated.
4. The code is hashed in memory and delivered by email when SMTP is configured.
5. The admin enters the code.
6. The session is created only after successful OTP verification.

To enable real email delivery:

```bash
npm install
copy .env.example .env
```

Then edit `.env` and configure:

```env
OTP_DELIVERY_MODE=email
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
SMTP_SECURE=true
SMTP_USER=yourgmail@gmail.com
SMTP_PASS=your_gmail_app_password
OTP_FROM="Secure Share <yourgmail@gmail.com>"
OTP_TO_EMAIL=yourgmail@gmail.com
```

Generate a strong OTP secret:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Paste the value into:

```env
OTP_SECRET=your_generated_secret
```

If SMTP is not configured or `nodemailer` is not installed, the system safely falls back to terminal mode for local learning.


## Email 2FA reliability update

If SMTP email delivery fails, the system no longer crashes. It logs the email error in the terminal and falls back to terminal OTP mode so the admin can still complete the local demo login. For real deployment, fix the SMTP credentials and keep `OTP_DELIVERY_MODE=email`.
