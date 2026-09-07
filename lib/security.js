'use strict';

/**
 * Security utilities for the Secure Share System.
 *
 *  - Password hashing  : Node's built-in scrypt (memory-hard KDF, like bcrypt)
 *  - File encryption   : AES-256-GCM (authenticated encryption) with a
 *                        random per-file key and IV. Blob layout on disk:
 *                        [ authTag (16 bytes) | ciphertext ]
 *  - Session tokens    : 256-bit random tokens
 */

const crypto = require('crypto');

const SCRYPT_N = 16384;  // cost factor (memory-hard)
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LEN = 64;

/**
 * Hash a plaintext password using scrypt with a random salt.
 * Format: scrypt$N$r$p$saltBase64$hashBase64
 * @param {string} password
 * @returns {string}
 */
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, KEY_LEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P });
  return ['scrypt', SCRYPT_N, SCRYPT_R, SCRYPT_P, salt.toString('base64'), hash.toString('base64')].join('$');
}

/**
 * Verify a plaintext password against a stored hash.
 * @param {string} password
 * @param {string} stored
 * @returns {boolean}
 */
function verifyPassword(password, stored) {
  try {
    const parts = stored.split('$');
    if (parts[0] !== 'scrypt' || parts.length !== 6) return false;
    const [, n, r, p, saltB64, hashB64] = parts;
    const salt = Buffer.from(saltB64, 'base64');
    const expected = Buffer.from(hashB64, 'base64');
    const actual = crypto.scryptSync(password, salt, expected.length, {
      N: Number(n), r: Number(r), p: Number(p)
    });
    return crypto.timingSafeEqual(actual, expected);
  } catch (e) {
    return false;
  }
}

/** Generate a 256-bit random hex token (sessions, CSRF, file names). */
function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

/** Validate a plaintext password against the system policy. */
function passwordPolicyError(password) {
  if (typeof password !== 'string') return 'Password is required.';
  if (password.length < 8) return 'Password must be at least 8 characters long.';
  if (!/[A-Z]/.test(password)) return 'Password must contain at least one uppercase letter.';
  if (!/[a-z]/.test(password)) return 'Password must contain at least one lowercase letter.';
  if (!/[0-9]/.test(password)) return 'Password must contain at least one number.';
  return null;
}

/** Validate email shape (basic). */
function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/** Validate username shape. */
function isValidUsername(username) {
  return typeof username === 'string' && /^[a-zA-Z0-9_.-]{3,30}$/.test(username);
}

/**
 * Encrypt a plaintext buffer with a fresh AES-256-GCM key.
 * @param {Buffer} plaintext
 * @returns {{ ciphertext: Buffer, key: Buffer, iv: Buffer }}
 */
function encryptBuffer(plaintext) {
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16 bytes
  const ciphertext = Buffer.concat([tag, enc]); // tag first so we can stream-decrypt
  return { ciphertext, key, iv };
}

/**
 * Decrypt a full blob produced by encryptBuffer (tag-first layout).
 * @param {Buffer} blob
 * @param {Buffer} key
 * @param {Buffer} iv
 * @returns {Buffer} plaintext (throws on tamper detection)
 */
function decryptBuffer(blob, key, iv) {
  if (blob.length < 17) throw new Error('Encrypted blob is corrupted (too short).');
  const tag = blob.subarray(0, 16);
  const ciphertext = blob.subarray(16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plain;
}

/**
 * Build a readable stream that decrypts an on-disk blob (tag-first layout)
 * without loading the whole file into memory.
 * @param {string} filePath
 * @param {Buffer} key
 * @param {Buffer} iv
 * @returns {import('stream').Readable}
 */
function createDecryptStream(filePath, key, iv) {
  const fs = require('fs');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);

  // Peek the 16-byte auth tag at the start of the file, then stream the rest.
  const fh = fs.openSync(filePath, 'r');
  const tag = Buffer.alloc(16);
  const bytesRead = fs.readSync(fh, tag, 0, 16, 0);
  fs.closeSync(fh);
  if (bytesRead !== 16) {
    const err = new Error('Encrypted file is corrupted.');
    err.code = 'EFILE_CORRUPT';
    throw err;
  }
  decipher.setAuthTag(tag);

  const input = fs.createReadStream(filePath, { start: 16 });
  return input.pipe(decipher);
}

module.exports = {
  hashPassword,
  verifyPassword,
  randomToken,
  passwordPolicyError,
  isValidEmail,
  isValidUsername,
  encryptBuffer,
  decryptBuffer,
  createDecryptStream,
};
