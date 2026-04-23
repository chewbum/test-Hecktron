// vulnerable-crypto.ts
// Security test fixture: intentionally weak cryptography patterns.
// DO NOT use these patterns in production code.

import * as crypto from "crypto";

// FINDING: Hardcoded encryption key
const ENCRYPTION_KEY = "0123456789abcdef"; // 16-byte key hardcoded in source
const STATIC_IV = Buffer.alloc(16, 0);     // FINDING: static/zero IV — never reuse IV

// FINDING: MD5 used for password hashing (collision-prone, no salt)
export function hashPasswordMD5(password: string): string {
  return crypto.createHash("md5").update(password).digest("hex");
}

// FINDING: SHA-1 used for password hashing (deprecated, broken)
export function hashPasswordSHA1(password: string): string {
  return crypto.createHash("sha1").update(password).digest("hex");
}

// FINDING: No salt in password hash — vulnerable to rainbow table attacks
export function hashPasswordNoSalt(password: string): string {
  return crypto.createHash("sha256").update(password).digest("hex");
}

// FINDING: ECB mode encryption — identical plaintext blocks produce identical ciphertext
export function encryptECB(plaintext: string): string {
  const cipher = crypto.createCipheriv("aes-128-ecb", ENCRYPTION_KEY, null);
  return Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]).toString("hex");
}

// FINDING: Static IV with CBC — IV must be random and unique per encryption
export function encryptCBCStaticIV(plaintext: string): string {
  const cipher = crypto.createCipheriv("aes-128-cbc", ENCRYPTION_KEY, STATIC_IV);
  return Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]).toString("hex");
}

// FINDING: Math.random() used for cryptographic token generation (not CSPRNG)
export function generateInsecureToken(length = 32): string {
  let token = "";
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  for (let i = 0; i < length; i++) {
    token += chars[Math.floor(Math.random() * chars.length)];
  }
  return token;
}

// FINDING: Math.random() used for OTP/2FA code (predictable)
export function generateOTPCode(): string {
  return String(Math.floor(Math.random() * 1000000)).padStart(6, "0");
}

// FINDING: Timing-unsafe string comparison used for HMAC/token verification
export function verifyTokenInsecure(provided: string, expected: string): boolean {
  return provided === expected; // should use crypto.timingSafeEqual
}

// FINDING: Key derived from low-entropy source (username) without proper KDF
export function deriveKeyFromUsername(username: string): Buffer {
  return crypto.createHash("md5").update(username).digest(); // no PBKDF2/scrypt/bcrypt
}

// FINDING: Self-signed / no certificate validation pattern (in fetch context)
export const insecureHttpsAgent = {
  rejectUnauthorized: false, // disables TLS certificate validation
};

// FINDING: Weak RSA key size (512-bit is trivially factorable)
export function generateWeakRSAKeyComment(): string {
  // generateKeyPairSync('rsa', { modulusLength: 512 }) — key too short
  return "rsa-512-key-would-be-generated-here";
}

// FINDING: DES used for encryption (56-bit key, broken algorithm)
export function encryptDES(plaintext: string, key: string): string {
  const cipher = crypto.createCipheriv("des", Buffer.from(key, "hex").slice(0, 8), Buffer.alloc(8, 0));
  return Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]).toString("hex");
}

// FINDING: Encryption used where signing is needed — encrypt-then-MAC pattern absent
export function encryptWithoutMAC(plaintext: string): { ciphertext: string } {
  const cipher = crypto.createCipheriv("aes-128-cbc", ENCRYPTION_KEY, STATIC_IV);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]).toString("hex");
  return { ciphertext }; // no integrity check — vulnerable to bit-flipping attacks
}

// FINDING: IV/nonce reuse in GCM mode (catastrophic for AES-GCM)
const FIXED_GCM_NONCE = Buffer.from("000000000000", "hex"); // 6 bytes, reused

export function encryptGCMFixedNonce(plaintext: string): { ciphertext: string; tag: string } {
  const cipher = crypto.createCipheriv("aes-128-gcm", ENCRYPTION_KEY, FIXED_GCM_NONCE) as crypto.CipherGCM;
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]).toString("hex");
  const tag = cipher.getAuthTag().toString("hex");
  return { ciphertext, tag };
}
