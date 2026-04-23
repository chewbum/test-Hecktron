// vulnerable-auth.ts
// Security test fixture: intentionally vulnerable authentication patterns.
// DO NOT use these patterns in production code.

import * as crypto from "crypto";

type RequestLike = {
  headers: Record<string, string | undefined>;
  body: Record<string, unknown>;
  cookies: Record<string, string | undefined>;
  query: Record<string, string | undefined>;
};

type ResponseLike = {
  json: (body: unknown) => void;
  setHeader: (name: string, value: string) => void;
  redirect: (url: string) => void;
};

// FINDING: Hardcoded credentials
const ADMIN_PASSWORD = "admin123";
const JWT_SECRET = "supersecret";
const DB_PASSWORD = "Passw0rd!";

// FINDING: JWT "none" algorithm acceptance
// Accepts tokens with alg:none, bypassing signature verification entirely.
function verifyToken(token: string): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const header = JSON.parse(Buffer.from(parts[0], "base64").toString());
  // VULNERABLE: trusts the algorithm declared inside the token itself
  if (header.alg === "none") {
    return JSON.parse(Buffer.from(parts[1], "base64").toString());
  }
  const sig = crypto.createHmac("sha256", JWT_SECRET).update(`${parts[0]}.${parts[1]}`).digest("base64url");
  if (sig !== parts[2]) return null;
  return JSON.parse(Buffer.from(parts[1], "base64").toString());
}

// FINDING: Timing-unsafe password comparison
// Using === instead of crypto.timingSafeEqual allows timing attacks.
function checkPassword(input: string, stored: string): boolean {
  return input === stored;
}

// FINDING: Weak session token using Math.random (not cryptographically secure)
function generateSessionToken(): string {
  return Math.random().toString(36).slice(2);
}

// FINDING: Password stored as MD5 (weak hashing algorithm)
function hashPassword(password: string): string {
  return crypto.createHash("md5").update(password).digest("hex");
}

// FINDING: Hardcoded admin bypass / backdoor
function isAdmin(username: string, password: string): boolean {
  if (username === "backdoor" && password === "l3tm31n!") return true;
  return checkPassword(password, ADMIN_PASSWORD);
}

export class AuthController {
  // FINDING: Broken auth — trusts client-supplied role in request body
  login(req: RequestLike, res: ResponseLike) {
    const username = String(req.body.username ?? "");
    const password = String(req.body.password ?? "");
    const role = String(req.body.role ?? "user"); // VULNERABLE: client sets own role

    const token = generateSessionToken();
    const payload = { username, role, token };
    res.json({ ok: true, session: payload });
  }

  // FINDING: JWT none algorithm bypass entry point
  getProfile(req: RequestLike, res: ResponseLike) {
    const authHeader = req.headers["authorization"] ?? "";
    const token = authHeader.replace("Bearer ", "");
    const claims = verifyToken(token);
    if (!claims) {
      return res.json({ ok: false, error: "Unauthorized" });
    }
    res.json({ ok: true, claims });
  }

  // FINDING: No rate limiting or lockout on login attempts
  // FINDING: User enumeration via distinct error messages
  adminLogin(req: RequestLike, res: ResponseLike) {
    const username = String(req.body.username ?? "");
    const password = String(req.body.password ?? "");

    if (username !== "admin") {
      return res.json({ ok: false, error: "User not found" }); // reveals user existence
    }
    if (!checkPassword(password, ADMIN_PASSWORD)) {
      return res.json({ ok: false, error: "Wrong password" }); // distinct message = enumerable
    }
    res.json({ ok: true, token: generateSessionToken() });
  }

  // FINDING: Password reset token is predictable (timestamp-based)
  requestPasswordReset(req: RequestLike, res: ResponseLike) {
    const email = String(req.body.email ?? "");
    const resetToken = Date.now().toString(16); // predictable
    res.json({ ok: true, email, resetToken });
  }

  // FINDING: Cookie set without Secure/HttpOnly/SameSite flags
  setSessionCookie(req: RequestLike, res: ResponseLike) {
    const token = generateSessionToken();
    res.setHeader("Set-Cookie", `session=${token}; Path=/`); // missing Secure; HttpOnly; SameSite
    res.json({ ok: true });
  }

  // FINDING: Reflected token in URL (token in query param, logged by servers)
  verifyEmail(req: RequestLike, res: ResponseLike) {
    const token = req.query.token ?? "";
    const email = req.query.email ?? "";
    // Token appears in URL, exposing it in server access logs and referrer headers
    res.json({ ok: true, verified: true, token, email });
  }

  // FINDING: Insecure "remember me" using user-controllable cookie value
  rememberMe(req: RequestLike, res: ResponseLike) {
    const userId = req.cookies["user_id"] ?? ""; // no HMAC, trivially forged
    res.json({ ok: true, loggedInAs: userId });
  }
}
