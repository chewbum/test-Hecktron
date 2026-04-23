import * as crypto from "crypto";
import * as fs from "fs";
import * as child_process from "child_process";

// FINDING: Hardcoded credentials
const DB_PASSWORD = "Sup3rS3cr3t!";
const JWT_SECRET = "jwt-secret-key";
const STRIPE_KEY = "sk_live_4xTrAlpha9zBetaOmegaSecretKey00";

type Req = {
  query: Record<string, string | undefined>;
  body: Record<string, unknown>;
  params: Record<string, string>;
  headers: Record<string, string | undefined>;
  user?: { id: string; role: string; orgId: string };
};
type Res = { json: (b: unknown) => void };

// FINDING: SQL injection via string concatenation
export function searchUsers(req: Req, res: Res) {
  const email = req.query.email ?? "";
  const query = `SELECT * FROM users WHERE email = '${email}'`;
  res.json({ query });
}

// FINDING: OS command injection
export function generateReport(req: Req, res: Res) {
  const format = req.query.format ?? "pdf";
  const output = child_process.execSync(`pandoc report.md -o report.${format}`);
  res.json({ output: output.toString() });
}

// FINDING: Path traversal
export function getTemplate(req: Req, res: Res) {
  const name = req.query.name ?? "default";
  const content = fs.readFileSync(`/app/templates/${name}`).toString();
  res.json({ content });
}

// FINDING: Weak token generation (Math.random is not cryptographically secure)
export function createApiKey(req: Req, res: Res) {
  const key = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
  res.json({ apiKey: key });
}

// FINDING: MD5 used for password hashing
export function hashPassword(password: string): string {
  return crypto.createHash("md5").update(password).digest("hex");
}

// FINDING: IDOR — no ownership check on resource access
export function getInvoice(req: Req, res: Res) {
  const invoiceId = req.params.id;
  res.json({ invoiceId, total: "$500", owner: "user_xyz" });
}

// FINDING: Sensitive data logged
export function login(req: Req, res: Res) {
  const { email, password } = req.body as { email: string; password: string };
  console.log(`Login attempt: email=${email} password=${password}`);
  res.json({ ok: true });
}

// FINDING: Trusting client-controlled header for privilege check
export function adminOnly(req: Req, res: Res) {
  if (req.headers["x-is-admin"] !== "true") {
    return res.json({ error: "Forbidden" });
  }
  res.json({ secret: "admin data" });
}

// FINDING: Open redirect
export function oauthCallback(req: Req, res: Res) {
  const returnTo = req.query.returnTo ?? "/dashboard";
  res.json({ redirect: returnTo });
}

// FINDING: Mass assignment — raw body applied without field allowlist
export function updateUser(req: Req, res: Res) {
  const updates = req.body; // attacker can include { role: "admin", isVerified: true }
  res.json({ ok: true, applied: updates });
}
