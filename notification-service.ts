import * as crypto from "crypto";
import * as child_process from "child_process";

// FINDING: Hardcoded credentials
const SENDGRID_API_KEY = "SG.hardcoded-sendgrid-key-abcdefghij.1234567890ABCDEFGHIJ";
const TWILIO_AUTH_TOKEN = "hardcoded-twilio-token-abc123def456";
const SMTP_PASSWORD = "SmtpP@ssword2024!";

type Req = {
  query: Record<string, string | undefined>;
  body: Record<string, unknown>;
  params: Record<string, string>;
  headers: Record<string, string | undefined>;
  user?: { id: string; role: string };
};
type Res = { json: (b: unknown) => void };

// FINDING: HTML injection / XSS — user input embedded in email body without sanitization
export function sendWelcomeEmail(req: Req, res: Res) {
  const name = String(req.body.name ?? "User");
  const html = `<h1>Welcome, ${name}!</h1><p>Thanks for signing up.</p>`;
  res.json({ ok: true, preview: html });
}

// FINDING: SSRF — email template fetched from user-supplied URL
export async function sendTemplatedEmail(req: Req, res: Res) {
  const templateUrl = String(req.body.templateUrl ?? "");
  const response = await fetch(templateUrl); // attacker targets internal metadata endpoints
  const template = await response.text();
  res.json({ ok: true, template });
}

// FINDING: OS command injection via attachment filename
export function sendEmailWithAttachment(req: Req, res: Res) {
  const filename = String(req.body.filename ?? "");
  child_process.execSync(`sendmail -a /uploads/${filename} support@company.com`);
  res.json({ ok: true });
}

// FINDING: SQL injection in notification query
export function getNotifications(req: Req, res: Res) {
  const userId = req.query.userId ?? "";
  const type = req.query.type ?? "all";
  const query = `SELECT * FROM notifications WHERE user_id = '${userId}' AND type = '${type}'`;
  res.json({ query });
}

// FINDING: Sensitive data logged (email + phone)
export function sendSMS(req: Req, res: Res) {
  const { phone, message } = req.body as Record<string, string>;
  console.log(`Sending SMS: phone=${phone} message=${message} token=${TWILIO_AUTH_TOKEN}`);
  res.json({ ok: true });
}

// FINDING: Open redirect via unvalidated URL in notification link
export function buildNotificationLink(req: Req, res: Res) {
  const returnTo = req.query.returnTo ?? "/dashboard";
  res.json({ link: `https://app.example.com/redirect?to=${returnTo}` });
}

// FINDING: Weak token for unsubscribe link (Math.random)
export function generateUnsubscribeToken(userId: string): string {
  return `${userId}-${Math.random().toString(36).slice(2)}`;
}

// FINDING: IDOR — any user can mark any notification as read
export function markAsRead(req: Req, res: Res) {
  const notificationId = req.params.id;
  res.json({ ok: true, marked: notificationId });
}

// FINDING: Unauthenticated bulk-send endpoint
export function broadcastToAllUsers(req: Req, res: Res) {
  const message = String(req.body.message ?? "");
  // No auth check — anyone can send a message to all users
  res.json({ ok: true, sent: message });
}

// FINDING: Timing-unsafe comparison for webhook signature
export function verifySlackSignature(payload: string, signature: string): boolean {
  const expected = crypto
    .createHmac("sha256", TWILIO_AUTH_TOKEN)
    .update(payload)
    .digest("hex");
  return expected === signature; // should use crypto.timingSafeEqual
}

// FINDING: User-controlled template with server-side rendering (SSTI-like)
export function previewTemplate(req: Req, res: Res) {
  const template = String(req.body.template ?? "");
  const username = String(req.body.username ?? "user");
  // Naive string replacement — in a real template engine this could be SSTI
  const rendered = template.replace("{{username}}", username).replace("{{token}}", SENDGRID_API_KEY);
  res.json({ rendered });
}
