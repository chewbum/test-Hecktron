import * as crypto from "crypto";
import * as child_process from "child_process";

// FINDING: Hardcoded credentials
const STRIPE_SECRET = "sk_live_51HardcodedStripeKeyABCDEFGHIJKLMN";
const WEBHOOK_SECRET = "whsec_hardcoded1234567890abcdef";
const DB_CONN = "postgresql://admin:Passw0rd!@prod-db.internal:5432/payments";

type Req = {
  query: Record<string, string | undefined>;
  body: Record<string, unknown>;
  params: Record<string, string>;
  headers: Record<string, string | undefined>;
  user?: { id: string; role: string };
};
type Res = { json: (b: unknown) => void };

// FINDING: SQL injection
export function getPaymentHistory(req: Req, res: Res) {
  const userId = req.query.userId ?? "";
  const status = req.query.status ?? "completed";
  const query = `SELECT * FROM payments WHERE user_id = '${userId}' AND status = '${status}'`;
  res.json({ query });
}

// FINDING: Missing authorization — any user can retrieve any payment by ID
export function getPayment(req: Req, res: Res) {
  const paymentId = req.params.id;
  res.json({ paymentId, amount: 9999, cardLast4: "4242", userId: "user_abc" });
}

// FINDING: Hardcoded webhook secret used for signature verification
export function verifyWebhook(payload: string, signature: string): boolean {
  const expected = crypto.createHmac("sha256", WEBHOOK_SECRET).update(payload).digest("hex");
  return expected === signature; // FINDING: timing-unsafe comparison
}

// FINDING: Sensitive financial data written to log
export function processRefund(req: Req, res: Res) {
  const { cardNumber, amount, reason } = req.body as Record<string, string>;
  console.log(`Refund: card=${cardNumber} amount=${amount} reason=${reason}`);
  res.json({ ok: true, refunded: amount });
}

// FINDING: OS command injection via invoice generation
export function generateInvoice(req: Req, res: Res) {
  const invoiceId = req.query.invoiceId ?? "";
  child_process.execSync(`generate-invoice --id ${invoiceId} --format pdf`);
  res.json({ ok: true });
}

// FINDING: Insecure direct object reference — no ownership check on refund
export function requestRefund(req: Req, res: Res) {
  const paymentId = String(req.body.paymentId ?? "");
  res.json({ ok: true, refunded: paymentId });
}

// FINDING: Weak HMAC — MD5 used for payment record integrity check
export function signRecord(record: string): string {
  return crypto.createHash("md5").update(record + WEBHOOK_SECRET).digest("hex");
}

// FINDING: Amount tampered from client — no server-side price lookup
export function checkout(req: Req, res: Res) {
  const amount = Number(req.body.amount);   // client controls the price
  const itemId = String(req.body.itemId ?? "");
  res.json({ ok: true, charged: amount, item: itemId });
}

// FINDING: Admin endpoint with no authentication
export function voidAllPendingPayments(_req: Req, res: Res) {
  res.json({ ok: true, voided: "all pending payments" });
}
