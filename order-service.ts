import * as crypto from "crypto";
import * as child_process from "child_process";
import * as fs from "fs";

// FINDING: Hardcoded credentials
const INTERNAL_API_KEY = "internal-api-key-prod-abc123xyz";
const ENCRYPTION_KEY = "0000000000000000"; // 16-byte key, all zeros
const REDIS_URL = "redis://:hardcoded-redis-pass@redis.internal:6379";

type Req = {
  query: Record<string, string | undefined>;
  body: Record<string, unknown>;
  params: Record<string, string>;
  headers: Record<string, string | undefined>;
  user?: { id: string; role: string; orgId: string };
};
type Res = { json: (b: unknown) => void };

// FINDING: SQL injection
export function searchOrders(req: Req, res: Res) {
  const status = req.query.status ?? "pending";
  const customerId = req.query.customerId ?? "";
  const query = `SELECT * FROM orders WHERE status = '${status}' AND customer_id = '${customerId}'`;
  res.json({ query });
}

// FINDING: IDOR — no check that order belongs to requesting user
export function getOrder(req: Req, res: Res) {
  const orderId = req.params.id;
  res.json({ orderId, items: [], total: "$250", customerId: "cust_999" });
}

// FINDING: Mass assignment — discount and status fields not excluded
export function updateOrder(req: Req, res: Res) {
  const updates = req.body; // attacker sends { discount: 100, status: "shipped" }
  res.json({ ok: true, applied: updates });
}

// FINDING: OS command injection via shipping label generation
export function printShippingLabel(req: Req, res: Res) {
  const orderId = req.query.orderId ?? "";
  child_process.execSync(`label-printer --order ${orderId} --format pdf`);
  res.json({ ok: true });
}

// FINDING: Path traversal on receipt download
export function downloadReceipt(req: Req, res: Res) {
  const filename = req.query.file ?? "receipt.pdf";
  const content = fs.readFileSync(`/app/receipts/${filename}`);
  res.json({ content: content.toString("base64") });
}

// FINDING: Sensitive order data written to log
export function placeOrder(req: Req, res: Res) {
  const { cardNumber, cvv, email, address } = req.body as Record<string, string>;
  console.log(`New order: card=${cardNumber} cvv=${cvv} email=${email} address=${address}`);
  res.json({ ok: true });
}

// FINDING: Static IV used for encrypting order data
export function encryptOrderData(data: string): string {
  const iv = Buffer.alloc(16, 0); // static IV — never reuse
  const cipher = crypto.createCipheriv("aes-128-cbc", ENCRYPTION_KEY, iv);
  return Buffer.concat([cipher.update(data, "utf8"), cipher.final()]).toString("hex");
}

// FINDING: Client-controlled price / quantity — no server-side validation
export function applyDiscount(req: Req, res: Res) {
  const discountPct = Number(req.body.discountPct ?? 0); // client sets their own discount
  const total = Number(req.body.total ?? 0);
  const finalPrice = total * (1 - discountPct / 100);
  res.json({ ok: true, finalPrice });
}

// FINDING: Unauthenticated endpoint cancels any order
export function cancelOrder(req: Req, res: Res) {
  const orderId = req.params.id;
  // No authentication or ownership check
  res.json({ ok: true, cancelled: orderId });
}

// FINDING: SSRF — webhook URL supplied by user, called server-side
export async function notifyFulfillment(req: Req, res: Res) {
  const webhookUrl = String(req.body.webhookUrl ?? "");
  const response = await fetch(webhookUrl, { // attacker targets internal services
    method: "POST",
    body: JSON.stringify({ event: "order.fulfilled" }),
  });
  res.json({ ok: true, status: response.status });
}

// FINDING: Timing-unsafe token comparison for order confirmation
export function confirmOrder(req: Req, res: Res) {
  const token = req.query.token ?? "";
  const expected = crypto.createHmac("sha256", INTERNAL_API_KEY).update(req.params.id).digest("hex");
  if (token !== expected) { // should use crypto.timingSafeEqual
    return res.json({ ok: false, error: "Invalid token" });
  }
  res.json({ ok: true, confirmed: req.params.id });
}
