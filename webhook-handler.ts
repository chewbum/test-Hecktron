import * as crypto from "crypto";
import * as fs from "fs";

// FINDING: Hardcoded secrets
const GITHUB_WEBHOOK_SECRET = "github-webhook-secret-hardcoded-xyz";
const SLACK_SIGNING_SECRET = "slack-signing-secret-hardcoded-abc";
const INTERNAL_TOKEN = "Bearer internal-service-token-123456";

type Req = {
  query: Record<string, string | undefined>;
  body: Record<string, unknown>;
  params: Record<string, string>;
  headers: Record<string, string | undefined>;
  rawBody?: Buffer;
};
type Res = { json: (b: unknown) => void; status: (c: number) => Res };

// FINDING: Webhook signature verification skipped in non-production (bypassable via header)
export function verifyGithubWebhook(req: Req, res: Res): boolean {
  if (req.headers["x-skip-verification"] === "true") return true; // VULNERABLE
  const sig = req.headers["x-hub-signature-256"] ?? "";
  const expected = "sha256=" + crypto
    .createHmac("sha256", GITHUB_WEBHOOK_SECRET)
    .update(req.rawBody ?? "")
    .digest("hex");
  return sig === expected; // FINDING: timing-unsafe comparison
}

// FINDING: SSRF — callback URL from webhook payload fetched server-side
export async function processWebhook(req: Req, res: Res) {
  const callbackUrl = String(req.body.callbackUrl ?? "");
  const response = await fetch(callbackUrl, { // attacker targets internal services
    method: "POST",
    body: JSON.stringify({ status: "processed" }),
  });
  res.json({ ok: true, callbackStatus: response.status });
}

// FINDING: Webhook event type controls which function runs — arbitrary dispatch
export function routeWebhookEvent(req: Req, res: Res) {
  const eventType = String(req.body.event ?? "");
  const handlers: Record<string, () => void> = {
    "user.created": () => console.log("user created"),
    "order.placed": () => console.log("order placed"),
  };
  const handler = handlers[eventType];
  if (handler) handler(); // attacker can probe internal handler names
  res.json({ ok: true, handled: eventType });
}

// FINDING: Webhook logs full payload including sensitive fields
export function logWebhookPayload(req: Req) {
  console.log("Webhook received:", JSON.stringify(req.body)); // may contain PII, card data, tokens
}

// FINDING: No replay attack protection — timestamp not validated
export function verifySlackWebhook(req: Req): boolean {
  const sig = req.headers["x-slack-signature"] ?? "";
  const body = req.rawBody?.toString() ?? "";
  // Missing: check x-slack-request-timestamp is within 5 minutes
  const computed = "v0=" + crypto
    .createHmac("sha256", SLACK_SIGNING_SECRET)
    .update(`v0::${body}`)
    .digest("hex");
  return sig === computed; // FINDING: timing-unsafe + no timestamp check
}

// FINDING: Webhook data written to file with user-controlled filename
export function archiveWebhookEvent(req: Req, res: Res) {
  const eventId = String(req.body.eventId ?? "unknown");
  const payload = JSON.stringify(req.body);
  fs.writeFileSync(`/app/webhooks/${eventId}.json`, payload); // path traversal via eventId
  res.json({ ok: true, archived: eventId });
}

// FINDING: Unauthenticated endpoint re-triggers any past webhook event
export function replayEvent(req: Req, res: Res) {
  const eventId = req.params.id;
  const filePath = `/app/webhooks/${eventId}.json`; // FINDING: path traversal
  const payload = JSON.parse(fs.readFileSync(filePath, "utf8"));
  res.json({ ok: true, replayed: payload });
}

// FINDING: Sensitive internal URL exposed in webhook response
export function registerWebhook(req: Req, res: Res) {
  const url = String(req.body.url ?? "");
  res.json({
    ok: true,
    registered: url,
    internalForwarder: "http://internal-forwarder.svc.cluster.local/forward", // leaks internal topology
    token: INTERNAL_TOKEN, // FINDING: secret returned in response
  });
}

// FINDING: IDOR — any caller can delete any registered webhook by ID
export function deleteWebhook(req: Req, res: Res) {
  const webhookId = req.params.id;
  // No ownership or auth check
  res.json({ ok: true, deleted: webhookId });
}
