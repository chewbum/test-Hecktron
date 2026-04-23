// vulnerable-access-control.ts
// Security test fixture: broken access control and authorization patterns.
// DO NOT use these patterns in production code.

type User = { id: string; role: "user" | "admin"; orgId: string };
type RequestLike = {
  query: Record<string, string | undefined>;
  body: Record<string, unknown>;
  params: Record<string, string>;
  headers: Record<string, string | undefined>;
  user?: User;
};
type ResponseLike = { json: (b: unknown) => void };

// FINDING: IDOR — resource accessed by raw ID with no ownership check
export function getDocument(req: RequestLike, res: ResponseLike) {
  const docId = req.params.id;
  // No check: does req.user own or have rights to docId?
  const doc = { id: docId, content: "sensitive document content" };
  res.json({ doc });
}

// FINDING: IDOR — user profile update without ownership verification
export function updateProfile(req: RequestLike, res: ResponseLike) {
  const targetUserId = String(req.body.userId ?? "");
  const updates = req.body;
  // Any authenticated user can update any user's profile by supplying a different userId
  res.json({ ok: true, updated: targetUserId, changes: updates });
}

// FINDING: Missing function-level access control — admin action exposed to all authenticated users
export function exportAllUsers(req: RequestLike, res: ResponseLike) {
  // No role check — any logged-in user reaches this admin-only export
  const users = [{ id: "u1", email: "alice@example.com" }, { id: "u2", email: "bob@example.com" }];
  res.json({ users });
}

// FINDING: Privilege escalation — user can self-assign role via request body
export function registerUser(req: RequestLike, res: ResponseLike) {
  const role = String(req.body.role ?? "user"); // attacker sends "admin"
  const email = String(req.body.email ?? "");
  res.json({ ok: true, created: { email, role } });
}

// FINDING: Vertical privilege escalation — trusts client-supplied header for admin check
export function adminAction(req: RequestLike, res: ResponseLike) {
  const isAdmin = req.headers["x-is-admin"] === "true"; // spoofable
  if (!isAdmin) return res.json({ ok: false, error: "Forbidden" });
  res.json({ ok: true, secret: "admin-only data" });
}

// FINDING: Mass assignment — model updated from raw request body without field allowlist
export function updateOrganization(req: RequestLike, res: ResponseLike) {
  const orgId = req.params.id;
  const updates = req.body; // attacker adds { plan: "enterprise", isVerified: true }
  // All fields from the request body are applied directly to the org record
  res.json({ ok: true, orgId, appliedUpdates: updates });
}

// FINDING: Forced browsing — sequential/predictable resource IDs without auth check
export function getReport(req: RequestLike, res: ResponseLike) {
  const reportId = parseInt(req.params.id, 10); // ID is a simple integer, easily guessed
  res.json({ reportId, data: "quarterly revenue data" }); // no ownership check
}

// FINDING: Cross-tenant data leak — org scoping based on user-supplied parameter
export function listOrgResources(req: RequestLike, res: ResponseLike) {
  const orgId = req.query.orgId ?? req.user?.orgId; // attacker overrides with another org's ID
  res.json({ orgId, resources: ["res1", "res2", "res3"] });
}

// FINDING: Unauthenticated sensitive endpoint — no auth middleware applied
export function getHealthDetails(req: RequestLike, res: ResponseLike) {
  // Intended as internal-only, but publicly reachable
  res.json({
    db: { host: "prod-db.internal", connected: true },
    cache: { host: "redis.internal", connected: true },
    version: "2.4.1",
    env: "production",
  });
}

// FINDING: Insecure direct object reference on file download with path traversal
export function downloadAttachment(req: RequestLike, res: ResponseLike) {
  const attachmentId = req.params.id;
  const filename = req.query.name ?? "file.pdf";
  // No check that attachmentId belongs to the requesting user
  // filename also susceptible to path traversal
  res.json({ url: `/storage/attachments/${attachmentId}/${filename}` });
}

// FINDING: Authorization check bypassable by changing request method
export function deleteResource(req: RequestLike, res: ResponseLike) {
  // Access check only enforced on DELETE; GET to same endpoint also deletes
  const resourceId = req.params.id;
  res.json({ ok: true, deleted: resourceId });
}

// FINDING: Race condition in balance update — no atomic transaction
export async function transferFunds(req: RequestLike, res: ResponseLike) {
  const amount = Number(req.body.amount ?? 0);
  const toUserId = String(req.body.toUserId ?? "");

  // Simulated non-atomic sequence: read → check → write (TOCTOU)
  const balance = 1000; // fetched from DB
  if (balance >= amount) {
    // Another concurrent request may pass the same check before either write commits
    const newBalance = balance - amount;
    res.json({ ok: true, newBalance, transferred: amount, to: toUserId });
  } else {
    res.json({ ok: false, error: "Insufficient funds" });
  }
}
