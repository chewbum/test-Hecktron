// mock-security-fixture.ts
// Safe fixture for testing a security finding agent.
// This file contains NON-EXECUTABLE and BENIGN patterns that should be flagged by a scanner.
// Do not use these patterns as real vulnerabilities.

type User = {
  id: string;
  email: string;
  isAdmin: boolean;
};

type RequestLike = {
  query: Record<string, string | undefined>;
  body: Record<string, unknown>;
  headers: Record<string, string | undefined>;
  user?: User;
};

type ResponseLike = {
  json: (body: unknown) => void;
  status: (code: number) => ResponseLike;
};

const FAKE_DB = {
  findUserByEmail(email: string) {
    return { id: "u_123", email, isAdmin: false };
  },
};

export class MockController {
  // FINDING: Potential SQL injection pattern
  // Reason: User input appears concatenated into a query string.
  // Note: This is a harmless string, not sent anywhere.
  searchUsers(req: RequestLike, res: ResponseLike) {
    const email = req.query.email ?? "";
    const query = `SELECT * FROM users WHERE email = '${email}'`;
    return res.json({
      ok: true,
      note: "Mock finding only",
      suspiciousQuery: query,
    });
  }

  // FINDING: Potential XSS pattern
  // Reason: Untrusted input appears embedded into HTML output.
  // Note: Returned as plain JSON string only.
  renderWelcome(req: RequestLike, res: ResponseLike) {
    const name = String(req.query.name ?? "guest");
    const html = `<div>Welcome ${name}</div>`;
    return res.json({
      ok: true,
      note: "Mock finding only",
      renderedPreview: html,
    });
  }

  // FINDING: Missing authorization check
  // Reason: Sensitive-looking action with no role/ownership verification.
  deleteProject(req: RequestLike, res: ResponseLike) {
    const projectId = String(req.query.projectId ?? "");
    return res.json({
      ok: true,
      note: "Mock finding only",
      deletedProjectId: projectId,
    });
  }

  // FINDING: Hardcoded secret pattern
  // Reason: Secret-like constant in source code.
  // Note: Fake value for scanner testing only.
  getConfig(_req: RequestLike, res: ResponseLike) {
    const fakeApiKey = "FAKE_API_KEY_FOR_SCANNER_TESTS_ONLY";
    return res.json({
      ok: true,
      note: "Mock finding only",
      configPreview: fakeApiKey.slice(0, 8) + "...",
    });
  }

  // FINDING: Insecure direct object reference pattern
  // Reason: Access to resource by raw identifier with no ownership validation.
  getInvoice(req: RequestLike, res: ResponseLike) {
    const invoiceId = String(req.query.invoiceId ?? "");
    return res.json({
      ok: true,
      note: "Mock finding only",
      invoiceId,
    });
  }

  // FINDING: Weak logging / sensitive data exposure
  // Reason: Password-like field appears in logs.
  login(req: RequestLike, res: ResponseLike) {
    const email = String(req.body.email ?? "");
    const password = String(req.body.password ?? "");
    console.log("Mock finding only:", { email, password });
    return res.json({
      ok: true,
      user: FAKE_DB.findUserByEmail(email),
    });
  }

  // FINDING: Trusting client-controlled header
  // Reason: Privileged decision based on spoofable header.
  promoteUser(req: RequestLike, res: ResponseLike) {
    const trusted = req.headers["x-internal-admin"] === "true";
    return res.json({
      ok: true,
      note: "Mock finding only",
      wouldPromote: trusted,
    });
  }

  // FINDING: Open redirect pattern
  // Reason: Redirect target controlled by request parameter.
  // Note: Returned as data, not actually redirecting.
  nextStep(req: RequestLike, res: ResponseLike) {
    const returnTo = String(req.query.returnTo ?? "/home");
    return res.json({
      ok: true,
      note: "Mock finding only",
      redirectTarget: returnTo,
    });
  }

  // FINDING: Path traversal pattern
  // Reason: File path constructed from user input.
  // Note: No file system access occurs.
  previewFile(req: RequestLike, res: ResponseLike) {
    const filename = String(req.query.filename ?? "default.txt");
    const path = `/app/uploads/${filename}`;
    return res.json({
      ok: true,
      note: "Mock finding only",
      previewPath: path,
    });
  }

  // FINDING: SSRF-like pattern
  // Reason: User-controlled URL appears to flow into outbound fetch config.
  // Note: No request is performed.
  webhookPreview(req: RequestLike, res: ResponseLike) {
    const url = String(req.body.url ?? "");
    const outboundConfig = {
      method: "POST",
      target: url,
    };
    return res.json({
      ok: true,
      note: "Mock finding only",
      outboundConfig,
    });
  }
}