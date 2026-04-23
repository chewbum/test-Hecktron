// vulnerable-injection.ts
// Security test fixture: command, template, and NoSQL injection patterns.
// DO NOT use these patterns in production code.

import * as child_process from "child_process";

type RequestLike = {
  query: Record<string, string | undefined>;
  body: Record<string, unknown>;
  params: Record<string, string>;
};

type ResponseLike = {
  json: (body: unknown) => void;
};

// FINDING: OS command injection via exec with string concatenation
export function pingHost(req: RequestLike, res: ResponseLike) {
  const host = req.query.host ?? "localhost";
  child_process.exec(`ping -c 1 ${host}`, (err, stdout) => {  // VULNERABLE
    res.json({ output: stdout });
  });
}

// FINDING: OS command injection via execSync
export function convertImage(req: RequestLike, res: ResponseLike) {
  const file = req.query.file ?? "";
  const result = child_process.execSync(`ffmpeg -i /uploads/${file} /out/${file}.mp4`); // VULNERABLE
  res.json({ output: result.toString() });
}

// FINDING: Command injection via spawn with shell:true
export function runScript(req: RequestLike, res: ResponseLike) {
  const script = req.query.script ?? "";
  child_process.spawn("bash", ["-c", script], { shell: true }); // VULNERABLE
  res.json({ ok: true });
}

// FINDING: NoSQL injection — MongoDB query built from user input directly
export function findUserMongo(req: RequestLike, res: ResponseLike) {
  const username = req.body.username; // attacker passes { $gt: "" } to bypass
  // db.users.find({ username: username }) — if username is { $gt: "" }, matches all users
  const query = { username }; // VULNERABLE — object operators not stripped
  res.json({ query, note: "Mock finding — not executed" });
}

// FINDING: NoSQL injection — password field accepts operator
export function loginMongo(req: RequestLike, res: ResponseLike) {
  const password = req.body.password; // attacker sends { $ne: null } to always match
  const query = { email: req.body.email, password }; // VULNERABLE
  res.json({ query, note: "Mock finding — not executed" });
}

// FINDING: Server-side template injection via string concatenation in template engine call
export function renderTemplate(req: RequestLike, res: ResponseLike) {
  const greeting = req.query.greeting ?? "Hello";
  // In engines like Pug or Handlebars, compiling user input is dangerous
  const templateStr = `p ${greeting}, welcome!`; // VULNERABLE if passed to pug.compile()
  res.json({ template: templateStr, note: "Mock finding — not compiled" });
}

// FINDING: LDAP injection — user input embedded in LDAP filter
export function ldapSearch(req: RequestLike, res: ResponseLike) {
  const username = req.query.username ?? "";
  const filter = `(&(objectClass=user)(sAMAccountName=${username}))`; // VULNERABLE — * or ) bypass
  res.json({ filter, note: "Mock finding — not executed" });
}

// FINDING: XPath injection — user input embedded in XPath query
export function xpathQuery(req: RequestLike, res: ResponseLike) {
  const username = req.query.username ?? "";
  const password = req.query.password ?? "";
  const expression = `//users/user[name='${username}' and password='${password}']`; // VULNERABLE
  res.json({ expression, note: "Mock finding — not executed" });
}

// FINDING: Regular expression injection (ReDoS) — user input used as regex pattern
export function searchContent(req: RequestLike, res: ResponseLike) {
  const pattern = req.query.pattern ?? "";
  const regex = new RegExp(pattern); // VULNERABLE — malicious pattern can hang the process
  const result = "sample content to search".match(regex);
  res.json({ matched: !!result });
}

// FINDING: HTTP header injection — user input embedded in response header
export function setRedirectHeader(req: RequestLike, res: ResponseLike) {
  const destination = req.query.destination ?? "/home";
  // If destination contains \r\n, attacker can inject arbitrary headers
  (res as unknown as { setHeader: (k: string, v: string) => void }).setHeader(
    "Location",
    destination // VULNERABLE — no \r\n stripping
  );
  res.json({ redirecting: true });
}

// FINDING: Log injection — user input written to log without sanitization
export function logAction(req: RequestLike, res: ResponseLike) {
  const action = req.query.action ?? "";
  // Attacker injects \n[CRITICAL] Admin logged in — spoofs log entries
  console.log(`User action: ${action}`); // VULNERABLE
  res.json({ ok: true });
}

// FINDING: JSON prototype pollution via merge of untrusted object
export function mergeSettings(req: RequestLike, res: ResponseLike) {
  const userSettings = req.body as Record<string, unknown>;
  const defaults: Record<string, unknown> = { theme: "light", lang: "en" };
  // Attacker body: { "__proto__": { "isAdmin": true } }
  for (const key in userSettings) {
    defaults[key] = userSettings[key]; // VULNERABLE — no hasOwnProperty / key allowlist
  }
  res.json({ settings: defaults });
}
