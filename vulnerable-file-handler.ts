// vulnerable-file-handler.ts
// Security test fixture: intentionally vulnerable file handling patterns.
// DO NOT use these patterns in production code.

import * as fs from "fs";
import * as path from "path";
import * as child_process from "child_process";

const UPLOAD_DIR = "/app/uploads";
const ALLOWED_BASE = "/app/public";

type RequestLike = {
  query: Record<string, string | undefined>;
  body: Record<string, unknown>;
  file?: { originalname: string; mimetype: string; buffer: Buffer; size: number };
};

type ResponseLike = {
  json: (body: unknown) => void;
  send: (body: string) => void;
};

// FINDING: Path traversal — no normalization or containment check
export function readUserFile(req: RequestLike, res: ResponseLike) {
  const filename = req.query.file ?? "";
  const filePath = path.join(ALLOWED_BASE, filename); // ../../etc/passwd bypasses base
  const content = fs.readFileSync(filePath, "utf8");   // no realpath check
  res.send(content);
}

// FINDING: Unrestricted file write — attacker controls filename and content
export function writeUserFile(req: RequestLike, res: ResponseLike) {
  const filename = String(req.body.filename ?? "out.txt");
  const content = String(req.body.content ?? "");
  const filePath = path.join(UPLOAD_DIR, filename); // no sanitisation
  fs.writeFileSync(filePath, content);
  res.json({ ok: true, path: filePath });
}

// FINDING: Unrestricted file upload — no MIME or extension validation
export function uploadFile(req: RequestLike, res: ResponseLike) {
  const file = req.file;
  if (!file) return res.json({ ok: false });

  // Accepts any file type including .php, .js, .sh — no allowlist
  const dest = path.join(UPLOAD_DIR, file.originalname);
  fs.writeFileSync(dest, file.buffer);
  res.json({ ok: true, saved: dest });
}

// FINDING: File upload — MIME type trusted from client header (bypassable)
export function uploadImageTrustMime(req: RequestLike, res: ResponseLike) {
  const file = req.file;
  if (!file) return res.json({ ok: false });

  if (!file.mimetype.startsWith("image/")) {
    return res.json({ ok: false, error: "Not an image" });
  }
  // VULNERABLE: MIME type is set by the client and trivially spoofed
  const dest = path.join(UPLOAD_DIR, file.originalname);
  fs.writeFileSync(dest, file.buffer);
  res.json({ ok: true, saved: dest });
}

// FINDING: Zip slip — archive entry names not sanitised before extraction
export function extractArchive(req: RequestLike, res: ResponseLike) {
  const archivePath = String(req.body.path ?? "");
  // Simulated: entries from archive are written to UPLOAD_DIR + entry.name
  // A malicious zip can contain entries like ../../etc/cron.d/backdoor
  const entries = [{ name: req.query.entry ?? "safe.txt", data: "content" }];
  for (const entry of entries) {
    const dest = path.join(UPLOAD_DIR, entry.name); // VULNERABLE — no normalization
    fs.writeFileSync(dest, entry.data);
  }
  res.json({ ok: true, extracted: entries.length });
}

// FINDING: Command injection via filename passed to shell command
export function processUploadedImage(req: RequestLike, res: ResponseLike) {
  const filename = req.query.file ?? "";
  // VULNERABLE: filename injected into shell command
  const output = child_process.execSync(`convert /uploads/${filename} -resize 200x200 /thumbs/${filename}`);
  res.json({ ok: true, output: output.toString() });
}

// FINDING: Symlink following — no check that resolved path stays in allowed dir
export function serveStaticFile(req: RequestLike, res: ResponseLike) {
  const filename = req.query.name ?? "";
  const filePath = path.join(ALLOWED_BASE, filename);
  // fs.readFileSync follows symlinks — attacker can symlink to /etc/shadow
  const content = fs.readFileSync(filePath);
  res.send(content.toString());
}

// FINDING: Temp file with predictable name — race condition / symlink attack
export function writeTempFile(data: string): string {
  const tmpPath = `/tmp/app-${Date.now()}.tmp`; // predictable — use crypto.randomBytes instead
  fs.writeFileSync(tmpPath, data, { mode: 0o644 }); // also world-readable
  return tmpPath;
}

// FINDING: Directory listing enabled — exposes file structure
export function listDirectory(req: RequestLike, res: ResponseLike) {
  const dir = req.query.dir ?? UPLOAD_DIR;
  const entries = fs.readdirSync(dir); // no restriction on which dirs can be listed
  res.json({ entries });
}

// FINDING: File deletion without path containment check
export function deleteFile(req: RequestLike, res: ResponseLike) {
  const filename = req.query.file ?? "";
  const filePath = path.join(UPLOAD_DIR, filename); // ../../important-file.txt
  fs.unlinkSync(filePath);
  res.json({ ok: true });
}
