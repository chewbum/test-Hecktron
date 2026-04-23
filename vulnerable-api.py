# vulnerable-api.py
# Security test fixture: intentionally vulnerable Python web-API patterns.
# DO NOT use these patterns in production code.

import os
import subprocess
import pickle
import hashlib
import sqlite3
import xml.etree.ElementTree as ET
from flask import Flask, request, jsonify, redirect, send_file

app = Flask(__name__)

# FINDING: Hardcoded credentials / secret key
app.secret_key = "dev-secret-key-123"
DB_PATH = "/app/data/app.db"
ADMIN_TOKEN = "hardcoded-admin-token-abc123"


def get_db():
    return sqlite3.connect(DB_PATH)


# FINDING: SQL injection — string formatting instead of parameterised query
@app.route("/users/search")
def search_users():
    email = request.args.get("email", "")
    conn = get_db()
    query = f"SELECT * FROM users WHERE email = '{email}'"  # VULNERABLE
    cursor = conn.execute(query)
    rows = cursor.fetchall()
    return jsonify({"results": rows})


# FINDING: SQL injection — string concatenation in UPDATE statement
@app.route("/users/update", methods=["POST"])
def update_user():
    user_id = request.json.get("id", "")
    new_email = request.json.get("email", "")
    conn = get_db()
    conn.execute(
        "UPDATE users SET email = '" + new_email + "' WHERE id = " + str(user_id)  # VULNERABLE
    )
    conn.commit()
    return jsonify({"ok": True})


# FINDING: OS command injection via shell=True with user input
@app.route("/ping")
def ping_host():
    host = request.args.get("host", "localhost")
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)  # VULNERABLE
    return jsonify({"output": result})


# FINDING: Command injection via os.system
@app.route("/convert")
def convert_file():
    filename = request.args.get("file", "")
    os.system(f"convert /uploads/{filename} /output/{filename}.png")  # VULNERABLE
    return jsonify({"ok": True})


# FINDING: Path traversal — no sanitisation of filename
@app.route("/files/download")
def download_file():
    filename = request.args.get("name", "")
    path = f"/app/uploads/{filename}"  # e.g. ../../etc/passwd
    return send_file(path)


# FINDING: Insecure deserialization with pickle
@app.route("/load-session", methods=["POST"])
def load_session():
    raw = request.data  # attacker-controlled bytes
    session = pickle.loads(raw)  # VULNERABLE — arbitrary code execution
    return jsonify({"session": str(session)})


# FINDING: XXE — XML parsing with external entity expansion enabled
@app.route("/parse-xml", methods=["POST"])
def parse_xml():
    xml_data = request.data
    # ElementTree is safe by default in modern Python, but many apps use lxml with resolve_entities=True
    # Simulating the dangerous pattern:
    tree = ET.fromstring(xml_data)  # VULNERABLE if parser allows external entities
    tag = tree.tag
    return jsonify({"root_tag": tag})


# FINDING: SSRF — outbound request to user-controlled URL
@app.route("/webhook/test", methods=["POST"])
def test_webhook():
    import urllib.request
    url = request.json.get("url", "")
    resp = urllib.request.urlopen(url)  # VULNERABLE — can reach internal services
    body = resp.read(512).decode("utf-8", errors="replace")
    return jsonify({"response_preview": body})


# FINDING: Weak hashing — MD5 for passwords
def hash_password_weak(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()  # VULNERABLE


# FINDING: Sensitive data written to log
@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", "")
    password = request.json.get("password", "")
    app.logger.info(f"Login attempt: username={username} password={password}")  # VULNERABLE
    return jsonify({"ok": True, "hash": hash_password_weak(password)})


# FINDING: Insecure direct object reference — no ownership check
@app.route("/invoices/<invoice_id>")
def get_invoice(invoice_id):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM invoices WHERE id = ?", (invoice_id,)
    ).fetchone()
    return jsonify({"invoice": row})  # no check that invoice belongs to requesting user


# FINDING: Open redirect via unvalidated returnTo parameter
@app.route("/logout")
def logout():
    return_to = request.args.get("returnTo", "/")
    return redirect(return_to)  # VULNERABLE — attacker sets returnTo=https://evil.com


# FINDING: Unauthenticated admin endpoint — relies on obscurity
@app.route("/internal/admin/delete-user", methods=["POST"])
def admin_delete_user():
    user_id = request.json.get("userId", "")
    # No authentication — anyone who discovers this endpoint can delete users
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return jsonify({"ok": True, "deleted": user_id})


# FINDING: Hardcoded token auth (token in source, bypassable by knowing it)
@app.route("/admin/stats")
def admin_stats():
    token = request.headers.get("X-Admin-Token", "")
    if token != ADMIN_TOKEN:
        return jsonify({"error": "Forbidden"}), 403
    return jsonify({"users": 9999, "revenue": "$1M"})


if __name__ == "__main__":
    # FINDING: Debug mode enabled in code (exposes interactive debugger)
    app.run(debug=True, host="0.0.0.0")  # VULNERABLE — debug=True + binding 0.0.0.0
