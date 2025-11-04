"""
Small, simple Flask web app demonstrating HashiCorp Vault Transit encryption (with namespace + key ops + timing).

Features
- Login page for two demo users
- Data entry page for customer records (name, age, address, SSN)
- Page showing stored data with sensitive fields encrypted (ciphertext)
- Page showing the same data in cleartext (runtime decryption via Transit)
- Buttons to rotate the Transit key and to re-wrap ciphertexts (single + batch)
- Displays elapsed time for single re-wrap and batch re-wrap operations

Storage
- SQLite database (customers.db) with columns:
  id INTEGER PK, name TEXT, age INTEGER,
  address_cipher TEXT, ssn_cipher TEXT

Vault prerequisites (one-time)
1) Start Vault (dev mode for local demo):
   vault server -dev -dev-root-token-id=root

2) In another shell, enable transit and create a key:
   export VAULT_ADDR=http://127.0.0.1:8200
   export VAULT_TOKEN=root
   vault secrets enable transit
   vault write -f transit/keys/customer-data

App configuration (env vars)
   export VAULT_ADDR=http://127.0.0.1:8200
   export VAULT_TOKEN=root  # or a scoped token w/ transit encrypt/decrypt/rewrap/rotate perms
   export VAULT_NAMESPACE=admin
   export VAULT_TRANSIT_KEY=customer-data
   export FLASK_SECRET_KEY=dev-secret

Run
   pip install flask hvac python-dotenv
   python vault_transit_demo_app_batch.py

Security notes (for real apps)
- Use proper auth (OIDC/SAML), CSRF protection, parameterized queries/ORM
- Use Vault AppRole/Kubernetes auth; never ship root tokens
- Validate/sanitize inputs; enforce password hashing, rate limiting, TLS, etc.
- Do NOT store plaintext SSNs; this demo never persists plaintext, only ciphertext
"""

from __future__ import annotations
import base64
import os
import sqlite3
import time
from functools import wraps
from typing import Dict, Any

from flask import (
    Flask, render_template_string, request, redirect, url_for, session, g, flash
)
import hvac

# -------------------- Flask setup --------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "change-me")
DB_PATH = os.path.join(os.path.dirname(__file__), "customers.db")

# Demo users (username -> password). In production, use hashed passwords + DB/IdP
USERS = {
    "alice": "password1",
    "bob": "password2",
}

# -------------------- Vault client helpers --------------------
VAULT_ADDR = os.environ.get("VAULT_ADDR")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN")
VAULT_NAMESPACE = os.environ.get("VAULT_NAMESPACE", "admin")  # set to your namespace
TRANSIT_KEY = os.environ.get("VAULT_TRANSIT_KEY", "customer-data")

if not VAULT_ADDR or not VAULT_TOKEN:
    print("[WARN] VAULT_ADDR/VAULT_TOKEN not set. Set env vars before running.")

client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN, namespace=VAULT_NAMESPACE)


def transit_encrypt(plaintext: str) -> str:
    if plaintext is None:
        plaintext = ""
    # Transit expects base64-encoded plaintext
    b64_plain = base64.b64encode(plaintext.encode("utf-8")).decode("utf-8")
    resp = client.secrets.transit.encrypt_data(
        name=TRANSIT_KEY,
        plaintext=b64_plain,
    )
    # ciphertext looks like: vault:v1:...
    return resp["data"]["ciphertext"]


def transit_decrypt(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    resp = client.secrets.transit.decrypt_data(
        name=TRANSIT_KEY,
        ciphertext=ciphertext,
    )
    b64_plain = resp["data"]["plaintext"]
    return base64.b64decode(b64_plain).decode("utf-8")


# -------------------- DB helpers --------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            age INTEGER,
            address_cipher TEXT NOT NULL,
            ssn_cipher TEXT NOT NULL
        );
        """
    )
    db.commit()


# -------------------- Auth utilities --------------------

def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapper


# -------------------- Routes --------------------

@app.route("/")
def index():
    if session.get("user"):
        return redirect(url_for("entry"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if USERS.get(username) == password:
            session["user"] = username
            flash("Logged in successfully.", "success")
            return redirect(url_for("entry"))
        flash("Invalid credentials.", "danger")

    return render_template_string(LOGIN_HTML)


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


@app.route("/entry", methods=["GET", "POST"])
@login_required
def entry():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        age = request.form.get("age", "").strip()
        address = request.form.get("address", "").strip()
        ssn = request.form.get("ssn", "").strip()

        # Basic validation
        if not name or not ssn:
            flash("Name and SSN are required.", "warning")
            return render_template_string(ENTRY_HTML)

        try:
            age_int = int(age) if age else None
        except ValueError:
            flash("Age must be a number.", "warning")
            return render_template_string(ENTRY_HTML)

        # Encrypt sensitive fields with Vault Transit before storing
        try:
            address_cipher = transit_encrypt(address)
            ssn_cipher = transit_encrypt(ssn)
        except Exception as e:
            flash(f"Vault encryption failed: {e}", "danger")
            return render_template_string(ENTRY_HTML)

        db = get_db()
        db.execute(
            "INSERT INTO customers (name, age, address_cipher, ssn_cipher) VALUES (?, ?, ?, ?)",
            (name, age_int, address_cipher, ssn_cipher),
        )
        db.commit()
        flash("Customer saved.", "success")
        return redirect(url_for("encrypted"))

    return render_template_string(ENTRY_HTML)


@app.route("/encrypted")
@login_required
def encrypted():
    db = get_db()
    rows = db.execute("SELECT * FROM customers ORDER BY id DESC").fetchall()
    return render_template_string(ENCRYPTED_HTML, rows=rows)


@app.route("/rewrap", methods=["POST"]) 
@login_required
def rewrap():
    """Re-wrap all stored ciphertexts to the latest key version (one-by-one)."""
    db = get_db()
    rows = db.execute("SELECT id, address_cipher, ssn_cipher FROM customers").fetchall()
    updated = 0
    failed = 0

    start = time.perf_counter()
    for r in rows:
        addr_ct = r["address_cipher"]
        ssn_ct = r["ssn_cipher"]
        try:
            new_addr = client.secrets.transit.rewrap_data(name=TRANSIT_KEY, ciphertext=addr_ct)["data"]["ciphertext"] if addr_ct else None
            new_ssn = client.secrets.transit.rewrap_data(name=TRANSIT_KEY, ciphertext=ssn_ct)["data"]["ciphertext"] if ssn_ct else None
            db.execute(
                "UPDATE customers SET address_cipher = ?, ssn_cipher = ? WHERE id = ?",
                (new_addr or addr_ct, new_ssn or ssn_ct, r["id"]),
            )
            updated += 1
        except Exception:
            failed += 1
    db.commit()
    elapsed = time.perf_counter() - start
    flash(f"Re-wrap (single) complete in {elapsed:.3f}s. Updated: {updated}, Failed: {failed}", "info")
    return redirect(url_for("encrypted"))


@app.route("/rewrap-batch", methods=["POST"]) 
@login_required
def rewrap_batch():
    """Use Vault Transit batch rewrap to update all ciphertexts to the latest key version.
    Uses a direct POST to the Transit API for compatibility across hvac versions.
    Shows total elapsed time.
    """
    db = get_db()
    rows = db.execute("SELECT id, address_cipher, ssn_cipher FROM customers ORDER BY id").fetchall()

    # Prepare batch inputs and keep mapping to row ids
    addr_inputs, addr_index = [], []
    ssn_inputs, ssn_index = [], []

    for r in rows:
        if r["address_cipher"]:
            addr_inputs.append({"ciphertext": r["address_cipher"]})
            addr_index.append(r["id"])
        if r["ssn_cipher"]:
            ssn_inputs.append({"ciphertext": r["ssn_cipher"]})
            ssn_index.append(r["id"])

    updated = 0
    failed = 0
    start = time.perf_counter()

    try:
        # Helper to call Transit rewrap with batch_input via raw adapter for broad hvac compatibility
        def batch_rewrap(batch_list):
            if not batch_list:
                return []
            resp = client.adapter.post(
                f"v1/transit/rewrap/{TRANSIT_KEY}",
                json={"batch_input": batch_list},
            )
            # Support hvac versions where adapter.post returns dict vs Response
            if isinstance(resp, dict):
                data = resp.get("data", {})
            else:
                data = resp.json().get("data", {})
            return data.get("batch_results", [])

        # Address batch
        if addr_inputs:
            addr_results = batch_rewrap(addr_inputs)
            for i, res in enumerate(addr_results):
                row_id = addr_index[i]
                ct = res.get("ciphertext")
                if ct:
                    db.execute("UPDATE customers SET address_cipher = ? WHERE id = ?", (ct, row_id))
                    updated += 1
                else:
                    failed += 1

        # SSN batch
        if ssn_inputs:
            ssn_results = batch_rewrap(ssn_inputs)
            for i, res in enumerate(ssn_results):
                row_id = ssn_index[i]
                ct = res.get("ciphertext")
                if ct:
                    db.execute("UPDATE customers SET ssn_cipher = ? WHERE id = ?", (ct, row_id))
                    updated += 1
                else:
                    failed += 1

        db.commit()
        elapsed = time.perf_counter() - start
        flash(f"Batch re-wrap complete in {elapsed:.3f}s. Updated: {updated}, Failed: {failed}", "info")
    except Exception as e:
        elapsed = time.perf_counter() - start
        db.rollback()
        flash(f"Batch re-wrap error after {elapsed:.3f}s: {e}", "danger")

    return redirect(url_for("encrypted"))


@app.route("/rotate-key", methods=["POST"]) 
@login_required
def rotate_key():
    try:
        client.secrets.transit.rotate_key(name=TRANSIT_KEY)
        flash("Transit key rotated. New encryptions will use the latest key version.", "success")
    except Exception as e:
        flash(f"Key rotation failed: {e}", "danger")
    return redirect(url_for("encrypted"))


@app.route("/clear")
@login_required
def cleartext():
    db = get_db()
    rows = db.execute("SELECT * FROM customers ORDER BY id DESC").fetchall()

    start = time.perf_counter()
    # Decrypt on-the-fly for display only
    clear_rows = []
    for r in rows:
        try:
            addr = transit_decrypt(r["address_cipher"]) if r["address_cipher"] else ""
            ssn = transit_decrypt(r["ssn_cipher"]) if r["ssn_cipher"] else ""
        except Exception as e:
            addr = f"<decrypt error: {e}>"
            ssn = f"<decrypt error: {e}>"
        clear_rows.append({
            "id": r["id"],
            "name": r["name"],
            "age": r["age"],
            "address": addr,
            "ssn": ssn,
        })

    elapsed = time.perf_counter() - start
    flash(f"Decrypt (single) complete in {elapsed:.3f}s for {len(rows)} records.", "info")

    return render_template_string(CLEAR_HTML, rows=clear_rows)


@app.route("/clear-batch")
@login_required
def cleartext_batch():
    """Render cleartext using Transit batch decrypt for better performance."""
    db = get_db()
    rows = db.execute("SELECT * FROM customers ORDER BY id DESC").fetchall()

    # Prepare batch inputs and index mapping
    addr_inputs, addr_index = [], []
    ssn_inputs, ssn_index = [], []
    for r in rows:
        if r["address_cipher"]:
            addr_inputs.append({"ciphertext": r["address_cipher"]})
            addr_index.append(r["id"])
        if r["ssn_cipher"]:
            ssn_inputs.append({"ciphertext": r["ssn_cipher"]})
            ssn_index.append(r["id"])

    def batch_decrypt(batch_list):
        if not batch_list:
            return []
        resp = client.adapter.post(
            f"v1/transit/decrypt/{TRANSIT_KEY}",
            json={"batch_input": batch_list},
        )
        # Support hvac versions where adapter.post returns dict vs Response
        if isinstance(resp, dict):
            data = resp.get("data", {})
        else:
            data = resp.json().get("data", {})
        return data.get("batch_results", [])

    start = time.perf_counter()
    try:
        addr_results = batch_decrypt(addr_inputs)
        ssn_results = batch_decrypt(ssn_inputs)
        elapsed = time.perf_counter() - start

        # Build maps from id -> plaintext (decoded)
        addr_map = {}
        for i, res in enumerate(addr_results):
            if "plaintext" in res:
                try:
                    addr_map[addr_index[i]] = base64.b64decode(res["plaintext"]).decode("utf-8")
                except Exception:
                    addr_map[addr_index[i]] = "<decode error>"
            else:
                addr_map[addr_index[i]] = "<decrypt error>"

        ssn_map = {}
        for i, res in enumerate(ssn_results):
            if "plaintext" in res:
                try:
                    ssn_map[ssn_index[i]] = base64.b64decode(res["plaintext"]).decode("utf-8")
                except Exception:
                    ssn_map[ssn_index[i]] = "<decode error>"
            else:
                ssn_map[ssn_index[i]] = "<decrypt error>"

        # Assemble rows in the same order as original query
        clear_rows = []
        for r in rows:
            clear_rows.append({
                "id": r["id"],
                "name": r["name"],
                "age": r["age"],
                "address": addr_map.get(r["id"], ""),
                "ssn": ssn_map.get(r["id"], ""),
            })

        flash(f"Batch decrypt complete in {elapsed:.3f}s for {len(rows)} records.", "info")
        return render_template_string(CLEAR_HTML, rows=clear_rows)
    except Exception as e:
        elapsed = time.perf_counter() - start
        flash(f"Batch decrypt error after {elapsed:.3f}s: {e}", "danger")
        # Fallback to non-batch cleartext page on error
        return redirect(url_for("cleartext"))

# -------------------- HTML Templates --------------------

BASE_CSS = """
<style>
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 2rem; }
  .nav a { margin-right: 1rem; }
  .card { border: 1px solid #e5e7eb; border-radius: 12px; padding: 1rem 1.25rem; margin: 1rem 0; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
  input, button, textarea { padding: .6rem .8rem; border: 1px solid #cbd5e1; border-radius: 10px; width: 100%; }
  label { font-weight: 600; margin-top: .6rem; display: block; }
  form { max-width: 520px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: .5rem .6rem; border-bottom: 1px solid #eee; font-size: 0.95rem; }
  .flash { padding: .6rem .8rem; border-radius: 8px; margin-bottom: 1rem; }
  .success { background: #ecfdf5; color: #065f46; }
  .danger { background: #fef2f2; color: #991b1b; }
  .warning { background: #fff7ed; color: #9a3412; }
  .info { background: #eff6ff; color: #1e40af; }
  /* Ensure nav buttons are visible & compact */
  .nav { margin-bottom: 1rem; }
  .nav form { display: inline; }
  .nav button { width: auto; display: inline-block; }
  /* Optional prominent actions bar */
  .actions { margin: .5rem 0 1rem; }
  .actions form { display: inline; margin-right: .5rem; }
  .actions button { width: auto; }
</style>
"""

NAV = """
<div class=\"nav\">
  <a href=\"{{ url_for('entry') }}\">Data Entry</a>
  <a href=\"{{ url_for('encrypted') }}\">Encrypted View</a>
  <a href=\"{{ url_for('cleartext') }}\">Cleartext View</a>
  <a href=\"{{ url_for('cleartext_batch') }}\">Cleartext (Batch)</a>
  <form action=\"{{ url_for('rewrap') }}\" method=\"post\"><button type=\"submit\">Re-wrap (single)</button></form>
  <form action=\"{{ url_for('rewrap_batch') }}\" method=\"post\"><button type=\"submit\">Re-wrap (batch API)</button></form>
  <form action=\"{{ url_for('rotate_key') }}\" method=\"post\"><button type=\"submit\">Rotate Key</button></form>
  <a href=\"{{ url_for('logout') }}\">Logout ({{ session.get('user') }})</a>
</div>
"""

FLASHES = """
{% with messages = get_flashed_messages(with_categories=true) %}
  {% if messages %}
    {% for cat, msg in messages %}
      <div class=\"flash {{ cat }}\">{{ msg }}</div>
    {% endfor %}
  {% endif %}
{% endwith %}
"""

# Actions bar used on all pages (defined before templates that reference it)
ACTIONS = """
<div class=\"actions\">
  <form action=\"{{ url_for('rewrap') }}\" method=\"post\"><button type=\"submit\">Re-wrap (single)</button></form>
  <form action=\"{{ url_for('rewrap_batch') }}\" method=\"post\"><button type=\"submit\">Re-wrap (batch API)</button></form>
  <form action=\"{{ url_for('rotate_key') }}\" method=\"post\"><button type=\"submit\">Rotate Key</button></form>
</div>
"""

LOGIN_HTML = BASE_CSS + """
<h2>Login</h2>
""" + FLASHES + """
<div class=\"card\">
  <form method=\"post\">
    <label for=\"username\">Username</label>
    <input id=\"username\" name=\"username\" placeholder=\"alice or bob\" required>

    <label for=\"password\">Password</label>
    <input id=\"password\" type=\"password\" name=\"password\" required>

    <div style=\"margin-top:1rem\"><button type=\"submit\">Log In</button></div>
  </form>
</div>
<p>Demo users: <code>alice/password1</code> or <code>bob/password2</code></p>
"""

ENTRY_HTML = BASE_CSS + NAV + FLASHES + """
<h2>Customer Data Entry</h2>
<div class=\"card\">
  <form method=\"post\">
    <label for=\"name\">Name</label>
    <input id=\"name\" name=\"name\" required>

    <label for=\"age\">Age</label>
    <input id=\"age\" name=\"age\" type=\"number\" min=\"0\" step=\"1\">

    <label for=\"address\">Address</label>
    <textarea id=\"address\" name=\"address\" rows=\"2\" placeholder=\"123 Main St, City, ST 00000\"></textarea>

    <label for=\"ssn\">Social Security Number</label>
    <input id=\"ssn\" name=\"ssn\" placeholder=\"###-##-####\" required>

    <div style=\"margin-top:1rem\"><button type=\"submit\">Save Customer</button></div>
  </form>
</div>
"""

ENCRYPTED_HTML = BASE_CSS + NAV + FLASHES + """
<h2>All Customers (Sensitive Fields Encrypted)</h2>
<div class=\"card\">
  <table>
    <thead>
      <tr>
        <th>ID</th><th>Name</th><th>Age</th><th>Address (ciphertext)</th><th>SSN (ciphertext)</th>
      </tr>
    </thead>
    <tbody>
      {% for r in rows %}
      <tr>
        <td>{{ r.id }}</td>
        <td>{{ r.name }}</td>
        <td>{{ r.age if r.age is not none else '' }}</td>
        <td style=\"word-break:break-all\">{{ r.address_cipher }}</td>
        <td style=\"word-break:break-all\">{{ r.ssn_cipher }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
"""

CLEAR_HTML = BASE_CSS + NAV + FLASHES + """
<h2>All Customers (Cleartext via Transit Decrypt)</h2>
<div class=\"card\">
  <table>
    <thead>
      <tr>
        <th>ID</th><th>Name</th><th>Age</th><th>Address</th><th>SSN</th>
      </tr>
    </thead>
    <tbody>
      {% for r in rows %}
      <tr>
        <td>{{ r.id }}</td>
        <td>{{ r.name }}</td>
        <td>{{ r.age if r.age is not none else '' }}</td>
        <td>{{ r.address }}</td>
        <td>{{ r.ssn }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
"""


# -------------------- Main --------------------
if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(host="0.0.0.0", port=5001, debug=True)
