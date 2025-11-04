# Vault Transit Demo App (Batch)

This Flask-based web application demonstrates **HashiCorp Vault Transit** encryption and rewrap operations, with timing metrics for each operation. It supports both individual and batch modes for encrypting, decrypting, and rewrapping sensitive customer data.

## 🚀 Features
- **Login page** for two demo users (`alice` / `bob`)
- **Data Entry** page for adding customer data (name, age, address, SSN)
- **Encrypted View**: Displays data stored with ciphertext values
- **Cleartext View**: Decrypts each record on demand using Vault Transit
- **Cleartext (Batch)**: Uses Vault’s batch decrypt API for faster results
- **Re-wrap buttons**: Rewrap all ciphertexts to latest key version (single or batch)
- **Rotate key**: Rotate the Vault Transit key directly from the UI
- **Elapsed time display**: Shows how long each decrypt/rewrap operation takes

## 🗄️ Storage
The app uses a lightweight **SQLite** database (`customers.db`) with:
```sql
id INTEGER PRIMARY KEY AUTOINCREMENT,
name TEXT,
age INTEGER,
address_cipher TEXT,
ssn_cipher TEXT
```
Plaintext values are **never stored**—only encrypted data.

## 🔐 Vault Setup
1. Start Vault (in dev mode for testing):
   ```bash
   vault server -dev -dev-root-token-id=root
   ```
2. In another terminal, enable and initialize the Transit secrets engine:
   ```bash
   export VAULT_ADDR=http://127.0.0.1:8200
   export VAULT_TOKEN=root
   vault secrets enable transit
   vault write -f transit/keys/customer-data
   ```

## ⚙️ Configuration
Set these environment variables before running:
```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root               # or scoped token with transit perms
export VAULT_NAMESPACE=admin
export VAULT_TRANSIT_KEY=customer-data
export FLASK_SECRET_KEY=dev-secret
```

## ▶️ Run the App
```bash
pip install flask hvac python-dotenv
python vault_transit_demo_app_batch.py
```
Then visit [http://localhost:5001](http://localhost:5001).

## 🧰 Demo Users
| Username | Password  |
|-----------|------------|
| alice     | password1  |
| bob       | password2  |

## 🔎 Vault Permissions Required
The Vault token must have capabilities for:
```
transit/encrypt/<key>
transit/decrypt/<key>
transit/rewrap/<key>
transit/keys/<key>/rotate
```

## ⚠️ Security Notes
- For demo purposes only – do **not** use in production as-is.
- Replace basic auth with proper **OIDC/SAML** or Vault auth methods (AppRole, Kubernetes, etc.)
- Use **TLS**, **input validation**, and **parameterized queries**.
- Never persist plaintext secrets or root tokens.
