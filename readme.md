# Vault Transit Demo App (Batch) & Seed Customers App (see below)

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
1. Start Vault (in dev mode for testing) or use an HCP Vault instance for easy repeatability:
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
Set these environment variables before running - change values as needed:
```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root               # or scoped token with transit perms
export VAULT_NAMESPACE=admin          # needed for HCP Vault
export VAULT_TRANSIT_KEY=customer-data
export FLASK_SECRET_KEY=<your_flask_secret>
export ALICE_PASSWORD=<set_alice_password>
export BOB_PASSWORD=<set_bob_password>
```

## ▶️ Run the App
```bash
pip install flask hvac python-dotenv
python vault_transit_demo_app_batch.py
```
Then visit [http://localhost:5001](http://localhost:5001).

## 🧰 Demo Users (local for demo only - these users do not interact with Vault directly)
| Username  |   Password   |
|-----------|--------------|
| alice     | <set-in-env> |
| bob       | <set-in-env> |

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


# How to Use `seed_customers.py`

This script populates the SQLite database (`customers.db`) used by the Vault Transit Demo App with fake customer data. It generates names, ages, addresses, and social security numbers, encrypts the sensitive fields with **HashiCorp Vault Transit**, and inserts the records into the database.

---

## 🧱 Prerequisites

Before running the script:

1. **Vault** must be running and the Transit secrets engine enabled.
2. The Vault key (`customer-data` by default) must already exist.
3. The environment variables for Vault and the database must be configured.

---

## ⚙️ Environment Variables

Set these variables to tell the script how to connect to Vault and where to find the database:

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=<your-token>
export VAULT_NAMESPACE=admin
export VAULT_TRANSIT_KEY=customer-data
export SEED_DB_PATH=customers.db  # optional; defaults to customers.db in current directory
```

> 💡 The Vault token must have `transit/encrypt/<key>` permissions.

---

## ▶️ Running the Script

You can run it directly from the command line:

```bash
pip install faker hvac
python seed_customers.py --count 100
```

* `--count` controls how many fake records to insert (default: 100).
* Each record includes:

  * `name`: Random full name
  * `age`: Random integer between 18 and 90
  * `address`: Random U.S. street address
  * `ssn`: Randomly formatted SSN (fake)

As it runs, it will:

* Generate fake customer data
* Encrypt each customer’s `address` and `ssn` using Vault Transit
* Insert encrypted data into the `customers` table
* Print progress every 10 records and a summary at the end

---

## 📋 Example Output

```
Seeding 100 fake customers into customers.db ...
Encrypted 10 / 100 records
Encrypted 20 / 100 records
...
✅ Done! Inserted 100 records into customers.db
```

---

## 🧩 Integration with the Demo App

Once seeding completes:

1. Launch the Flask app (`vault_transit_demo_app_batch.py`).
2. Log in as `alice` or `bob`.
3. View the **Encrypted View** or **Cleartext View** to confirm the seeded data.

---

## 🧰 Troubleshooting

* **Vault errors**: Ensure your token has proper permissions and Transit is enabled.
* **Database missing**: Make sure the `customers.db` file exists or let the Flask app create it once first.
* **No data visible**: Check that the `customers` table name matches exactly and that you are in the correct directory.

---

## 🧼 Cleanup

To clear all seeded data:

```bash
sqlite3 customers.db "DELETE FROM customers;"
```

---

### ✅ Summary

`seed_customers.py` is a simple seeding tool for quickly populating the Vault Transit Demo App database with realistic but fake encrypted customer data, enabling you to test encryption, decryption, and rewrap performance under load.
