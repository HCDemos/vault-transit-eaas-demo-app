# README — Verify SQLite Database Encryption

This guide shows how to confirm that the **Vault Transit Demo App (Batch)** stores only **encrypted ciphertext** for sensitive customer fields.

---

## 🧠 Purpose

The app saves customer data (name, age, address, SSN) to a local SQLite database (`customers.db`).  Sensitive fields (`address` and `ssn`) are encrypted by **HashiCorp Vault Transit** before storage. These steps verify that **no plaintext** values appear in the database.

---

## ⚙️ Requirements

* The app has already been run and contains data in `customers.db`.
* `sqlite3` is installed (included with most Python distributions).

---

## 🧪 Quick One-Liner

Run this from your terminal:

```bash
sqlite3 customers.db ".headers on" ".mode column" \
  "PRAGMA table_info(customers);" \
  "SELECT id, name, age, substr(address_cipher,1,14) AS addr_prefix, substr(ssn_cipher,1,14) AS ssn_prefix FROM customers LIMIT 10;" \
  "SELECT COUNT(*) AS total,
          SUM(address_cipher LIKE 'vault:%') AS addr_vault_like,
          SUM(ssn_cipher LIKE 'vault:%')    AS ssn_vault_like
     FROM customers;"
```

This will show:

* The schema for the `customers` table
* A sample of ciphertext prefixes
* Counts verifying that every encrypted column begins with `vault:`

---

## 🔍 Step-by-Step Verification

### 1️⃣ Open the Database

```bash
sqlite3 customers.db
```

### 2️⃣ List Tables

```sql
.tables
```

You should see:

```
customers
```

### 3️⃣ View Schema

```sql
.schema customers
```

Expected columns:

```
id | name | age | address_cipher | ssn_cipher
```

### 4️⃣ Sample Records

```sql
.headers on
.mode column
SELECT id, name, age,
       substr(address_cipher,1,20) AS address_prefix,
       substr(ssn_cipher,1,20)     AS ssn_prefix
FROM customers
LIMIT 10;
```

Output should show ciphertext starting with `vault:v1:` or similar.

### 5️⃣ Validate Ciphertext Format

```sql
SELECT COUNT(*)            AS total,
       SUM(address_cipher LIKE 'vault:%') AS addr_cipher_is_vault,
       SUM(ssn_cipher     LIKE 'vault:%') AS ssn_cipher_is_vault
FROM customers;
```

Both counts (`addr_cipher_is_vault` and `ssn_cipher_is_vault`) should equal `total`, confirming that **all sensitive fields are encrypted.**

### 6️⃣ (Optional) View Full Ciphertext

```sql
SELECT * FROM customers LIMIT 3;
```

Each encrypted field will appear as a long `vault:v1:...` string.

---

## 🐍 Python Alternative

If you prefer Python instead of the SQLite shell:

```python
import sqlite3
conn = sqlite3.connect('customers.db')
c = conn.cursor()
print('Schema:')
for row in c.execute("PRAGMA table_info(customers);"): print(row)
print('\nSample rows:')
for row in c.execute("SELECT id, name, age, substr(address_cipher,1,20), substr(ssn_cipher,1,20) FROM customers LIMIT 10;"):
    print(row)
print('\nCounts:')
for row in c.execute("SELECT COUNT(*), SUM(address_cipher LIKE 'vault:%'), SUM(ssn_cipher LIKE 'vault:%') FROM customers;"):
    print({'total': row[0], 'addr_vault_like': row[1], 'ssn_vault_like': row[2]})
```

---

## ✅ Expected Result

Every `address_cipher` and `ssn_cipher` value starts with `vault:` and no plaintext addresses or SSNs exist in the database — demonstrating that **data-at-rest encryption** with HashiCorp Vault Transit is functioning correctly.

---
