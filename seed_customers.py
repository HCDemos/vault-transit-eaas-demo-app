"""
Seed script for the Vault Transit demo app.

Generates N fake customer records and inserts them into the demo app's
SQLite database, encrypting sensitive fields (address, ssn) using
HashiCorp Vault Transit in the specified namespace.

Usage (defaults to 100 records):
    pip install faker hvac

    export VAULT_ADDR=http://127.0.0.1:8200
    export VAULT_TOKEN=root                       # or a scoped token
    export VAULT_NAMESPACE=admin                  # match your setup
    export VAULT_TRANSIT_KEY=customer-data        # match your app key
    # optional: export SEED_DB_PATH=./customers.db  # default ./customers.db

    python seed_customers.py --count 100

This script will create the 'customers' table if it does not yet exist.
"""
from __future__ import annotations
import argparse
import base64
import os
import random
import sqlite3
from typing import Optional

import hvac
from faker import Faker

# -------------------- Config --------------------
VAULT_ADDR: Optional[str] = os.environ.get("VAULT_ADDR")
VAULT_TOKEN: Optional[str] = os.environ.get("VAULT_TOKEN")
VAULT_NAMESPACE: str = os.environ.get("VAULT_NAMESPACE", "admin")
TRANSIT_KEY: str = os.environ.get("VAULT_TRANSIT_KEY", "customer-data")
DB_PATH: str = os.environ.get("SEED_DB_PATH", "./customers.db")

if not VAULT_ADDR or not VAULT_TOKEN:
    raise SystemExit(
        "VAULT_ADDR and VAULT_TOKEN must be set in the environment."
    )

client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN, namespace=VAULT_NAMESPACE)


def transit_encrypt(plaintext: str) -> str:
    if plaintext is None:
        plaintext = ""
    b64_plain = base64.b64encode(plaintext.encode("utf-8")).decode("utf-8")
    resp = client.secrets.transit.encrypt_data(name=TRANSIT_KEY, plaintext=b64_plain)
    return resp["data"]["ciphertext"]


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
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
    conn.commit()


def insert_customer(conn: sqlite3.Connection, name: str, age: int, address: str, ssn: str) -> None:
    addr_ct = transit_encrypt(address)
    ssn_ct = transit_encrypt(ssn)
    conn.execute(
        "INSERT INTO customers (name, age, address_cipher, ssn_cipher) VALUES (?, ?, ?, ?)",
        (name, age, addr_ct, ssn_ct),
    )


def main(count: int) -> None:
    fake = Faker("en_US")
    # You can add deterministic seeding if desired: Faker.seed(1234)

    # Connect DB
    conn = sqlite3.connect(DB_PATH)
    try:
        ensure_schema(conn)
        total = 0
        for i in range(count):
            name = fake.name()
            age = random.randint(18, 90)
            address = fake.address().replace("\n", ", ")
            ssn = fake.ssn()
            insert_customer(conn, name, age, address, ssn)
            total += 1
            if total % 10 == 0:
                conn.commit()
                print(f"Inserted {total}/{count} records...")
        conn.commit()
        print(f"Done. Inserted {total} records into {DB_PATH} using key '{TRANSIT_KEY}' in namespace '{VAULT_NAMESPACE}'.")
    finally:
        conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed the Vault Transit demo app DB with fake customers.")
    parser.add_argument("--count", type=int, default=100, help="Number of records to insert (default: 100)")
    args = parser.parse_args()
    main(args.count)
