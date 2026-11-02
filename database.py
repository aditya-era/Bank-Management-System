"""Database layer: connection helper, schema creation and non-destructive migration."""
import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("BANK_DB", os.path.join(BASE_DIR, "bank.db"))

# New columns added on top of the original two tables (table -> [(column, definition)])
MIGRATIONS = {
    "users": [
        ("full_name", "text"),
        ("email", "text"),
        ("mobile", "text"),
        ("account_number", "text"),
        ("account_type", "text"),
        ("dob", "text"),
        ("address", "text"),
        ("created_at", "text"),
    ],
    "transactions": [
        ("txn_ref", "text"),
        ("status", "text default 'Completed'"),
        ("counterparty_account", "text"),
        ("balance_after", "real"),
    ],
}

INDEXES = [
    "create unique index if not exists idx_users_username on users(lower(username))",
    "create unique index if not exists idx_users_email on users(lower(email)) where email is not null",
    "create unique index if not exists idx_users_account on users(account_number) where account_number is not null",
    "create index if not exists idx_txn_user on transactions(user_id, id)",
]


def get_db():
    """Open a connection in autocommit mode; financial code opens transactions explicitly."""
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn


def create_database():
    conn = get_db()
    try:
        with open(os.path.join(BASE_DIR, "schema.sql"), "r", encoding="utf-8") as f:
            conn.executescript(f.read())
        for table, cols in MIGRATIONS.items():
            existing = {r["name"] for r in conn.execute(f"pragma table_info({table})")}
            for name, definition in cols:
                if name not in existing:
                    conn.execute(f"alter table {table} add column {name} {definition}")
        for stmt in INDEXES:
            try:
                conn.execute(stmt)
            except sqlite3.IntegrityError:
                # Old data had duplicates; leave the app's own checks to enforce uniqueness.
                pass
    finally:
        conn.close()
