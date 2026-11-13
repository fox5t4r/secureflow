import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

from .ai.providers import DEFAULTS


class Store:
    def __init__(self, directory):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.directory, 0o700)
        self.keyfile = self.directory / "vault.key"
        if not self.keyfile.exists():
            descriptor = os.open(self.keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(Fernet.generate_key())
        self.key = self.keyfile.read_bytes()
        self.vault = Fernet(self.key)
        self.path = self.directory / "secureflow.sqlite3"
        with self.connect() as db:
            db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS admins(username TEXT PRIMARY KEY, password_hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, username TEXT, expires REAL);
            CREATE TABLE IF NOT EXISTS attempts(ip TEXT, at REAL);
            CREATE TABLE IF NOT EXISTS targets(id TEXT PRIMARY KEY,name TEXT,url TEXT,source_path TEXT,username TEXT,credential TEXT);
            CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,target_id TEXT,target_name TEXT,status TEXT,created_at TEXT,data TEXT);
            CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT);
            CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,at REAL,event TEXT,username TEXT,detail TEXT);
            """)
        os.chmod(self.path, 0o600)

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def bootstrap(self):
        with self.connect() as db:
            if db.execute("SELECT 1 FROM admins LIMIT 1").fetchone():
                return None
            password = secrets.token_urlsafe(24)
            db.execute(
                "INSERT INTO admins VALUES (?,?)", ("admin", generate_password_hash(password))
            )
            path = self.directory / "initial-admin.txt"
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as stream:
                stream.write("username=admin\npassword=" + password + "\n")
            return path

    def audit(self, event, username="", detail=""):
        with self.connect() as db:
            db.execute(
                "INSERT INTO audit(at,event,username,detail) VALUES (?,?,?,?)",
                (time.time(), event, username, detail),
            )

    def settings(self):
        result = dict(DEFAULTS)
        with self.connect() as db:
            result.update({r["key"]: r["value"] for r in db.execute("SELECT * FROM settings")})
        return result

    def job(self, identifier):
        with self.connect() as db:
            row = db.execute("SELECT * FROM jobs WHERE id=?", (identifier,)).fetchone()
        return json.loads(row["data"]) if row else None

    def save_job(self, job):
        with self.connect() as db:
            db.execute(
                "INSERT INTO jobs VALUES (?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,data=excluded.data",
                (
                    job["id"],
                    job["target_id"],
                    job["target_name"],
                    job["status"],
                    job["created_at"],
                    json.dumps(job, ensure_ascii=False),
                ),
            )

    def jobs(self):
        with self.connect() as db:
            return [
                json.loads(r["data"])
                for r in db.execute("SELECT data FROM jobs ORDER BY created_at DESC")
            ]

    def targets(self, private=False):
        with self.connect() as db:
            result = [dict(r) for r in db.execute("SELECT * FROM targets ORDER BY name")]
        for target in result:
            target["has_credentials"] = bool(target["credential"])
            if not private:
                del target["credential"]
        return result
