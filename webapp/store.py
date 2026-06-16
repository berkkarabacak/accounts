"""Accounts data store — sqlite users + the Jira connection vault.

Passwords are PBKDF2 (bk_common.passwords); connection tokens are Fernet-encrypted
at rest. All access goes through small functions here so the HTTP layer stays thin.
"""
import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

from cryptography.fernet import Fernet

from bk_common import config, passwords

DB_PATH = Path(__file__).resolve().parent.parent / "accounts.db"
_lock = threading.Lock()


def _ensure_vault_key() -> str:
    """Read the Fernet key, creating it (0600) only if the file is MISSING.
    Never overwrites an existing key — a read error must not orphan stored tokens."""
    p = config.HOME / ".bk_vault_key"
    if p.exists():
        return p.read_text(encoding="utf-8").strip()
    key = Fernet.generate_key().decode()
    try:
        fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key)
        return key
    except FileExistsError:                      # another process won the race
        return p.read_text(encoding="utf-8").strip()


_FERNET = Fernet(_ensure_vault_key().encode())


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def host(base_url: str) -> str:
    s = (base_url or "").strip()
    if not s.startswith("http"):
        s = "https://" + s
    return (urlparse(s).hostname or "").lower()


def normalize(base_url: str) -> str:
    base = (base_url or "").strip().rstrip("/")
    return base if base.startswith("http") else "https://" + base


def enc(s: str) -> str:
    return _FERNET.encrypt((s or "").encode()).decode()


def dec(s: str) -> str:
    return _FERNET.decrypt((s or "").encode()).decode()


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def _add_column(c, table, col, decl):
    cols = [r[1] for r in c.execute("PRAGMA table_info(%s)" % table).fetchall()]
    if col not in cols:
        c.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, col, decl))


def init_db():
    with _lock, _db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL,
            display_name TEXT, salt TEXT NOT NULL, pwd TEXT NOT NULL, created TEXT NOT NULL)""")
        # identity-provider binding (added later; safe migration for existing DBs)
        _add_column(c, "users", "provider", "TEXT NOT NULL DEFAULT 'password'")
        _add_column(c, "users", "google_sub", "TEXT")
        c.execute("""CREATE TABLE IF NOT EXISTS connections(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            ctype TEXT NOT NULL DEFAULT 'jira-cloud', name TEXT NOT NULL,
            base_url TEXT NOT NULL, email TEXT NOT NULL, token_enc TEXT NOT NULL,
            created TEXT NOT NULL)""")
        # one credential can serve many sites — store the full list as JSON
        # (base_url stays as the primary/first site for backward compatibility)
        _add_column(c, "connections", "sites", "TEXT")


# -- users --
def user_public(row) -> dict:
    return {"id": row["id"], "email": row["email"], "display_name": row["display_name"]}


def get_user(email: str):
    with _lock, _db() as c:
        return c.execute("SELECT * FROM users WHERE email=?", (email.strip().lower(),)).fetchone()


def get_user_by_id(uid: int):
    with _lock, _db() as c:
        return c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


def create_user(email: str, password: str, display_name: str = ""):
    email = email.strip().lower()
    salt, pwd = passwords.hash_password(password)
    name = (display_name or "").strip() or email.split("@")[0]
    with _lock, _db() as c:
        if c.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            raise ValueError("That email is already registered.")
        cur = c.execute("INSERT INTO users(email,display_name,salt,pwd,created) VALUES(?,?,?,?,?)",
                        (email, name, salt, pwd, now()))
        uid = cur.lastrowid
    return {"id": uid, "email": email, "display_name": name}


def check_password(row, password: str) -> bool:
    return bool(row) and passwords.verify_password(password, row["salt"], row["pwd"])


def find_or_create_google_user(sub: str, email: str, display_name: str = "") -> dict:
    """Provider-bound Google sign-in. Match on the stable Google subject; never
    silently take over an existing password account that happens to share the email."""
    import secrets as _s
    email = (email or "").strip().lower()
    name = (display_name or email.split("@")[0]).strip()
    with _lock, _db() as c:
        if sub:
            row = c.execute("SELECT * FROM users WHERE google_sub=?", (sub,)).fetchone()
            if row:
                return user_public(row)
        row = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if row:
            if (row["provider"] or "password") == "google":
                if sub and not row["google_sub"]:
                    c.execute("UPDATE users SET google_sub=? WHERE id=?", (sub, row["id"]))
                return user_public(row)
            raise ValueError("This email already has a password account — sign in with your password.")
        salt, pwd = passwords.hash_password(_s.token_urlsafe(24))  # unusable local password
        cur = c.execute(
            "INSERT INTO users(email,display_name,salt,pwd,created,provider,google_sub) VALUES(?,?,?,?,?,?,?)",
            (email, name, salt, pwd, now(), "google", sub))
        uid = cur.lastrowid
    return {"id": uid, "email": email, "display_name": name}


# -- connections (vault) --
def _sites_of(row) -> list:
    """The site list for a connection. Falls back to [base_url] for old rows."""
    raw = row["sites"] if "sites" in row.keys() else None
    if raw:
        try:
            vals = [normalize(s) for s in json.loads(raw) if s and s.strip()]
            if vals:
                return vals
        except Exception:
            pass
    return [row["base_url"]] if row["base_url"] else []


def _clean_sites(sites) -> list:
    """Normalise + de-dupe a list of site URLs, preserving order."""
    out = []
    for s in (sites or []):
        if not s or not str(s).strip():
            continue
        u = normalize(str(s))
        if u not in out:
            out.append(u)
    return out


def conn_public(row) -> dict:
    sites = _sites_of(row)
    return {"id": row["id"], "ctype": row["ctype"], "name": row["name"], "email": row["email"],
            "base_url": sites[0] if sites else "", "host": host(sites[0]) if sites else "",
            "sites": sites, "hosts": [host(s) for s in sites]}


def list_connections(uid: int) -> list:
    with _lock, _db() as c:
        rows = c.execute("SELECT * FROM connections WHERE user_id=? ORDER BY id", (uid,)).fetchall()
    return [conn_public(r) for r in rows]


def get_connection(uid: int, cid: int):
    with _lock, _db() as c:
        return c.execute("SELECT * FROM connections WHERE id=? AND user_id=?", (cid, uid)).fetchone()


def add_connection(uid, name, sites, email, token, ctype="jira-cloud"):
    site_list = _clean_sites(sites)
    if not site_list:
        raise ValueError("At least one site URL is required.")
    base = site_list[0]
    with _lock, _db() as c:
        cur = c.execute(
            "INSERT INTO connections(user_id,ctype,name,base_url,email,token_enc,created,sites) VALUES(?,?,?,?,?,?,?,?)",
            (uid, ctype, (name or host(base)).strip(), base, email.strip(),
             enc(token.strip()), now(), json.dumps(site_list)))
        row = c.execute("SELECT * FROM connections WHERE id=?", (cur.lastrowid,)).fetchone()
    return conn_public(row)


def update_connection(uid, cid, name=None, sites=None, email=None, token=None):
    with _lock, _db() as c:
        row = c.execute("SELECT * FROM connections WHERE id=? AND user_id=?", (cid, uid)).fetchone()
        if not row:
            return None
        site_list = _clean_sites(sites) if sites is not None else _sites_of(row)
        if not site_list:
            raise ValueError("At least one site URL is required.")
        new_tok = enc(token.strip()) if token else row["token_enc"]
        c.execute("UPDATE connections SET name=?,base_url=?,email=?,token_enc=?,sites=? WHERE id=?",
                  (name if name is not None else row["name"], site_list[0],
                   email.strip() if email is not None else row["email"], new_tok,
                   json.dumps(site_list), cid))
        row = c.execute("SELECT * FROM connections WHERE id=?", (cid,)).fetchone()
    return conn_public(row)


def upsert_connection(uid, base_url, email, token, ctype="jira-cloud", name=""):
    """Single-site insert/update for app-side 'remember' (e.g. Crosschecker)."""
    base = normalize(base_url)
    with _lock, _db() as c:
        row = c.execute("SELECT id FROM connections WHERE user_id=? AND ctype=? AND base_url=?",
                        (uid, ctype, base)).fetchone()
        if row:
            c.execute("UPDATE connections SET name=?,email=?,token_enc=?,sites=? WHERE id=?",
                      ((name or host(base)).strip(), email.strip(), enc(token.strip()),
                       json.dumps([base]), row["id"]))
            return row["id"]
        cur = c.execute(
            "INSERT INTO connections(user_id,ctype,name,base_url,email,token_enc,created,sites) VALUES(?,?,?,?,?,?,?,?)",
            (uid, ctype, (name or host(base)).strip(), base, email.strip(),
             enc(token.strip()), now(), json.dumps([base])))
        return cur.lastrowid


def delete_connection(uid, cid) -> bool:
    with _lock, _db() as c:
        return c.execute("DELETE FROM connections WHERE id=? AND user_id=?", (cid, uid)).rowcount > 0


def delete_connections(uid, ctype="jira-cloud"):
    with _lock, _db() as c:
        c.execute("DELETE FROM connections WHERE user_id=? AND ctype=?", (uid, ctype))


def resolve(uid, cid):
    """Public connection info plus the decrypted token (for app server-to-server use)."""
    row = get_connection(uid, cid)
    if not row:
        return None
    d = conn_public(row)
    d["token"] = dec(row["token_enc"])
    return d
