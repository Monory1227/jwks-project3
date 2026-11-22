import base64
import hashlib
import os
import sqlite3
import threading
import time
import uuid
from collections import deque

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from flask import Flask, g, jsonify, request

DB_FILE = "totally_not_my_privateKeys.db"
app = Flask(__name__)


# ---------- Argon2id password hashing (settings are configurable) ----------
ARGON2_TIME_COST = 2         # iterations
ARGON2_MEMORY_COST = 65536   # in KiB (64 MB)
ARGON2_PARALLELISM = 2       # lanes
ARGON2_HASH_LEN = 32         # bytes
ARGON2_SALT_LEN = 16         # bytes


def hash_password(password: str) -> str:
    """Argon2id hash with a random salt. Returns a PHC-format string."""
    kdf = Argon2id(
        salt=os.urandom(ARGON2_SALT_LEN),
        length=ARGON2_HASH_LEN,
        iterations=ARGON2_TIME_COST,
        lanes=ARGON2_PARALLELISM,
        memory_cost=ARGON2_MEMORY_COST,
    )
    return kdf.derive_phc_encoded(password.encode("utf-8"))


# ---------- AES encryption of private keys ----------
def _aes_key() -> bytes:
    """Derive a 32-byte AES-256 key from the NOT_MY_KEY environment variable."""
    secret = os.environ.get("NOT_MY_KEY")
    if not secret:
        raise RuntimeError("NOT_MY_KEY environment variable is not set")
    return hashlib.sha256(secret.encode("utf-8")).digest()


def encrypt_bytes(plaintext: bytes) -> bytes:
    """AES-GCM encrypt. Returns nonce (12 bytes) + ciphertext."""
    nonce = os.urandom(12)
    return nonce + AESGCM(_aes_key()).encrypt(nonce, plaintext, None)


def decrypt_bytes(blob: bytes) -> bytes:
    """Reverse of encrypt_bytes."""
    nonce, ciphertext = blob[:12], blob[12:]
    return AESGCM(_aes_key()).decrypt(nonce, ciphertext, None)


# ---------- rate limiter (sliding time window: 10 requests per second) ----------
RATE_LIMIT = 10      # max requests ...
RATE_WINDOW = 1.0    # ... in any window of this many seconds
_request_times = deque()
_rate_lock = threading.Lock()


def allow_request() -> bool:
    now = time.monotonic()
    with _rate_lock:
        # Forget requests that have already left the window.
        while _request_times and now - _request_times[0] >= RATE_WINDOW:
            _request_times.popleft()
        if len(_request_times) < RATE_LIMIT:
            _request_times.append(now)
            return True
        return False


def reset_rate_limiter():
    """Clear the window (handy for tests)."""
    with _rate_lock:
        _request_times.clear()


# ---------- database helpers ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_FILE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    db = sqlite3.connect(DB_FILE)
    db.execute("""CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )""")
    db.commit()
    return db


def generate_key(db, exp):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    # Only the AES-encrypted bytes are ever written to the database.
    db.execute(
        "INSERT INTO keys(key, exp) VALUES (?, ?)", (encrypt_bytes(pem), exp)
    )
    db.commit()


def seed_keys():
    """Make sure there is at least one valid key and one expired key."""
    db = init_db()
    now = int(time.time())
    if not db.execute("SELECT 1 FROM keys WHERE exp > ?", (now,)).fetchone():
        generate_key(db, now + 3600)
    if not db.execute("SELECT 1 FROM keys WHERE exp <= ?", (now,)).fetchone():
        generate_key(db, now - 3600)
    db.close()


# ---------- JWKS ----------
def b64url_uint(n):
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@app.get("/.well-known/jwks.json")
def jwks():
    rows = get_db().execute(
        "SELECT kid, key FROM keys WHERE exp > ?", (int(time.time()),)
    ).fetchall()
    keys = []
    for r in rows:
        pem = decrypt_bytes(r["key"])
        priv = serialization.load_pem_private_key(pem, password=None)
        nums = priv.public_key().public_numbers()
        keys.append({
            "kty": "RSA", "alg": "RS256", "use": "sig",
            "kid": str(r["kid"]),
            "n": b64url_uint(nums.n),
            "e": b64url_uint(nums.e),
        })
    return jsonify(keys=keys)


# ---------- user registration ----------
@app.post("/register")
def register():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="JSON body required"), 400

    username = data.get("username")
    email = data.get("email")
    if not isinstance(username, str) or not username.strip():
        return jsonify(error="username is required"), 400
    if email is not None and not isinstance(email, str):
        return jsonify(error="email must be a string"), 400

    username = username.strip()
    email = email.strip() if email else None  # empty email stored as NULL

    password = str(uuid.uuid4())              # UUIDv4 password
    password_hash = hash_password(password)   # Argon2id hash (salt included)

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users(username, password_hash, email) VALUES (?, ?, ?)",
            (username, password_hash, email),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="username or email already registered"), 409

    return jsonify(password=password), 201


# ---------- auth ----------
def requested_username():
    """Username from a JSON body or HTTP Basic auth, if the client sent one."""
    body = request.get_json(silent=True)
    if isinstance(body, dict) and isinstance(body.get("username"), str):
        return body["username"]
    if request.authorization and request.authorization.username:
        return request.authorization.username
    return None


@app.post("/auth")
def auth():
    # Rate limit first, so rejected requests are never logged.
    if not allow_request():
        return jsonify(error="Too Many Requests"), 429

    db = get_db()
    now = int(time.time())
    expired = "expired" in request.args

    if expired:
        row = db.execute(
            "SELECT kid, key FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
            (now,),
        ).fetchone()
        exp = now - 3600
    else:
        row = db.execute(
            "SELECT kid, key FROM keys WHERE exp > ? LIMIT 1", (now,)
        ).fetchone()
        exp = now + 3600

    if not row:
        return jsonify(error="no suitable key"), 500

    username = requested_username()
    user_row = None
    if username:
        user_row = db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
    user_id = user_row["id"] if user_row else None

    token = jwt.encode(
        {"sub": username or "userABC", "iat": now, "exp": exp},
        decrypt_bytes(row["key"]),
        algorithm="RS256",
        headers={"kid": str(row["kid"])},
    )

    # Log only successful requests.
    db.execute(
        "INSERT INTO auth_logs(request_ip, user_id) VALUES (?, ?)",
        (request.remote_addr or "unknown", user_id),
    )
    if user_id is not None:
        db.execute(
            "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
            (user_id,),
        )
    db.commit()
    return token


if __name__ == "__main__":
    _aes_key()  # fail fast if NOT_MY_KEY is missing
    seed_keys()
    app.run(port=8080)