"""Tests for the Project 3 JWKS server: AES-encrypted keys, user registration,
authentication logging and the rate limiter."""
import base64
import json
import re
import runpy
import sqlite3
import time

import jwt
import pytest
from cryptography.exceptions import InvalidKey, InvalidTag
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from flask import Flask
from jwt.algorithms import RSAAlgorithm

import app as server

TEST_KEY = "unit-test-secret-not-a-real-key"
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)


class FakeClock:
    """Stands in for the time module so rate-limit tests are deterministic."""

    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now

    def time(self):
        return time.time()


@pytest.fixture(autouse=True)
def _env_and_limiter(monkeypatch):
    """Every test gets a known NOT_MY_KEY and an empty rate-limit window."""
    monkeypatch.setenv("NOT_MY_KEY", TEST_KEY)
    server.reset_rate_limiter()
    yield
    server.reset_rate_limiter()


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Test client backed by a throwaway SQLite file."""
    monkeypatch.setattr(server, "DB_FILE", str(tmp_path / "test.db"))
    server.seed_keys()
    return server.app.test_client()


def query(sql, params=()):
    db = sqlite3.connect(server.DB_FILE)
    try:
        return db.execute(sql, params).fetchall()
    finally:
        db.close()


def fetch_jwks(client):
    return client.get("/.well-known/jwks.json").get_json()["keys"]


def register(client, username="mario", email="mario@example.com"):
    return client.post("/register", json={"username": username, "email": email})


# ---------- AES encryption ----------
def test_encrypt_decrypt_round_trip():
    blob = server.encrypt_bytes(b"secret key material")
    assert blob != b"secret key material"
    assert server.decrypt_bytes(blob) == b"secret key material"


def test_encryption_uses_a_fresh_nonce_each_time():
    first = server.encrypt_bytes(b"same plaintext")
    second = server.encrypt_bytes(b"same plaintext")
    assert first != second
    assert first[:12] != second[:12]


def test_decrypt_with_wrong_key_fails(monkeypatch):
    blob = server.encrypt_bytes(b"data")
    monkeypatch.setenv("NOT_MY_KEY", "a completely different key")
    with pytest.raises(InvalidTag):
        server.decrypt_bytes(blob)


def test_missing_env_key_raises(monkeypatch):
    monkeypatch.delenv("NOT_MY_KEY")
    with pytest.raises(RuntimeError):
        server.encrypt_bytes(b"data")


# ---------- key storage ----------
def test_keys_are_encrypted_in_database(client):
    rows = query("SELECT key, exp FROM keys")
    assert len(rows) == 2
    for blob, _ in rows:
        assert b"PRIVATE KEY" not in blob  # never stored as readable PEM
        assert server.decrypt_bytes(blob).startswith(b"-----BEGIN PRIVATE KEY-----")


def test_seed_keys_does_not_duplicate(client):
    server.seed_keys()
    assert query("SELECT COUNT(*) FROM keys") == [(2,)]


# ---------- JWKS ----------
def test_jwks_serves_only_unexpired_keys(client):
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    keys = resp.get_json()["keys"]
    assert len(keys) == 1
    assert keys[0]["kty"] == "RSA"
    assert keys[0]["alg"] == "RS256"
    assert {"kid", "n", "e"} <= keys[0].keys()


# ---------- /auth ----------
def test_auth_token_verifies_against_jwks(client):
    token = client.post("/auth").get_data(as_text=True)
    kid = jwt.get_unverified_header(token)["kid"]
    jwk = next(k for k in fetch_jwks(client) if k["kid"] == kid)
    public_key = RSAAlgorithm.from_jwk(json.dumps(jwk))
    claims = jwt.decode(token, public_key, algorithms=["RS256"])
    assert claims["sub"] == "userABC"


def test_auth_token_names_registered_user(client):
    register(client)
    token = client.post("/auth", json={"username": "mario"}).get_data(as_text=True)
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["sub"] == "mario"


def test_auth_expired_uses_expired_key(client):
    token = client.post("/auth?expired=true").get_data(as_text=True)
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["exp"] < time.time()
    kid = jwt.get_unverified_header(token)["kid"]
    assert kid not in [k["kid"] for k in fetch_jwks(client)]


def test_auth_accepts_basic_auth_and_json_body(client):
    creds = base64.b64encode(b"userABC:password123").decode()
    resp = client.post(
        "/auth",
        json={"username": "userABC", "password": "password123"},
        headers={"Authorization": f"Basic {creds}"},
    )
    assert resp.status_code == 200


def test_auth_accepts_basic_auth_alone(client):
    register(client)
    creds = base64.b64encode(b"mario:whatever").decode()
    resp = client.post("/auth", headers={"Authorization": f"Basic {creds}"})
    assert resp.status_code == 200
    assert query("SELECT user_id FROM auth_logs") == [(1,)]


def test_auth_without_keys_returns_500_and_is_not_logged(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "DB_FILE", str(tmp_path / "empty.db"))
    server.init_db().close()
    resp = server.app.test_client().post("/auth")
    assert resp.status_code == 500
    assert query("SELECT COUNT(*) FROM auth_logs") == [(0,)]


# ---------- /register ----------
def test_register_returns_uuid_password(client):
    resp = register(client)
    assert resp.status_code == 201
    assert UUID4.fullmatch(resp.get_json()["password"])


def test_register_stores_argon2id_hash_not_plaintext(client):
    password = register(client).get_json()["password"]
    stored = query("SELECT password_hash FROM users WHERE username = 'mario'")[0][0]
    assert stored.startswith("$argon2id$")
    assert password not in stored
    Argon2id.verify_phc_encoded(password.encode(), stored)  # raises if wrong
    with pytest.raises(InvalidKey):
        Argon2id.verify_phc_encoded(b"the wrong password", stored)


def test_register_hashes_use_a_random_salt(client):
    register(client, "one", "one@example.com")
    register(client, "two", "two@example.com")
    hashes = [r[0] for r in query("SELECT password_hash FROM users")]
    assert hashes[0] != hashes[1]


def test_register_rejects_duplicate_username(client):
    assert register(client).status_code == 201
    assert register(client, email="other@example.com").status_code == 409


def test_register_rejects_duplicate_email(client):
    assert register(client).status_code == 201
    assert register(client, username="other").status_code == 409


@pytest.mark.parametrize(
    "payload",
    [
        {"email": "a@b.c"},
        {"username": ""},
        {"username": "   "},
        {"username": 123},
        {"username": "x", "email": 5},
        ["not", "a", "dict"],
    ],
)
def test_register_rejects_bad_input(client, payload):
    assert client.post("/register", json=payload).status_code == 400


def test_register_requires_json_body(client):
    assert client.post("/register").status_code == 400


def test_users_without_email_do_not_collide(client):
    assert client.post("/register", json={"username": "a", "email": ""}).status_code == 201
    assert client.post("/register", json={"username": "b"}).status_code == 201
    assert query("SELECT email FROM users ORDER BY id") == [(None,), (None,)]


# ---------- auth logging ----------
def test_auth_logs_successful_request_with_user_id(client):
    register(client)
    client.post(
        "/auth",
        json={"username": "mario"},
        environ_base={"REMOTE_ADDR": "203.0.113.9"},
    )
    ip, stamp, user_id = query(
        "SELECT request_ip, request_timestamp, user_id FROM auth_logs"
    )[0]
    assert ip == "203.0.113.9"
    assert stamp
    assert user_id == query("SELECT id FROM users WHERE username = 'mario'")[0][0]


def test_auth_logs_null_user_for_unknown_or_missing_username(client):
    client.post("/auth", json={"username": "nobody"})
    client.post("/auth")
    assert query("SELECT user_id FROM auth_logs ORDER BY id") == [(None,), (None,)]


def test_auth_updates_last_login(client):
    register(client)
    assert query("SELECT last_login FROM users")[0][0] is None
    client.post("/auth", json={"username": "mario"})
    assert query("SELECT last_login FROM users")[0][0] is not None


# ---------- rate limiter ----------
def test_rate_limit_allows_ten_requests_per_second_then_429(client, monkeypatch):
    clock = FakeClock()
    monkeypatch.setattr(server, "time", clock)
    codes = [client.post("/auth").status_code for _ in range(15)]
    assert codes == [200] * 10 + [429] * 5
    clock.now += 1.01  # a second later the window has moved on
    assert client.post("/auth").status_code == 200


def test_rate_limited_requests_are_not_logged(client, monkeypatch):
    monkeypatch.setattr(server, "time", FakeClock())
    codes = [client.post("/auth").status_code for _ in range(12)]
    assert codes.count(429) == 2
    assert query("SELECT COUNT(*) FROM auth_logs") == [(10,)]


def test_rate_limiter_uses_a_sliding_window(monkeypatch):
    clock = FakeClock()
    monkeypatch.setattr(server, "time", clock)
    assert all(server.allow_request() for _ in range(5))  # t = 0.0
    clock.now += 0.5
    assert all(server.allow_request() for _ in range(5))  # t = 0.5
    assert not server.allow_request()  # window is full
    clock.now += 0.51  # t = 1.01: the first five have expired
    assert all(server.allow_request() for _ in range(5))
    assert not server.allow_request()


# ---------- program entry point ----------
def test_main_block_seeds_keys_and_starts_server(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # the default DB file is created in the cwd
    started = {}
    monkeypatch.setattr(Flask, "run", lambda self, *a, **kw: started.update(kw))
    runpy.run_path(server.__file__, run_name="__main__")
    assert started["port"] == 8080
    assert (tmp_path / "totally_not_my_privateKeys.db").exists()