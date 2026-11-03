"""Schema v6 (contract §3.2) and the shared-secret credential store (§3.1, §3.3)."""

import base64
import os
import sqlite3

import pytest

from moodle_mcp.crypto import DecryptError, Kek, open_
from moodle_mcp.registry import Registry
from moodle_mcp.siteauth import (
    ConfirmError,
    SharedSecretCredentialStore,
    SignatureAuthenticator,
    derive_mac_key,
    mac_field,
    secret_hash,
    verify_message,
)


def make_kek() -> Kek:
    return Kek(os.urandom(32))


V5_DB = """
CREATE TABLE meta (schema_version INTEGER NOT NULL);
CREATE TABLE tenants (
  site_id      TEXT PRIMARY KEY CHECK (site_id GLOB '[a-z0-9]*' AND length(site_id) BETWEEN 2 AND 63),
  moodle_url   TEXT NOT NULL,
  token_ct     BLOB NOT NULL,
  litellm_ct   BLOB,
  bearer_hash  BLOB NOT NULL UNIQUE,
  kek_id       TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  pseudonymize INTEGER NOT NULL DEFAULT 1 CHECK (pseudonymize IN (0,1)),
  assignment_title_heuristic TEXT NOT NULL DEFAULT 'title'
               CHECK (assignment_title_heuristic IN ('full','title','off')),
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL
);
CREATE TABLE reg_codes (code_hash BLOB PRIMARY KEY, site_id TEXT NOT NULL, moodle_url TEXT NOT NULL,
  expires_at INTEGER NOT NULL, used_at INTEGER);
CREATE TABLE oauth_grants (grant_id TEXT PRIMARY KEY, site_id TEXT NOT NULL, moodle_userid INTEGER NOT NULL,
  client_id TEXT NOT NULL, scope TEXT NOT NULL, resource TEXT NOT NULL, wstoken_ct BLOB NOT NULL,
  moodle_tokenid INTEGER NOT NULL, valid_until INTEGER NOT NULL, kek_id TEXT NOT NULL,
  created_at INTEGER NOT NULL, revoked_at INTEGER);
INSERT INTO meta VALUES (5);
INSERT INTO tenants VALUES ('demo', 'https://moodle.example', X'00', NULL, X'01', 'k', 'active', 1, 'title', 1, 2);
INSERT INTO tenants VALUES ('dup-a', 'https://same.example/m', X'00', NULL, X'02', 'k', 'disabled', 0, 'off', 1, 2);
INSERT INTO tenants VALUES ('dup-b', 'https://SAME.example/m/', X'00', NULL, X'03', 'k', 'active', 1, 'full', 1, 2);
INSERT INTO tenants VALUES ('local', 'http://localhost:8080', X'00', NULL, X'04', 'k', 'active', 1, 'title', 1, 2);
INSERT INTO oauth_grants VALUES ('g1', 'demo', 3, 'c', 's', 'r', X'00', 1, 9, 'k', 1, NULL);
"""


def test_v5_to_v6_keeps_rows_and_fills_host_key(tmp_path):
    db = tmp_path / "v5.sqlite3"
    with sqlite3.connect(db) as conn:
        conn.executescript(V5_DB)
    registry = Registry.open(str(db), make_kek())
    demo = registry.get("demo")
    assert (demo.host_key, demo.origin, demo.tier, demo.auth_mode) == ("moodle.example", "operator", "standard", "legacy_file")
    assert demo.token_ct == b"\x00" and demo.bearer_hash == b"\x01"
    a, b = registry.get("dup-a"), registry.get("dup-b")
    assert a.host_key is None and b.host_key is None  # collision -> NULL for both, logged
    assert (a.status, a.pseudonymize, a.assignment_title_heuristic) == ("disabled", False, "off")
    assert registry.get("local").host_key is None  # not a public https host
    assert registry.get_by_host_key("moodle.example").site_id == "demo"
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT schema_version FROM meta").fetchone()[0] == 6
        assert conn.execute("SELECT COUNT(*) FROM oauth_grants").fetchone()[0] == 1
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"site_credentials", "site_registrations"} <= tables and "tenants_v6" not in tables
    Registry.open(str(db), make_kek())  # idempotent


def test_check_constraints_forbid_site_tokens_on_self_registered(tmp_path):
    registry = Registry.open(str(tmp_path / "hub.sqlite3"), make_kek())
    t = registry.add_self_registered(
        "self-a1b2c3", "https://s.example", "s.example", status="active", site_identifier_hash=None,
        plugin_version=1, moodle_release="5.1", consent_version="2026-11-01", consent_at=0,
    )
    assert (t.token_ct, t.bearer_hash, t.tier, t.origin, t.auth_mode) == (None, None, "limited", "self_registered", "shared_secret")
    assert registry.verify_bearer(t.site_id, "anything") is None
    with registry._connect() as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE tenants SET token_ct = X'00' WHERE site_id = ?", (t.site_id,))
    with registry._connect() as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE tenants SET bearer_hash = X'00' WHERE site_id = ?", (t.site_id,))
    with registry._connect() as conn:  # operator rows still need their token + bearer
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO tenants (site_id, moodle_url, kek_id, created_at, updated_at) VALUES ('op', 'https://o.example', 'k', 0, 0)"
            )
    with pytest.raises(Exception):
        registry.add_self_registered(
            "self-other", "https://s.example", "s.example", status="active", site_identifier_hash=None,
            plugin_version=1, moodle_release="5.1", consent_version="2026-11-01", consent_at=0,
        )  # host_key UNIQUE
    registry.set_status(t.site_id, "pending")
    assert registry.get(t.site_id).status == "pending"


def _store(tmp_path):
    kek = make_kek()
    registry = Registry.open(str(tmp_path / "hub.sqlite3"), kek)
    registry.add_self_registered(
        "s-site", "https://s.example", "s.example", status="active", site_identifier_hash=None,
        plugin_version=1, moodle_release="5.1", consent_version="2026-11-01", consent_at=0,
    )
    clock = {"t": 1_800_000_000}
    return registry, kek, SharedSecretCredentialStore(registry, kek, clock=lambda: clock["t"]), clock


def test_secret_is_hashed_and_mac_key_sealed(tmp_path):
    registry, kek, store, _ = _store(tmp_path)
    issued = store.issue("s-site")
    assert issued.version == 1 and len(issued.site_secret) == 43
    raw = (tmp_path / "hub.sqlite3").read_bytes()
    assert issued.site_secret.encode() not in raw
    with registry._connect() as conn:
        dump = "\n".join(conn.iterdump())
    assert issued.site_secret not in dump
    mac_key = derive_mac_key(issued.site_secret, "s-site", 1)
    assert mac_key not in raw and mac_key.hex() not in dump
    cred = store.credentials("s-site")[0]
    assert cred.secret_hash == secret_hash(issued.site_secret) and cred.state == "pending"
    assert bytes(open_(kek, cred.mac_key_ct, "s-site", mac_field(1), moodle_url="https://s.example")) == mac_key
    with pytest.raises(DecryptError):
        open_(make_kek(), cred.mac_key_ct, "s-site", mac_field(1), moodle_url="https://s.example")
    with pytest.raises(DecryptError):
        open_(kek, cred.mac_key_ct, "s-site", mac_field(2), moodle_url="https://s.example")


def test_confirm_rotate_lifecycle(tmp_path):
    registry, kek, store, clock = _store(tmp_path)
    first = store.issue("s-site")
    assert store.authenticator("s-site", "https://s.example") is None  # nothing signs before confirm
    assert store.authenticate("s-site", first.site_secret) is None  # pending is not "current"
    with pytest.raises(ConfirmError, match="invalid_site_credentials"):
        store.confirm("s-site", 1, "wrong")
    assert store.confirm("s-site", 1, first.site_secret)
    assert store.confirm("s-site", 1, first.site_secret)  # idempotent
    assert store.authenticate("s-site", first.site_secret) == 1
    auth = store.authenticator("s-site", "https://s.example")
    claims = verify_message(derive_mac_key(first.site_secret, "s-site", 1), auth.sign({"typ": "t", "exp": 2**40}), "t")
    assert claims["kv"] == 1

    second = store.issue("s-site")  # re-registration / rotate: current keeps signing
    assert second.version == 2
    assert store.authenticator("s-site", "https://s.example").version == 1
    third = store.issue("s-site")  # an unconfirmed pending is replaced (max one)
    assert third.version == 3
    assert [c.state for c in store.credentials("s-site")] == ["current", "retired", "pending"]
    with pytest.raises(ConfirmError, match="nothing_to_confirm"):
        store.confirm("s-site", 2, first.site_secret)
    with pytest.raises(ConfirmError, match="invalid_site_credentials"):
        store.confirm("s-site", 2, second.site_secret)  # retired pending
    store.confirm("s-site", 3, third.site_secret)
    assert store.authenticator("s-site", "https://s.example").version == 3
    assert store.authenticate("s-site", first.site_secret) is None  # old secret no longer authenticates
    assert store.authenticate("s-site", third.site_secret) == 3

    late = store.issue("s-site")
    clock["t"] += 3601
    with pytest.raises(ConfirmError, match="pending_secret_expired"):
        store.confirm("s-site", late.version, late.site_secret)
    assert store.authenticate("s-site", third.site_secret) == 3
    store.retire_all("s-site")
    assert store.authenticator("s-site", "https://s.example") is None


def test_delete_cascades_credentials(tmp_path):
    registry, kek, store, _ = _store(tmp_path)
    store.issue("s-site")
    registry.delete("s-site")
    assert store.credentials("s-site") == []


def test_signature_authenticator_is_a_stub():
    with pytest.raises(NotImplementedError):
        SignatureAuthenticator().sign({})
    with pytest.raises(NotImplementedError):
        SignatureAuthenticator().verify("x", "t")


def test_secret_hash_is_over_the_transmitted_string():
    secret = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()
    import hashlib

    assert secret_hash(secret) == hashlib.sha256(secret.encode()).digest()
