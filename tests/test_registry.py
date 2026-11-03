import base64
import os
import sqlite3
import time

import pytest

from moodle_mcp.crypto import DecryptError, Kek
from moodle_mcp.registry import (
    DuplicateSite,
    Registry,
    TenantError,
    normalize_moodle_url,
    ws_endpoint,
)


def make_kek(raw=None):
    return Kek(raw or os.urandom(32))


def make_registry(tmp_path, kek=None):
    registry = Registry.open(str(tmp_path / "hub.sqlite3"), kek or make_kek())
    return registry


def test_add_get_and_ciphertext_only(tmp_path):
    registry = make_registry(tmp_path)
    registry.add("site-a", "https://moodle.example/", b"plain-secret-token", b"litellm-key", "bearer-a")
    tenant = registry.get("site-a")
    assert tenant is not None
    assert tenant.moodle_url == "https://moodle.example"
    assert tenant.status == "active"
    assert bytes(registry.moodle_token(tenant)) == b"plain-secret-token"
    assert bytes(registry.litellm_key(tenant)) == b"litellm-key"
    raw_db = (tmp_path / "hub.sqlite3").read_bytes()
    assert b"plain-secret-token" not in raw_db
    assert b"litellm-key" not in raw_db
    assert b"bearer-a" not in raw_db
    with pytest.raises(DuplicateSite):
        registry.add("site-a", "https://moodle.example", b"x", None, "other")


def test_cross_tenant_ciphertext_fails(tmp_path):
    registry = make_registry(tmp_path)
    registry.add("site-a", "https://a.example", b"token-a", None, "bearer-a")
    registry.add("site-b", "https://b.example", b"token-b", None, "bearer-b")
    tenant_a = registry.get("site-a")
    tenant_b = registry.get("site-b")
    with sqlite3.connect(tmp_path / "hub.sqlite3") as conn:
        conn.execute("UPDATE tenants SET token_ct = ? WHERE site_id = ?", (tenant_a.token_ct, "site-b"))
    tenant_b = registry.get("site-b")
    with pytest.raises(DecryptError):
        registry.moodle_token(tenant_b)


def test_kek_ids_and_wrong_kek_mismatch(tmp_path):
    registry = make_registry(tmp_path)
    assert registry.kek_ids() == set()
    registry.add("site-a", "https://a.example", b"token-a", None, "bearer-a")
    assert registry.kek_ids() == {registry._kek.kek_id}
    other = make_registry(tmp_path, make_kek())
    assert other.kek_ids() != {other._kek.kek_id}


def test_site_id_and_url_validation(tmp_path, monkeypatch):
    registry = make_registry(tmp_path)
    for site_id in ("A", "a", "-a", "a_b", "a/b", "a" * 64):
        with pytest.raises(TenantError):
            registry.add(site_id, "https://moodle.example", b"x", None, "bearer")
    bad_urls = [
        "http://moodle.example",
        "https://user:pass@moodle.example",
        "https://user@moodle.example",
        "https://moodle.example/?x=1",
        "https://moodle.example/#frag",
        "https:///nohost",
    ]
    for url in bad_urls:
        with pytest.raises(TenantError):
            normalize_moodle_url(url)
    assert normalize_moodle_url("https://Moodle.Example/") == "https://moodle.example"
    assert normalize_moodle_url("https://moodle.example/moodle/") == "https://moodle.example/moodle"
    assert ws_endpoint("https://moodle.example") == "https://moodle.example/webservice/rest/server.php"
    monkeypatch.setenv("UBIONAI_HUB_ALLOW_HTTP", "1")
    assert normalize_moodle_url("http://moodle.example/", allow_http=True) == "http://moodle.example"


def test_verify_bearer_unknown_disabled_and_wrong(tmp_path):
    registry = make_registry(tmp_path)
    registry.add("site-a", "https://a.example", b"token-a", None, "bearer-a")
    assert registry.verify_bearer("unknown", "bearer-a") is None
    assert registry.verify_bearer("site-a", "wrong") is None
    registry.set_status("site-a", "disabled")
    assert registry.verify_bearer("site-a", "bearer-a") is None
    registry.set_status("site-a", "active")
    assert registry.verify_bearer("site-a", "bearer-a") is not None


def test_delete_removes_row_and_bytes(tmp_path):
    registry = make_registry(tmp_path)
    registry.add("site-a", "https://a.example", b"delete-me-please", None, "bearer-a")
    registry.delete("site-a")
    assert registry.get("site-a") is None
    raw_db = (tmp_path / "hub.sqlite3").read_bytes()
    assert b"delete-me-please" not in raw_db
    with pytest.raises(TenantError):
        registry.delete("site-a")


def test_pseudonymize_flag_roundtrip(tmp_path):
    registry = make_registry(tmp_path)
    registry.add("site-a", "https://a.example", b"token-a", None, "bearer-a")
    registry.add("site-b", "https://b.example", b"token-b", None, "bearer-b", pseudonymize=False)
    assert registry.get("site-a").pseudonymize is True
    assert registry.get("site-b").pseudonymize is False
    assert {tenant.site_id: tenant.pseudonymize for tenant in registry.list()} == {
        "site-a": True,
        "site-b": False,
    }
    registry.rotate_pseudonymize("site-b", True)
    assert registry.get("site-b").pseudonymize is True
    registry.rotate_pseudonymize("site-b", False)
    assert registry.get("site-b").pseudonymize is False


def test_assignment_title_heuristic_roundtrip(tmp_path):
    registry = make_registry(tmp_path)
    registry.add("site-a", "https://a.example", b"token-a", None, "bearer-a")
    assert registry.get("site-a").assignment_title_heuristic == "title"
    registry.set_assignment_title_heuristic("site-a", "full")
    assert registry.get("site-a").assignment_title_heuristic == "full"
    registry.set_assignment_title_heuristic("site-a", "off")
    assert registry.list()[0].assignment_title_heuristic == "off"
    with pytest.raises(TenantError):
        registry.set_assignment_title_heuristic("site-a", "loose")
    assert registry.get("site-a").assignment_title_heuristic == "off"


def test_schema_v1_migrates_to_v6(tmp_path):
    db = tmp_path / "old.sqlite3"
    with sqlite3.connect(db) as conn:
        conn.executescript(
            """
            CREATE TABLE meta (schema_version INTEGER NOT NULL);
            CREATE TABLE tenants (
              site_id      TEXT PRIMARY KEY,
              moodle_url   TEXT NOT NULL,
              token_ct     BLOB NOT NULL,
              litellm_ct   BLOB,
              bearer_hash  BLOB NOT NULL UNIQUE,
              kek_id       TEXT NOT NULL,
              status       TEXT NOT NULL DEFAULT 'active',
              created_at   INTEGER NOT NULL,
              updated_at   INTEGER NOT NULL
            );
            CREATE TABLE reg_codes (
              code_hash  BLOB PRIMARY KEY,
              site_id    TEXT NOT NULL,
              moodle_url TEXT NOT NULL,
              expires_at INTEGER NOT NULL,
              used_at    INTEGER
            );
            INSERT INTO meta(schema_version) VALUES (1);
            INSERT INTO tenants VALUES
              ('old-site', 'https://old.example', X'00', NULL, X'01', 'old-kek', 'active', 1, 2);
            """
        )
    registry = Registry.open(str(db), make_kek())
    tenant = registry.get("old-site")
    assert tenant is not None
    assert tenant.pseudonymize is True
    assert tenant.assignment_title_heuristic == "title"
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT schema_version FROM meta").fetchone()[0] == 6
        columns ={row[1] for row in conn.execute("PRAGMA table_info(tenants)")}
        assert "pseudonymize" in columns
        assert "assignment_title_heuristic" in columns
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert "pseudonym_map" in tables


def test_registration_codes_are_atomic_and_expire(tmp_path):
    registry = make_registry(tmp_path)
    code = registry.issue_code("site-a", "https://a.example/", 60)
    now = int(time.time())
    assert registry.claim_code(code, now) == ("site-a", "https://a.example")
    assert registry.claim_code(code, now) is None
    expired = registry.issue_code("site-a", "https://a.example", 60)
    assert registry.claim_code(expired, now + 120) is None
    unknown = registry.issue_code("site-a", "https://a.example", 60)
    assert registry.claim_code("not-" + unknown, now) is None


def test_schema_v3_migrates_to_v6(tmp_path):
    db = tmp_path / "v3.sqlite3"
    with sqlite3.connect(db) as conn:
        conn.executescript(
            """
            CREATE TABLE meta (schema_version INTEGER NOT NULL);
            CREATE TABLE tenants (
              site_id      TEXT PRIMARY KEY,
              moodle_url   TEXT NOT NULL,
              token_ct     BLOB NOT NULL,
              litellm_ct   BLOB,
              bearer_hash  BLOB NOT NULL UNIQUE,
              kek_id       TEXT NOT NULL,
              status       TEXT NOT NULL DEFAULT 'active',
              pseudonymize INTEGER NOT NULL DEFAULT 1,
              created_at   INTEGER NOT NULL,
              updated_at   INTEGER NOT NULL
            );
            CREATE TABLE reg_codes (
              code_hash  BLOB PRIMARY KEY,
              site_id    TEXT NOT NULL,
              moodle_url TEXT NOT NULL,
              expires_at INTEGER NOT NULL,
              used_at    INTEGER
            );
            INSERT INTO meta(schema_version) VALUES (3);
            """
        )
    registry = Registry.open(str(db), make_kek())
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT schema_version FROM meta").fetchone()[0] == 6
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert "pseudonym_map" in tables
    assert registry.kek_ids() == set()
