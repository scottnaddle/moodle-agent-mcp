import os
import re
import sqlite3
import time

from moodle_mcp.crypto import Kek
from moodle_mcp.pseudonym import (
    PLACEHOLDER_RE,
    Pseudonymizer,
    RegistryPseudonymMap,
)
from moodle_mcp.registry import Registry


def make_registry(tmp_path, kek):
    return Registry.open(str(tmp_path / "hub.sqlite3"), kek)


def make_pseudonymizer(registry, kek, site_id="site-a", key=b"k" * 32, ttl=86400):
    return Pseudonymizer(
        key, RegistryPseudonymMap(registry, site_id, kek, ttl=ttl)
    )


def test_db_contains_no_plaintext(tmp_path):
    kek = Kek(os.urandom(32))
    registry = make_registry(tmp_path, kek)
    p = make_pseudonymizer(registry, kek)
    masked = p.pseudonymize("김민수 학생의 학번은 20231234입니다")
    assert PLACEHOLDER_RE.search(masked)
    raw = (tmp_path / "hub.sqlite3").read_bytes()
    assert "김민수".encode() not in raw
    assert "20231234".encode() not in raw
    assert b"name" in raw


def test_aad_binds_site_and_placeholder(tmp_path):
    kek = Kek(os.urandom(32))
    registry = make_registry(tmp_path, kek)
    p = make_pseudonymizer(registry, kek)
    masked = p.pseudonymize("김민수")
    placeholder = PLACEHOLDER_RE.search(masked).group(0)
    now = int(time.time())
    with sqlite3.connect(tmp_path / "hub.sqlite3") as conn:
        row = conn.execute(
            "SELECT placeholder, category, value_ct, kek_id, expires_at"
            " FROM pseudonym_map WHERE site_id = ?",
            ("site-a",),
        ).fetchone()
        conn.execute(
            "INSERT INTO pseudonym_map"
            " (site_id, placeholder, category, value_ct, kek_id, expires_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            ("site-b", *row),
        )
    assert registry.pmap_get("site-b", placeholder, now) is None

    with sqlite3.connect(tmp_path / "hub.sqlite3") as conn:
        conn.execute(
            "UPDATE pseudonym_map SET placeholder = ? WHERE site_id = ?",
            ("[이름_11111111]", "site-a"),
        )
    assert registry.pmap_get("site-a", "[이름_11111111]", now) is None
    assert registry.pmap_get("site-a", placeholder, now) is None


def test_ttl_expiry_and_purge(tmp_path):
    kek = Kek(os.urandom(32))
    registry = make_registry(tmp_path, kek)
    placeholder = "[이름_deadbeef]"
    now = int(time.time())
    registry.pmap_put("site-a", placeholder, "name", "김민수", 1, now - 10)
    p = make_pseudonymizer(registry, kek)
    assert placeholder in p.unresolved(placeholder)

    registry.pmap_put("site-a", "[이름_feedface]", "name", "홍길동", 1, now - 10)
    assert registry.pmap_purge(now=now) == 2


def test_registry_reopen_restores(tmp_path):
    kek = Kek(os.urandom(32))
    key = b"k" * 32
    registry = make_registry(tmp_path, kek)
    p1 = make_pseudonymizer(registry, kek, key=key)
    masked = p1.pseudonymize("김민수 학생")
    assert "김민수" not in masked

    reopened = make_registry(tmp_path, kek)
    p2 = make_pseudonymizer(reopened, kek, key=key)
    assert p2.restore(masked) == "김민수 학생"
    assert p2.unresolved(masked) == set()


def test_foreign_kek_id_is_ignored_and_purged(tmp_path):
    kek = Kek(os.urandom(32))
    registry = make_registry(tmp_path, kek)
    p = make_pseudonymizer(registry, kek)
    masked = p.pseudonymize("김민수")
    placeholder = PLACEHOLDER_RE.search(masked).group(0)
    with sqlite3.connect(tmp_path / "hub.sqlite3") as conn:
        conn.execute(
            "UPDATE pseudonym_map SET kek_id = 'foreign' WHERE site_id = ?",
            ("site-a",),
        )
    assert registry.pmap_get("site-a", placeholder, int(time.time())) is None
    with sqlite3.connect(tmp_path / "hub.sqlite3") as conn:
        count = conn.execute("SELECT COUNT(*) FROM pseudonym_map").fetchone()[0]
    assert count == 0


def test_delete_removes_map_rows(tmp_path):
    kek = Kek(os.urandom(32))
    registry = make_registry(tmp_path, kek)
    registry.add("site-a", "https://a.example", b"token-a", None, "bearer-a")
    p = make_pseudonymizer(registry, kek)
    p.pseudonymize("김민수")
    registry.delete("site-a")
    with sqlite3.connect(tmp_path / "hub.sqlite3") as conn:
        count = conn.execute("SELECT COUNT(*) FROM pseudonym_map").fetchone()[0]
    assert count == 0


def test_map_keeps_first_seen_original_verbatim(tmp_path):
    kek = Kek(os.urandom(32))
    key = b"k" * 32
    registry = make_registry(tmp_path, kek)
    p = make_pseudonymizer(registry, kek, key=key)
    first = p.pseudonymize("HONG@Example.com")
    placeholder = PLACEHOLDER_RE.search(first).group(0)
    assert p.pseudonymize("hong@example.com") == first
    assert p.restore(placeholder) == "HONG@Example.com"

    reopened = make_registry(tmp_path, kek)
    p2 = make_pseudonymizer(reopened, kek, key=key)
    assert p2.restore(placeholder) == "HONG@Example.com"
