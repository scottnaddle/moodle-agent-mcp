import argparse
import base64
import hashlib
import io
import json
import os
import re
import sqlite3
import stat
import time

import pytest

from moodle_mcp import admin
from moodle_mcp.admin import _parse_ttl, build_parser, main
from moodle_mcp.crypto import load_kek, seal
from moodle_mcp.registry import Registry


@pytest.fixture
def admin_env(tmp_path, monkeypatch):
    monkeypatch.delenv("MOODLE_TOKEN", raising=False)
    monkeypatch.delenv("MCP_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("UBIONAI_HUB_PUBLIC_URL", raising=False)
    monkeypatch.delenv("UBIONAI_HUB_TENANT_SECRETS_DIR", raising=False)
    kek_file = tmp_path / "kek"
    kek_file.write_bytes(base64.b64encode(os.urandom(32)) + b"\n")
    os.chmod(kek_file, 0o600)
    db = tmp_path / "hub.sqlite3"
    monkeypatch.setenv("UBIONAI_HUB_DB", str(db))
    monkeypatch.setenv("UBIONAI_HUB_KEK_FILE", str(kek_file))
    return tmp_path, db, kek_file


def secret_file(path, value):
    path.write_bytes(value)
    os.chmod(path, 0o600)
    return path


def add_tenant(admin_env, capsys, site_id="site-a", moodle_url="https://a.test"):
    tmp_path, db, kek_file = admin_env
    token = secret_file(tmp_path / f"token-{site_id}", b"moodle-token")
    bearer_out = tmp_path / f"bearer-{site_id}"
    assert main([
        "add", "--site-id", site_id, "--moodle-url", moodle_url,
        "--moodle-token-file", str(token), "--bearer-out", str(bearer_out),
    ]) == 0  # fmt: skip
    capsys.readouterr()
    return db, kek_file


def seed_oauth(db, kek_file, site_id, clients, grants, tokens=(), moodle_url="https://a.test"):
    """Insert OAuth clients, grants and tokens the way the AS does."""
    kek = load_kek(kek_file)
    now = int(time.time())
    conn = sqlite3.connect(str(db))
    sealed = {}
    try:
        for client_id, source, client_name in clients:
            conn.execute(
                "INSERT INTO oauth_clients"
                " (site_id, client_id, redirect_uris, client_name, source, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (site_id, client_id, "[]", client_name, source, now),
            )
        for grant_id, userid, client_id, scope, tokenid in grants:
            ct = seal(
                kek,
                b"moodle-wstoken",
                site_id,
                f"user_wstoken:{grant_id}:{userid}",
                moodle_url=moodle_url,
            )
            sealed[grant_id] = ct
            conn.execute(
                "INSERT INTO oauth_grants"
                " (grant_id, site_id, moodle_userid, client_id, scope, resource, wstoken_ct,"
                "  moodle_tokenid, valid_until, kek_id, created_at, revoked_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                (
                    grant_id,
                    site_id,
                    userid,
                    client_id,
                    scope,
                    f"https://hub.test/t/{site_id}/mcp",
                    ct,
                    tokenid,
                    now + 3600,
                    kek.kek_id,
                    now,
                ),
            )
        for kind, grant_id in tokens:
            conn.execute(
                "INSERT INTO oauth_tokens (token_hash, kind, grant_id, expires_at, used_at)"
                " VALUES (?, ?, ?, ?, NULL)",
                (
                    hashlib.sha256(f"{kind}-{grant_id}".encode()).digest(),
                    kind,
                    grant_id,
                    now + 3600,
                ),
            )
        conn.commit()
    finally:
        conn.close()
    return sealed


def oauth_rows(db):
    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    try:
        return {
            table: [dict(row) for row in conn.execute(f"SELECT * FROM {table}")]
            for table in ("oauth_clients", "oauth_grants", "oauth_tokens")
        }
    finally:
        conn.close()


def oauth_env(tmp_path, monkeypatch, site_id="site-a"):
    """A public URL and a usable tenant secret file so the Moodle revoke path is reachable."""
    secrets_dir = tmp_path / "secrets"
    site_dir = secrets_dir / site_id
    site_dir.mkdir(parents=True, exist_ok=True)
    secret_file(site_dir / "oauth.secret", b"s" * 40)
    monkeypatch.setenv("UBIONAI_HUB_PUBLIC_URL", "https://hub.test")
    monkeypatch.setenv("UBIONAI_HUB_TENANT_SECRETS_DIR", str(secrets_dir))
    return secrets_dir


def fake_moodle_revoke(monkeypatch, result=True):
    calls = []

    async def fake(tenant, secret, issuer, userid, tokenid):
        calls.append({"tenant": tenant, "issuer": issuer, "userid": userid, "tokenid": tokenid})
        return result

    monkeypatch.setattr(admin, "_moodle_revoke", fake)
    return calls


def test_ttl_parser():
    assert _parse_ttl(None) == 86400
    assert _parse_ttl("3600") == 3600
    assert _parse_ttl("30m") == 1800
    assert _parse_ttl("24h") == 86400
    with pytest.raises(ValueError):
        _parse_ttl("bogus")


def test_no_secret_valued_arguments():
    parser = build_parser()
    forbidden = re.compile(r"(token|key|bearer)", re.IGNORECASE)
    for action in parser._actions:
        if not isinstance(action, argparse._SubParsersAction):
            continue
        for command in action.choices.values():
            for option in command._actions:
                if forbidden.search(option.dest):
                    assert option.dest.endswith("_file") or option.dest.endswith("_out"), option.dest


def test_add_list_rotate_disable_enable_delete(admin_env, capsys):
    tmp_path, db, kek_file = admin_env
    token = secret_file(tmp_path / "token", b"moodle-token-one")
    litellm = secret_file(tmp_path / "litellm", b"litellm-one")
    bearer_out = tmp_path / "bearer-a"
    assert main([
        "add", "--site-id", "site-a", "--moodle-url", "https://a.test",
        "--moodle-token-file", str(token), "--litellm-key-file", str(litellm),
        "--bearer-out", str(bearer_out),
    ]) == 0  # fmt: skip
    assert stat.S_IMODE(bearer_out.stat().st_mode) == 0o600
    bearer_a = bearer_out.read_text()
    capsys.readouterr()

    assert main(["list", "--json"]) == 0
    listing = json.loads(capsys.readouterr().out)
    assert listing == [
        {
            "site_id": "site-a",
            "moodle_url": "https://a.test",
            "status": "active",
            "has_litellm": True,
            "kek_id": load_kek(kek_file).kek_id,
            "pseudonymize": True,
            "assignment_title_heuristic": "title",
            "created_at": listing[0]["created_at"],
            "updated_at": listing[0]["updated_at"],
        }
    ]
    assert "moodle-token-one" not in json.dumps(listing)
    assert "litellm-one" not in json.dumps(listing)
    assert bearer_a not in json.dumps(listing)

    registry = Registry.open(str(db), load_kek(kek_file))
    assert registry.verify_bearer("site-a", bearer_a) is not None

    new_token = secret_file(tmp_path / "token2", b"moodle-token-two")
    new_bearer_out = tmp_path / "bearer-a2"
    assert main([
        "rotate", "--site-id", "site-a", "--moodle-token-file", str(new_token),
        "--new-bearer", "--bearer-out", str(new_bearer_out),
    ]) == 0  # fmt: skip
    bearer_a2 = new_bearer_out.read_text()
    tenant = registry.get("site-a")
    assert bytes(registry.moodle_token(tenant)) == b"moodle-token-two"
    assert registry.verify_bearer("site-a", bearer_a2) is not None
    assert registry.verify_bearer("site-a", bearer_a) is None

    assert main(["disable", "--site-id", "site-a"]) == 0
    assert registry.verify_bearer("site-a", bearer_a2) is None
    assert main(["enable", "--site-id", "site-a"]) == 0
    assert registry.verify_bearer("site-a", bearer_a2) is not None

    assert main(["delete", "--site-id", "site-a"]) == 1
    assert registry.get("site-a") is not None
    capsys.readouterr()
    assert main(["delete", "--site-id", "site-a", "--yes"]) == 0
    output = capsys.readouterr().out
    assert "deleted site=site-a at=" in output
    assert registry.get("site-a") is None


def test_add_and_rotate_via_stdin(admin_env, monkeypatch):
    tmp_path, db, kek_file = admin_env
    bearer_out = tmp_path / "bearer-b"
    monkeypatch.setattr("sys.stdin", io.StringIO("stdin-token\n"))
    assert main([
        "add", "--site-id", "site-b", "--moodle-url", "https://b.test",
        "--moodle-token-file", "-", "--bearer-out", str(bearer_out),
    ]) == 0  # fmt: skip
    registry = Registry.open(str(db), load_kek(kek_file))
    assert bytes(registry.moodle_token(registry.get("site-b"))) == b"stdin-token"
    monkeypatch.setattr("sys.stdin", io.StringIO("stdin-token-two\n"))
    assert main(["rotate", "--site-id", "site-b", "--moodle-token-file", "-"]) == 0
    assert bytes(registry.moodle_token(registry.get("site-b"))) == b"stdin-token-two"


def test_bearer_out_refuses_overwrite(admin_env, capsys):
    tmp_path, _, _ = admin_env
    token = secret_file(tmp_path / "token", b"moodle-token")
    bearer_out = tmp_path / "bearer"
    assert main([
        "add", "--site-id", "site-a", "--moodle-url", "https://a.test",
        "--moodle-token-file", str(token), "--bearer-out", str(bearer_out),
    ]) == 0  # fmt: skip
    capsys.readouterr()
    assert main([
        "rotate", "--site-id", "site-a", "--new-bearer", "--bearer-out", str(bearer_out),
    ]) == 1  # fmt: skip
    assert bearer_out.read_text()  # old bearer is untouched


def test_add_and_rotate_pseudonymize_flag(admin_env, capsys):
    tmp_path, db, kek_file = admin_env
    token = secret_file(tmp_path / "token", b"moodle-token")
    bearer_out = tmp_path / "bearer"
    assert main([
        "add", "--site-id", "site-a", "--moodle-url", "https://a.test",
        "--moodle-token-file", str(token), "--bearer-out", str(bearer_out),
        "--no-pseudonymize",
    ]) == 0  # fmt: skip
    capsys.readouterr()
    registry = Registry.open(str(db), load_kek(kek_file))
    assert registry.get("site-a").pseudonymize is False

    assert main(["list", "--json"]) == 0
    listing = json.loads(capsys.readouterr().out)
    assert listing[0]["pseudonymize"] is False

    assert main(["rotate", "--site-id", "site-a", "--pseudonymize"]) == 0
    assert registry.get("site-a").pseudonymize is True
    assert main(["rotate", "--site-id", "site-a", "--no-pseudonymize"]) == 0
    assert registry.get("site-a").pseudonymize is False


def test_rotate_assignment_title_heuristic(admin_env, capsys):
    tmp_path, db, kek_file = admin_env
    token = secret_file(tmp_path / "token", b"moodle-token")
    assert main([
        "add", "--site-id", "site-a", "--moodle-url", "https://a.test",
        "--moodle-token-file", str(token), "--bearer-out", str(tmp_path / "bearer"),
    ]) == 0  # fmt: skip
    registry = Registry.open(str(db), load_kek(kek_file))
    assert registry.get("site-a").assignment_title_heuristic == "title"
    assert main(
        ["rotate", "--site-id", "site-a", "--assignment-title-heuristic", "full"]
    ) == 0
    assert registry.get("site-a").assignment_title_heuristic == "full"
    capsys.readouterr()
    with pytest.raises(SystemExit):
        main(["rotate", "--site-id", "site-a", "--assignment-title-heuristic", "loose"])
    assert registry.get("site-a").assignment_title_heuristic == "full"


def test_errors_do_not_echo_secrets(admin_env, capsys):
    tmp_path, _, _ = admin_env
    token = secret_file(tmp_path / "token", b"SUPERSECRET-TOKEN")
    bearer_out = tmp_path / "bearer"
    assert main([
        "add", "--site-id", "INVALID!", "--moodle-url", "https://a.test",
        "--moodle-token-file", str(token), "--bearer-out", str(bearer_out),
    ]) == 1  # fmt: skip
    captured = capsys.readouterr()
    assert "SUPERSECRET-TOKEN" not in captured.out
    assert "SUPERSECRET-TOKEN" not in captured.err


def test_purge_pseudonyms_counts_and_site_filter(admin_env, capsys):
    _, db, kek_file = admin_env
    registry = Registry.open(str(db), load_kek(kek_file))
    now = int(time.time())
    registry.pmap_put("site-a", "[이름_deadbeef]", "name", "김민수", 1, 0)
    registry.pmap_put("site-a", "[이름_feedface]", "name", "홍길동", 1, 0)
    registry.pmap_put("site-b", "[이름_cafebabe]", "name", "이영희", 1, 0)
    registry.pmap_put("site-a", "[이름_00000000]", "name", "박지성", 3600, now)
    capsys.readouterr()

    assert main(["purge-pseudonyms", "--site-id", "site-a"]) == 0
    output = capsys.readouterr().out
    assert output.strip() == "purged 2"
    assert "김민수" not in output and "홍길동" not in output

    assert main(["purge-pseudonyms"]) == 0
    assert capsys.readouterr().out.strip() == "purged 1"


CIMD_CLIENT = "https://claude.ai/oauth/mcp-oauth-client-metadata"


def test_oauth_list_empty_and_populated(admin_env, capsys):
    tmp_path, db, kek_file = admin_env
    add_tenant(admin_env, capsys)

    assert main(["oauth-list", "--site-id", "site-a"]) == 0
    out = capsys.readouterr().out
    assert "site=site-a" in out
    assert "clients:" in out and "grants:" in out
    assert "(none)" in out

    sealed = seed_oauth(
        db,
        kek_file,
        "site-a",
        clients=[
            ("dcr_one", "dcr", "Claude Code"),
            ("dcr_two", "dcr", None),
            (CIMD_CLIENT, "cimd", "Claude.ai"),
        ],
        grants=[
            ("grant-a", 3, "dcr_one", "moodle:read", 77),
            ("grant-b", 4, CIMD_CLIENT, "moodle:read moodle:write", 88),
        ],
        tokens=[("access", "grant-a"), ("refresh", "grant-a"), ("access", "grant-b")],
    )

    assert main(["oauth-list", "--site-id", "site-a"]) == 0
    out = capsys.readouterr().out
    assert "client_id=dcr_one source=dcr client_name=Claude Code" in out
    assert f"client_id={CIMD_CLIENT} source=cimd" in out
    assert "active_grants=1" in out
    assert "grant_id=grant-a moodle_userid=3 client_id=dcr_one scope=moodle:read" in out
    assert "live_tokens=2" in out

    assert main(["oauth-list", "--site-id", "site-a", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["site_id"] == "site-a"
    assert len(data["clients"]) == 3
    assert len(data["grants"]) == 2
    assert {client["source"] for client in data["clients"]} == {"dcr", "cimd"}
    assert {grant["grant_id"] for grant in data["grants"]} == {"grant-a", "grant-b"}

    rendered = out + json.dumps(data)
    assert "moodle-wstoken" not in rendered
    for blob in sealed.values():
        assert blob.hex() not in rendered
        assert base64.b64encode(blob).decode() not in rendered
    for row in oauth_rows(db)["oauth_tokens"]:
        assert row["token_hash"].hex() not in rendered

    assert main(["oauth-list", "--site-id", "site-missing"]) == 1
    assert "error: site not found" in capsys.readouterr().err


def test_oauth_revoke_dry_run_changes_nothing(admin_env, capsys):
    tmp_path, db, kek_file = admin_env
    add_tenant(admin_env, capsys)
    seed_oauth(
        db,
        kek_file,
        "site-a",
        clients=[("dcr_one", "dcr", "Claude Code"), ("dcr_two", "dcr", None), (CIMD_CLIENT, "cimd", "Claude.ai")],
        grants=[
            ("grant-a", 3, "dcr_one", "moodle:read", 77),
            ("grant-b", 4, "dcr_two", "moodle:read", 88),
            ("grant-c", 5, CIMD_CLIENT, "moodle:read", 99),
        ],
        tokens=[("access", "grant-a")],
    )
    before = oauth_rows(db)

    assert main(["oauth-revoke", "--site-id", "site-a", "--client-id", "dcr_one"]) == 0
    out = capsys.readouterr().out
    assert "DRY-RUN would revoke grant=grant-a userid=3 client=dcr_one" in out
    assert "grants=1 clients=0" in out
    assert oauth_rows(db) == before

    assert main([
        "oauth-revoke", "--site-id", "site-a", "--client-id", "dcr_one", "--delete-client",
    ]) == 0  # fmt: skip
    out = capsys.readouterr().out
    assert "DRY-RUN would delete client=dcr_one" in out
    assert "grants=1 clients=1" in out
    assert oauth_rows(db) == before

    assert main(["oauth-revoke", "--site-id", "site-a", "--all"]) == 0
    out = capsys.readouterr().out
    assert out.count("DRY-RUN would revoke grant=") == 3
    assert out.count("DRY-RUN would delete client=") == 3
    assert "grants=3 clients=3" in out
    assert oauth_rows(db) == before


def test_oauth_revoke_yes_by_client(admin_env, capsys, monkeypatch):
    tmp_path, db, kek_file = admin_env
    add_tenant(admin_env, capsys)
    seed_oauth(
        db,
        kek_file,
        "site-a",
        clients=[("dcr_one", "dcr", "Claude Code")],
        grants=[("grant-a", 3, "dcr_one", "moodle:read", 77)],
        tokens=[("access", "grant-a"), ("refresh", "grant-a")],
    )
    oauth_env(tmp_path, monkeypatch)
    calls = fake_moodle_revoke(monkeypatch)

    assert main(["oauth-revoke", "--site-id", "site-a", "--client-id", "dcr_one", "--yes"]) == 0
    out = capsys.readouterr().out
    assert "revoked grant=grant-a moodle=ok" in out

    assert len(calls) == 1
    assert calls[0]["userid"] == 3
    assert calls[0]["tokenid"] == 77
    assert calls[0]["issuer"] == "https://hub.test/t/site-a"

    rows = oauth_rows(db)
    grant = rows["oauth_grants"][0]
    assert grant["revoked_at"] is not None
    assert all(token["used_at"] is not None for token in rows["oauth_tokens"])


def test_oauth_revoke_delete_client(admin_env, capsys, monkeypatch):
    tmp_path, db, kek_file = admin_env
    add_tenant(admin_env, capsys)
    seed_oauth(
        db,
        kek_file,
        "site-a",
        clients=[("dcr_one", "dcr", "Claude Code"), ("dcr_two", "dcr", None)],
        grants=[("grant-a", 3, "dcr_one", "moodle:read", 77)],
        tokens=[("access", "grant-a")],
    )
    oauth_env(tmp_path, monkeypatch)
    fake_moodle_revoke(monkeypatch)

    assert main([
        "oauth-revoke", "--site-id", "site-a", "--client-id", "dcr_one", "--delete-client", "--yes",
    ]) == 0  # fmt: skip
    out = capsys.readouterr().out
    assert "deleted client=dcr_one" in out

    rows = oauth_rows(db)
    assert [client["client_id"] for client in rows["oauth_clients"]] == ["dcr_two"]
    assert rows["oauth_grants"][0]["revoked_at"] is not None


def test_oauth_revoke_all(admin_env, capsys, monkeypatch):
    tmp_path, db, kek_file = admin_env
    add_tenant(admin_env, capsys)
    seed_oauth(
        db,
        kek_file,
        "site-a",
        clients=[
            ("dcr_one", "dcr", "Claude Code"),
            ("dcr_two", "dcr", None),
            (CIMD_CLIENT, "cimd", "Claude.ai"),
        ],
        grants=[
            ("grant-a", 3, "dcr_one", "moodle:read", 77),
            ("grant-b", 4, "dcr_two", "moodle:read", 88),
            ("grant-c", 5, CIMD_CLIENT, "moodle:read", 99),
        ],
        tokens=[("access", "grant-a"), ("access", "grant-b"), ("access", "grant-c")],
    )
    oauth_env(tmp_path, monkeypatch)
    fake_moodle_revoke(monkeypatch)

    assert main(["oauth-revoke", "--site-id", "site-a", "--all", "--yes"]) == 0
    out = capsys.readouterr().out
    assert out.count("revoked grant=") == 3
    assert out.count("deleted client=") == 3

    rows = oauth_rows(db)
    assert rows["oauth_clients"] == []
    assert all(grant["revoked_at"] is not None for grant in rows["oauth_grants"])
    assert all(token["used_at"] is not None for token in rows["oauth_tokens"])


def test_oauth_revoke_moodle_failure_exit3(admin_env, capsys, monkeypatch):
    tmp_path, db, kek_file = admin_env
    add_tenant(admin_env, capsys)
    seed_oauth(
        db,
        kek_file,
        "site-a",
        clients=[("dcr_one", "dcr", "Claude Code")],
        grants=[("grant-a", 3, "dcr_one", "moodle:read", 77)],
        tokens=[("access", "grant-a")],
    )
    oauth_env(tmp_path, monkeypatch)
    fake_moodle_revoke(monkeypatch, result=False)

    assert main(["oauth-revoke", "--site-id", "site-a", "--client-id", "dcr_one", "--yes"]) == 3
    out = capsys.readouterr().out
    assert "revoked grant=grant-a moodle=failed" in out

    rows = oauth_rows(db)
    assert rows["oauth_grants"][0]["revoked_at"] is not None
    assert rows["oauth_tokens"][0]["used_at"] is not None


def test_oauth_revoke_skip_moodle_and_missing_secret(admin_env, capsys, monkeypatch):
    tmp_path, db, kek_file = admin_env
    add_tenant(admin_env, capsys)
    seed_oauth(
        db,
        kek_file,
        "site-a",
        clients=[("dcr_one", "dcr", "Claude Code"), ("dcr_two", "dcr", None)],
        grants=[
            ("grant-a", 3, "dcr_one", "moodle:read", 77),
            ("grant-b", 4, "dcr_two", "moodle:read", 88),
        ],
        tokens=[("access", "grant-a"), ("access", "grant-b")],
    )
    oauth_env(tmp_path, monkeypatch)
    calls = fake_moodle_revoke(monkeypatch)

    assert main([
        "oauth-revoke", "--site-id", "site-a", "--client-id", "dcr_one", "--skip-moodle", "--yes",
    ]) == 3  # fmt: skip
    captured = capsys.readouterr()
    assert "warning: moodle token not revoked grant=grant-a" in captured.err
    assert "revoked grant=grant-a moodle=skipped" in captured.out
    assert calls == []

    monkeypatch.delenv("UBIONAI_HUB_TENANT_SECRETS_DIR", raising=False)
    assert main(["oauth-revoke", "--site-id", "site-a", "--client-id", "dcr_two", "--yes"]) == 3
    captured = capsys.readouterr()
    assert "warning: moodle token not revoked grant=grant-b" in captured.err
    assert "revoked grant=grant-b moodle=skipped" in captured.out
    assert calls == []
    assert oauth_rows(db)["oauth_grants"][1]["revoked_at"] is not None


def test_oauth_revoke_requires_one_target(admin_env):
    with pytest.raises(SystemExit) as excinfo:
        main(["oauth-revoke", "--site-id", "site-a"])
    assert excinfo.value.code == 2

    with pytest.raises(SystemExit) as excinfo:
        main(["oauth-revoke", "--site-id", "site-a", "--client-id", "c", "--grant-id", "g"])
    assert excinfo.value.code == 2

    with pytest.raises(SystemExit) as excinfo:
        main(["oauth-revoke", "--site-id", "site-a", "--all", "--yes", "--dry-run"])
    assert excinfo.value.code == 2


def test_oauth_revoke_unknown_site(admin_env, capsys):
    assert main(["oauth-revoke", "--site-id", "site-missing", "--all", "--yes"]) == 1
    assert "error: site not found" in capsys.readouterr().err
