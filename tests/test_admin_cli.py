import argparse
import base64
import io
import json
import os
import re
import stat

import pytest

from moodle_mcp.admin import _parse_ttl, build_parser, main
from moodle_mcp.crypto import load_kek
from moodle_mcp.registry import Registry


@pytest.fixture
def admin_env(tmp_path, monkeypatch):
    monkeypatch.delenv("MOODLE_TOKEN", raising=False)
    monkeypatch.delenv("MCP_BEARER_TOKEN", raising=False)
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
