import base64
import logging
import os
import sqlite3
import time

import pytest
import respx
from starlette.testclient import TestClient

from moodle_mcp.crypto import load_kek
from moodle_mcp.registry import Registry
from moodle_mcp.server import create_app

MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
TOOL_CALL = {
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {"name": "site_info", "arguments": {}},
}


def build(tmp_path, monkeypatch):
    monkeypatch.delenv("MOODLE_TOKEN", raising=False)
    monkeypatch.delenv("MCP_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("UBIONAI_HUB_ALLOW_HTTP", raising=False)
    monkeypatch.setenv("UBIONAI_HUB_PUBLIC_URL", "https://hub.test")
    monkeypatch.setenv("UBIONAI_HUB_EGRESS_IP", "203.0.113.9")
    kek_file = tmp_path / "kek"
    kek_file.write_bytes(base64.b64encode(os.urandom(32)) + b"\n")
    os.chmod(kek_file, 0o600)
    db = tmp_path / "hub.sqlite3"
    app = create_app(hub_db=str(db), kek_file=str(kek_file))
    registry = Registry.open(str(db), load_kek(kek_file))
    return TestClient(app, base_url="http://hub.test"), registry, db


def payload(code, site_url="https://reg-a.test", token="wstoken-a"):
    return {"registration_code": code, "site_url": site_url, "wstoken": token}


def test_valid_registration_and_bearer_works(tmp_path, monkeypatch):
    client, registry, _ = build(tmp_path, monkeypatch)
    code = registry.issue_code("reg-a", "https://reg-a.test", 3600)
    with TestClient(client.app, base_url="http://hub.test") as live, respx.mock as router:
        route = router.post("https://reg-a.test/webservice/rest/server.php").respond(
            json={"sitename": "A", "siteurl": "https://reg-a.test", "userid": 7}
        )
        response = live.post("/register", json=payload(code))
        assert response.status_code == 200, response.text
        data = response.json()
        assert data["site_id"] == "reg-a"
        assert data["mcp_endpoint"] == "https://hub.test/t/reg-a/mcp"
        assert data["egress_ip"] == "203.0.113.9"
        assert data["mcp_bearer"]

        response = live.post(
            "/t/reg-a/mcp",
            json=TOOL_CALL,
            headers={**MCP_HEADERS, "Authorization": f"Bearer {data['mcp_bearer']}"},
        )
        assert response.status_code == 200
        assert route.call_count == 2
        assert "wstoken=wstoken-a" in route.calls.last.request.content.decode()


def test_reused_expired_and_url_mismatch_codes(tmp_path, monkeypatch):
    client, registry, db = build(tmp_path, monkeypatch)
    with TestClient(client.app, base_url="http://hub.test") as live, respx.mock as router:
        router.post("https://reg-a.test/webservice/rest/server.php").respond(
            json={"siteurl": "https://reg-a.test"}
        )
        code = registry.issue_code("reg-a", "https://reg-a.test", 3600)
        assert live.post("/register", json=payload(code)).status_code == 200
        assert live.post("/register", json=payload(code)).status_code == 403

        mismatch = registry.issue_code("reg-a", "https://reg-a.test", 3600)
        assert live.post("/register", json=payload(mismatch, "https://reg-b.test")).status_code == 403

        expired = registry.issue_code("reg-a", "https://reg-a.test", 3600)
        with sqlite3.connect(db) as conn:
            conn.execute("UPDATE reg_codes SET expires_at = 0 WHERE used_at IS NULL")
        assert live.post("/register", json=payload(expired)).status_code == 403


def test_moodle_rejection_does_not_burn_code(tmp_path, monkeypatch):
    client, registry, _ = build(tmp_path, monkeypatch)
    code = registry.issue_code("reg-a", "https://reg-a.test", 3600)
    with TestClient(client.app, base_url="http://hub.test") as live, respx.mock as router:
        router.post("https://reg-a.test/webservice/rest/server.php").respond(status_code=403)
        assert live.post("/register", json=payload(code)).status_code == 400
    assert registry.lookup_code(code, int(time.time())) == ("reg-a", "https://reg-a.test")


def test_size_content_type_and_duplicate(tmp_path, monkeypatch):
    client, registry, _ = build(tmp_path, monkeypatch)
    with TestClient(client.app, base_url="http://hub.test") as live, respx.mock as router:
        route = router.post("https://reg-a.test/webservice/rest/server.php").respond(
            json={"siteurl": "https://reg-a.test"}
        )
        too_large = b'{"registration_code":"' + b"x" * 17_000 + b'"}'
        assert live.post(
            "/register", content=too_large, headers={"Content-Type": "application/json"}
        ).status_code == 413
        assert live.post(
            "/register", content=b"{}", headers={"Content-Type": "text/plain"}
        ).status_code == 415

        registry.add("reg-a", "https://reg-a.test", b"old", None, "old-bearer")
        code = registry.issue_code("reg-a", "https://reg-a.test", 3600)
        assert live.post("/register", json=payload(code)).status_code == 409


def test_register_body_and_secrets_never_logged(tmp_path, monkeypatch, caplog):
    client, registry, _ = build(tmp_path, monkeypatch)
    code = registry.issue_code("reg-a", "https://reg-a.test", 3600)
    caplog.set_level(logging.DEBUG)
    with TestClient(client.app, base_url="http://hub.test") as live, respx.mock as router:
        router.post("https://reg-a.test/webservice/rest/server.php").respond(
            json={"siteurl": "https://reg-a.test"}
        )
        assert live.post("/register", json=payload(code)).status_code == 200
    assert code not in caplog.text
    assert "wstoken-a" not in caplog.text
