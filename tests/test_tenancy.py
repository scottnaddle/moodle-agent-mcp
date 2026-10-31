import base64
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor

import pytest
import respx
from starlette.testclient import TestClient

from moodle_mcp.crypto import load_kek
from moodle_mcp.moodle import MoodleClient, MoodleError
from moodle_mcp.registry import Registry
from moodle_mcp.server import create_app, create_mcp

MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"},
    },
}
PLACEHOLDER_RE = re.compile(r"\[(?:이름|학번|이메일|전화번호|주민번호)_[0-9a-f]{8}\]")
TOOL_CALL = {
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {"name": "site_info", "arguments": {}},
}


def write_kek(path):
    raw = os.urandom(32)
    path.write_bytes(base64.b64encode(raw) + b"\n")
    os.chmod(path, 0o600)
    return raw


@pytest.fixture
def multi(tmp_path, monkeypatch):
    monkeypatch.delenv("MOODLE_TOKEN", raising=False)
    monkeypatch.delenv("MCP_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("UBIONAI_HUB_ALLOW_HTTP", raising=False)
    monkeypatch.setenv("UBIONAI_HUB_PUBLIC_URL", "https://hub.test")
    kek_file = tmp_path / "kek"
    write_kek(kek_file)
    db = tmp_path / "hub.sqlite3"
    registry = Registry.open(str(db), load_kek(kek_file))
    registry.add("aa", "https://a.test", b"token-a", None, "bearer-a")
    registry.add("bb", "https://b.test", b"token-b", None, "bearer-b")
    app = create_app(hub_db=str(db), kek_file=str(kek_file))
    with TestClient(app, base_url="http://hub.test") as client:
        yield client, registry, kek_file


def headers(bearer):
    out = dict(MCP_HEADERS)
    if bearer is not None:
        out["Authorization"] = f"Bearer {bearer}"
    return out


def test_site_info_uses_tenant_a(multi):
    client, _, _ = multi
    with respx.mock as router:
        route_a = router.post("https://a.test/webservice/rest/server.php").respond(
            json={"sitename": "A", "siteurl": "https://a.test", "userid": 1}
        )
        route_b = router.post("https://b.test/webservice/rest/server.php").respond(
            json={"sitename": "B", "siteurl": "https://b.test", "userid": 2}
        )
        response = client.post("/t/aa/mcp", json=TOOL_CALL, headers=headers("bearer-a"))
        assert response.status_code == 200, response.text
        assert route_a.call_count == 1
        assert route_b.call_count == 0
        body = route_a.calls.last.request.content.decode()
        assert "wstoken=token-a" in body


def test_cross_tenant_bearer_is_forbidden_without_moodle_call(multi):
    client, _, _ = multi
    with respx.mock as router:
        route_a = router.post("https://a.test/webservice/rest/server.php").respond(json={})
        route_b = router.post("https://b.test/webservice/rest/server.php").respond(json={})
        response = client.post("/t/bb/mcp", json=TOOL_CALL, headers=headers("bearer-a"))
        assert response.status_code == 403
        assert response.json() == {"error": "forbidden"}
        assert route_a.call_count == 0
        assert route_b.call_count == 0


def test_auth_status_and_identical_forbidden_body(multi):
    client, registry, _ = multi
    for auth in (None, "Basic x", "Bearer ", "Bearer  spaced", "bearer lower"):
        assert client.post("/t/aa/mcp", json=TOOL_CALL, headers=headers(auth)).status_code == 401
    unknown = client.post("/t/nope/mcp", json=TOOL_CALL, headers=headers("bearer-a"))
    cross = client.post("/t/bb/mcp", json=TOOL_CALL, headers=headers("bearer-a"))
    registry.set_status("bb", "disabled")
    disabled = client.post("/t/bb/mcp", json=TOOL_CALL, headers=headers("bearer-b"))
    assert unknown.status_code == cross.status_code == disabled.status_code == 403
    assert unknown.content == cross.content == disabled.content
    assert client.get("/t/aa/mcp?authorization=Bearer%20bearer-a").status_code == 401


@pytest.mark.parametrize(
    "path",
    [
        "/mcp",
        "/t/aa/../mcp",
        "/t/aa%2fmcp",
        "/t/aa%2fb/mcp",
        "/t/aa/mcp/extra",
        "/t/AA/mcp",
        "/t/aa",
    ],
)
def test_bad_paths_are_404(multi, path):
    client, _, _ = multi
    assert client.post(path, json=TOOL_CALL, headers=headers("bearer-a")).status_code == 404


def test_health_needs_no_auth(multi):
    client, _, _ = multi
    assert client.get("/health").json() == {"status": "ok"}
    assert client.head("/health").status_code == 200
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.head("/healthz").status_code == 200


def test_tool_outputs_are_pseudonymized(multi):
    client, _, _ = multi
    with respx.mock as router:
        router.post("https://a.test/webservice/rest/server.php").respond(
            json={
                "sitename": "A",
                "siteurl": "https://a.test",
                "userid": 1,
                "fullname": "김철수",
            }
        )
        response = client.post("/t/aa/mcp", json=TOOL_CALL, headers=headers("bearer-a"))
    assert response.status_code == 200, response.text
    body = response.text
    assert "김철수" not in body
    assert PLACEHOLDER_RE.search(body)


def test_tool_outputs_not_pseudonymized_when_flag_is_off(multi):
    client, registry, _ = multi
    registry.add("cc", "https://c.test", b"token-c", None, "bearer-c", pseudonymize=False)
    with respx.mock as router:
        router.post("https://c.test/webservice/rest/server.php").respond(
            json={
                "sitename": "C",
                "siteurl": "https://c.test",
                "userid": 3,
                "fullname": "김철수",
            }
        )
        response = client.post("/t/cc/mcp", json=TOOL_CALL, headers=headers("bearer-c"))
    assert response.status_code == 200, response.text
    assert "김철수" in response.text
    assert not PLACEHOLDER_RE.search(response.text)


def test_tool_output_mapping_is_per_request(multi):
    client, _, _ = multi
    with respx.mock as router:
        router.post("https://a.test/webservice/rest/server.php").respond(
            json={"sitename": "A", "siteurl": "https://a.test", "userid": 1, "fullname": "김철수"}
        )
        router.post("https://b.test/webservice/rest/server.php").respond(
            json={"sitename": "B", "siteurl": "https://b.test", "userid": 2, "fullname": "홍길동"}
        )

        def invoke(index):
            site, bearer, name = (
                ("aa", "bearer-a", "김철수")
                if index % 2 == 0
                else ("bb", "bearer-b", "홍길동")
            )
            response = client.post(f"/t/{site}/mcp", json=TOOL_CALL, headers=headers(bearer))
            return name, response.status_code, response.text

        with ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(invoke, range(50)))
        for name, status, text in results:
            assert status == 200
            assert name not in text
            assert PLACEHOLDER_RE.search(text)


def test_concurrent_calls_are_isolated(multi):
    client, _, _ = multi
    with respx.mock as router:
        route_a = router.post("https://a.test/webservice/rest/server.php").respond(
            json={"sitename": "A", "siteurl": "https://a.test", "userid": 1}
        )
        route_b = router.post("https://b.test/webservice/rest/server.php").respond(
            json={"sitename": "B", "siteurl": "https://b.test", "userid": 2}
        )

        def invoke(index):
            site, bearer = ("aa", "bearer-a") if index % 2 == 0 else ("bb", "bearer-b")
            response = client.post(f"/t/{site}/mcp", json=TOOL_CALL, headers=headers(bearer))
            return site, response.status_code

        with ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(invoke, range(50)))
        assert all(status == 200 for _, status in results)
        for call in route_a.calls:
            assert "wstoken=token-a" in call.request.content.decode()
        for call in route_b.calls:
            assert "wstoken=token-b" in call.request.content.decode()


async def test_no_tenant_context_raises():
    from mcp.server.fastmcp.exceptions import ToolError

    mcp = create_mcp(None)
    with pytest.raises(ToolError, match="no tenant context") as exc:
        await mcp.call_tool("site_info", {})
    assert isinstance(exc.value.__cause__, MoodleError)


def test_logs_and_output_contain_no_secrets(multi, caplog, capsys):
    client, _, kek_file = multi
    caplog.set_level(logging.DEBUG)
    with respx.mock as router:
        router.post("https://a.test/webservice/rest/server.php").respond(
            json={"sitename": "A", "siteurl": "https://a.test", "userid": 1}
        )
        response = client.post("/t/aa/mcp", json=TOOL_CALL, headers=headers("bearer-a"))
        assert response.status_code == 200
    captured = capsys.readouterr()
    keystring = kek_file.read_text().strip()
    combined = caplog.text + captured.out + captured.err
    for secret in ("token-a", "bearer-a", keystring):
        assert secret not in combined


def test_single_tenant_mode_still_works(monkeypatch):
    monkeypatch.setenv("MOODLE_TOKEN", "single-token")
    monkeypatch.setenv("MCP_BEARER_TOKEN", "single-bearer")
    monkeypatch.setenv("MOODLE_WS_ENDPOINT", "https://single.test/webservice/rest/server.php")
    monkeypatch.delenv("UBIONAI_HUB_DB", raising=False)
    with TestClient(create_app(), base_url="http://mcp.internal") as client:
        assert client.get("/health").status_code == 200
        response = client.post("/mcp", json=INIT, headers=headers("single-bearer"))
        assert response.status_code == 200


def test_startup_fails_closed(tmp_path, monkeypatch):
    db = str(tmp_path / "hub.sqlite3")
    monkeypatch.delenv("UBIONAI_HUB_KEK_FILE", raising=False)
    monkeypatch.delenv("MOODLE_TOKEN", raising=False)
    monkeypatch.delenv("MCP_BEARER_TOKEN", raising=False)
    with pytest.raises(RuntimeError):
        create_app(hub_db=db)
    monkeypatch.setenv("MOODLE_TOKEN", "global-token")
    kek_file = tmp_path / "kek"
    write_kek(kek_file)
    with pytest.raises(RuntimeError):
        create_app(hub_db=db, kek_file=str(kek_file))
