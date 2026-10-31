import pytest
from starlette.testclient import TestClient

from moodle_mcp.server import create_app

from .conftest import BEARER

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


@pytest.fixture
def client():
    with TestClient(create_app(), base_url="http://mcp.internal") as c:
        yield c


def test_refuses_to_start_without_bearer(monkeypatch):
    monkeypatch.setenv("MCP_BEARER_TOKEN", "")
    with pytest.raises(RuntimeError, match="MCP_BEARER_TOKEN"):
        create_app()
    monkeypatch.delenv("MCP_BEARER_TOKEN")
    with pytest.raises(RuntimeError):
        create_app()


def test_health_without_token(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer wrong"}, {"Authorization": BEARER}])
def test_mcp_rejects_missing_or_bad_token(client, headers):
    r = client.post("/mcp", json=INIT, headers={**MCP_HEADERS, **headers})
    assert r.status_code == 401
    assert r.json() == {"error": "unauthorized"}
    assert r.headers["www-authenticate"] == "Bearer"


def test_other_paths_require_auth(client):
    assert client.get("/").status_code == 401
    assert client.post("/health").status_code == 401


def test_initialize_and_list_tools_with_token(client):
    auth = {**MCP_HEADERS, "Authorization": f"Bearer {BEARER}"}
    r = client.post("/mcp", json=INIT, headers=auth)
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/json")
    body = r.json()
    assert body["result"]["serverInfo"]["name"] == "moodle"

    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, headers=auth)
    assert r.status_code == 200, r.text
    names = {t["name"] for t in r.json()["result"]["tools"]}
    assert {"site_info", "grade_submission", "bulk_grade"} <= names
