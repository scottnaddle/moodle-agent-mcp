import pytest

ENDPOINT = "https://moodle.test/webservice/rest/server.php"
MOODLE_TOKEN = "fake-moodle-token-123"
BEARER = "fake-bearer-token-xyz"


@pytest.fixture(autouse=True)
def fake_env(monkeypatch):
    monkeypatch.setenv("MOODLE_WS_ENDPOINT", ENDPOINT)
    monkeypatch.setenv("MOODLE_TOKEN", MOODLE_TOKEN)
    monkeypatch.setenv("MCP_BEARER_TOKEN", BEARER)
    monkeypatch.setenv("MCP_PORT", "8791")
