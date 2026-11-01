"""Phase 0 spike: E2E of the OAuth prototype with the official MCP SDK client on 127.0.0.1."""

import base64
import hashlib
import secrets
import socket
import threading
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken
from pydantic import AnyUrl

from moodle_mcp.oauth_spike import StubMoodleDelegate, create_spike_app

SITE = "demo"
REDIRECT = "http://127.0.0.1:53682/callback"
CIMD_URL = "https://client.example/oauth/client-metadata.json"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _cimd_fetcher(url: str) -> dict:
    assert url == CIMD_URL
    return {"client_id": CIMD_URL, "client_name": "Test CIMD client", "redirect_uris": ["http://127.0.0.1/callback"]}


@pytest.fixture(scope="module")
def hub():
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    app = create_spike_app(base, {SITE, "other"}, StubMoodleDelegate(base, user_id=42), _cimd_fetcher)
    app.config.trusted_cimd = app.config.trusted_cimd + (CIMD_URL,)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield app, base
    server.should_exit = True
    thread.join(timeout=5)


class MemStorage(TokenStorage):
    def __init__(self):
        self.tokens: OAuthToken | None = None
        self.client: OAuthClientInformationFull | None = None

    async def get_tokens(self):
        return self.tokens

    async def set_tokens(self, tokens):
        self.tokens = tokens

    async def get_client_info(self):
        return self.client

    async def set_client_info(self, client_info):
        self.client = client_info


class BrowserSim:
    """redirect_handler/callback_handler pair: follows hub -> stub Moodle -> hub callback -> client."""

    def __init__(self, redirect_prefix: str):
        self.prefix = redirect_prefix
        self.result: dict[str, str] = {}
        self.authorize_url = ""

    async def redirect(self, url: str) -> None:
        self.authorize_url = url
        async with httpx.AsyncClient(follow_redirects=False) as c:
            for _ in range(5):
                resp = await c.get(url)
                assert resp.status_code == 302, resp.text
                url = resp.headers["location"]
                if urlsplit(url).netloc == urlsplit(self.prefix).netloc:
                    self.result = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
                    return
        raise AssertionError("never reached client redirect")

    async def callback(self):
        return self.result["code"], self.result.get("state")


def _provider(base: str, storage: MemStorage, browser: BrowserSim, cimd: str | None = None) -> OAuthClientProvider:
    return OAuthClientProvider(
        server_url=f"{base}/t/{SITE}/mcp",
        client_metadata=OAuthClientMetadata(
            client_name="pytest-sdk-client",
            redirect_uris=[AnyUrl(REDIRECT)],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            token_endpoint_auth_method="none",
        ),
        storage=storage,
        redirect_handler=browser.redirect,
        callback_handler=browser.callback,
        client_metadata_url=cimd,
    )


async def _call_whoami(base: str, auth: OAuthClientProvider) -> dict:
    async with httpx.AsyncClient(auth=auth, follow_redirects=False) as http, streamable_http_client(
        f"{base}/t/{SITE}/mcp", http_client=http
    ) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            assert {t.name for t in tools.tools} == {"whoami", "echo"}
            result = await session.call_tool("whoami", {})
            assert not result.isError, result
            return result.structuredContent


async def test_sdk_e2e_discovery_dcr_pkce_tool(hub):
    app, base = hub
    app.request_log.clear()
    storage, browser = MemStorage(), BrowserSim(REDIRECT)
    who = await _call_whoami(base, _provider(base, storage, browser))

    assert who["moodle_userid"] == "42"
    assert who["aud"] == f"{base}/t/{SITE}/mcp"
    assert storage.client.client_id.startswith("dcr_")
    # RFC 9207: iss returned with the code and equal to the issuer
    assert browser.result["iss"] == f"{base}/t/{SITE}"
    # RFC 8707: SDK sent resource on authorize
    q = parse_qs(urlsplit(browser.authorize_url).query)
    assert q["resource"] == [f"{base}/t/{SITE}/mcp"]
    assert q["code_challenge_method"] == ["S256"]
    log = "\n".join(app.request_log)
    print("\n--- request log ---\n" + log)
    order = [
        f"POST /t/{SITE}/mcp",
        f"GET /.well-known/oauth-protected-resource/t/{SITE}/mcp",
        f"GET /.well-known/oauth-authorization-server/t/{SITE}",
        f"POST /t/{SITE}/oauth/register",
        f"GET /t/{SITE}/oauth/authorize",
        "GET /_stub/moodle/authorize",
        f"GET /t/{SITE}/oauth/callback",
        f"POST /t/{SITE}/oauth/token",
    ]
    pos = -1
    for step in order:
        idx = next(i for i, line in enumerate(app.request_log) if i > pos and line.startswith(step))
        pos = idx


async def test_sdk_e2e_cimd(hub):
    app, base = hub
    app.request_log.clear()
    storage, browser = MemStorage(), BrowserSim(REDIRECT)
    who = await _call_whoami(base, _provider(base, storage, browser, cimd=CIMD_URL))
    assert who["client_id"] == CIMD_URL
    assert not any("/oauth/register" in line for line in app.request_log)


async def test_sdk_refresh_on_expiry(hub):
    app, base = hub
    storage, browser = MemStorage(), BrowserSim(REDIRECT)
    app.config.access_ttl = 1
    try:
        provider = _provider(base, storage, browser)
        await _call_whoami(base, provider)
        first_refresh = storage.tokens.refresh_token
        time.sleep(1.2)
        app.request_log.clear()
        await _call_whoami(base, provider)
    finally:
        app.config.access_ttl = 3600
    assert storage.tokens.refresh_token != first_refresh  # rotated
    assert any(line.startswith(f"POST /t/{SITE}/oauth/token") for line in app.request_log)
    assert not any("/oauth/authorize" in line for line in app.request_log)  # no re-login


# --- raw protocol negative tests ---------------------------------------------------------


def _pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


async def _register(c: httpx.AsyncClient, base: str, uris=(REDIRECT,)) -> httpx.Response:
    return await c.post(f"{base}/t/{SITE}/oauth/register", json={"redirect_uris": list(uris), "client_name": "raw"})


async def _authorize(c, base, client_id, challenge, resource=None, redirect=REDIRECT, method="S256"):
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect,
        "state": "st",
        "resource": resource or f"{base}/t/{SITE}/mcp",
    }
    if challenge is not None:
        params["code_challenge"] = challenge
        params["code_challenge_method"] = method
    url = f"{base}/t/{SITE}/oauth/authorize"
    resp = await c.get(url, params=params)
    for _ in range(3):
        loc = resp.headers.get("location", "")
        if resp.status_code != 302 or loc.startswith(redirect):
            break
        resp = await c.get(loc)
    return resp


def _q(resp):
    return {k: v[0] for k, v in parse_qs(urlsplit(resp.headers["location"]).query).items()}


async def _tokens(c, base):
    client_id = (await _register(c, base)).json()["client_id"]
    verifier, challenge = _pkce()
    code = _q(await _authorize(c, base, client_id, challenge))["code"]
    resp = await c.post(
        f"{base}/t/{SITE}/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "redirect_uri": REDIRECT,
            "code_verifier": verifier,
            "resource": f"{base}/t/{SITE}/mcp",
        },
    )
    assert resp.status_code == 200, resp.text
    return client_id, resp.json()


async def test_401_challenge_and_metadata(hub):
    _, base = hub
    async with httpx.AsyncClient() as c:
        r = await c.post(f"{base}/t/{SITE}/mcp", json={})
        assert r.status_code == 401
        www = r.headers["www-authenticate"]
        assert f'resource_metadata="{base}/.well-known/oauth-protected-resource/t/{SITE}/mcp"' in www
        prm = (await c.get(f"{base}/.well-known/oauth-protected-resource/t/{SITE}/mcp")).json()
        assert prm["resource"] == f"{base}/t/{SITE}/mcp"
        assert prm["authorization_servers"] == [f"{base}/t/{SITE}"]
        for path in (
            f"/.well-known/oauth-authorization-server/t/{SITE}",
            f"/.well-known/openid-configuration/t/{SITE}",
            f"/t/{SITE}/.well-known/openid-configuration",
        ):
            md = (await c.get(base + path)).json()
            assert md["issuer"] == f"{base}/t/{SITE}"
            assert md["code_challenge_methods_supported"] == ["S256"]
            assert md["token_endpoint_auth_methods_supported"] == ["none"]
            assert md["client_id_metadata_document_supported"] is True


async def test_refresh_rotation_and_reuse_detection(hub):
    _, base = hub
    async with httpx.AsyncClient() as c:
        client_id, t1 = await _tokens(c, base)
        url = f"{base}/t/{SITE}/oauth/token"
        r2 = await c.post(url, data={"grant_type": "refresh_token", "refresh_token": t1["refresh_token"], "client_id": client_id})
        assert r2.status_code == 200
        t2 = r2.json()
        assert t2["refresh_token"] != t1["refresh_token"]
        # replay old refresh -> invalid_grant and the whole family dies
        r3 = await c.post(url, data={"grant_type": "refresh_token", "refresh_token": t1["refresh_token"], "client_id": client_id})
        assert r3.status_code == 400 and r3.json()["error"] == "invalid_grant"
        r4 = await c.post(url, data={"grant_type": "refresh_token", "refresh_token": t2["refresh_token"], "client_id": client_id})
        assert r4.json()["error"] == "invalid_grant"
        mcp = await c.post(f"{base}/t/{SITE}/mcp", json={}, headers={"Authorization": f"Bearer {t2['access_token']}"})
        assert mcp.status_code == 401 and 'error="invalid_token"' in mcp.headers["www-authenticate"]


async def test_wrong_resource_rejected(hub):
    _, base = hub
    async with httpx.AsyncClient() as c:
        client_id = (await _register(c, base)).json()["client_id"]
        _, challenge = _pkce()
        resp = await _authorize(c, base, client_id, challenge, resource=f"{base}/t/other/mcp")
        q = _q(resp)
        assert q["error"] == "invalid_target" and q["iss"] == f"{base}/t/{SITE}"
        cid, t = await _tokens(c, base)
        r = await c.post(
            f"{base}/t/{SITE}/oauth/token",
            data={"grant_type": "refresh_token", "refresh_token": t["refresh_token"], "client_id": cid, "resource": "https://evil.example/mcp"},
        )
        assert r.json()["error"] == "invalid_target"


async def test_token_for_other_site_rejected(hub):
    _, base = hub
    async with httpx.AsyncClient() as c:
        _, t = await _tokens(c, base)  # aud = /t/demo/mcp
        r = await c.post(f"{base}/t/other/mcp", json={}, headers={"Authorization": f"Bearer {t['access_token']}"})
        assert r.status_code == 401
        ok = await c.post(
            f"{base}/t/{SITE}/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": f"Bearer {t['access_token']}", "Accept": "application/json, text/event-stream"},
        )
        assert ok.status_code == 200


async def test_missing_or_plain_pkce_rejected(hub):
    _, base = hub
    async with httpx.AsyncClient() as c:
        client_id = (await _register(c, base)).json()["client_id"]
        assert _q(await _authorize(c, base, client_id, None))["error"] == "invalid_request"
        assert _q(await _authorize(c, base, client_id, "x" * 43, method="plain"))["error"] == "invalid_request"
        # wrong verifier at token endpoint
        _, challenge = _pkce()
        code = _q(await _authorize(c, base, client_id, challenge))["code"]
        r = await c.post(
            f"{base}/t/{SITE}/oauth/token",
            data={"grant_type": "authorization_code", "code": code, "client_id": client_id, "redirect_uri": REDIRECT, "code_verifier": secrets.token_urlsafe(48)},
        )
        assert r.json()["error"] == "invalid_grant"


async def test_redirect_uri_allowlist(hub):
    _, base = hub
    async with httpx.AsyncClient() as c:
        bad = await _register(c, base, uris=("https://evil.example/cb",))
        assert bad.status_code == 400 and bad.json()["error"] == "invalid_redirect_uri"
        ok = await _register(c, base, uris=("https://claude.ai/api/mcp/auth_callback",))
        assert ok.status_code == 201
        # authorize with an unregistered redirect -> 400, never redirected
        _, challenge = _pkce()
        r = await c.get(
            f"{base}/t/{SITE}/oauth/authorize",
            params={"response_type": "code", "client_id": ok.json()["client_id"], "redirect_uri": "https://claude.com/api/mcp/auth_callback",
                    "code_challenge": challenge, "code_challenge_method": "S256", "resource": f"{base}/t/{SITE}/mcp"},
        )
        assert r.status_code == 400


async def test_untrusted_cimd_rejected(hub):
    _, base = hub
    async with httpx.AsyncClient() as c:
        _, challenge = _pkce()
        r = await _authorize(c, base, "https://attacker.example/meta.json", challenge)
        assert r.status_code == 400


async def test_revoke_refresh_kills_family(hub):
    _, base = hub
    async with httpx.AsyncClient() as c:
        cid, t = await _tokens(c, base)
        r = await c.post(f"{base}/t/{SITE}/oauth/revoke", data={"token": t["refresh_token"], "client_id": cid})
        assert r.status_code == 200
        mcp = await c.post(f"{base}/t/{SITE}/mcp", json={}, headers={"Authorization": f"Bearer {t['access_token']}"})
        assert mcp.status_code == 401
