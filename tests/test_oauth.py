"""Per-user OAuth (Easy Connect trial): hub AS/RS with a fake local_ubionai plugin + Moodle WS."""

import base64
import json
import os
import secrets
import socket
import sqlite3
import threading
import time
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken
from pydantic import AnyUrl
from starlette.testclient import TestClient

from moodle_mcp import oauth as oauth_mod
from moodle_mcp.crypto import load_kek
from moodle_mcp.oauth import USER_SERVICE_FUNCTIONS, sign_message, verify_message
from moodle_mcp.registry import Registry
from moodle_mcp.server import create_app

SITE = "demo"
MOODLE = "https://moodle.test"
SECRET = b"test-only-shared-secret-" + b"x" * 24
REDIRECT = "http://127.0.0.1:53682/callback"
TENANT_TOKEN = "tenant-service-token"
TENANT_BEARER = "tenant-static-bearer"
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}

USERS = {
    # userid: (profile, courses)
    3: ("teacher", [{"id": 2, "shortname": "P0A", "fullname": "Course A"}]),
    2: ("admin", []),
    5: ("mobile", []),
}


class FakeMoodle:
    """local_ubionai oauth endpoints + REST server.php, as an httpx transport."""

    def __init__(self) -> None:
        self.codes: dict[str, tuple[int, str]] = {}
        self.tokens: dict[str, tuple[int, int]] = {}  # wstoken -> (userid, tokenid)
        self.revoked: list[tuple[int, int]] = []
        self.calls: list[tuple[str, str, dict]] = []  # (who, wsfunction, params)
        self.next_tokenid = 100

    # browser leg (plugin oauth/authorize.php after login + consent)
    def approve(self, url: str, userid: int, deny: bool = False) -> str:
        req = parse_qs(urlsplit(url).query)["req"][0]
        claims = verify_message(SECRET, req, "authz_req")
        assert claims and claims["aud"] == MOODLE and claims["site"] == SITE
        if deny:
            return claims["callback"] + "?" + urlencode({"error": "access_denied", "state": claims["state"]})
        code = secrets.token_urlsafe(16)
        self.codes[code] = (userid, claims["state"])
        return claims["callback"] + "?" + urlencode({"code": code, "state": claims["state"]})

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.url.host == "moodle.test"
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        path = request.url.path
        if path == "/local/ubionai/oauth/exchange.php":
            claims = verify_message(SECRET, form.get("assertion", ""), "exchange")
            if not claims or claims["aud"] != MOODLE:
                return httpx.Response(400, json={"error": "invalid_grant"})
            entry = self.codes.pop(claims["code"], None)
            if entry is None or entry[1] != claims["state"]:
                return httpx.Response(400, json={"error": "invalid_grant"})
            userid = entry[0]
            token = f"user-token-{userid}-{secrets.token_hex(4)}"
            self.next_tokenid += 1
            self.tokens[token] = (userid, self.next_tokenid)
            return httpx.Response(
                200, json={"userid": userid, "tokenid": self.next_tokenid, "wstoken": token, "validuntil": int(time.time()) + 30 * 86400}
            )
        if path == "/local/ubionai/oauth/revoke.php":
            claims = verify_message(SECRET, form.get("assertion", ""), "revoke")
            if not claims:
                return httpx.Response(400, json={"error": "invalid_request"})
            self.revoked.append((claims["userid"], claims["tokenid"]))
            self.tokens = {k: v for k, v in self.tokens.items() if v[1] != claims["tokenid"]}
            return httpx.Response(200, json={"revoked": True})
        if path == "/webservice/rest/server.php":
            return self.ws(form)
        return httpx.Response(404)

    def ws(self, form: dict) -> httpx.Response:
        token, fn = form.pop("wstoken"), form.pop("wsfunction")
        form.pop("moodlewsrestformat", None)
        if token == TENANT_TOKEN:
            self.calls.append(("tenant", fn, form))
            if fn == "core_webservice_get_site_info":
                return httpx.Response(200, json={"userid": 9, "sitename": "Fake", "userissiteadmin": False})
            if fn == "core_course_get_courses":
                return httpx.Response(200, json=[{"id": 1, "format": "site"}, {"id": 2, "fullname": "Course A"}])
            return httpx.Response(200, json={})
        if token not in self.tokens:
            return httpx.Response(200, json={"exception": "moodle_exception", "errorcode": "invalidtoken", "message": "Invalid token"})
        userid = self.tokens[token][0]
        profile, courses = USERS[userid]
        self.calls.append((f"user{userid}", fn, form))
        if fn == "core_webservice_get_site_info":
            functions = sorted(USER_SERVICE_FUNCTIONS) + (["core_user_get_users", "core_message_send_instant_messages"] if profile == "mobile" else [])
            return httpx.Response(
                200,
                json={"userid": userid, "sitename": "Fake", "userissiteadmin": profile == "admin",
                      "functions": [{"name": f, "version": "1"} for f in functions]},
            )
        if fn == "core_enrol_get_users_courses":
            assert form["userid"] == str(userid)
            return httpx.Response(200, json=courses)
        if fn == "core_course_get_courses":
            return httpx.Response(200, json={"exception": "required_capability_exception", "errorcode": "nopermissions", "message": "no"})
        return httpx.Response(200, json={})


def _kek(path):
    path.write_bytes(base64.b64encode(os.urandom(32)) + b"\n")
    os.chmod(path, 0o600)


def _secret_dir(tmp_path, site=SITE, mode=0o600, value=SECRET):
    d = tmp_path / "tenants" / site
    d.mkdir(parents=True, exist_ok=True)
    f = d / "oauth.secret"
    f.write_bytes(value + b"\n")
    os.chmod(f, mode)
    return tmp_path / "tenants"


@pytest.fixture
def env(tmp_path, monkeypatch):
    for name in ("MOODLE_TOKEN", "MCP_BEARER_TOKEN", "UBIONAI_HUB_TENANT_SECRETS_DIR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("UBIONAI_HUB_ALLOW_HTTP", raising=False)
    kek_file = tmp_path / "kek"
    _kek(kek_file)
    db = tmp_path / "hub.sqlite3"
    registry = Registry.open(str(db), load_kek(kek_file))
    registry.add(SITE, MOODLE, TENANT_TOKEN.encode(), None, TENANT_BEARER)
    registry.add("legacy", "https://legacy.test", b"legacy-token", None, "legacy-bearer")
    secrets_dir = _secret_dir(tmp_path)
    return {"db": str(db), "kek": str(kek_file), "secrets": str(secrets_dir), "registry": registry, "tmp": tmp_path}


def _app(env, monkeypatch, public="https://hub.test", moodle=None):
    monkeypatch.setenv("UBIONAI_HUB_PUBLIC_URL", public)
    moodle = moodle or FakeMoodle()
    app = create_app(
        hub_db=env["db"], kek_file=env["kek"], tenant_secrets_dir=env["secrets"],
        moodle_transport=httpx.MockTransport(moodle.handler),
    )
    return app, moodle


# --- SDK end to end (real uvicorn on 127.0.0.1, official MCP OAuth client) -----------------


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def live(env, monkeypatch):
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    app, moodle = _app(env, monkeypatch, public=base)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield base, moodle
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


class Browser:
    """Follows hub authorize -> (fake) Moodle consent -> hub callback -> client redirect, with cookies."""

    def __init__(self, moodle: FakeMoodle, userid: int, deny: bool = False):
        self.moodle, self.userid, self.deny = moodle, userid, deny
        self.result: dict[str, str] = {}
        self.moodle_url = ""

    async def redirect(self, url: str) -> None:
        async with httpx.AsyncClient(follow_redirects=False) as c:
            for _ in range(5):
                if url.startswith(MOODLE):
                    self.moodle_url = url
                    url = self.moodle.approve(url, self.userid, self.deny)
                    continue
                if url.startswith(REDIRECT):
                    self.result = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
                    return
                resp = await c.get(url)
                assert resp.status_code == 302, resp.text
                url = resp.headers["location"]
        raise AssertionError("never reached the client redirect")

    async def callback(self):
        if "code" not in self.result:
            raise RuntimeError(f"authorization failed: {self.result}")
        return self.result["code"], self.result.get("state")


def _provider(base, storage, browser):
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
    )


async def _session_calls(base, auth, calls):
    out = []
    async with httpx.AsyncClient(auth=auth, follow_redirects=False) as http, streamable_http_client(
        f"{base}/t/{SITE}/mcp", http_client=http
    ) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            for name, args in calls:
                result = await session.call_tool(name, args)
                assert not result.isError, result
                out.append(json.loads(result.content[0].text))
    return out


async def test_sdk_teacher_end_to_end(live):
    base, moodle = live
    storage, browser = MemStorage(), Browser(moodle, userid=3)
    courses, preview, info = await _session_calls(
        base,
        _provider(base, storage, browser),
        [
            ("list_courses", {}),
            ("create_assignment", {"course_id": 2, "section": 0, "name": "Essay 1"}),
            ("site_info", {}),
        ],
    )
    assert [c["id"] for c in courses["courses"]] == [2]
    assert preview["preview"] is True and preview["module"]["name"] == "Essay 1"
    assert info["userid"] == 3
    # Everything ran with the teacher's own token; list_courses used the enrolment function.
    fns = [(who, fn) for who, fn, _ in moodle.calls]
    assert ("user3", "core_enrol_get_users_courses") in fns
    assert not any(who == "tenant" for who, _ in fns)
    assert not any(fn == "core_course_get_courses" for _, fn in fns)
    assert browser.result["iss"] == f"{base}/t/{SITE}"
    req = parse_qs(urlsplit(browser.moodle_url).query)["req"][0]
    claims = verify_message(SECRET, req, "authz_req")
    assert claims["callback"] == f"{base}/t/{SITE}/oauth/callback"
    assert claims["client_name"] == "pytest-sdk-client" and claims["redirect_host"] == "127.0.0.1"


async def test_sdk_refresh_on_expiry(live, monkeypatch):
    base, moodle = live
    storage, browser = MemStorage(), Browser(moodle, userid=3)
    provider = _provider(base, storage, browser)
    await _session_calls(base, provider, [("site_info", {})])
    first = storage.tokens.refresh_token
    storage.tokens.expires_in = 0
    provider.context.token_expiry_time = time.time() - 1
    browser.result = {}
    await _session_calls(base, provider, [("site_info", {})])
    assert storage.tokens.refresh_token != first  # rotated, no new login (browser.result untouched)
    assert browser.result == {}


@pytest.mark.parametrize("userid,reason", [(2, "site administrator"), (5, "ubionai_user service")])
async def test_sdk_admin_and_foreign_service_tokens_refused(live, userid, reason):
    base, moodle = live
    storage, browser = MemStorage(), Browser(moodle, userid=userid)
    with pytest.raises(Exception):
        await _session_calls(base, _provider(base, storage, browser), [("site_info", {})])
    assert browser.result["error"] == "access_denied"
    assert reason in browser.result["error_description"]
    assert moodle.revoked and moodle.revoked[0][0] == userid  # the minted token was revoked again
    assert storage.tokens is None


async def test_sdk_user_denies_in_moodle(live):
    base, moodle = live
    storage, browser = MemStorage(), Browser(moodle, userid=3, deny=True)
    with pytest.raises(Exception):
        await _session_calls(base, _provider(base, storage, browser), [("site_info", {})])
    assert browser.result["error"] == "access_denied"


# --- protocol tests (TestClient) ----------------------------------------------------------


def _pkce():
    import hashlib

    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


@pytest.fixture
def hub(env, monkeypatch):
    app, moodle = _app(env, monkeypatch)
    with TestClient(app, base_url="https://hub.test", follow_redirects=False) as client:
        yield client, moodle, env


def _register(client, uris=(REDIRECT,)):
    return client.post(f"/t/{SITE}/oauth/register", json={"redirect_uris": list(uris), "client_name": "raw"})


def _authorize(client, client_id, challenge, resource=None, redirect=REDIRECT, method="S256"):
    params = {
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect, "state": "client-state",
        "resource": resource or f"https://hub.test/t/{SITE}/mcp",
    }
    if challenge is not None:
        params.update(code_challenge=challenge, code_challenge_method=method)
    return client.get(f"/t/{SITE}/oauth/authorize", params=params)


def _q(resp):
    return {k: v[0] for k, v in parse_qs(urlsplit(resp.headers["location"]).query).items()}


def _login(client, moodle, userid=3, client_id=None):
    client_id = client_id or _register(client).json()["client_id"]
    verifier, challenge = _pkce()
    resp = _authorize(client, client_id, challenge)
    assert resp.status_code == 302 and resp.headers["location"].startswith(f"{MOODLE}/local/ubionai/oauth/authorize.php?req=")
    back = client.get(moodle.approve(resp.headers["location"], userid))
    return client_id, verifier, back


def _tokens(client, moodle, userid=3):
    client_id, verifier, back = _login(client, moodle, userid)
    q = _q(back)
    assert q["state"] == "client-state" and q["iss"] == f"https://hub.test/t/{SITE}"
    resp = client.post(f"/t/{SITE}/oauth/token", data={
        "grant_type": "authorization_code", "code": q["code"], "client_id": client_id,
        "redirect_uri": REDIRECT, "code_verifier": verifier, "resource": f"https://hub.test/t/{SITE}/mcp",
    })
    assert resp.status_code == 200, resp.text
    return client_id, resp.json()


def _mcp(client, bearer, site=SITE, tool="site_info", args=None):
    headers = dict(MCP_HEADERS)
    if bearer is not None:
        headers["Authorization"] = f"Bearer {bearer}"
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args or {}}}
    return client.post(f"/t/{site}/mcp", json=body, headers=headers)


def _tool_json(resp):
    assert resp.status_code == 200, resp.text
    return json.loads(resp.json()["result"]["content"][0]["text"])


def test_metadata_uses_public_https_url_behind_proxy(env, monkeypatch):
    app, _ = _app(env, monkeypatch, public="https://hub.example/")
    # The proxy talks plain http to the hub; every URL still says https://hub.example.
    with TestClient(app, base_url="http://127.0.0.1:8090") as client:
        unauth = client.post(f"/t/{SITE}/mcp", json={})
        assert unauth.status_code == 401
        assert unauth.headers["www-authenticate"] == (
            f'Bearer resource_metadata="https://hub.example/.well-known/oauth-protected-resource/t/{SITE}/mcp",'
            ' scope="moodle:read moodle:write"'
        )
        prm = client.get(f"/.well-known/oauth-protected-resource/t/{SITE}/mcp").json()
        assert prm == {
            "resource": f"https://hub.example/t/{SITE}/mcp",
            "authorization_servers": [f"https://hub.example/t/{SITE}"],
            "scopes_supported": ["moodle:read", "moodle:write"],
            "bearer_methods_supported": ["header"],
        }
        for path in (f"/.well-known/oauth-authorization-server/t/{SITE}", f"/.well-known/openid-configuration/t/{SITE}",
                     f"/t/{SITE}/.well-known/openid-configuration"):
            md = client.get(path).json()
            assert md["issuer"] == f"https://hub.example/t/{SITE}"
            assert all(md[k].startswith("https://hub.example/t/demo/oauth/") for k in
                       ("authorization_endpoint", "token_endpoint", "registration_endpoint", "revocation_endpoint"))
            assert md["code_challenge_methods_supported"] == ["S256"]


def test_public_url_must_be_https(env, monkeypatch):
    for bad in ("http://hub.example", ""):
        monkeypatch.setenv("UBIONAI_HUB_PUBLIC_URL", bad)
        with pytest.raises(RuntimeError):
            create_app(hub_db=env["db"], kek_file=env["kek"], tenant_secrets_dir=env["secrets"])


def test_static_bearer_still_works_on_oauth_tenant(hub):
    client, moodle, _ = hub
    assert _tool_json(_mcp(client, TENANT_BEARER))["userid"] == 9
    courses = _tool_json(_mcp(client, TENANT_BEARER, tool="list_courses"))
    assert [c["id"] for c in courses["courses"]] == [1, 2]
    assert [(who, fn) for who, fn, _ in moodle.calls] == [
        ("tenant", "core_webservice_get_site_info"), ("tenant", "core_course_get_courses")]


def test_tenant_without_secret_is_unchanged(hub):
    client, _, _ = hub
    assert client.get("/.well-known/oauth-protected-resource/t/legacy/mcp").status_code == 404
    assert client.get("/.well-known/oauth-authorization-server/t/legacy").status_code == 404
    assert client.post("/t/legacy/oauth/register", json={"redirect_uris": [REDIRECT]}).status_code == 404
    unauth = client.post("/t/legacy/mcp", json={}, headers=MCP_HEADERS)
    assert unauth.status_code == 401 and unauth.headers["www-authenticate"] == "Bearer"
    assert _mcp(client, "wrong").status_code == 401  # OAuth tenant: invalid_token challenge
    wrong = client.post("/t/legacy/mcp", json={}, headers={**MCP_HEADERS, "Authorization": "Bearer wrong"})
    assert wrong.status_code == 403 and wrong.json() == {"error": "forbidden"}


def test_oauth_disabled_without_secrets_dir(env, monkeypatch):
    monkeypatch.setenv("UBIONAI_HUB_PUBLIC_URL", "https://hub.test")
    app = create_app(hub_db=env["db"], kek_file=env["kek"])
    with TestClient(app, base_url="https://hub.test") as client:
        assert client.get(f"/.well-known/oauth-protected-resource/t/{SITE}/mcp").status_code == 404
        assert client.post(f"/t/{SITE}/mcp", json={}).headers["www-authenticate"] == "Bearer"


def test_secret_file_with_loose_mode_disables_oauth(env, monkeypatch):
    os.chmod(os.path.join(env["secrets"], SITE, "oauth.secret"), 0o644)
    app, _ = _app(env, monkeypatch)
    with TestClient(app, base_url="https://hub.test") as client:
        assert client.get(f"/.well-known/oauth-protected-resource/t/{SITE}/mcp").status_code == 404


def test_teacher_token_flow_and_encrypted_storage(hub):
    client, moodle, env = hub
    _, tokens = _tokens(client, moodle)
    courses = _tool_json(_mcp(client, tokens["access_token"], tool="list_courses", args={"ids": [2, 7]}))
    assert [c["id"] for c in courses["courses"]] == [2]
    assert moodle.calls[-1][:2] == ("user3", "core_enrol_get_users_courses")
    wstoken = next(iter(moodle.tokens))
    with sqlite3.connect(env["db"]) as conn:
        dump = "\n".join(conn.iterdump())
        rows = conn.execute("SELECT moodle_userid, moodle_tokenid, revoked_at FROM oauth_grants").fetchall()
    assert wstoken not in dump and tokens["access_token"] not in dump and tokens["refresh_token"] not in dump
    assert rows == [(3, 101, None)]


def test_grants_survive_restart(hub, monkeypatch):
    client, moodle, env = hub
    _, tokens = _tokens(client, moodle)
    app2, _ = _app(env, monkeypatch, moodle=moodle)
    with TestClient(app2, base_url="https://hub.test") as client2:
        assert _tool_json(_mcp(client2, tokens["access_token"]))["userid"] == 3


def test_callback_requires_browser_binding_cookie(hub):
    client, moodle, _ = hub
    client_id = _register(client).json()["client_id"]
    _, challenge = _pkce()
    resp = _authorize(client, client_id, challenge)
    back_url = moodle.approve(resp.headers["location"], 3)
    client.cookies.clear()
    back = client.get(back_url)
    assert back.status_code == 400
    assert moodle.calls == [] and moodle.codes  # never exchanged


def test_signed_request_and_backchannel_fields(hub):
    client, moodle, _ = hub
    client_id = _register(client).json()["client_id"]
    _, challenge = _pkce()
    resp = _authorize(client, client_id, challenge)
    req = parse_qs(urlsplit(resp.headers["location"]).query)["req"][0]
    assert verify_message(b"y" * 48, req, "authz_req") is None
    assert verify_message(SECRET, req, "exchange") is None
    claims = verify_message(SECRET, req, "authz_req")
    assert claims["aud"] == MOODLE and claims["site"] == SITE and claims["iss"] == f"https://hub.test/t/{SITE}"
    assert claims["exp"] <= time.time() + 600
    cookie = resp.headers["set-cookie"].lower()
    assert "httponly" in cookie and "secure" in cookie and "samesite=lax" in cookie and f"path=/t/{SITE}/oauth/" in cookie


def test_refresh_rotation_reuse_revokes_moodle_token(hub):
    client, moodle, _ = hub
    client_id, t1 = _tokens(client, moodle)
    url = f"/t/{SITE}/oauth/token"
    t2 = client.post(url, data={"grant_type": "refresh_token", "refresh_token": t1["refresh_token"], "client_id": client_id}).json()
    assert t2["refresh_token"] != t1["refresh_token"]
    assert _mcp(client, t2["access_token"]).status_code == 200
    replay = client.post(url, data={"grant_type": "refresh_token", "refresh_token": t1["refresh_token"], "client_id": client_id})
    assert replay.status_code == 400 and replay.json()["error"] == "invalid_grant"
    assert moodle.revoked == [(3, 101)]
    again = client.post(url, data={"grant_type": "refresh_token", "refresh_token": t2["refresh_token"], "client_id": client_id})
    assert again.json()["error"] == "invalid_grant"
    dead = _mcp(client, t2["access_token"])
    assert dead.status_code == 401 and 'error="invalid_token"' in dead.headers["www-authenticate"]


def test_revoke_endpoint_revokes_moodle_token(hub):
    client, moodle, _ = hub
    client_id, t = _tokens(client, moodle)
    assert client.post(f"/t/{SITE}/oauth/revoke", data={"token": t["refresh_token"], "client_id": client_id}).status_code == 200
    assert moodle.revoked == [(3, 101)]
    assert _mcp(client, t["access_token"]).status_code == 401


def test_code_single_use_and_pkce(hub):
    client, moodle, _ = hub
    client_id, verifier, back = _login(client, moodle)
    code = _q(back)["code"]
    data = {"grant_type": "authorization_code", "code": code, "client_id": client_id, "redirect_uri": REDIRECT,
            "code_verifier": secrets.token_urlsafe(48)}
    assert client.post(f"/t/{SITE}/oauth/token", data=data).json()["error"] == "invalid_grant"
    data["code_verifier"] = verifier
    assert client.post(f"/t/{SITE}/oauth/token", data=data).json()["error"] == "invalid_grant"  # burnt
    assert _authorize(client, client_id, None).headers["location"].startswith(REDIRECT)
    assert _q(_authorize(client, client_id, None))["error"] == "invalid_request"
    assert _q(_authorize(client, client_id, "x" * 43, method="plain"))["error"] == "invalid_request"


def test_resource_and_cross_site(hub, env):
    client, moodle, env = hub
    env["registry"].add("other", "https://other.test", b"t", None, "other-bearer")
    _secret_dir(env["tmp"], site="other")
    client_id = _register(client).json()["client_id"]
    _, challenge = _pkce()
    q = _q(_authorize(client, client_id, challenge, resource="https://hub.test/t/other/mcp"))
    assert q["error"] == "invalid_target" and q["iss"] == f"https://hub.test/t/{SITE}"
    _, t = _tokens(client, moodle)
    assert _mcp(client, t["access_token"], site="other").status_code == 401
    assert _mcp(client, t["access_token"]).status_code == 200


def test_redirect_uri_allowlist(hub):
    client, _, _ = hub
    bad = _register(client, uris=("https://evil.example/cb",))
    assert bad.status_code == 400 and bad.json()["error"] == "invalid_redirect_uri"
    ok = _register(client, uris=("https://claude.ai/api/mcp/auth_callback", "https://claude.com/api/mcp/auth_callback"))
    assert ok.status_code == 201
    other = _register(client, uris=("http://localhost:33418/callback",)).json()["client_id"]
    _, challenge = _pkce()
    # a registered loopback redirect may change port only
    assert _authorize(client, other, challenge, redirect="http://localhost:9999/callback").status_code == 302
    assert _authorize(client, other, challenge, redirect="http://localhost:9999/other").status_code == 400
    assert _authorize(client, ok.json()["client_id"], challenge, redirect="https://evil.example/cb").status_code == 400


def test_cimd_trusted_only(hub, monkeypatch):
    client, moodle, _ = hub
    assert _authorize(client, "https://attacker.example/meta.json", _pkce()[1]).status_code == 400
    trusted = oauth_mod.TRUSTED_CIMD[0]
    app_oauth = client.app.oauth

    async def fetch(url):
        assert url == trusted
        return {"client_id": trusted, "client_name": "Claude Code", "redirect_uris": ["http://localhost/callback"]}

    monkeypatch.setattr(app_oauth, "cimd_fetcher", fetch)
    resp = _authorize(client, trusted, _pkce()[1], redirect="http://localhost:4567/callback")
    assert resp.status_code == 302 and resp.headers["location"].startswith(MOODLE)


def test_signing_roundtrip_rejects_tampering():
    token = sign_message(SECRET, {"typ": "revoke", "exp": int(time.time()) + 60, "userid": 3})
    assert verify_message(SECRET, token, "revoke")["userid"] == 3
    body, mac = token.split(".")
    assert verify_message(SECRET, body + "." + mac[:-2] + "AA", "revoke") is None
    assert verify_message(SECRET, sign_message(SECRET, {"typ": "revoke", "exp": 1}), "revoke") is None
