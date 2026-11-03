"""/m/<host_key> routing, the unregistered-site page and OAuth for self-registered tenants
(contract §5, §6, §4.3). TestClient + fake DNS + MockTransport, no network."""

import base64
import hashlib
import json
import os
import secrets
import sqlite3
from urllib.parse import parse_qs, quote, urlsplit

import httpx
import pytest
from starlette.testclient import TestClient

from moodle_mcp.crypto import load_kek
from moodle_mcp.registry import Registry
from moodle_mcp.server import create_app

from .selfreg_helpers import HOST, HOST_KEY, HUB, FakeDNS, FakeSite

REDIRECT = "https://claude.ai/api/mcp/auth_callback"
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


@pytest.fixture
def env(tmp_path, monkeypatch):
    for name in ("MOODLE_TOKEN", "MCP_BEARER_TOKEN", "UBIONAI_HUB_TENANT_SECRETS_DIR", "UBIONAI_HUB_ALLOW_HTTP"):
        monkeypatch.delenv(name, raising=False)
    kek = tmp_path / "kek"
    kek.write_bytes(base64.b64encode(os.urandom(32)) + b"\n")
    os.chmod(kek, 0o600)
    return {"db": str(tmp_path / "hub.sqlite3"), "kek": str(kek), "mp": monkeypatch}


def _client(env, host_routes="1", legacy="1", **extra):
    env["mp"].setenv("UBIONAI_HUB_PUBLIC_URL", HUB)
    env["mp"].setenv("UBIONAI_HUB_SELF_REGISTRATION", "1")
    env["mp"].setenv("UBIONAI_HUB_HOST_ROUTES", host_routes)
    env["mp"].setenv("UBIONAI_HUB_LEGACY_TENANT_ROUTES", legacy)
    for key, value in extra.items():
        env["mp"].setenv(key, value)
    site, dns = FakeSite(), FakeDNS()
    app = create_app(hub_db=env["db"], kek_file=env["kek"], tenant_secrets_dir="",
                     moodle_transport=httpx.MockTransport(site.handler), site_resolver=dns)
    return TestClient(app, base_url=HUB, follow_redirects=False), site, dns, app


def _registry(env):
    return Registry.open(env["db"], load_kek(env["kek"]))


def _register_and_confirm(client, site):
    resp = client.post("/api/v1/sites/register", json=site.new_registration())
    assert resp.status_code == 201, resp.text
    data = resp.json()
    site.adopt(data)
    ok = client.post(f"/api/v1/sites/{data['site_key']}/confirm", json={"secret_version": data["secret_version"]},
                     headers={"Authorization": f"Bearer {data['site_secret']}"})
    assert ok.status_code == 200
    return data


def _pkce():
    verifier = secrets.token_urlsafe(48)
    return verifier, base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def _authorize(client, base, client_id, challenge, resource):
    return client.get(f"{base}/oauth/authorize", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT, "state": "st",
        "code_challenge": challenge, "code_challenge_method": "S256", "resource": resource,
    })


def _login(client, site, base, client_id, userid=3):
    verifier, challenge = _pkce()
    resp = _authorize(client, base, client_id, challenge, f"{HUB}{base}/mcp")
    assert resp.status_code == 302, resp.text
    assert resp.headers["location"].startswith(f"https://{HOST}/moodle/local/ubionai/oauth/authorize.php?req=")
    assert f"Path={base}/oauth/" in resp.headers["set-cookie"]
    back = client.get(site.approve(resp.headers["location"], userid))
    assert back.status_code == 302, back.text
    q = {k: v[0] for k, v in parse_qs(urlsplit(back.headers["location"]).query).items()}
    assert q["iss"] == f"{HUB}{base}" and q["state"] == "st"
    tok = client.post(f"{base}/oauth/token", data={
        "grant_type": "authorization_code", "code": q["code"], "client_id": client_id, "redirect_uri": REDIRECT,
        "code_verifier": verifier, "resource": f"{HUB}{base}/mcp",
    })
    assert tok.status_code == 200, tok.text
    return tok.json()


def _mcp(client, path, bearer, tool="list_courses"):
    headers = dict(MCP_HEADERS, Authorization=f"Bearer {bearer}")
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": {}}}
    return client.post(path, json=body, headers=headers)


# --- flags ----------------------------------------------------------------------------------


def test_host_routes_flag_off_is_404_everywhere(env):
    client, site, _, _ = _client(env, host_routes="0")
    with client:
        for path in (f"/m/{HOST_KEY}/mcp", f"/m/{HOST_KEY}/oauth/authorize", f"/m/{HOST_KEY}/oauth/register",
                     f"/.well-known/oauth-protected-resource/m/{HOST_KEY}/mcp",
                     f"/.well-known/oauth-authorization-server/m/{HOST_KEY}"):
            assert client.get(path).status_code == 404, path
        data = client.post("/api/v1/sites/register", json=site.new_registration()).json()
        assert data["mcp_url"] is None and data["oauth"]["issuers"] == [f"{HUB}/t/{data['site_key']}"]


# --- unregistered hosts: static OAuth surface + page ----------------------------------------


def test_unregistered_host_static_surface(env):
    client, site, dns, app = _client(env)
    with client:
        unauth = client.post(f"/m/{HOST_KEY}/mcp", json={})
        assert unauth.status_code == 401
        assert unauth.headers["www-authenticate"].startswith(
            f'Bearer resource_metadata="{HUB}/.well-known/oauth-protected-resource/m/{HOST_KEY}/mcp"')
        bad = client.post(f"/m/{HOST_KEY}/mcp", json={}, headers={"Authorization": "Bearer nope"})
        assert bad.status_code == 401 and 'error="invalid_token"' in bad.headers["www-authenticate"]
        prm = client.get(f"/.well-known/oauth-protected-resource/m/{HOST_KEY}/mcp").json()
        assert prm["resource"] == f"{HUB}/m/{HOST_KEY}/mcp" and prm["authorization_servers"] == [f"{HUB}/m/{HOST_KEY}"]
        for path in (f"/.well-known/oauth-authorization-server/m/{HOST_KEY}",
                     f"/.well-known/openid-configuration/m/{HOST_KEY}",
                     f"/m/{HOST_KEY}/.well-known/openid-configuration"):
            meta = client.get(path).json()
            assert meta["issuer"] == f"{HUB}/m/{HOST_KEY}"
            assert meta["registration_endpoint"] == f"{HUB}/m/{HOST_KEY}/oauth/register"
        dcr = client.post(f"/m/{HOST_KEY}/oauth/register", json={"redirect_uris": [REDIRECT], "client_name": "Claude"})
        assert dcr.status_code == 201 and dcr.json()["client_id"].startswith("dcr_s1.")
        assert client.post(f"/m/{HOST_KEY}/oauth/register", json={"redirect_uris": ["https://evil.example/cb"]}).status_code == 400
        assert client.post(f"/m/{HOST_KEY}/oauth/token", data={"grant_type": "x"}).status_code == 404
    with sqlite3.connect(env["db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM oauth_clients").fetchone()[0] == 0  # nothing stored
        assert conn.execute("SELECT COUNT(*) FROM tenants").fetchone()[0] == 0
    assert dns.calls == [] and site.seen == []  # no outbound lookups for arbitrary hosts


def test_unregistered_page_is_escaped_static_and_locked_down(env):
    client, *_ = _client(env)
    with client:
        resp = client.get(f"/m/{HOST_KEY}/oauth/authorize", params={
            "client_id": "<b>x</b>", "state": "<script>alert(1)</script>", "redirect_uri": REDIRECT,
            "response_type": "code",
        })
        assert resp.status_code == 404
        body = resp.text
        assert "아직 UBION AI에 연결되지 않았습니다" in body and HOST_KEY in body
        assert "<script>" not in body and "<b>x</b>" not in body
        assert "https://lms.school.example/moodle" in body  # request text for the administrator
        assert "학교 내부망" in body
        csp = resp.headers["content-security-policy"]
        assert csp.startswith("default-src 'none'; style-src 'sha256-") and "frame-ancestors 'none'" in csp
        assert "form-action 'none'" in csp
        assert resp.headers["cache-control"] == "no-store"
        assert resp.headers["x-robots-tag"] == "noindex" and resp.headers["referrer-policy"] == "no-referrer"
        # Back button: only to an allowlisted redirect, carrying access_denied + state + iss (URL-encoded).
        assert "error=access_denied" in body and "site_not_registered" in body
        assert quote("<script>alert(1)</script>", safe="") in body
        no_back = client.get(f"/m/{HOST_KEY}/oauth/authorize", params={"redirect_uri": "https://evil.example/cb"})
        assert "evil.example" not in no_back.text and "error=access_denied" not in no_back.text
        en = client.get(f"/m/{HOST_KEY}/oauth/authorize", headers={"Accept-Language": "en-US,en;q=0.9"})
        assert "not connected to UBION AI yet" in en.text and 'lang="en"' in en.text


def test_page_rate_limit(env):
    client, *_ = _client(env)
    with client:
        codes = [client.get(f"/m/{HOST_KEY}/oauth/authorize").status_code for _ in range(61)]
    assert codes[:60] == [404] * 60 and codes[60] == 429


def test_pending_and_disabled_pages(env):
    client, site, _, _ = _client(env)
    with client:
        key = client.post("/api/v1/sites/register", json=site.new_registration()).json()["site_key"]
        # Registered but not confirmed: no signer yet -> page, not an OAuth redirect
        assert client.get(f"/m/{HOST_KEY}/oauth/authorize").status_code == 403
        reg = _registry(env)
        reg.set_status(key, "pending")
        resp = client.get(f"/m/{HOST_KEY}/oauth/authorize")
        assert resp.status_code == 403 and "연결 검토 중입니다" in resp.text
        reg.set_status(key, "disabled")
        resp = client.get(f"/m/{HOST_KEY}/oauth/authorize")
        assert resp.status_code == 403 and "사용할 수 없습니다" in resp.text


@pytest.mark.parametrize(
    "path, canonical",
    [
        ("/m/LMS.school.example/moodle/mcp", f"/m/{HOST_KEY}/mcp"),
        ("/m/lms.school.example:443/moodle/mcp", f"/m/{HOST_KEY}/mcp"),
        ("/m/lms.school.example/moodle//mcp", f"/m/{HOST_KEY}/mcp"),
        ("/m/lms.school.example./moodle/mcp", f"/m/{HOST_KEY}/mcp"),
        ("/m/%ED%95%9C%EA%B5%AD.kr/mcp", "/m/xn--3e0b707e.kr/mcp"),
    ],
)
def test_non_canonical_urls(env, path, canonical):
    client, *_ = _client(env)
    with client:
        resp = client.post(path, json={})
    assert resp.status_code == 400
    assert resp.json() == {"error": "non_canonical_url", "canonical_url": HUB + canonical}


def test_non_canonical_authorize_page_and_unsupported_hosts(env):
    client, *_ = _client(env)
    with client:
        page = client.get("/m/LMS.school.example/moodle/oauth/authorize")
        assert page.status_code == 400 and f"{HUB}/m/{HOST_KEY}/oauth/authorize" in page.text
        assert "content-security-policy" in page.headers
        for host in ("localhost", "10.0.0.1", "moodle.local", "intranet", "a.example:8443", "a.example/%2e%2e"):
            resp = client.post(f"/m/{host}/mcp", json={})
            assert resp.status_code == 404 and resp.json()["error"] == "unsupported_host", host


# --- registered self-registered tenant: OAuth on /m/ and /t/ ---------------------------------


def test_self_registered_oauth_flow_and_audience_separation(env):
    client, site, dns, app = _client(env)
    with client:
        early = client.post(f"/m/{HOST_KEY}/oauth/register", json={"redirect_uris": [REDIRECT]}).json()["client_id"]
        data = _register_and_confirm(client, site)
        key = data["site_key"]
        m_base, t_base = f"/m/{HOST_KEY}", f"/t/{key}"

        # The stateless client_id issued before registration still works afterwards.
        m_tokens = _login(client, site, m_base, early)
        resp = _mcp(client, f"{m_base}/mcp", m_tokens["access_token"])
        assert resp.status_code == 200, resp.text
        assert "Existing course" in resp.text
        assert "core_enrol_get_users_courses" in site.calls

        # Every hub -> Moodle connection went to the vetted IP with SNI/Host = name (asserted in FakeSite).
        assert {p for _, _, p in site.seen} >= {
            "/moodle/local/ubionai/register_callback.php", "/moodle/local/ubionai/oauth/exchange.php",
            "/moodle/webservice/rest/server.php"}

        # Audience: an /m/ token is refused on /t/ and vice versa.
        assert _mcp(client, f"{t_base}/mcp", m_tokens["access_token"]).status_code == 401
        t_client = client.post(f"{t_base}/oauth/register", json={"redirect_uris": [REDIRECT]}).json()["client_id"]
        t_tokens = _login(client, site, t_base, t_client)
        assert _mcp(client, f"{t_base}/mcp", t_tokens["access_token"]).status_code == 200
        assert _mcp(client, f"{m_base}/mcp", t_tokens["access_token"]).status_code == 401
        refresh = client.post(f"{t_base}/oauth/token", data={
            "grant_type": "refresh_token", "refresh_token": m_tokens["refresh_token"], "client_id": early})
        assert refresh.status_code in (400, 401)

        # No static bearer path and no chat proxy for self-registered tenants.
        assert client.post(f"{t_base}/v1/chat/completions", json={"messages": []},
                           headers={"Authorization": "Bearer x"}).status_code == 403


def test_forged_stateless_client_ids_are_refused(env):
    client, site, _, app = _client(env)
    with client:
        good = client.post(f"/m/{HOST_KEY}/oauth/register", json={"redirect_uris": [REDIRECT]}).json()["client_id"]
        _register_and_confirm(client, site)
        prefix, body, mac = good.split(".")
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        payload["r"] = ["http://127.0.0.1:9/cb"]
        forged_body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        other_host = app.oauth.stateless_client_id("other.example", [REDIRECT], None)
        _, challenge = _pkce()
        for cid in (f"{prefix}.{forged_body}.{mac}", good[:-2] + ("AA" if not good.endswith("AA") else "BB"), other_host):
            resp = _authorize(client, f"/m/{HOST_KEY}", cid, challenge, f"{HUB}/m/{HOST_KEY}/mcp")
            assert resp.status_code == 400 and "invalid client_id" in resp.text
            tok = client.post(f"/m/{HOST_KEY}/oauth/token", data={"grant_type": "authorization_code", "client_id": cid})
            assert tok.status_code == 401


def test_dns_rebinding_after_registration_blocks_moodle_traffic(env):
    client, site, dns, app = _client(env)
    with client:
        _register_and_confirm(client, site)
        cid = client.post(f"/m/{HOST_KEY}/oauth/register", json={"redirect_uris": [REDIRECT]}).json()["client_id"]
        tokens = _login(client, site, f"/m/{HOST_KEY}", cid)
        seen_before = len(site.seen)
        dns.records[HOST] = ["169.254.169.254"]  # the site's DNS now points at cloud metadata
        resp = _mcp(client, f"/m/{HOST_KEY}/mcp", tokens["access_token"])
        assert resp.status_code == 200 and "request failed" in resp.text  # tool error, no request sent
        assert len(site.seen) == seen_before
        # The back channel (exchange) is refused too: login now fails before reaching Moodle.
        verifier, challenge = _pkce()
        start = _authorize(client, f"/m/{HOST_KEY}", cid, challenge, f"{HUB}/m/{HOST_KEY}/mcp")
        back = client.get(site.approve(start.headers["location"], 3))
        assert "error=access_denied" in back.headers["location"]
        assert len(site.seen) == seen_before


def test_legacy_routes_flag_off_hides_self_registered_on_t(env):
    client, site, _, _ = _client(env, legacy="0")
    with client:
        data = _register_and_confirm(client, site)
        key = data["site_key"]
        assert client.post(f"/t/{key}/mcp", json={}).status_code == 404
        assert client.get(f"/.well-known/oauth-protected-resource/t/{key}/mcp").status_code == 404
        assert client.get(f"/.well-known/oauth-protected-resource/m/{HOST_KEY}/mcp").json()["resource"].endswith("/mcp")


def test_operator_tenant_with_host_key_on_m_requires_oauth(env):
    client, site, _, _ = _client(env)
    reg = _registry(env)
    reg.add("op-site", "https://op.example", b"op-token", None, "op-bearer")
    assert reg.get("op-site").host_key == "op.example"
    with client:
        # Static bearers are not accepted on /m/; no legacy_file secret -> static surface.
        resp = client.post("/m/op.example/mcp", json={}, headers={"Authorization": "Bearer op-bearer"})
        assert resp.status_code == 401
        assert client.get("/m/op.example/oauth/authorize").status_code == 403
