"""Scott's decisions of 2026-11-03 (registration contract §8.3), hub side.

1. New sites are active at once (tier=limited); operator switches: auto-activate flag, per-site disable.
2. Provisional limits from configuration: teachers per site (new grant refused) and requests per
   day (429 daily_limit_exceeded).
3. Re-registration keeps teacher grants only when the site identity (site_identifier_hash) matches.
4. A host owned by an operator tenant is refused with 409; nothing is linked automatically.
5. Secrets (site_secret, mac_key, tokens) never reach the logs.

TestClient + fake DNS + MockTransport, no network. All values are fake.
"""

import base64
import logging
import os
from urllib.parse import parse_qs, urlsplit

import pytest

from moodle_mcp import admin
from moodle_mcp.limits import DailyUsage, TierLimits, seconds_to_utc_midnight
from moodle_mcp.server import create_app

from .selfreg_helpers import HOST_KEY, HUB, SITE_URL, FakeSite
from .test_host_routes import REDIRECT, _authorize, _client, _login, _mcp, _pkce, _register_and_confirm, _registry


@pytest.fixture
def env(tmp_path, monkeypatch):
    for name in ("MOODLE_TOKEN", "MCP_BEARER_TOKEN", "UBIONAI_HUB_TENANT_SECRETS_DIR", "UBIONAI_HUB_ALLOW_HTTP",
                 "UBIONAI_HUB_LIMITED_MAX_TEACHERS", "UBIONAI_HUB_LIMITED_DAILY_REQUESTS",
                 "UBIONAI_HUB_REG_AUTO_ACTIVATE"):
        monkeypatch.delenv(name, raising=False)
    kek = tmp_path / "kek"
    kek.write_bytes(base64.b64encode(os.urandom(32)) + b"\n")
    os.chmod(kek, 0o600)
    return {"db": str(tmp_path / "hub.sqlite3"), "kek": str(kek), "mp": monkeypatch}


def _client_id(client, base):
    return client.post(f"{base}/oauth/register", json={"redirect_uris": [REDIRECT]}).json()["client_id"]


def _attempt_login(client, site, base, client_id, userid):
    """OAuth up to the redirect back to the client; returns its query parameters (+ verifier)."""
    verifier, challenge = _pkce()
    resp = _authorize(client, base, client_id, challenge, f"{HUB}{base}/mcp")
    assert resp.status_code == 302, resp.text
    back = client.get(site.approve(resp.headers["location"], userid))
    assert back.status_code == 302, back.text
    query = {k: v[0] for k, v in parse_qs(urlsplit(back.headers["location"]).query).items()}
    return query, verifier


# --- 1. auto-activation and the operator switches ---------------------------------------------


def test_new_site_active_immediately_and_operator_can_disable_it(env):
    client, site, _, _ = _client(env)
    with client:
        data = _register_and_confirm(client, site)
        assert data["tenant"]["status"] == "active" and data["tenant"]["tier"] == "limited"
        base = f"/m/{HOST_KEY}"
        tokens = _login(client, site, base, _client_id(client, base))
        assert _mcp(client, f"{base}/mcp", tokens["access_token"]).status_code == 200

        # Operator CLI by host_key: the site stops at once and re-registering cannot undo it.
        env["mp"].setenv("UBIONAI_HUB_DB", env["db"])
        env["mp"].setenv("UBIONAI_HUB_KEK_FILE", env["kek"])
        assert admin.main(["disable", "--host", HOST_KEY]) == 0
        assert _registry(env).get(data["site_key"]).status == "disabled"
        assert _mcp(client, f"{base}/mcp", tokens["access_token"]).status_code == 401
        page = client.get(f"{base}/oauth/authorize")
        assert page.status_code == 403 and "사용할 수 없습니다" in page.text
        again = client.post("/api/v1/sites/register", json=site.new_registration())
        assert again.status_code == 403 and again.json()["error"] == "host_blocked"

        assert admin.main(["enable", "--host", HOST_KEY]) == 0
        assert _mcp(client, f"{base}/mcp", tokens["access_token"]).status_code == 200


def test_auto_activate_off_creates_pending(env):
    client, site, _, _ = _client(env, UBIONAI_HUB_REG_AUTO_ACTIVATE="0")
    with client:
        data = client.post("/api/v1/sites/register", json=site.new_registration()).json()
        assert data["tenant"] == {"status": "pending", "tier": "limited", "limits": TierLimits().describe()}


# --- 2. limits ----------------------------------------------------------------------------------


def test_limits_come_from_configuration(env):
    assert TierLimits().describe() == {"max_teachers": 5, "daily_requests": 200, "concurrency": 1, "llm_proxy": False}
    client, site, _, _ = _client(env, UBIONAI_HUB_LIMITED_MAX_TEACHERS="7", UBIONAI_HUB_LIMITED_DAILY_REQUESTS="900")
    with client:
        data = _register_and_confirm(client, site)
        assert data["tenant"]["limits"]["max_teachers"] == 7
        assert data["tenant"]["limits"]["daily_requests"] == 900
        status = client.get(f"/api/v1/sites/{data['site_key']}/status",
                            headers={"Authorization": f"Bearer {data['site_secret']}"}).json()
        assert status["limits"]["max_teachers"] == 7 and status["limits"]["daily_requests"] == 900


@pytest.mark.parametrize("name", ["UBIONAI_HUB_LIMITED_MAX_TEACHERS", "UBIONAI_HUB_LIMITED_DAILY_REQUESTS"])
@pytest.mark.parametrize("value", ["0", "-1", "abc", "1.5"])
def test_invalid_limit_configuration_refuses_to_start(env, name, value):
    env["mp"].setenv("UBIONAI_HUB_PUBLIC_URL", HUB)
    env["mp"].setenv("UBIONAI_HUB_SELF_REGISTRATION", "1")
    env["mp"].setenv(name, value)
    with pytest.raises(RuntimeError, match=name):
        create_app(hub_db=env["db"], kek_file=env["kek"], tenant_secrets_dir="")


def test_teacher_limit_refuses_new_teachers_only(env):
    client, site, _, _ = _client(env, UBIONAI_HUB_LIMITED_MAX_TEACHERS="2")
    with client:
        _register_and_confirm(client, site)
        base = f"/m/{HOST_KEY}"
        cid = _client_id(client, base)
        first = _login(client, site, base, cid, userid=11)
        _login(client, site, base, cid, userid=12)

        # A third teacher gets no grant; their freshly issued Moodle token is revoked again.
        query, _ = _attempt_login(client, site, base, cid, userid=13)
        assert query["error"] == "access_denied" and query["error_description"] == "teacher_limit_reached"
        assert "code" not in query
        assert site.revoked and site.revoked[-1][0] == 13

        # Teachers already connected can reconnect (new client, new grant) and keep working.
        again = _login(client, site, base, _client_id(client, base), userid=11)
        assert _mcp(client, f"{base}/mcp", again["access_token"]).status_code == 200
        assert _mcp(client, f"{base}/mcp", first["access_token"]).status_code == 200

        # The /t/ family shares the same per-site teacher count.
        t_base = f"/t/{_registry(env).get_by_host_key(HOST_KEY).site_id}"
        query, _ = _attempt_login(client, site, t_base, _client_id(client, t_base), userid=14)
        assert query["error_description"] == "teacher_limit_reached"


def test_teacher_limit_rechecked_at_token_endpoint(env):
    client, site, _, _ = _client(env, UBIONAI_HUB_LIMITED_MAX_TEACHERS="1")
    with client:
        _register_and_confirm(client, site)
        base = f"/m/{HOST_KEY}"
        cid = _client_id(client, base)
        # Two new teachers pass the callback before either has redeemed their code.
        q1, v1 = _attempt_login(client, site, base, cid, userid=21)
        q2, v2 = _attempt_login(client, site, base, cid, userid=22)

        def redeem(query, verifier):
            return client.post(f"{base}/oauth/token", data={
                "grant_type": "authorization_code", "code": query["code"], "client_id": cid,
                "redirect_uri": REDIRECT, "code_verifier": verifier, "resource": f"{HUB}{base}/mcp"})

        assert redeem(q1, v1).status_code == 200
        late = redeem(q2, v2)
        assert late.status_code == 400
        assert late.json() == {"error": "invalid_grant", "error_description": "teacher_limit_reached"}


def test_daily_request_limit_returns_429(env):
    client, site, _, _ = _client(env, UBIONAI_HUB_LIMITED_DAILY_REQUESTS="3")
    with client:
        _register_and_confirm(client, site)
        base = f"/m/{HOST_KEY}"
        tokens = _login(client, site, base, _client_id(client, base))
        codes = [_mcp(client, f"{base}/mcp", tokens["access_token"]).status_code for _ in range(3)]
        assert codes == [200, 200, 200]
        over = _mcp(client, f"{base}/mcp", tokens["access_token"])
        assert over.status_code == 429
        body = over.json()
        assert body["error"] == "daily_limit_exceeded" and isinstance(body["error_description"], str)
        assert 1 <= body["retry_after"] <= 86_400
        assert over.headers["retry-after"] == str(body["retry_after"])
        assert over.headers["cache-control"] == "no-store"
        # Unauthenticated requests are not counted and still get the OAuth challenge.
        assert client.post(f"{base}/mcp", json={}).status_code == 401


def test_daily_usage_counter_rolls_over_at_utc_midnight(env):
    from moodle_mcp.crypto import load_kek
    from moodle_mcp.registry import Registry

    now = [1_793_664_000.0 + 86_400 - 10]  # 10 s before 00:00 UTC
    usage = DailyUsage(Registry.open(env["db"], load_kek(env["kek"])), clock=lambda: now[0])
    assert usage.hit("s1", 2) is None and usage.hit("s1", 2) is None
    assert usage.hit("s1", 2) == 10
    assert usage.count("s1") == 2  # refused requests are not counted
    assert usage.hit("s2", 2) is None  # per tenant
    now[0] += 11
    assert usage.hit("s1", 2) is None and usage.count("s1") == 1
    assert seconds_to_utc_midnight(1_793_664_000) == 86_400


# --- 3. re-registration and grants --------------------------------------------------------------


def test_reregistration_same_site_keeps_grants(env):
    client, site, _, _ = _client(env)
    with client:
        _register_and_confirm(client, site)
        base = f"/m/{HOST_KEY}"
        tokens = _login(client, site, base, _client_id(client, base))
        resp = client.post("/api/v1/sites/register", json=site.new_registration())
        assert resp.status_code == 200 and resp.json()["grants_kept"] is True
        assert _mcp(client, f"{base}/mcp", tokens["access_token"]).status_code == 200


def test_reregistration_different_site_revokes_every_grant(env):
    client, site, _, _ = _client(env)
    with client:
        data = _register_and_confirm(client, site)
        base = f"/m/{HOST_KEY}"
        cid = _client_id(client, base)
        a = _login(client, site, base, cid, userid=31)
        b = _login(client, site, base, cid, userid=32)
        other = "ab" * 32  # another Moodle installation on the same wwwroot
        resp = client.post("/api/v1/sites/register", json=site.new_registration(site_identifier_hash=other))
        assert resp.status_code == 200 and resp.json()["grants_kept"] is False
        assert resp.json()["site_key"] == data["site_key"]
        for tokens in (a, b):
            assert _mcp(client, f"{base}/mcp", tokens["access_token"]).status_code == 401
            refresh = client.post(f"{base}/oauth/token", data={
                "grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": cid})
            assert refresh.status_code == 400
        # The new identity is recorded: a further re-registration of that site keeps new grants.
        site.adopt(resp.json())
        client.post(f"/api/v1/sites/{data['site_key']}/confirm", json={"secret_version": site.version},
                    headers={"Authorization": f"Bearer {site.secret}"})
        fresh = _login(client, site, base, cid, userid=31)
        again = client.post("/api/v1/sites/register", json=site.new_registration(site_identifier_hash=other))
        assert again.json()["grants_kept"] is True
        assert _mcp(client, f"{base}/mcp", fresh["access_token"]).status_code == 200


# --- 4. operator tenant on the same host ----------------------------------------------------------


def test_operator_host_conflict_is_409_and_nothing_is_linked(env):
    client, site, _, _ = _client(env)
    _registry(env).add("school-op", SITE_URL, b"op-token", None, "op-bearer")
    with client:
        resp = client.post("/api/v1/sites/register", json=site.new_registration())
    assert resp.status_code == 409 and resp.json()["error"] == "site_managed_by_operator"
    tenants = _registry(env).list()
    assert [(t.site_id, t.origin, t.auth_mode) for t in tenants] == [("school-op", "operator", "legacy_file")]
    assert tenants[0].token_ct is not None and tenants[0].bearer_hash is not None


# --- 5. secrets never in logs -------------------------------------------------------------------


def _secret_forms(value: bytes | str) -> list[str]:
    raw = value.encode() if isinstance(value, str) else value
    forms = [raw.hex(), base64.urlsafe_b64encode(raw).rstrip(b"=").decode(), base64.b64encode(raw).decode()]
    if isinstance(value, str):
        forms.append(value)
    return forms


def test_site_secret_and_mac_key_never_logged(env, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    client, site, _, _ = _client(env, UBIONAI_HUB_LIMITED_DAILY_REQUESTS="2", UBIONAI_HUB_LIMITED_MAX_TEACHERS="1")
    secrets_seen: list[bytes | str] = []
    with client:
        data = _register_and_confirm(client, site)
        key = data["site_key"]
        secrets_seen += [data["site_secret"], site.mac_key]
        auth = {"Authorization": f"Bearer {data['site_secret']}"}
        assert client.get(f"/api/v1/sites/{key}/status", headers=auth).status_code == 200
        # Failure paths log too: a wrong secret, a stale confirm.
        assert client.get(f"/api/v1/sites/{key}/status", headers={"Authorization": "Bearer " + "x" * 43}).status_code == 401
        rotated = client.post(f"/api/v1/sites/{key}/rotate", json={}, headers=auth).json()
        secrets_seen.append(rotated["site_secret"])
        assert client.post(f"/api/v1/sites/{key}/confirm", json={"secret_version": rotated["secret_version"]},
                           headers={"Authorization": f"Bearer {rotated['site_secret']}"}).status_code == 200
        site.adopt(rotated)
        secrets_seen.append(site.mac_key)

        base = f"/m/{HOST_KEY}"
        cid = _client_id(client, base)
        tokens = _login(client, site, base, cid, userid=41)
        secrets_seen += [tokens["access_token"], tokens["refresh_token"], *site.tokens]
        _attempt_login(client, site, base, cid, userid=42)  # teacher limit path
        for _ in range(3):  # daily limit path
            _mcp(client, f"{base}/mcp", tokens["access_token"])

        # Re-registration as a different site (grant revocation path) issues another secret.
        rereg = client.post("/api/v1/sites/register",
                            json=site.new_registration(site_identifier_hash="cd" * 32)).json()
        secrets_seen.append(rereg["site_secret"])
        site.adopt(rereg)
        secrets_seen.append(site.mac_key)

    captured = capsys.readouterr()
    combined = caplog.text + captured.out + captured.err
    assert "self-registration" in caplog.text  # the hub did log these flows
    for secret in secrets_seen:
        for form in _secret_forms(secret):
            assert form not in combined
