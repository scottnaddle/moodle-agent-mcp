"""Self-registration API (contract §1, §3.3, §4). Fake DNS + MockTransport, no network."""

import asyncio
import base64
import json
import os
import sqlite3
from dataclasses import dataclass

import httpx
import pytest

from moodle_mcp.crypto import load_kek
from moodle_mcp.registry import Registry
from moodle_mcp.server import create_app

from .selfreg_helpers import HOST, HOST_KEY, HUB, PUBLIC_IP, SITE_URL, FakeDNS, FakeSite, b64

REGISTER = "/api/v1/sites/register"


@dataclass
class Hub:
    app: object
    site: FakeSite
    dns: FakeDNS
    db: str
    kek: str

    @property
    def registry(self) -> Registry:
        return Registry.open(self.db, load_kek(self.kek))

    def client(self, ip: str = "9.9.9.9") -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app, client=(ip, 1234)), base_url=HUB)


@pytest.fixture
def make_hub(tmp_path, monkeypatch):
    for name in ("MOODLE_TOKEN", "MCP_BEARER_TOKEN", "UBIONAI_HUB_TENANT_SECRETS_DIR", "UBIONAI_HUB_ALLOW_HTTP"):
        monkeypatch.delenv(name, raising=False)
    kek = tmp_path / "kek"
    kek.write_bytes(base64.b64encode(os.urandom(32)) + b"\n")
    os.chmod(kek, 0o600)
    db = tmp_path / "hub.sqlite3"

    def build(site: FakeSite | None = None, dns: FakeDNS | None = None, **env: str) -> Hub:
        defaults = {
            "UBIONAI_HUB_PUBLIC_URL": HUB,
            "UBIONAI_HUB_SELF_REGISTRATION": "1",
            "UBIONAI_HUB_HOST_ROUTES": "1",
            "UBIONAI_HUB_EGRESS_IP": "5.6.7.9",
        }
        for key, value in {**defaults, **env}.items():
            monkeypatch.setenv(key, value)
        site = site or FakeSite()
        dns = dns or FakeDNS()
        app = create_app(hub_db=str(db), kek_file=str(kek), tenant_secrets_dir="",
                         moodle_transport=httpx.MockTransport(site.handler), site_resolver=dns)
        return Hub(app, site, dns, str(db), str(kek))

    return build


async def register(hub: Hub, body=None, ip="9.9.9.9", **overrides):
    body = body if body is not None else hub.site.new_registration(**overrides)
    async with hub.client(ip) as c:
        return await c.post(REGISTER, json=body)


async def call(hub: Hub, method: str, path: str, secret: str | None = None, body=None):
    headers = {"Authorization": f"Bearer {secret}"} if secret else {}
    async with hub.client() as c:
        if method == "GET":
            return await c.get(path, headers=headers)
        return await c.post(path, json=body if body is not None else {}, headers=headers)


def assert_error(resp, status, code):
    assert resp.status_code == status, resp.text
    data = resp.json()
    assert data["error"] == code, data
    assert isinstance(data["error_description"], str)
    assert resp.headers["cache-control"] == "no-store"
    assert "access-control-allow-origin" not in resp.headers


# --- happy path ---------------------------------------------------------------------------


async def test_register_confirm_status(make_hub):
    hub = make_hub()
    resp = await register(hub)
    assert resp.status_code == 201, resp.text
    data = resp.json()
    key = data["site_key"]
    assert key.startswith("lms-school-example-moodle-")
    assert data["schema"] == "ubionai.site-registration-result/v1"
    assert data["secret_version"] == 1 and data["secret_state"] == "pending_confirm"
    assert len(data["site_secret"]) == 43
    assert data["tenant"] == {"status": "active", "tier": "limited",
                              "limits": {"max_teachers": 5, "daily_requests": 200, "concurrency": 1, "llm_proxy": False}}
    assert data["mcp_url"] == f"{HUB}/m/{HOST_KEY}/mcp"
    assert data["legacy_mcp_url"] == f"{HUB}/t/{key}/mcp"
    assert data["confirm_url"] == f"{HUB}/api/v1/sites/{key}/confirm"
    assert data["oauth"]["issuers"] == [f"{HUB}/m/{HOST_KEY}", f"{HUB}/t/{key}"]
    assert data["oauth"]["allowed_callbacks"] == [f"{HUB}/m/{HOST_KEY}/oauth/callback", f"{HUB}/t/{key}/oauth/callback"]
    assert data["mac"] == {"alg": "HMAC-SHA256", "kdf": "HKDF-SHA256", "salt": "ubionai-site-v1",
                           "info": f"oauth-mac|{key}|v1"}
    assert data["auth_mode"] == "shared_secret" and data["egress_ips"] == ["5.6.7.9"]
    assert data["hub_keys_url"] == f"{HUB}/.well-known/ubionai-hub-keys.json"
    assert resp.headers["cache-control"] == "no-store"
    # The callback went to the vetted IP with the host name in Host/SNI, no cookies / auth.
    assert hub.site.seen[-1] == (PUBLIC_IP, HOST, "/moodle/local/ubionai/register_callback.php")

    tenant = hub.registry.get(key)
    assert (tenant.origin, tenant.tier, tenant.token_ct, tenant.bearer_hash, tenant.host_key) == (
        "self_registered", "limited", None, None, HOST_KEY)
    secret = data["site_secret"]
    assert_error(await call(hub, "GET", f"/api/v1/sites/{key}/status", secret), 401, "invalid_site_credentials")

    resp = await call(hub, "POST", f"/api/v1/sites/{key}/confirm", secret, {"secret_version": 1})
    assert resp.status_code == 200 and resp.json() == {"secret_version": 1, "secret_state": "current"}
    resp = await call(hub, "POST", f"/api/v1/sites/{key}/confirm", secret, {"secret_version": 1})
    assert resp.json() == {"secret_version": 1, "secret_state": "current"}  # idempotent

    resp = await call(hub, "GET", f"/api/v1/sites/{key}/status", secret)
    assert resp.status_code == 200
    status = resp.json()
    assert status["site_key"] == key and status["status"] == "active" and status["tier"] == "limited"
    assert status["secret_version"] == 1 and status["plugin_version_seen"] == 2026110300
    assert status["registered_at"].endswith("Z") and status["last_verified_at"].endswith("Z")
    assert status["mcp_url"] == data["mcp_url"] and status["legacy_mcp_url"] == data["legacy_mcp_url"]

    raw = open(hub.db, "rb").read()
    with sqlite3.connect(hub.db) as conn:
        dump = "\n".join(conn.iterdump())
    assert secret not in dump and secret.encode() not in raw
    with sqlite3.connect(hub.db) as conn:
        audit = conn.execute(
            "SELECT host_key, site_id, outcome, error, client_ip_prefix FROM site_registrations").fetchall()
    assert audit == [(HOST_KEY, key, "created", None, "9.9.9.0/24")]


async def test_lost_response_reregister_keeps_one_tenant_and_current(make_hub):
    hub = make_hub()
    first = (await register(hub)).json()
    key = first["site_key"]
    await call(hub, "POST", f"/api/v1/sites/{key}/confirm", first["site_secret"], {"secret_version": 1})

    lost = await register(hub)  # new nonce, response "lost"
    assert lost.status_code == 200 and lost.json()["secret_version"] == 2 and lost.json()["site_key"] == key
    again = await register(hub)
    assert again.status_code == 200 and again.json()["secret_version"] == 3
    assert len([t for t in hub.registry.list() if t.host_key == HOST_KEY]) == 1
    oauth = hub.app.oauth
    states = [c.state for c in oauth.credentials.credentials(key)]
    assert states.count("pending") == 1 and states.count("current") == 1
    assert oauth.authenticator(hub.registry.get(key)).version == 1  # current still signs before confirm

    resp = await call(hub, "GET", f"/api/v1/sites/{key}/status", first["site_secret"])
    assert resp.status_code == 200 and resp.json()["secret_version"] == 1
    assert_error(await call(hub, "POST", f"/api/v1/sites/{key}/confirm", lost.json()["site_secret"],
                            {"secret_version": 2}), 401, "invalid_site_credentials")
    new_secret = again.json()["site_secret"]
    assert (await call(hub, "POST", f"/api/v1/sites/{key}/confirm", new_secret, {"secret_version": 3})).status_code == 200
    assert oauth.authenticator(hub.registry.get(key)).version == 3
    for path, body in ((f"/api/v1/sites/{key}/rotate", {}), (f"/api/v1/sites/{key}/status", None)):
        resp = await call(hub, "GET" if body is None else "POST", path, first["site_secret"], body)
        assert_error(resp, 401, "invalid_site_credentials")


async def test_rotate(make_hub):
    hub = make_hub()
    first = (await register(hub)).json()
    key, secret = first["site_key"], first["site_secret"]
    await call(hub, "POST", f"/api/v1/sites/{key}/confirm", secret, {"secret_version": 1})
    rotated = await call(hub, "POST", f"/api/v1/sites/{key}/rotate", secret, {})
    assert rotated.status_code == 200
    body = rotated.json()
    assert body["secret_version"] == 2 and body["secret_state"] == "pending_confirm"
    assert body["mac"]["info"] == f"oauth-mac|{key}|v2"
    assert hub.site.callback_hits == 1  # rotate needs no callback
    assert (await call(hub, "POST", f"/api/v1/sites/{key}/confirm", body["site_secret"], {"secret_version": 2})).status_code == 200
    assert_error(await call(hub, "POST", f"/api/v1/sites/{key}/rotate", secret, {}), 401, "invalid_site_credentials")
    assert_error(await call(hub, "POST", f"/api/v1/sites/{key}/confirm", body["site_secret"], {"secret_version": 9}),
                 409, "nothing_to_confirm")


# --- error codes (§4.1) ---------------------------------------------------------------------


async def test_request_validation_errors(make_hub):
    hub = make_hub()
    async with hub.client() as c:
        assert_error(await c.post(REGISTER, content=b"{}", headers={"content-type": "text/plain"}),
                     415, "unsupported_media_type")
        assert_error(await c.post(REGISTER, content=b"{" + b" " * 17000 + b"}",
                                  headers={"content-type": "application/json"}), 413, "request_too_large")
        assert_error(await c.post(REGISTER, content=b"not json", headers={"content-type": "application/json"}),
                     400, "invalid_request")
        assert_error(await c.get(REGISTER), 405, "invalid_request")
    body = hub.site.new_registration()
    del body["challenge_sha256"]
    assert_error(await register(hub, body), 400, "invalid_request")
    for bad in ({"wstoken": "x"}, {"token": "x"}, {"password": "x"}):
        assert_error(await register(hub, **bad), 400, "invalid_request")
    assert_error(await register(hub, plugin={"component": "local_ubionai", "version": 1, "release": "x", "wstoken": "x"}),
                 400, "invalid_request")
    assert_error(await register(hub, moodle={"release": "5", "version": 2025100601.01, "branch": "501"}),
                 400, "invalid_request")  # version must be a string
    assert_error(await register(hub, auth_modes=["signature"]), 400, "invalid_request")
    assert hub.site.callback_hits == 0
    resp = await register(hub, future_field={"anything": 1})  # unknown fields are ignored
    assert resp.status_code == 201


@pytest.mark.parametrize(
    "overrides, status, code",
    [
        ({"site_url": "https://lms.school.example/moodle?x=1"}, 400, "invalid_site_url"),
        ({"site_url": "https://user@lms.school.example/moodle"}, 400, "invalid_site_url"),
        ({"site_url": "https://lms.school.example/" + "x" * 260}, 400, "invalid_site_url"),
        ({"site_url": "http://lms.school.example/moodle"}, 400, "unsupported_scheme"),
        ({"site_url": "https://lms.school.example:8443/moodle"}, 403, "port_not_allowed"),
        ({"site_url": "https://10.0.0.5/moodle", "wwwroot_host": "10.0.0.5"}, 403, "private_address_not_supported"),
        ({"site_url": "https://moodle.school.internal", "wwwroot_host": "moodle.school.internal"}, 403,
         "private_address_not_supported"),
        ({"wwwroot_host": "www.lms.school.example"}, 422, "site_url_mismatch"),
        ({"plugin": {"component": "local_ubionai", "version": 2025010100, "release": "0.6.0"}}, 426,
         "plugin_upgrade_required"),
    ],
)
async def test_policy_errors(make_hub, overrides, status, code):
    hub = make_hub()
    assert_error(await register(hub, **overrides), status, code)
    assert hub.site.callback_hits == 0


async def test_consent_errors(make_hub):
    hub = make_hub()
    body = hub.site.new_registration()
    body["consent"]["accepted"] = False
    assert_error(await register(hub, body), 403, "consent_required")
    body = hub.site.new_registration()
    body["consent"]["scopes"] = ["hub_processing"]
    assert_error(await register(hub, body), 403, "consent_required")
    body = hub.site.new_registration()
    body["consent"]["terms_version"] = "2026-01-01"
    assert_error(await register(hub, body), 403, "consent_outdated")


async def test_dns_private_and_unreachable(make_hub):
    hub = make_hub(dns=FakeDNS({HOST: ["1.2.3.4", "10.1.1.1"], "hub.example": ["5.6.7.8"]}))
    assert_error(await register(hub), 403, "private_address_not_supported")
    hub = make_hub(dns=FakeDNS({HOST: ["169.254.169.254"]}))
    assert_error(await register(hub), 403, "private_address_not_supported")
    hub = make_hub(dns=FakeDNS({"hub.example": ["5.6.7.8"]}))
    assert_error(await register(hub), 502, "callback_unreachable")
    assert hub.site.callback_hits == 0


async def test_callback_points_at_the_hub_itself(make_hub):
    hub = make_hub(dns=FakeDNS({HOST: ["5.6.7.8"], "hub.example": ["5.6.7.8"]}))
    assert_error(await register(hub), 403, "private_address_not_supported")
    hub = make_hub(dns=FakeDNS({HOST: ["5.6.7.9"], "hub.example": ["5.6.7.8"]}))  # egress IP
    assert_error(await register(hub), 403, "private_address_not_supported")


# Hub and Moodle site behind the same CDN: the public URL resolves to shared anycast addresses.
CDN = ["104.21.10.20", "2606:4700::6810:a14"]


async def test_cdn_shared_addresses_blocked_by_default(make_hub, caplog):
    hub = make_hub(dns=FakeDNS({HOST: CDN, "hub.example": CDN}))
    with caplog.at_level("INFO", logger="moodle_mcp.registration"):
        assert_error(await register(hub), 403, "private_address_not_supported")
    assert "reason=self_address" in caplog.text
    assert hub.site.callback_hits == 0


async def test_cdn_shared_addresses_with_self_addresses(make_hub):
    dns = FakeDNS({HOST: CDN, "hub.example": CDN})
    hub = make_hub(FakeSite(ip=CDN[0]), dns, UBIONAI_HUB_SELF_ADDRESSES="5.6.7.10, 2001:db9::10")
    resp = await register(hub)
    assert resp.status_code in (200, 201), resp.text
    assert "hub.example" not in dns.calls  # no DNS-based self-vet


async def test_self_vet_dns_off(make_hub):
    dns = FakeDNS({HOST: CDN, "hub.example": CDN})
    hub = make_hub(FakeSite(ip=CDN[0]), dns, UBIONAI_HUB_SELF_VET_DNS="0")
    resp = await register(hub)
    assert resp.status_code in (200, 201), resp.text
    assert "hub.example" not in dns.calls


async def test_self_addresses_still_blocks_origin_and_egress(make_hub, caplog):
    env = {"UBIONAI_HUB_SELF_ADDRESSES": "5.6.7.10"}
    hub = make_hub(dns=FakeDNS({HOST: ["5.6.7.10"], "hub.example": CDN}), **env)
    with caplog.at_level("INFO", logger="moodle_mcp.registration"):
        assert_error(await register(hub), 403, "private_address_not_supported")
    assert "reason=self_address" in caplog.text
    hub = make_hub(dns=FakeDNS({HOST: ["::ffff:5.6.7.10"], "hub.example": CDN}), **env)
    assert_error(await register(hub), 403, "private_address_not_supported")
    hub = make_hub(dns=FakeDNS({HOST: ["5.6.7.9"], "hub.example": CDN}), **env)  # egress IP
    assert_error(await register(hub), 403, "private_address_not_supported")
    hub = make_hub(dns=FakeDNS({HOST: ["1.2.3.4", "10.1.1.1"], "hub.example": CDN}), **env)
    caplog.clear()
    with caplog.at_level("INFO", logger="moodle_mcp.registration"):
        assert_error(await register(hub), 403, "private_address_not_supported")
    assert "reason=non_public" in caplog.text


def test_self_addresses_invalid_refuses_start(make_hub):
    with pytest.raises(RuntimeError, match="UBIONAI_HUB_SELF_ADDRESSES"):
        make_hub(UBIONAI_HUB_SELF_ADDRESSES="10.0.0.0/8")


def _cb(site, **changes):
    def handler(request):
        nonce = request.url.params["nonce"]
        doc = {"typ": "ubionai-register-callback/v1", "nonce": nonce, "challenge": b64(site.pending[nonce]),
               "wwwroot": site.site_url, "plugin_version": 2026110300}
        doc.update(changes)
        return httpx.Response(200, json=doc)
    return handler


@pytest.mark.parametrize(
    "override, status, code",
    [
        (lambda s: lambda r: httpx.Response(404, json={"error": "unknown_nonce"}), 422, "callback_mismatch"),
        (lambda s: _cb(s, nonce=b64(b"x" * 32)), 422, "callback_mismatch"),
        (lambda s: _cb(s, challenge=b64(b"y" * 32)), 422, "callback_mismatch"),
        (lambda s: _cb(s, wwwroot="https://lms.school.example"), 422, "callback_mismatch"),
        (lambda s: _cb(s, plugin_version=2026110301), 422, "callback_mismatch"),
        (lambda s: _cb(s, typ="other"), 502, "callback_bad_response"),
        (lambda s: lambda r: httpx.Response(301, headers={"location": "https://www.lms.school.example/moodle"}), 422,
         "callback_redirected"),
        (lambda s: lambda r: httpx.Response(500, json={}), 502, "callback_bad_response"),
        (lambda s: lambda r: httpx.Response(200, text="<html>login</html>", headers={"content-type": "text/html"}), 502,
         "callback_bad_response"),
        (lambda s: lambda r: httpx.Response(200, content=b'{"a":"' + b"x" * 9000 + b'"}',
                                            headers={"content-type": "application/json"}), 502, "callback_bad_response"),
        (lambda s: lambda r: (_ for _ in ()).throw(httpx.ConnectError("tls", request=r)), 502, "callback_unreachable"),
    ],
)
async def test_callback_failures(make_hub, override, status, code):
    hub = make_hub()
    hub.site.callback_override = override(hub.site)
    assert_error(await register(hub), status, code)
    assert hub.registry.list() == []


async def test_callback_wwwroot_normalised_equal_is_accepted(make_hub):
    hub = make_hub()
    hub.site.callback_override = _cb(hub.site, wwwroot="https://LMS.school.example/moodle/")
    assert (await register(hub)).status_code == 201


async def test_callback_timeout(make_hub):
    hub = make_hub()
    hub.app.registration.fetcher.timeout = 0.05

    async def slow(request):
        await asyncio.sleep(1)
        return httpx.Response(200, json={})

    hub.site.callback_override = slow
    assert_error(await register(hub), 504, "callback_timeout")


async def test_nonce_reuse_and_failed_attempt_audit(make_hub):
    hub = make_hub()
    body = hub.site.new_registration()
    assert (await register(hub, body)).status_code == 201
    assert_error(await register(hub, body), 409, "nonce_reused")
    hub.site.callback_override = lambda r: httpx.Response(404, json={})
    failed = hub.site.new_registration()
    assert_error(await register(hub, failed), 422, "callback_mismatch")
    hub.app.registration.limiter.negative_clear(f"neg:{HOST_KEY}")
    assert_error(await register(hub, failed), 409, "nonce_reused")  # the nonce is spent even on failure
    rows = sqlite3.connect(hub.db).execute("SELECT outcome, error FROM site_registrations ORDER BY id").fetchall()
    assert rows == [("created", None), ("failed", "callback_mismatch")]


async def test_concurrent_registrations_for_one_host(make_hub):
    hub = make_hub()
    gate = asyncio.Event()
    entered = asyncio.Event()
    normal = _cb(hub.site)

    async def held(request):
        entered.set()
        await gate.wait()
        return normal(request)

    hub.site.callback_override = held
    first = asyncio.create_task(register(hub))
    await entered.wait()
    second = await register(hub)
    assert_error(second, 409, "registration_in_progress")
    assert second.headers["retry-after"] == "15" and second.json()["retry_after"] == 15
    gate.set()
    assert (await first).status_code == 201
    assert len(hub.registry.list()) == 1


async def test_verifier_busy(make_hub):
    hub = make_hub()
    hub.app.registration._verifying = 20
    resp = await register(hub)
    assert_error(resp, 503, "verifier_busy")
    assert "retry-after" in resp.headers


async def test_operator_tenant_and_blocked_hosts(make_hub, monkeypatch):
    hub = make_hub()
    hub.registry.add("school-op", SITE_URL, b"op-token", None, "op-bearer")
    assert_error(await register(hub), 409, "site_managed_by_operator")
    assert hub.registry.get("school-op").token_ct is not None

    hub = make_hub(UBIONAI_HUB_REG_BLOCKED_HOSTS="other.example,lms.school.example")
    hub.registry.delete("school-op")
    assert_error(await register(hub), 403, "host_blocked")
    assert hub.site.callback_hits == 0

    hub = make_hub(UBIONAI_HUB_REG_BLOCKED_HOSTS="")
    key = (await register(hub)).json()["site_key"]
    hub.registry.set_status(key, "disabled")
    assert_error(await register(hub), 403, "host_blocked")  # operator disable cannot be undone by re-registering


async def test_site_endpoints_errors(make_hub):
    hub = make_hub()
    assert_error(await call(hub, "GET", "/api/v1/sites/nope-000000/status", "x"), 404, "site_not_found")
    hub.registry.add("op-site", "https://op.example", b"t", None, "b")
    assert_error(await call(hub, "GET", "/api/v1/sites/op-site/status", "b"), 404, "site_not_found")
    data = (await register(hub)).json()
    key = data["site_key"]
    assert_error(await call(hub, "GET", f"/api/v1/sites/{key}/status"), 401, "invalid_site_credentials")
    assert_error(await call(hub, "POST", f"/api/v1/sites/{key}/confirm", data["site_secret"], {"secret_version": "1"}),
                 400, "invalid_request")
    with sqlite3.connect(hub.db) as conn:
        conn.execute("UPDATE site_credentials SET expires_at = 1 WHERE site_id = ?", (key,))
    assert_error(await call(hub, "POST", f"/api/v1/sites/{key}/confirm", data["site_secret"], {"secret_version": 1}),
                 410, "pending_secret_expired")
    async with hub.client() as c:
        assert_error(await c.post(f"/api/v1/sites/{key}/status"), 405, "invalid_request")
        assert_error(await c.get(f"/api/v1/sites/{key}/deregister"), 404, "invalid_request")


async def test_rate_limits(make_hub):
    hub = make_hub()
    for i in range(10):
        resp = await register(hub, ip="7.7.7.7", site_url=f"https://a{i}.example", wwwroot_host=f"a{i}.example")
        assert resp.status_code != 429
    resp = await register(hub, ip="7.7.7.7")
    assert_error(resp, 429, "rate_limited")
    assert int(resp.headers["retry-after"]) > 0 and resp.json()["retry_after"] > 0
    assert (await register(hub, ip="7.7.8.1")).status_code == 201  # another IP

    hub = make_hub()
    hub.app.registration._reregistrations_since = lambda host_key, since: 0  # isolate the host rule
    for i in range(5):
        assert (await register(hub, ip=f"8.0.{i}.1")).status_code != 429
    assert_error(await register(hub, ip="8.0.9.1"), 429, "rate_limited")  # host_key 5/hour


async def test_negative_cache_grows(make_hub):
    hub = make_hub()
    limiter = hub.app.registration.limiter
    hub.site.callback_override = lambda r: httpx.Response(404, json={})
    assert_error(await register(hub), 422, "callback_mismatch")
    resp = await register(hub)
    assert_error(resp, 429, "rate_limited")
    assert 0 < int(resp.headers["retry-after"]) <= 60
    assert hub.site.callback_hits == 1  # the victim site is not called again
    limiter._negative[f"neg:{HOST_KEY}"] = (1, 0.0)  # pretend the minute passed
    assert_error(await register(hub), 422, "callback_mismatch")
    resp = await register(hub)
    assert 60 < int(resp.headers["retry-after"]) <= 120


async def test_reregistration_limit_holds_site_for_review(make_hub):
    hub = make_hub()
    key = (await register(hub, ip="1.1.1.1")).json()["site_key"]
    for i in range(3):
        assert (await register(hub, ip=f"1.1.{i + 2}.1")).status_code == 200
    resp = await register(hub, ip="1.1.9.1")
    assert_error(resp, 429, "rate_limited")
    assert hub.registry.get(key).status == "pending"


async def test_pending_creation_rules(make_hub):
    hub = make_hub(UBIONAI_HUB_REG_AUTO_ACTIVATE="0")
    assert (await register(hub)).json()["tenant"]["status"] == "pending"

    other = FakeSite(site_url="https://clone.example", ip="2.2.2.2")
    dns = FakeDNS({"clone.example": ["2.2.2.2"], "hub.example": ["5.6.7.8"]})
    hub2 = make_hub(site=other, dns=dns, UBIONAI_HUB_REG_AUTO_ACTIVATE="1")
    body = other.new_registration(site_identifier_hash=hub.site.new_registration()["site_identifier_hash"])
    resp = await register(hub2, body)
    assert resp.status_code == 201 and resp.json()["tenant"]["status"] == "pending"  # cloned siteidentifier


async def test_disabled_flag_and_internal_error(make_hub, monkeypatch):
    hub = make_hub(UBIONAI_HUB_SELF_REGISTRATION="0")
    resp = await register(hub)
    assert_error(resp, 503, "registration_disabled")
    assert resp.json()["retry_after"] == 21600

    hub = make_hub()

    def boom(*a, **k):
        raise RuntimeError("db gone")

    monkeypatch.setattr(hub.app.registration, "_register_verified", boom)
    assert_error(await register(hub), 500, "internal_error")


async def test_well_known_documents(make_hub, tmp_path):
    hub = make_hub()
    async with hub.client() as c:
        meta = await c.get("/.well-known/ubionai-hub.json")
        keys = await c.get("/.well-known/ubionai-hub-keys.json")
    assert meta.status_code == 200 and meta.json()["auth_modes"] == ["shared_secret"]
    assert meta.json()["hub_keys_url"] == f"{HUB}/.well-known/ubionai-hub-keys.json"
    assert keys.json() == {"issuer": HUB, "keys": []}
    assert keys.headers["cache-control"] == "public, max-age=3600"

    jwks = tmp_path / "hub-public-keys.json"
    fake = {"kty": "OKP", "crv": "Ed25519", "x": b64(b"\x01" * 32), "kid": "hub-test-a", "use": "sig",
            "alg": "EdDSA", "status": "next"}
    jwks.write_text(json.dumps({"keys": [fake]}))
    hub = make_hub(UBIONAI_HUB_PUBLIC_KEYS_FILE=str(jwks))
    async with hub.client() as c:
        assert (await c.get("/.well-known/ubionai-hub-keys.json")).json()["keys"] == [fake]
        assert (await c.get("/.well-known/ubionai-hub.json")).json()["auth_modes"] == ["shared_secret"]
    jwks.write_text(json.dumps({"keys": [{**fake, "d": b64(b"\x02" * 32)}]}))  # private member refused
    with pytest.raises(RuntimeError):
        make_hub(UBIONAI_HUB_PUBLIC_KEYS_FILE=str(jwks))


def test_default_tier_must_be_limited(make_hub):
    with pytest.raises(RuntimeError, match="limited"):
        make_hub(UBIONAI_HUB_REG_DEFAULT_TIER="standard")
