"""Operator link-host / unlink-host (decision #4, docs/OPERATOR-LINK.md).

An operator tenant's host may self-register only after `moodle-hub-admin link-host`; the shared
secret then serves /m/<host_key> while /t/ and the legacy credentials stay untouched.
TestClient + fake DNS + MockTransport, no network. All values are fake.
"""

import base64
import logging
import os
import sqlite3

import httpx
import pytest
from starlette.testclient import TestClient

from moodle_mcp import admin
from moodle_mcp.server import create_app

from .selfreg_helpers import HOST, HOST_KEY, HUB, SITE_URL, FakeDNS, FakeSite
from .test_host_routes import REDIRECT, _login, _mcp, _registry
from .test_reg_decisions import _secret_forms

OP = "school-op"


@pytest.fixture
def env(tmp_path, monkeypatch):
    for name in ("MOODLE_TOKEN", "MCP_BEARER_TOKEN", "UBIONAI_HUB_TENANT_SECRETS_DIR", "UBIONAI_HUB_ALLOW_HTTP",
                 "UBIONAI_HUB_REG_ALLOWED_PORTS"):
        monkeypatch.delenv(name, raising=False)
    kek = tmp_path / "kek"
    kek.write_bytes(base64.b64encode(os.urandom(32)) + b"\n")
    os.chmod(kek, 0o600)
    db = str(tmp_path / "hub.sqlite3")
    monkeypatch.setenv("UBIONAI_HUB_DB", db)  # for the admin CLI
    monkeypatch.setenv("UBIONAI_HUB_KEK_FILE", str(kek))
    return {"db": db, "kek": str(kek), "mp": monkeypatch}


class OperatorSite(FakeSite):
    """Operator tenants use the hub's normal transport (not pinned); FakeSite asserts pinning, so
    unpinned requests are mapped onto the vetted IP here and recorded."""

    def __init__(self) -> None:
        super().__init__()
        self.unpinned: list[str] = []

    async def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == self.host:
            self.unpinned.append(request.url.path)
            request.url = request.url.copy_with(host=self.ip)
            request.extensions = {**request.extensions, "sni_hostname": self.host}
        return await super().handler(request)


def _client(env, host_routes="1"):
    env["mp"].setenv("UBIONAI_HUB_PUBLIC_URL", HUB)
    env["mp"].setenv("UBIONAI_HUB_SELF_REGISTRATION", "1")
    env["mp"].setenv("UBIONAI_HUB_HOST_ROUTES", host_routes)
    site, dns = OperatorSite(), FakeDNS()
    app = create_app(hub_db=env["db"], kek_file=env["kek"], tenant_secrets_dir="",
                     moodle_transport=httpx.MockTransport(site.handler), site_resolver=dns)
    return TestClient(app, base_url=HUB, follow_redirects=False), site


def _add_operator(env, site_id=OP, url=SITE_URL, bearer="op-bearer"):
    _registry(env).add(site_id, url, b"op-token", None, bearer)


def _snapshot(env, site_id=OP):
    with sqlite3.connect(env["db"]) as conn:
        return conn.execute(
            "SELECT origin, tier, auth_mode, status, token_ct, bearer_hash, moodle_url FROM tenants"
            " WHERE site_id = ?", (site_id,),
        ).fetchone()


def _audit(env):
    with sqlite3.connect(env["db"]) as conn:
        return conn.execute("SELECT site_id, host_key, action FROM operator_link_audit ORDER BY id").fetchall()


def _confirm(client, data):
    return client.post(f"/api/v1/sites/{data['site_key']}/confirm", json={"secret_version": data["secret_version"]},
                       headers={"Authorization": f"Bearer {data['site_secret']}"})


# --- CLI ------------------------------------------------------------------------------------


def test_link_and_unlink_cli(env, capsys):
    _add_operator(env, url="https://internal-moodle.example")  # moodle_url host differs from --url
    before = _snapshot(env)
    reg = _registry(env)
    assert reg.get(OP).host_key == "internal-moodle.example"
    # A tenant already routed under another host_key is not silently re-routed.
    assert admin.main(["link-host", "--site", OP, "--url", "https://LMS.school.example/moodle/"]) == 1
    assert "refusing to re-route" in capsys.readouterr().err
    with sqlite3.connect(env["db"]) as conn:
        conn.execute("UPDATE tenants SET host_key = NULL WHERE site_id = ?", (OP,))

    assert admin.main(["link-host", "--site", OP, "--url", "https://LMS.school.example/moodle/"]) == 0
    out = capsys.readouterr()
    assert f"linked site={OP} host_key={HOST_KEY}" in out.out and "differs" in out.err
    tenant = reg.get(OP)
    assert tenant.host_key == HOST_KEY and tenant.operator_linked and tenant.link_approved_at
    assert _snapshot(env) == before  # origin, tier, auth_mode, status, token, bearer, moodle_url

    assert admin.main(["link-host", "--site-id", OP, "--url", SITE_URL]) == 0  # idempotent
    assert "already linked" in capsys.readouterr().out
    assert reg.get(OP).link_approved_at == tenant.link_approved_at

    assert admin.main(["list", "--json"]) == 0
    assert '"linked": true' in capsys.readouterr().out

    assert admin.main(["unlink-host", "--site", OP]) == 0
    assert f"unlinked site={OP} host_key={HOST_KEY} revoked_m_grants=0" in capsys.readouterr().out
    tenant = reg.get(OP)
    assert not tenant.operator_linked and tenant.host_key == HOST_KEY
    assert _snapshot(env) == before
    assert admin.main(["unlink-host", "--site", OP]) == 1
    assert "not linked" in capsys.readouterr().err
    assert _audit(env) == [(OP, HOST_KEY, "link"), (OP, HOST_KEY, "unlink")]


def test_link_refusals(env, capsys):
    _add_operator(env)  # owns HOST_KEY
    _add_operator(env, "other-op", "https://internal-other.example", bearer="other-bearer")
    with sqlite3.connect(env["db"]) as conn:
        conn.execute("UPDATE tenants SET host_key = NULL WHERE site_id = 'other-op'")
    assert admin.main(["link-host", "--site", "other-op", "--url", SITE_URL]) == 1
    assert f"already belongs to site={OP}" in capsys.readouterr().err
    assert _registry(env).get("other-op").host_key is None
    for url in ("https://10.0.0.1/moodle", "https://moodle.local", "http://lms.school.example", "not a url"):
        assert admin.main(["link-host", "--site", "other-op", "--url", url]) == 1, url
        assert "invalid --url" in capsys.readouterr().err
    assert admin.main(["link-host", "--site", "nope", "--url", "https://x.example"]) == 1
    assert _audit(env) == []
    assert all(not t.operator_linked for t in _registry(env).list())


def test_self_registered_tenant_cannot_be_linked(env, capsys):
    client, site = _client(env)
    with client:
        key = client.post("/api/v1/sites/register", json=site.new_registration()).json()["site_key"]
    assert admin.main(["link-host", "--site", key, "--url", SITE_URL]) == 1
    assert "only operator tenants" in capsys.readouterr().err


def test_schema_v7_is_idempotent(env):
    _add_operator(env)
    for _ in range(2):
        reg = _registry(env)
    reg.link_host(OP, HOST_KEY)
    reg = _registry(env)
    assert reg.get(OP).operator_linked
    with sqlite3.connect(env["db"]) as conn:
        assert conn.execute("SELECT schema_version FROM meta").fetchone()[0] == 7


# --- registration ---------------------------------------------------------------------------


def test_unlinked_operator_host_stays_409(env):
    _add_operator(env)
    client, site = _client(env)
    with client:
        resp = client.post("/api/v1/sites/register", json=site.new_registration())
    assert resp.status_code == 409 and resp.json()["error"] == "site_managed_by_operator"
    assert site.callback_hits == 1  # verified first, then refused
    with sqlite3.connect(env["db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM site_credentials").fetchone()[0] == 0


def test_linked_but_host_routes_off_stays_409(env):
    _add_operator(env)
    _registry(env).link_host(OP, HOST_KEY)
    client, site = _client(env, host_routes="0")
    with client:
        resp = client.post("/api/v1/sites/register", json=site.new_registration())
    assert resp.status_code == 409 and resp.json()["error"] == "site_managed_by_operator"


def test_linked_registration_routes_m_and_leaves_legacy_alone(env):
    _add_operator(env)
    before = _snapshot(env)
    assert admin.main(["link-host", "--site", OP, "--url", SITE_URL]) == 0
    client, site = _client(env)
    m_base = f"/m/{HOST_KEY}"
    with client:
        resp = client.post("/api/v1/sites/register", json=site.new_registration())
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["site_key"] == OP and data["grants_kept"] is True
        assert data["tenant"]["tier"] == "standard" and data["auth_mode"] == "shared_secret"
        assert data["mcp_url"] == f"{HUB}{m_base}/mcp" and data["legacy_mcp_url"] is None
        assert data["oauth"]["issuers"] == [f"{HUB}{m_base}"]
        assert data["mac"]["info"] == f"oauth-mac|{OP}|v{data['secret_version']}"

        # Before the confirm /m/ has no signer: static surface, no OAuth redirect.
        assert client.get(f"{m_base}/oauth/authorize").status_code == 403
        assert _confirm(client, data).status_code == 200
        site.adopt(data)
        status = client.get(f"/api/v1/sites/{OP}/status", headers={"Authorization": f"Bearer {data['site_secret']}"})
        assert status.status_code == 200 and status.json()["legacy_mcp_url"] is None

        # /m/: OAuth signed with the site's mac_key (FakeSite checks the HMAC and kv), MCP works.
        assert client.get(f"/.well-known/oauth-protected-resource{m_base}/mcp").json()["resource"] == f"{HUB}{m_base}/mcp"
        cid = client.post(f"{m_base}/oauth/register", json={"redirect_uris": [REDIRECT]}).json()["client_id"]
        tokens = _login(client, site, m_base, cid)
        resp = _mcp(client, f"{m_base}/mcp", tokens["access_token"])
        assert resp.status_code == 200 and "Existing course" in resp.text
        assert "/moodle/local/ubionai/oauth/exchange.php" in site.unpinned  # operator transport

        # /t/: untouched. No oauth.secret -> OAuth stays off there, the static bearer still rules.
        challenge = client.post(f"/t/{OP}/mcp", json={})
        assert challenge.status_code == 401 and challenge.headers["www-authenticate"] == "Bearer"
        assert _mcp(client, f"/t/{OP}/mcp", tokens["access_token"]).status_code == 403
        assert client.get(f"/.well-known/oauth-protected-resource/t/{OP}/mcp").status_code == 404
        assert _snapshot(env) == before

        # Re-registration by the same Moodle keeps the /m/ grant.
        again = client.post("/api/v1/sites/register", json=site.new_registration()).json()
        assert again["grants_kept"] is True
        assert _mcp(client, f"{m_base}/mcp", tokens["access_token"]).status_code == 200

        # Unlink: secret gone, /m/ grants revoked, registration back to 409.
        assert admin.main(["unlink-host", "--site", OP]) == 0
        assert _mcp(client, f"{m_base}/mcp", tokens["access_token"]).status_code == 401
        assert client.get(f"/api/v1/sites/{OP}/status",
                          headers={"Authorization": f"Bearer {data['site_secret']}"}).status_code == 404
        resp = client.post("/api/v1/sites/register", json=site.new_registration())
        assert resp.status_code == 409 and resp.json()["error"] == "site_managed_by_operator"
        # The host still has a tenant: known-host behaviour (not the unknown-host 404).
        assert client.get(f"/.well-known/oauth-protected-resource{m_base}/mcp").status_code == 200
    assert _snapshot(env) == before
    with sqlite3.connect(env["db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM site_credentials").fetchone()[0] == 0
        outcomes = [r[0] for r in conn.execute("SELECT outcome FROM site_registrations ORDER BY id")]
    assert outcomes == ["linked", "linked", "failed"]


def test_linked_host_still_needs_the_callback(env):
    _add_operator(env)
    _registry(env).link_host(OP, HOST_KEY)
    client, site = _client(env)
    site.callback_override = lambda request: httpx.Response(404)
    with client:
        resp = client.post("/api/v1/sites/register", json=site.new_registration())
    assert resp.status_code == 422 and resp.json()["error"] == "callback_mismatch"
    with sqlite3.connect(env["db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM site_credentials").fetchone()[0] == 0


def test_linked_registration_by_another_moodle_revokes_only_m_grants(env):
    _add_operator(env)
    _registry(env).link_host(OP, HOST_KEY)
    client, site = _client(env)
    m_base = f"/m/{HOST_KEY}"
    with client:
        data = client.post("/api/v1/sites/register", json=site.new_registration()).json()
        assert _confirm(client, data).status_code == 200
        site.adopt(data)
        cid = client.post(f"{m_base}/oauth/register", json={"redirect_uris": [REDIRECT]}).json()["client_id"]
        tokens = _login(client, site, m_base, cid)
        with sqlite3.connect(env["db"]) as conn:  # a /t/ grant of the same tenant (legacy family)
            conn.execute(
                "INSERT INTO oauth_grants (grant_id, site_id, moodle_userid, client_id, scope, resource,"
                " wstoken_ct, moodle_tokenid, valid_until, kek_id, created_at)"
                " SELECT 'legacy-grant', site_id, 9, client_id, scope, ?, wstoken_ct, 1, valid_until, kek_id,"
                " created_at FROM oauth_grants LIMIT 1",
                (f"{HUB}/t/{OP}/mcp",),
            )
        other = client.post("/api/v1/sites/register", json=site.new_registration(site_identifier_hash="cd" * 32))
        assert other.status_code == 200 and other.json()["grants_kept"] is False
        assert _mcp(client, f"{m_base}/mcp", tokens["access_token"]).status_code == 401
    with sqlite3.connect(env["db"]) as conn:
        assert conn.execute("SELECT revoked_at FROM oauth_grants WHERE grant_id = 'legacy-grant'").fetchone()[0] is None


def test_unknown_host_metadata_404_known_host_200(env):
    _add_operator(env)
    _registry(env).link_host(OP, HOST_KEY)
    client, _ = _client(env)
    with client:
        assert client.get(f"/.well-known/oauth-protected-resource/m/{HOST_KEY}/mcp").status_code == 200
        assert client.get(f"/.well-known/oauth-authorization-server/m/{HOST_KEY}").status_code == 200
        assert client.post(f"/m/{HOST_KEY}/mcp", json={}).status_code == 401
        for path in ("/.well-known/oauth-protected-resource/m/unknown.example/mcp",
                     "/.well-known/oauth-authorization-server/m/unknown.example",
                     "/m/unknown.example/mcp", "/m/unknown.example/oauth/register"):
            assert client.get(path).status_code == 404, path
            assert client.post(path, json={}).status_code == 404, path
        page = client.get("/m/unknown.example/oauth/authorize")
        assert page.status_code == 404 and "content-security-policy" in page.headers


def test_link_flow_never_logs_secrets(env, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    _add_operator(env)
    secrets_seen: list = ["op-bearer", b"op-token"]
    assert admin.main(["link-host", "--site", OP, "--url", SITE_URL]) == 0
    client, site = _client(env)
    with client:
        data = client.post("/api/v1/sites/register", json=site.new_registration()).json()
        assert _confirm(client, data).status_code == 200
        site.adopt(data)
        secrets_seen += [data["site_secret"], site.mac_key]
        cid = client.post(f"/m/{HOST_KEY}/oauth/register", json={"redirect_uris": [REDIRECT]}).json()["client_id"]
        tokens = _login(client, site, f"/m/{HOST_KEY}", cid)
        secrets_seen += [tokens["access_token"], tokens["refresh_token"], *site.tokens]
        _mcp(client, f"/m/{HOST_KEY}/mcp", tokens["access_token"])
        rotated = client.post(f"/api/v1/sites/{OP}/rotate", json={},
                              headers={"Authorization": f"Bearer {data['site_secret']}"}).json()
        secrets_seen.append(rotated["site_secret"])
        assert admin.main(["unlink-host", "--site", OP]) == 0
    captured = capsys.readouterr()
    combined = caplog.text + captured.out + captured.err
    assert "operator link" in caplog.text and "linked operator" in caplog.text
    for secret in secrets_seen:
        for form in _secret_forms(secret):
            assert form not in combined
    with sqlite3.connect(env["db"]) as conn:
        rows = conn.execute("SELECT * FROM operator_link_audit").fetchall()
    for secret in secrets_seen:
        for form in _secret_forms(secret):
            assert form not in repr(rows)
