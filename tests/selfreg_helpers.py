"""Fakes for self-registration tests: DNS, a Moodle site with local_ubionai, no network.

All values are fake. Addresses are globally routable look-alikes so the address policy passes;
nothing ever connects (httpx.MockTransport sits below the pinning layer).
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import time
from urllib.parse import parse_qs, urlsplit

import httpx

from moodle_mcp.oauth import USER_SERVICE_FUNCTIONS
from moodle_mcp.siteauth import derive_mac_key, verify_message

HOST = "lms.school.example"
SITE_URL = f"https://{HOST}/moodle"
HOST_KEY = f"{HOST}/moodle"
PUBLIC_IP = "1.2.3.4"
HUB = "https://hub.example"
PLUGIN_VERSION = 2026110300


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class FakeDNS:
    def __init__(self, records: dict[str, list[str]] | None = None) -> None:
        self.records = records if records is not None else {HOST: [PUBLIC_IP], "hub.example": ["5.6.7.8"]}
        self.calls: list[str] = []

    async def __call__(self, host: str, port: int) -> list[str]:
        self.calls.append(host)
        if host not in self.records:
            raise OSError("NXDOMAIN")
        return list(self.records[host])


class FakeSite:
    """Moodle + local_ubionai (register_callback.php, oauth/*.php, REST) as an httpx transport."""

    def __init__(self, site_url: str = SITE_URL, ip: str = PUBLIC_IP) -> None:
        self.site_url = site_url
        parts = urlsplit(site_url)
        self.host = parts.hostname
        self.base_path = parts.path
        self.ip = ip
        self.pending: dict[str, bytes] = {}  # nonce -> challenge
        self.callback_override = None  # callable(request) -> httpx.Response
        self.callback_hits = 0
        self.seen: list[tuple[str, str, str]] = []  # (url host, Host header, path)
        # OAuth side: site_secret / site_key / version as stored by the plugin after confirm
        self.secret: str | None = None
        self.site_key: str | None = None
        self.version: int | None = None
        self.codes: dict[str, tuple[int, str]] = {}
        self.tokens: dict[str, tuple[int, int]] = {}
        self.revoked: list[tuple[int, int]] = []
        self.next_tokenid = 100
        self.calls: list[str] = []

    # plugin side of registration ------------------------------------------------------
    def new_registration(self, **overrides) -> dict:
        nonce = b64(os.urandom(32))
        challenge = os.urandom(32)
        self.pending[nonce] = challenge
        body = {
            "schema": "ubionai.site-registration/v1",
            "site_url": self.site_url,
            "wwwroot_host": self.host,
            "moodle": {"release": "5.1.1+ (Build: 20260115)", "version": "2025100601.01", "branch": "501"},
            "plugin": {"component": "local_ubionai", "version": PLUGIN_VERSION, "release": "0.7.0"},
            "site_identifier_hash": hashlib.sha256(b"ubionai-site-v1\0fake-" + self.host.encode()).hexdigest(),
            "callback_nonce": nonce,
            "challenge_sha256": b64(hashlib.sha256(challenge).digest()),
            "consent": {
                "accepted": True,
                "terms_version": "2026-11-01",
                "accepted_at": "2026-11-03T05:12:00Z",
                "scopes": ["hub_processing", "llm_provider_transfer"],
            },
            "locale": "ko",
            "auth_modes": ["shared_secret"],
        }
        body.update(overrides)
        return body

    def adopt(self, result: dict) -> None:
        self.secret = result["site_secret"]
        self.site_key = result["site_key"]
        self.version = result["secret_version"]

    @property
    def mac_key(self) -> bytes:
        assert self.secret and self.site_key and self.version
        return derive_mac_key(self.secret, self.site_key, self.version)

    def verify(self, token: str, typ: str) -> dict:
        claims = verify_message(self.mac_key, token, typ)
        assert claims is not None, f"bad {typ} signature"
        assert claims["kv"] == self.version
        return claims

    # browser leg of OAuth ---------------------------------------------------------------
    def approve(self, url: str, userid: int) -> str:
        req = parse_qs(urlsplit(url).query)["req"][0]
        claims = self.verify(req, "authz_req")
        assert claims["aud"] == self.site_url
        code = secrets.token_urlsafe(16)
        self.codes[code] = (userid, claims["state"])
        return claims["callback"] + "?" + f"code={code}&state={claims['state']}"

    async def handler(self, request: httpx.Request) -> httpx.Response:
        self.seen.append((request.url.host, request.headers.get("host", ""), request.url.path))
        assert request.url.host == self.ip, "connection was not pinned to the vetted IP"
        assert request.headers.get("host") == self.host
        assert request.extensions.get("sni_hostname") == self.host
        path = request.url.path
        if path == self.base_path + "/local/ubionai/register_callback.php":
            self.callback_hits += 1
            if self.callback_override is not None:
                result = self.callback_override(request)
                if hasattr(result, "__await__"):
                    result = await result
                return result
            nonce = request.url.params.get("nonce", "")
            challenge = self.pending.get(nonce)
            if challenge is None or request.headers.get("cookie") or request.headers.get("authorization"):
                return httpx.Response(404, json={"error": "unknown_nonce"})
            return httpx.Response(
                200,
                json={
                    "typ": "ubionai-register-callback/v1",
                    "nonce": nonce,
                    "challenge": b64(challenge),
                    "wwwroot": self.site_url,
                    "plugin_version": PLUGIN_VERSION,
                    "site_identifier_hash": "00" * 32,
                },
                headers={"Cache-Control": "no-store"},
            )
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        if path == self.base_path + "/local/ubionai/oauth/exchange.php":
            claims = self.verify(form["assertion"], "exchange")
            entry = self.codes.pop(claims["code"], None)
            if entry is None or entry[1] != claims["state"]:
                return httpx.Response(400, json={"error": "invalid_grant"})
            userid = entry[0]
            token = f"user-token-{userid}-{secrets.token_hex(4)}"
            self.next_tokenid += 1
            self.tokens[token] = (userid, self.next_tokenid)
            return httpx.Response(200, json={"userid": userid, "tokenid": self.next_tokenid, "wstoken": token,
                                             "validuntil": int(time.time()) + 86400})
        if path == self.base_path + "/local/ubionai/oauth/revoke.php":
            claims = self.verify(form["assertion"], "revoke")
            self.revoked.append((claims["userid"], claims["tokenid"]))
            return httpx.Response(200, json={"revoked": True})
        if path == self.base_path + "/webservice/rest/server.php":
            token, fn = form.pop("wstoken"), form.pop("wsfunction")
            self.calls.append(fn)
            if token not in self.tokens:
                return httpx.Response(200, json={"exception": "x", "errorcode": "invalidtoken", "message": "no"})
            userid = self.tokens[token][0]
            if fn == "core_webservice_get_site_info":
                return httpx.Response(200, json={
                    "userid": userid, "userissiteadmin": False,
                    "functions": [{"name": f} for f in sorted(USER_SERVICE_FUNCTIONS)],
                })
            if fn == "core_enrol_get_users_courses":
                return httpx.Response(200, json=[{"id": 2, "shortname": "C2", "fullname": "Existing course"}])
            return httpx.Response(200, json={})
        return httpx.Response(404)
