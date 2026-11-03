"""Site self-registration API (registration contract v1 = option 1, shared secret).

``POST /api/v1/sites/register`` proves control of a Moodle wwwroot with a callback to
``{wwwroot}/local/ubionai/register_callback.php`` (ACME http-01 style), then creates a
``tier=limited`` tenant without any site token or static bearer and issues a ``site_secret``
once. ``confirm`` promotes the pending secret, ``rotate`` issues a new one, ``status`` reports.
The hub stores only ``sha256(site_secret)`` and the KEK-sealed derived MAC key.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import quote, urlsplit

from .crypto import Kek
from .hostkey import (
    HostKeyError,
    normalize_host_key,
    normalize_hostname,
    normalize_site_url,
    parse_ports,
    site_key_for,
)
from .netutil import (
    AddressPolicy,
    FetchError,
    IPNetwork,
    SafeFetcher,
    client_ip_key,
    client_prefix_key,
    parse_networks,
    trusted_client_ip,
)
from .ratelimit import DAY, HOUR, RateLimiter, Rule
from .registry import DuplicateSite, Registry, Tenant
from .siteauth import (
    MAC_SALT,
    ConfirmError,
    IssuedCredential,
    SharedSecretCredentialStore,
    b64url,
    mac_info,
    unb64url,
)

logger = logging.getLogger(__name__)

REQUEST_SCHEMA = "ubionai.site-registration/v1"
RESULT_SCHEMA = "ubionai.site-registration-result/v1"
CALLBACK_TYP = "ubionai-register-callback/v1"
CALLBACK_PATH = "/local/ubionai/register_callback.php"
PLUGIN_COMPONENT = "local_ubionai"
CONSENT_SCOPES = frozenset({"hub_processing", "llm_provider_transfer"})
FORBIDDEN_KEYS = frozenset({"wstoken", "token", "password"})
MAX_BODY = 16_384
TOTAL_TIMEOUT = 15.0
AUDIT_RETENTION = 90 * DAY
VERIFIER_CONCURRENCY = 20
IN_PROGRESS_RETRY = 15
LIMITED_LIMITS = {"max_teachers": 5, "daily_tool_calls": 300, "concurrency": 1, "llm_proxy": False}

_B64_43 = re.compile(r"[A-Za-z0-9_-]{43}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_TERMS = re.compile(r"\d{4}-\d{2}-\d{2}")
_MOODLE_VERSION = re.compile(r"\d{10}(\.\d{1,2})?")
_SITE_KEY_PATH = re.compile(r"^/api/v1/sites/([a-z0-9][a-z0-9-]{1,62})/(confirm|rotate|status)$")

HUB_META_PATH = "/.well-known/ubionai-hub.json"
HUB_KEYS_PATH = "/.well-known/ubionai-hub-keys.json"


def _flag(name: str, default: str) -> bool:
    return (os.environ.get(name) or default).strip() == "1"


@dataclass(frozen=True)
class RegistrationConfig:
    """Feature flags and policy (contract §6.4). Defaults are the contract's."""

    enabled: bool = False
    host_routes: bool = False
    legacy_routes: bool = True
    auto_activate: bool = True
    allowed_ports: frozenset[int] = frozenset({443})
    deny_cidrs: tuple[IPNetwork, ...] = ()
    blocked_hosts: frozenset[str] = frozenset()
    min_plugin_version: int = 2026110300
    min_terms_version: str = "2026-11-01"
    trusted_proxies: tuple[IPNetwork, ...] = ()
    daily_new_tenants: int = 200
    public_keys: tuple[dict[str, Any], ...] = ()

    @classmethod
    def from_env(cls) -> "RegistrationConfig":
        tier = (os.environ.get("UBIONAI_HUB_REG_DEFAULT_TIER") or "limited").strip()
        if tier != "limited":
            raise ValueError("UBIONAI_HUB_REG_DEFAULT_TIER must be 'limited' (self-registration is lowest tier)")
        ports = parse_ports(os.environ.get("UBIONAI_HUB_REG_ALLOWED_PORTS"))
        min_plugin = (os.environ.get("UBIONAI_HUB_REG_MIN_PLUGIN_VERSION") or "2026110300").strip()
        if not min_plugin.isdigit():
            raise ValueError("UBIONAI_HUB_REG_MIN_PLUGIN_VERSION must be an integer")
        terms = (os.environ.get("UBIONAI_HUB_REG_MIN_TERMS_VERSION") or "2026-11-01").strip()
        if not _TERMS.fullmatch(terms):
            raise ValueError("UBIONAI_HUB_REG_MIN_TERMS_VERSION must be YYYY-MM-DD")
        blocked: set[str] = set()
        for entry in (os.environ.get("UBIONAI_HUB_REG_BLOCKED_HOSTS") or "").split(","):
            if entry.strip():
                try:
                    blocked.add(normalize_host_key(entry.strip(), frozenset(range(1, 65536))))
                except HostKeyError:
                    raise ValueError(f"UBIONAI_HUB_REG_BLOCKED_HOSTS: invalid entry '{entry.strip()}'") from None
        return cls(
            enabled=_flag("UBIONAI_HUB_SELF_REGISTRATION", "0"),
            host_routes=_flag("UBIONAI_HUB_HOST_ROUTES", "0"),
            legacy_routes=_flag("UBIONAI_HUB_LEGACY_TENANT_ROUTES", "1"),
            auto_activate=_flag("UBIONAI_HUB_REG_AUTO_ACTIVATE", "1"),
            allowed_ports=ports,
            deny_cidrs=parse_networks(os.environ.get("UBIONAI_HUB_REG_DENY_CIDRS")),
            blocked_hosts=frozenset(blocked),
            min_plugin_version=int(min_plugin),
            min_terms_version=terms,
            trusted_proxies=parse_networks(os.environ.get("UBIONAI_HUB_TRUSTED_PROXIES")),
            public_keys=load_public_keys(os.environ.get("UBIONAI_HUB_PUBLIC_KEYS_FILE")),
        )


_PUBLIC_JWK_MEMBERS = frozenset({"kty", "crv", "x", "kid", "use", "alg", "status", "nbf", "exp"})


def load_public_keys(path: str | None) -> tuple[dict[str, Any], ...]:
    """Optional hub public key set for option 2 (§7.3): a JSON list of Ed25519 public JWKs.

    The hub never generates keys here; anything that looks like private key material is refused.
    """
    if not path:
        return ()
    with open(path, "rb") as handle:
        data = json.loads(handle.read())
    keys = data.get("keys") if isinstance(data, dict) else data
    if not isinstance(keys, list):
        raise ValueError("UBIONAI_HUB_PUBLIC_KEYS_FILE must hold a list of public JWKs")
    out = []
    for key in keys:
        if not isinstance(key, dict) or not set(key) <= _PUBLIC_JWK_MEMBERS:
            raise ValueError("UBIONAI_HUB_PUBLIC_KEYS_FILE: only public JWK members are allowed")
        if key.get("kty") != "OKP" or key.get("crv") != "Ed25519" or not isinstance(key.get("x"), str):
            raise ValueError("UBIONAI_HUB_PUBLIC_KEYS_FILE: Ed25519 OKP keys only")
        if not isinstance(key.get("kid"), str) or key.get("status", "current") not in ("current", "next"):
            raise ValueError("UBIONAI_HUB_PUBLIC_KEYS_FILE: kid and status (current|next) required")
        out.append(dict(key))
    return tuple(out)


class ApiError(Exception):
    def __init__(self, status: int, code: str, description: str, retry_after: int | None = None) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.description = description
        self.retry_after = retry_after


def _rfc3339(ts: int | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_rfc3339(value: str) -> int | None:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return int(dt.timestamp())


def _has_forbidden_key(value: Any, depth: int = 0) -> bool:
    if depth > 8:
        return True
    if isinstance(value, dict):
        return any(
            (isinstance(k, str) and k.lower() in FORBIDDEN_KEYS) or _has_forbidden_key(v, depth + 1)
            for k, v in value.items()
        )
    if isinstance(value, list):
        return any(_has_forbidden_key(v, depth + 1) for v in value)
    return False


def _str(value: Any, max_len: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= max_len


@dataclass(frozen=True)
class RegistrationRequest:
    site_url: str
    wwwroot_host: str
    moodle_release: str
    plugin_version: int
    site_identifier_hash: bytes
    nonce: str
    challenge_sha256: str
    consent_accepted: bool
    consent_scopes: frozenset[str]
    terms_version: str
    consent_at: int
    contact: dict[str, str] | None


def parse_registration(body: Any) -> RegistrationRequest:
    """Schema check (§1.3). Unknown top-level fields are ignored; token-like keys are refused."""

    def bad(desc: str) -> ApiError:
        return ApiError(400, "invalid_request", desc)

    if not isinstance(body, dict):
        raise bad("body must be a JSON object")
    if _has_forbidden_key(body):
        raise bad("site tokens and passwords are never accepted")
    if body.get("schema") != REQUEST_SCHEMA:
        raise bad(f"schema must be {REQUEST_SCHEMA}")
    moodle, plugin, consent = body.get("moodle"), body.get("plugin"), body.get("consent")
    if not isinstance(moodle, dict) or not isinstance(plugin, dict) or not isinstance(consent, dict):
        raise bad("moodle, plugin and consent objects are required")
    if not isinstance(body.get("site_url"), str) or not _str(body.get("wwwroot_host"), 253):
        raise bad("site_url and wwwroot_host are required")
    if not _str(moodle.get("release"), 100) or not (
        isinstance(moodle.get("version"), str) and _MOODLE_VERSION.fullmatch(moodle["version"])
    ):
        raise bad("moodle.release and moodle.version (string) are required")
    if not (isinstance(moodle.get("branch"), str) and moodle["branch"].isdigit() and len(moodle["branch"]) <= 6):
        raise bad("moodle.branch is required")
    version = plugin.get("version")
    if plugin.get("component") != PLUGIN_COMPONENT or not isinstance(version, int) or isinstance(version, bool):
        raise bad("plugin.component must be local_ubionai and plugin.version an integer")
    if not _str(plugin.get("release"), 50):
        raise bad("plugin.release is required")
    sih = body.get("site_identifier_hash")
    if not (isinstance(sih, str) and _HEX64.fullmatch(sih)):
        raise bad("site_identifier_hash must be 64 lowercase hex characters")
    nonce, csha = body.get("callback_nonce"), body.get("challenge_sha256")
    if not (isinstance(nonce, str) and _B64_43.fullmatch(nonce)):
        raise bad("callback_nonce must be 32 bytes base64url")
    if not (isinstance(csha, str) and _B64_43.fullmatch(csha)):
        raise bad("challenge_sha256 must be 32 bytes base64url")
    accepted = consent.get("accepted")
    terms = consent.get("terms_version")
    scopes = consent.get("scopes")
    accepted_at = consent.get("accepted_at")
    if not isinstance(accepted, bool) or not (isinstance(terms, str) and _TERMS.fullmatch(terms)):
        raise bad("consent.accepted (boolean) and consent.terms_version (YYYY-MM-DD) are required")
    if not isinstance(scopes, list) or not all(isinstance(s, str) for s in scopes):
        raise bad("consent.scopes must be a list of strings")
    consent_at = _parse_rfc3339(accepted_at) if isinstance(accepted_at, str) else None
    if consent_at is None:
        raise bad("consent.accepted_at must be RFC 3339")
    modes = body.get("auth_modes", ["shared_secret"])
    if not isinstance(modes, list) or "shared_secret" not in modes:
        raise bad("auth_modes must include shared_secret (v1)")
    contact = body.get("admin_contact")
    contact_out: dict[str, str] | None = None
    if contact is not None:
        if not isinstance(contact, dict) or not _str(contact.get("email"), 254) or "@" not in contact["email"]:
            raise bad("admin_contact.email is invalid")
        contact_out = {"email": contact["email"]}
        if contact.get("name") is not None:
            if not _str(contact.get("name"), 100):
                raise bad("admin_contact.name is invalid")
            contact_out["name"] = contact["name"]
    return RegistrationRequest(
        site_url=body["site_url"],
        wwwroot_host=body["wwwroot_host"],
        moodle_release=moodle["release"],
        plugin_version=version,
        site_identifier_hash=bytes.fromhex(sih),
        nonce=nonce,
        challenge_sha256=csha,
        consent_accepted=accepted,
        consent_scopes=frozenset(scopes),
        terms_version=terms,
        consent_at=consent_at,
        contact=contact_out,
    )


_FETCH_ERRORS = {
    "blocked": (403, "private_address_not_supported", "the site resolves to a non-public address (not supported in v1)"),
    "unreachable": (502, "callback_unreachable", "the hub could not reach the registration callback"),
    "redirected": (422, "callback_redirected", "the registration callback redirected; check $CFG->wwwroot"),
    "too_large": (502, "callback_bad_response", "the registration callback response was too large"),
    "timeout": (504, "callback_timeout", "the registration callback timed out"),
}


@dataclass
class RegistrationAPI:
    """``/api/v1/sites/…`` and ``/.well-known/ubionai-hub*.json`` (served before OAuth routes)."""

    registry: Registry
    kek: Kek
    public_url: str
    config: RegistrationConfig
    egress_ips: list[str] = field(default_factory=list)
    fetcher: SafeFetcher | None = None
    limiter: RateLimiter = field(default_factory=RateLimiter)
    clock: Callable[[], float] = time.time
    _in_progress: set[str] = field(default_factory=set)
    _verifying: int = 0
    _self_vetted: bool = False

    def __post_init__(self) -> None:
        self.public_url = self.public_url.rstrip("/")
        self.store = SharedSecretCredentialStore(self.registry, self.kek, clock=lambda: int(self.clock()))
        policy = AddressPolicy(extra_deny=self.config.deny_cidrs)
        for ip in self.egress_ips:
            try:
                policy.self_addresses.add(ipaddress.ip_address(ip.split("/", 1)[0]))
            except ValueError:
                pass
        if self.fetcher is None:
            self.fetcher = SafeFetcher(policy=policy)
        else:
            self.fetcher.policy = policy
        hub_host = urlsplit(self.public_url).hostname or ""
        self.fetcher.headers = {
            "Accept": "application/json",
            "User-Agent": f"UBIONAI-Hub-Verifier/1 (+https://{hub_host}/bot)",
        }

    # --- routing --------------------------------------------------------------------------
    @staticmethod
    def handles(path: str) -> bool:
        return path.startswith("/api/v1/sites/") or path in (HUB_META_PATH, HUB_KEYS_PATH)

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        path = scope.get("path", "")
        method = scope.get("method", "")
        raw = scope.get("raw_path")
        try:
            if raw and raw.decode("latin-1") != path:
                raise ApiError(404, "invalid_request", "not found")
            if not self.config.enabled:
                raise ApiError(503, "registration_disabled", "self-registration is not enabled on this hub", 6 * HOUR)
            if path == HUB_META_PATH:
                await self._send(send, 200, self.hub_metadata(), cache="public, max-age=3600")
                return
            if path == HUB_KEYS_PATH:
                await self._send(send, 200, self.hub_keys(), cache="public, max-age=3600")
                return
            if path == "/api/v1/sites/register":
                if method != "POST":
                    raise ApiError(405, "invalid_request", "use POST")
                body = await self._json_body(scope, receive)
                status, payload = await self._register_with_deadline(scope, body)
                await self._send(send, status, payload)
                return
            match = _SITE_KEY_PATH.fullmatch(path)
            if match is None:
                raise ApiError(404, "invalid_request", "not found")
            site_key, action = match.groups()
            if (action == "status") != (method == "GET") or method not in ("GET", "POST"):
                raise ApiError(405, "invalid_request", "method not allowed")
            body = await self._json_body(scope, receive) if method == "POST" else None
            status, payload = self.site_action(scope, site_key, action, body)
            await self._send(send, status, payload)
        except ApiError as exc:
            await self._error(send, exc)
        except Exception:  # pragma: no cover - defensive
            logger.exception("registration API failure path=%s", path)
            await self._error(send, ApiError(500, "internal_error", "internal error"))

    # --- I/O helpers ----------------------------------------------------------------------
    @staticmethod
    def _headers(scope: Any) -> dict[bytes, bytes]:
        return {name.lower(): value for name, value in scope.get("headers", [])}

    async def _json_body(self, scope: Any, receive: Any) -> Any:
        headers = self._headers(scope)
        ctype = headers.get(b"content-type", b"").split(b";", 1)[0].strip().lower()
        if ctype != b"application/json":
            raise ApiError(415, "unsupported_media_type", "Content-Type must be application/json")
        try:
            declared = int(headers.get(b"content-length", b"0"))
        except ValueError:
            declared = 0
        if declared > MAX_BODY:
            raise ApiError(413, "request_too_large", "body exceeds 16 KiB")
        chunks: list[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                break
            if message["type"] != "http.request":
                continue
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > MAX_BODY:
                raise ApiError(413, "request_too_large", "body exceeds 16 KiB")
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        try:
            return json.loads(b"".join(chunks))
        except (ValueError, UnicodeDecodeError):
            raise ApiError(400, "invalid_request", "body must be JSON") from None

    @staticmethod
    async def _send(send: Any, status: int, body: dict[str, Any], cache: str = "no-store",
                    extra: list[tuple[bytes, bytes]] | None = None) -> None:
        payload = json.dumps(body).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
            (b"cache-control", cache.encode()),
            (b"x-content-type-options", b"nosniff"),
        ] + (extra or [])
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": payload})

    async def _error(self, send: Any, exc: ApiError) -> None:
        body: dict[str, Any] = {"error": exc.code, "error_description": exc.description}
        extra = []
        if exc.retry_after is not None:
            body["retry_after"] = exc.retry_after
            extra.append((b"retry-after", str(exc.retry_after).encode()))
        await self._send(send, exc.status, body, extra=extra)

    def client_ip(self, scope: Any) -> str:
        peer = (scope.get("client") or ("", 0))[0]
        xff = self._headers(scope).get(b"x-forwarded-for")
        return trusted_client_ip(peer, xff.decode("latin-1") if xff else None, self.config.trusted_proxies)

    # --- URLs -----------------------------------------------------------------------------
    def mcp_url(self, tenant: Tenant) -> str | None:
        if not self.config.host_routes or tenant.host_key is None:
            return None
        return f"{self.public_url}/m/{tenant.host_key}/mcp"

    def legacy_mcp_url(self, tenant: Tenant) -> str:
        return f"{self.public_url}/t/{tenant.site_id}/mcp"

    def issuers(self, tenant: Tenant) -> list[str]:
        out = []
        if self.config.host_routes and tenant.host_key is not None:
            out.append(f"{self.public_url}/m/{tenant.host_key}")
        out.append(f"{self.public_url}/t/{tenant.site_id}")
        return out

    def hub_metadata(self) -> dict[str, Any]:
        return {
            "issuer": self.public_url,
            "api_version": "v1",
            "registration_endpoint": f"{self.public_url}/api/v1/sites/register",
            "auth_modes": ["shared_secret"],  # "signature" only once option 2 ships
            "min_plugin_version": self.config.min_plugin_version,
            "min_terms_version": self.config.min_terms_version,
            "hub_keys_url": f"{self.public_url}{HUB_KEYS_PATH}",
            "egress_ips": self.egress_ips,
            "host_routes": self.config.host_routes,
        }

    def hub_keys(self) -> dict[str, Any]:
        return {"issuer": self.public_url, "keys": [dict(k) for k in self.config.public_keys]}

    def issued_payload(self, tenant: Tenant, issued: IssuedCredential) -> dict[str, Any]:
        return {
            "schema": RESULT_SCHEMA,
            "site_key": tenant.site_id,
            "site_secret": issued.site_secret,
            "secret_version": issued.version,
            "secret_state": "pending_confirm",
            "confirm_url": f"{self.public_url}/api/v1/sites/{tenant.site_id}/confirm",
            "confirm_by": _rfc3339(issued.expires_at),
            "tenant": {"status": tenant.status, "tier": tenant.tier, "limits": dict(LIMITED_LIMITS)},
            "mcp_url": self.mcp_url(tenant),
            "legacy_mcp_url": self.legacy_mcp_url(tenant),
            "oauth": {
                "allowed_callbacks": [f"{iss}/oauth/callback" for iss in self.issuers(tenant)],
                "issuers": self.issuers(tenant),
            },
            "auth_mode": "shared_secret",
            "mac": {
                "alg": "HMAC-SHA256",
                "kdf": "HKDF-SHA256",
                "salt": MAC_SALT.decode(),
                "info": mac_info(tenant.site_id, issued.version),
            },
            "egress_ips": self.egress_ips,
            "hub_keys_url": f"{self.public_url}{HUB_KEYS_PATH}",
        }

    # --- register -------------------------------------------------------------------------
    async def _register_with_deadline(self, scope: Any, body: Any) -> tuple[int, dict[str, Any]]:
        try:
            async with asyncio.timeout(TOTAL_TIMEOUT):
                return await self.register(scope, body)
        except TimeoutError:
            raise ApiError(500, "internal_error", "registration took too long") from None

    def _policy(self, req: RegistrationRequest) -> tuple[str, str, str]:
        """Steps 1–2 of §1.2: normalise, compare wwwroot_host, port/host form, blocklist, versions, consent."""
        try:
            site = normalize_site_url(req.site_url, self.config.allowed_ports)
        except HostKeyError as exc:
            status = 400 if exc.code in ("invalid_site_url", "unsupported_scheme") else 403
            raise ApiError(status, exc.code, str(exc)) from None
        try:
            claimed_host = normalize_hostname(req.wwwroot_host)
        except HostKeyError:
            claimed_host = None
        if claimed_host != site.host:
            raise ApiError(422, "site_url_mismatch", "wwwroot_host does not match site_url")
        if site.host_key in self.config.blocked_hosts or site.host in self.config.blocked_hosts:
            raise ApiError(403, "host_blocked", "this site cannot be registered; contact the hub operator")
        if req.plugin_version < self.config.min_plugin_version:
            raise ApiError(426, "plugin_upgrade_required", "upgrade local_ubionai")
        if not req.consent_accepted or not CONSENT_SCOPES <= req.consent_scopes:
            raise ApiError(403, "consent_required", "the administrator has not accepted the terms")
        if req.terms_version < self.config.min_terms_version:
            raise ApiError(403, "consent_outdated", "the accepted terms are outdated; upgrade the plugin")
        return site.url, site.host_key, site.host

    def _rate_limit(self, ip: str, host_key: str) -> None:
        wait = self.limiter.negative_wait(f"neg:{host_key}")
        if wait is not None:
            raise ApiError(429, "rate_limited", "recent verification failures for this site", wait)
        ip_key = client_ip_key(ip)
        rules = (
            Rule(f"ip:{ip_key}", 10, HOUR),
            Rule(f"ip:{ip_key}", 30, DAY),
            Rule(f"net:{client_prefix_key(ip)}", 30, DAY),
            Rule(f"host:{host_key}", 5, HOUR),
            Rule(f"host:{host_key}", 20, DAY),
        )
        wait = self.limiter.hit(*rules)
        if wait is not None:
            raise ApiError(429, "rate_limited", "too many registration attempts", wait)

    async def _vet_self(self) -> None:
        """Refuse callbacks to the hub itself (resolved lazily, once, with the fetcher's resolver)."""
        if self._self_vetted:
            return
        self._self_vetted = True
        assert self.fetcher is not None
        host = urlsplit(self.public_url).hostname
        if not host:
            return
        try:
            addresses = [host] if _is_ip(host) else await self.fetcher.resolve(host, 443)
        except OSError:
            return
        for address in addresses:
            try:
                self.fetcher.policy.self_addresses.add(ipaddress.ip_address(address.strip("[]")))
            except ValueError:
                pass

    def _audit(self, nonce_hash: bytes, host_key: str, ip: str, plugin_version: int) -> int:
        now = int(self.clock())
        try:
            with self.registry._connect() as conn:
                conn.execute("DELETE FROM site_registrations WHERE created_at < ?", (now - AUDIT_RETENTION,))
                cur = conn.execute(
                    "INSERT INTO site_registrations (host_key, site_id, nonce_hash, client_ip_prefix, outcome,"
                    " error, plugin_version, created_at) VALUES (?, NULL, ?, ?, 'started', NULL, ?, ?)",
                    (host_key, nonce_hash, client_prefix_key(ip), plugin_version, now),
                )
                return int(cur.lastrowid or 0)
        except sqlite3.IntegrityError:
            raise ApiError(409, "nonce_reused", "callback_nonce was already used; generate a new one") from None

    def _audit_done(self, audit_id: int, outcome: str, error: str | None, site_id: str | None) -> None:
        with self.registry._connect() as conn:
            conn.execute(
                "UPDATE site_registrations SET outcome = ?, error = ?, site_id = ? WHERE id = ?",
                (outcome, error, site_id, audit_id),
            )

    def _reregistrations_since(self, host_key: str, since: int) -> int:
        with self.registry._connect() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM site_registrations WHERE host_key = ? AND outcome = 'reregistered'"
                " AND created_at >= ?",
                (host_key, since),
            ).fetchone()[0]

    async def _verify_callback(self, req: RegistrationRequest, site_url: str) -> None:
        assert self.fetcher is not None
        url = f"{site_url}{CALLBACK_PATH}?nonce={quote(req.nonce, safe='')}"
        try:
            doc = await self.fetcher.get_json(url)
        except FetchError as exc:
            logger.info("registration callback failed url_host=%s: %s", urlsplit(site_url).hostname, exc)
            if exc.kind == "status":
                if exc.status == 404:
                    raise ApiError(422, "callback_mismatch", "the callback did not recognise this request") from None
                raise ApiError(502, "callback_bad_response", "the callback did not return the expected JSON") from None
            status, code, desc = _FETCH_ERRORS[exc.kind]
            raise ApiError(status, code, desc) from None
        if not isinstance(doc, dict) or doc.get("typ") != CALLBACK_TYP:
            raise ApiError(502, "callback_bad_response", "the callback did not return the expected JSON")
        nonce, challenge, wwwroot = doc.get("nonce"), doc.get("challenge"), doc.get("wwwroot")
        if not isinstance(nonce, str) or not _consteq(nonce, req.nonce):
            raise ApiError(422, "callback_mismatch", "callback nonce mismatch")
        if not (isinstance(challenge, str) and _B64_43.fullmatch(challenge)):
            raise ApiError(422, "callback_mismatch", "callback challenge missing")
        if not _consteq(b64url(hashlib.sha256(unb64url(challenge)).digest()), req.challenge_sha256):
            raise ApiError(422, "callback_mismatch", "callback challenge mismatch")
        try:
            same_root = isinstance(wwwroot, str) and normalize_site_url(wwwroot, self.config.allowed_ports).url == site_url
        except HostKeyError:
            same_root = False
        if not same_root:
            raise ApiError(422, "callback_mismatch", "callback wwwroot differs from site_url")
        if doc.get("plugin_version") != req.plugin_version or isinstance(doc.get("plugin_version"), bool):
            raise ApiError(422, "callback_mismatch", "callback plugin_version mismatch")

    def _new_site_key(self, host_key: str) -> str:
        for length in (6, 8, 10, 12, 14):
            candidate = site_key_for(host_key, length)
            if self.registry.get(candidate) is None:
                return candidate
        raise ApiError(500, "internal_error", "could not allocate a site key")

    async def register(self, scope: Any, body: Any) -> tuple[int, dict[str, Any]]:
        req = parse_registration(body)
        site_url, host_key, _host = self._policy(req)
        ip = self.client_ip(scope)
        self._rate_limit(ip, host_key)
        if host_key in self._in_progress:
            raise ApiError(409, "registration_in_progress", "another registration for this site is running",
                           IN_PROGRESS_RETRY)
        if self._verifying >= VERIFIER_CONCURRENCY:
            raise ApiError(503, "verifier_busy", "the verifier is busy", 5)
        self._in_progress.add(host_key)
        self._verifying += 1
        audit_id: int | None = None
        try:
            audit_id = self._audit(hashlib.sha256(req.nonce.encode()).digest(), host_key, ip, req.plugin_version)
            await self._vet_self()
            try:
                await self._verify_callback(req, site_url)
            except ApiError:
                self.limiter.negative_fail(f"neg:{host_key}")
                raise
            self.limiter.negative_clear(f"neg:{host_key}")
            status, payload, site_id, outcome = self._register_verified(req, site_url, host_key)
            self._audit_done(audit_id, outcome, None, site_id)
            return status, payload
        except ApiError as exc:
            if audit_id:
                self._audit_done(audit_id, "failed", exc.code, None)
            raise
        finally:
            self._verifying -= 1
            self._in_progress.discard(host_key)

    def _register_verified(
        self, req: RegistrationRequest, site_url: str, host_key: str
    ) -> tuple[int, dict[str, Any], str, str]:
        now = int(self.clock())
        contact = json.dumps(req.contact).encode() if req.contact else None
        tenant = self.registry.get_by_host_key(host_key)
        if tenant is not None and not tenant.self_registered:
            raise ApiError(409, "site_managed_by_operator", "this site is managed by the hub operator")
        if tenant is not None and tenant.status == "disabled":
            raise ApiError(403, "host_blocked", "this site cannot be registered; contact the hub operator")
        if tenant is None:
            status = "active" if self.config.auto_activate else "pending"
            if self.registry.count_self_registered_since(now - DAY) >= self.config.daily_new_tenants:
                logger.warning("self-registration: daily new-tenant limit reached; %s created pending", host_key)
                status = "pending"
            if self.registry.site_identifier_elsewhere(req.site_identifier_hash, host_key):
                logger.warning("self-registration: %s shares a Moodle siteidentifier with another host"
                               " (cloned database?); created pending for operator review", host_key)
                status = "pending"
            try:
                tenant = self.registry.add_self_registered(
                    self._new_site_key(host_key), site_url, host_key, status=status,
                    site_identifier_hash=req.site_identifier_hash, plugin_version=req.plugin_version,
                    moodle_release=req.moodle_release, consent_version=req.terms_version,
                    consent_at=req.consent_at, contact=contact,
                )
            except DuplicateSite:
                raise ApiError(409, "registration_in_progress", "the site was registered concurrently",
                               IN_PROGRESS_RETRY) from None
            logger.info("self-registration: tenant created site=%s host=%s status=%s", tenant.site_id, host_key, status)
            issued = self.store.issue(tenant.site_id)
            return 201, self.issued_payload(tenant, issued), tenant.site_id, "created"
        if self._reregistrations_since(host_key, now - DAY) >= 3:
            self.registry.set_status(tenant.site_id, "pending")
            logger.warning("self-registration: %s re-registered more than 3 times in 24h; set pending", host_key)
            raise ApiError(429, "rate_limited", "too many re-registrations; the site is held for review", DAY)
        self.registry.record_verification(
            tenant.site_id, plugin_version=req.plugin_version, moodle_release=req.moodle_release,
            site_identifier_hash=req.site_identifier_hash, consent_version=req.terms_version,
            consent_at=req.consent_at, contact=contact,
        )
        tenant = self.registry.get(tenant.site_id) or tenant
        issued = self.store.issue(tenant.site_id)  # current (if any) keeps working until confirm
        logger.info("self-registration: re-registered site=%s version=%s", tenant.site_id, issued.version)
        return 200, self.issued_payload(tenant, issued), tenant.site_id, "reregistered"

    # --- confirm / rotate / status --------------------------------------------------------
    def site_action(self, scope: Any, site_key: str, action: str, body: Any) -> tuple[int, dict[str, Any]]:
        wait = self.limiter.hit(Rule(f"site:{site_key}", 30, HOUR))
        if wait is not None:
            raise ApiError(429, "rate_limited", "too many requests for this site", wait)
        tenant = self.registry.get(site_key)
        if tenant is None or not tenant.self_registered:
            raise ApiError(404, "site_not_found", "unknown site_key; register again")
        presented = _bearer(self._headers(scope).get(b"authorization"))
        if presented is None:
            raise ApiError(401, "invalid_site_credentials", "Authorization: Bearer <site_secret> required")
        if tenant.status == "disabled":
            raise ApiError(403, "host_blocked", "this site is disabled; contact the hub operator")
        if action == "confirm":
            version = body.get("secret_version") if isinstance(body, dict) else None
            if not isinstance(version, int) or isinstance(version, bool) or version < 1:
                raise ApiError(400, "invalid_request", "secret_version (integer) is required")
            try:
                self.store.confirm(site_key, version, presented)
            except ConfirmError as exc:
                status = {"invalid_site_credentials": 401, "nothing_to_confirm": 409, "pending_secret_expired": 410}
                raise ApiError(status[exc.code], exc.code, exc.code.replace("_", " ")) from None
            return 200, {"secret_version": version, "secret_state": "current"}
        version = self.store.authenticate(site_key, presented)
        if version is None:
            raise ApiError(401, "invalid_site_credentials", "site_secret does not match the current secret")
        if action == "rotate":
            if not isinstance(body, dict):
                raise ApiError(400, "invalid_request", "body must be a JSON object")
            issued = self.store.issue(site_key)
            return 200, self.issued_payload(tenant, issued)
        return 200, {
            "site_key": tenant.site_id,
            "status": tenant.status,
            "tier": tenant.tier,
            "limits": dict(LIMITED_LIMITS),
            "mcp_url": self.mcp_url(tenant),
            "legacy_mcp_url": self.legacy_mcp_url(tenant),
            "secret_version": version,
            "registered_at": _rfc3339(tenant.created_at),
            "last_verified_at": _rfc3339(tenant.last_verified_at),
            "plugin_version_seen": tenant.plugin_version,
        }


def _consteq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _bearer(value: bytes | None) -> str | None:
    if not value:
        return None
    scheme, _, token = value.decode("latin-1").partition(" ")
    if scheme != "Bearer" or not token or token.strip() != token or len(token) > 200:
        return None
    return token
