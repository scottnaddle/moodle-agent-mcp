"""Per-user OAuth 2.1 for tenants (Easy Connect, hub-staging trial).

The hub is the authorization server and resource server for ``/t/<site>/mcp``. User login is
delegated to the tenant's Moodle (plugin ``local_ubionai`` 0.6.0-spike2):

1. ``/t/<site>/oauth/authorize`` validates the client request (PKCE S256, exact ``resource``,
   redirect allowlist) and redirects the browser to
   ``<moodle_url>/local/ubionai/oauth/authorize.php?req=<signed request>``.
2. The plugin requires Moodle login, refuses site admins and non-teachers, shows a consent page and
   redirects back to ``/t/<site>/oauth/callback?code=…&state=…``.
3. The hub redeems the code over the back channel (``oauth/exchange.php``, signed) for a web service
   token of that teacher (service ``ubionai_user`` only), checks it with
   ``core_webservice_get_site_info`` (not a site admin, function list within the whitelist) and
   stores it sealed with the KEK.
4. The client gets hub access/refresh tokens; MCP calls with an access token run with the
   teacher's own Moodle token.

Hub <-> plugin messages are signed by the tenant's ``SiteAuthenticator`` (``siteauth``):
``auth_mode=legacy_file`` reads ``$UBIONAI_HUB_TENANT_SECRETS_DIR/<site>/oauth.secret`` (a tenant
without that file keeps working with its static bearer only); ``auth_mode=shared_secret``
(self-registered, ``registration``) uses the confirmed site credential's MAC key and adds ``kv``.

The same tenant is also reachable as ``/m/<host_key>/…`` (``TenantRef``); each URL family is its
own issuer / resource, so tokens do not cross between them. Self-registered tenants are reached
only through ``PinnedPublicTransport`` (resolve, vet public, pin the IP on every connection).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import html
import ipaddress
import json
import logging
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable
from urllib.parse import urlencode, urlsplit

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

from .crypto import PURPOSE_DCR_STATELESS, Kek, derive_key, open_, seal
from .limits import TierLimits
from .moodle import MoodleClient, MoodleError
from .netutil import (
    BlockedAddress,
    PinnedPublicTransport,
    ResolveError,
    Resolver,
    ip_allowed,  # noqa: F401 - re-exported (tests, callers of the spike API)
    vet_host,
)
from .netutil import system_resolve as _system_resolve
from .regpage import page_language, render_site_page
from .registry import SITE_ID_RE, Registry, Tenant, ws_endpoint
from .siteauth import (
    MAC_PREFIX,  # noqa: F401 - re-exported
    FileSecretAuthenticator,
    SharedSecretCredentialStore,
    SiteAuthenticator,
    b64url,
    sign_message,  # noqa: F401 - re-exported
    unb64url,
    verify_message,  # noqa: F401 - re-exported
)

logger = logging.getLogger(__name__)

SCOPES = ["moodle:read", "moodle:write"]
# error_description when a limited-tier site already has its maximum number of teachers.
TEACHER_LIMIT_ERROR = "teacher_limit_reached"
ALLOWED_REDIRECTS = (
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
)
SECRET_FILE = "oauth.secret"
MIN_SECRET_LEN = 32
CODE_TTL = 60
REQUEST_TTL = 600
BACKCHANNEL_TTL = 60
ACCESS_TTL = 3600
REFRESH_TTL = 30 * 86400
COOKIE = "ubionai_oauth"
STATELESS_DCR_PREFIX = "dcr_s1."
# Functions of the plugin's ubionai_user service (local_ubionai db/services.php). A token whose
# site_info lists anything else (moodle_mobile_app, a manual service, injected functions) is refused.
USER_SERVICE_FUNCTIONS = frozenset(
    {
        "core_webservice_get_site_info",
        "core_enrol_get_users_courses",
        "core_course_get_courses_by_field",
        "core_course_get_contents",
        "core_enrol_get_enrolled_users",
        "mod_assign_get_assignments",
        "mod_assign_get_submissions",
        "mod_assign_get_grades",
        "mod_assign_save_grade",
        "local_ubionai_create_module",
        "local_ubionai_update_module",
        "local_ubionai_get_course_assignments",
        "local_ubionai_list_course_assignments",
    }
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS oauth_clients (
  site_id       TEXT NOT NULL,
  client_id     TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,
  client_name   TEXT,
  source        TEXT NOT NULL CHECK (source IN ('dcr','cimd')),
  created_at    INTEGER NOT NULL,
  PRIMARY KEY (site_id, client_id)
);
CREATE TABLE IF NOT EXISTS oauth_grants (
  grant_id       TEXT PRIMARY KEY,
  site_id        TEXT NOT NULL,
  moodle_userid  INTEGER NOT NULL,
  client_id      TEXT NOT NULL,
  scope          TEXT NOT NULL,
  resource       TEXT NOT NULL,
  wstoken_ct     BLOB NOT NULL,
  moodle_tokenid INTEGER NOT NULL,
  valid_until    INTEGER NOT NULL,
  kek_id         TEXT NOT NULL,
  created_at     INTEGER NOT NULL,
  revoked_at     INTEGER
);
CREATE TABLE IF NOT EXISTS oauth_tokens (
  token_hash BLOB PRIMARY KEY,
  kind       TEXT NOT NULL CHECK (kind IN ('access','refresh')),
  grant_id   TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at    INTEGER
);
CREATE INDEX IF NOT EXISTS oauth_tokens_grant ON oauth_tokens(grant_id);
CREATE INDEX IF NOT EXISTS oauth_grants_site_user ON oauth_grants(site_id, moodle_userid);
"""


class OAuthConfigError(Exception):
    """Raised for invalid OAuth configuration (public URL, secret files)."""


def _now() -> int:
    return int(time.time())


def _hash(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


_b64 = b64url
_unb64 = unb64url


def validate_public_url(url: str) -> str:
    """The public base URL must be https (loopback http is allowed for local tests)."""
    url = url.rstrip("/")
    parts = urlsplit(url)
    if not parts.hostname or parts.query or parts.fragment or parts.username or parts.password:
        raise OAuthConfigError("UBIONAI_HUB_PUBLIC_URL invalid")
    if parts.scheme == "https":
        return url
    if parts.scheme == "http" and _is_loopback_host(parts.hostname):
        return url
    raise OAuthConfigError("UBIONAI_HUB_PUBLIC_URL must be https for OAuth")


def load_tenant_secret(secrets_dir: str, site_id: str) -> bytes | None:
    """Read ``<secrets_dir>/<site_id>/oauth.secret``; None when absent or unusable (logged)."""
    if not SITE_ID_RE.fullmatch(site_id):
        return None
    path = os.path.join(secrets_dir, site_id, SECRET_FILE)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError:
        logger.error("oauth secret unreadable site=%s", site_id)
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:
        logger.error("oauth secret must be a regular file with mode 0600/0400 site=%s", site_id)
        return None
    try:
        with open(path, "rb") as handle:
            secret = handle.read().strip()
    except OSError:
        logger.error("oauth secret unreadable site=%s", site_id)
        return None
    if len(secret) < MIN_SECRET_LEN:
        logger.error("oauth secret shorter than %d bytes site=%s", MIN_SECRET_LEN, site_id)
        return None
    return secret


def _is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _is_loopback(uri: str) -> bool:
    parts = urlsplit(uri)
    return parts.scheme == "http" and bool(parts.hostname) and _is_loopback_host(parts.hostname or "")


def redirect_allowed(uri: str) -> bool:
    """Hub-wide allowlist: Claude callbacks + loopback (Claude Code, any port)."""
    return uri in ALLOWED_REDIRECTS or _is_loopback(uri)


def redirect_matches(registered: list[str], requested: str) -> bool:
    """Exact match, except loopback redirects may differ only in port (RFC 8252 §7.3)."""
    if requested in registered:
        return True
    if not _is_loopback(requested):
        return False
    req = urlsplit(requested)
    for uri in registered:
        reg = urlsplit(uri)
        if _is_loopback(uri) and (reg.scheme, reg.hostname, reg.path, reg.query) == (
            req.scheme,
            req.hostname,
            req.path,
            req.query,
        ):
            return True
    return False


def _user_field(grant_id: str, userid: int) -> str:
    return f"user_wstoken:{grant_id}:{userid}"


@dataclass
class Client:
    client_id: str
    redirect_uris: list[str]
    client_name: str | None
    source: str


@dataclass
class AuthRequest:
    site: str
    client_id: str
    client_name: str
    redirect_uri: str
    client_state: str | None
    code_challenge: str
    resource: str
    scope: str
    bind: str
    exp: float
    base_path: str = ""


@dataclass(frozen=True)
class TenantRef:
    """A tenant as addressed by one URL family: ``/t/<site_id>`` or ``/m/<host_key>`` (contract §6.3).

    issuer / resource / cookie path derive from ``base_path``, so a token issued for one family is
    refused on the other (separate RFC 8707 audiences).
    """

    site_id: str
    base_path: str

    @classmethod
    def legacy(cls, site_id: str) -> "TenantRef":
        return cls(site_id, f"/t/{site_id}")

    @classmethod
    def host(cls, site_id: str, host_key: str) -> "TenantRef":
        return cls(site_id, f"/m/{host_key}")

    @property
    def host_key(self) -> str | None:
        return self.base_path[3:] if self.base_path.startswith("/m/") else None


def _as_ref(ref: "TenantRef | str") -> TenantRef:
    return ref if isinstance(ref, TenantRef) else TenantRef.legacy(ref)


@dataclass
class PendingCode:
    """An authorization code that has a sealed Moodle token waiting for the token request."""

    site: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    resource: str
    scope: str
    grant_id: str
    moodle_userid: int
    moodle_tokenid: int
    wstoken_ct: bytes
    valid_until: int
    exp: float


@dataclass(frozen=True)
class Grant:
    grant_id: str
    site_id: str
    moodle_userid: int
    client_id: str
    scope: str
    resource: str
    wstoken_ct: bytes
    moodle_tokenid: int
    valid_until: int


class CimdError(Exception):
    """A Client ID Metadata Document could not be fetched or is unusable (reason is log-safe)."""


def cimd_url_ok(client_id: str) -> bool:
    """CIMD client_id: https URL with a host and a real path; no userinfo, fragment or dot segments."""
    try:
        parts = urlsplit(client_id)
        parts.port  # noqa: B018 - raises ValueError on a bad port
    except ValueError:
        return False
    if parts.scheme != "https" or not parts.hostname or parts.username is not None or parts.password is not None:
        return False
    if "#" in client_id or "\\" in client_id or any(ord(c) <= 0x20 or ord(c) == 0x7F for c in client_id):
        return False
    segments = parts.path.split("/")
    return len(parts.path) > 1 and not any(seg in (".", "..") for seg in segments)


def _max_age(cache_control: str) -> int | None:
    directives = [d.strip().lower() for d in cache_control.split(",")]
    if "no-store" in directives or "no-cache" in directives:
        return 0
    for d in directives:
        if d.startswith("max-age="):
            try:
                return int(d[8:].strip('"'))
            except ValueError:
                return None
    return None


@dataclass
class CimdFetcher:
    """Fetches Client ID Metadata Documents (MCP 2025-11-25) with SSRF protection and a TTL cache.

    The host is resolved here, every address must be public, and the TCP connection goes to the
    vetted address (TLS SNI and certificate checks still use the host name), so DNS rebinding
    between check and connect cannot reach an internal address. Redirects are followed manually,
    https only, and re-vetted. Proxies from the environment are ignored for the same reason.
    """

    transport: httpx.AsyncBaseTransport | None = None
    resolve: Resolver = _system_resolve
    timeout: float = 5.0
    max_bytes: int = 64 * 1024
    max_redirects: int = 3
    default_ttl: int = 600
    min_ttl: int = 60
    max_ttl: int = 3600
    negative_ttl: int = 30
    clock: Callable[[], float] = time.monotonic
    cache: dict[str, tuple[float, dict[str, Any] | None]] = field(default_factory=dict)

    async def __call__(self, url: str) -> dict[str, Any]:
        now = self.clock()
        hit = self.cache.get(url)
        if hit is not None and hit[0] > now:
            if hit[1] is None:
                raise CimdError("cached failure")
            return hit[1]
        try:
            async with asyncio.timeout(self.timeout):
                doc, ttl = await self._fetch(url)
        except (CimdError, TimeoutError, httpx.HTTPError, OSError, ValueError) as exc:
            self._store(url, None, self.negative_ttl)
            if isinstance(exc, CimdError):
                raise
            raise CimdError("timeout" if isinstance(exc, TimeoutError) else type(exc).__name__) from exc
        self._store(url, doc, ttl)
        return doc

    def _store(self, url: str, doc: dict[str, Any] | None, ttl: int) -> None:
        now = self.clock()
        if len(self.cache) > 1000:
            for key in [k for k, (exp, _) in self.cache.items() if exp <= now]:
                del self.cache[key]
            if len(self.cache) > 1000:
                self.cache.clear()
        self.cache[url] = (now + ttl, doc)

    async def _vetted_ip(self, host: str, port: int) -> str:
        try:
            return await vet_host(host, port, self.resolve)
        except (ResolveError, BlockedAddress) as exc:
            raise CimdError(str(exc)) from None

    async def _fetch(self, url: str) -> tuple[dict[str, Any], int]:
        async with httpx.AsyncClient(
            transport=self.transport, timeout=self.timeout, follow_redirects=False, trust_env=False
        ) as client:
            target = url
            for _ in range(self.max_redirects + 1):
                parts = urlsplit(target)
                if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
                    raise CimdError("non-https or malformed URL")
                host, port = parts.hostname, parts.port or 443
                ip = await self._vetted_ip(host, port)
                ip_host = f"[{ip}]" if ":" in ip else ip
                netloc = ip_host if port == 443 else f"{ip_host}:{port}"
                pinned = parts._replace(netloc=netloc, fragment="").geturl()
                host_header = host if port == 443 else f"{host}:{port}"
                if ":" in host:
                    host_header = f"[{host}]" if port == 443 else f"[{host}]:{port}"
                request = client.build_request(
                    "GET",
                    pinned,
                    headers={"Host": host_header, "Accept": "application/json"},
                    extensions={"sni_hostname": host},
                )
                resp = await client.send(request, stream=True)
                try:
                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("location", "")
                        target = str(httpx.URL(target).join(location))
                        continue
                    if resp.status_code != 200:
                        raise CimdError(f"HTTP {resp.status_code}")
                    declared = resp.headers.get("content-length")
                    if declared and declared.isdigit() and int(declared) > self.max_bytes:
                        raise CimdError("document too large")
                    body = bytearray()
                    async for chunk in resp.aiter_bytes():
                        body += chunk
                        if len(body) > self.max_bytes:
                            raise CimdError("document too large")
                    max_age = _max_age(resp.headers.get("cache-control", ""))
                finally:
                    await resp.aclose()
                try:
                    doc = json.loads(bytes(body))
                except (ValueError, UnicodeDecodeError) as exc:
                    raise CimdError("document is not JSON") from exc
                if not isinstance(doc, dict):
                    raise CimdError("document is not a JSON object")
                ttl = self.default_ttl if max_age is None else max(self.min_ttl, min(self.max_ttl, max_age))
                return doc, ttl
            raise CimdError("too many redirects")


CLIENT_SECRET_METHODS = frozenset({"client_secret_basic", "client_secret_post", "client_secret_jwt"})


def cimd_problem(client_id: str, doc: dict[str, Any]) -> str | None:
    """Why a fetched CIMD may not be used for ``client_id`` (None when it is acceptable)."""
    if doc.get("client_id") != client_id:
        return "client_id in document does not match the URL"
    uris = doc.get("redirect_uris")
    if not isinstance(uris, list) or not uris or not all(isinstance(u, str) for u in uris):
        return "redirect_uris missing"
    method = doc.get("token_endpoint_auth_method", "none")
    if method in CLIENT_SECRET_METHODS or "client_secret" in doc:
        return "client secrets are not allowed in a metadata document"
    if method != "none":
        return f"unsupported token_endpoint_auth_method {method!r}"
    grants = doc.get("grant_types", ["authorization_code"])
    if not isinstance(grants, list) or "authorization_code" not in grants:
        return "authorization_code grant not listed"
    return None


def _display_name(value: Any) -> str | None:
    """Client-supplied name for the consent page: printable, single line, bounded (escaped by Moodle s())."""
    if not isinstance(value, str):
        return None
    cleaned = "".join(c for c in value if c.isprintable()).strip()
    return cleaned[:100] or None


def _oauth_error(error: str, description: str, status: int = 400) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status,
        headers={"Cache-Control": "no-store"},
    )


def _page(message: str, status: int) -> HTMLResponse:
    return HTMLResponse(
        f"<!doctype html><title>UBION AI</title><p>{html.escape(message)}</p>",
        status_code=status,
        headers={"Cache-Control": "no-store"},
    )


@dataclass
class OAuthServer:
    """Tenant-scoped AS + token verification for the RS (``TenantRouterMiddleware``)."""

    registry: Registry
    kek: Kek
    public_url: str
    secrets_dir: str
    transport: httpx.AsyncBaseTransport | None = None
    cimd_fetcher: CimdFetcher = field(default_factory=CimdFetcher)
    access_ttl: int = ACCESS_TTL
    refresh_ttl: int = REFRESH_TTL
    requests: dict[str, AuthRequest] = field(default_factory=dict)
    codes: dict[bytes, PendingCode] = field(default_factory=dict)
    # Hub -> Moodle transport for self-registered tenants: resolves, vets and pins every
    # connection to a public IP (contract §4.3). Defaults to PinnedPublicTransport(transport).
    pinned_transport: httpx.AsyncBaseTransport | None = None
    # UBIONAI_HUB_LEGACY_TENANT_ROUTES=0: /t/<site> serves operator tenants only.
    legacy_self_registered: bool = True
    # Rate limit for the static "ask your administrator" page (IP -> 60/min).
    page_limit: Callable[[Request], int | None] | None = None
    # tier=limited: at most limits.max_teachers distinct teachers with a live grant (§8.3 #2).
    limits: TierLimits = field(default_factory=TierLimits)
    _tasks: set[asyncio.Task[Any]] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.public_url = validate_public_url(self.public_url)
        with self.registry._connect() as conn:
            conn.executescript(_SCHEMA)
            conn.execute("UPDATE meta SET schema_version = 5 WHERE schema_version < 5")
        if self.pinned_transport is None:
            self.pinned_transport = PinnedPublicTransport(self.transport)
        self.credentials = SharedSecretCredentialStore(self.registry, self.kek)
        self.router = Starlette(routes=self._routes())

    # --- tenancy / urls -------------------------------------------------------------------
    def issuer(self, ref: TenantRef | str) -> str:
        return self.public_url + _as_ref(ref).base_path

    def resource(self, ref: TenantRef | str) -> str:
        return self.issuer(ref) + "/mcp"

    def prm_url(self, ref: TenantRef | str) -> str:
        return f"{self.public_url}/.well-known/oauth-protected-resource{_as_ref(ref).base_path}/mcp"

    def secret(self, site: str) -> bytes | None:
        if not self.secrets_dir:
            return None
        return load_tenant_secret(self.secrets_dir, site)

    def authenticator(self, tenant: Tenant, ref: TenantRef | None = None) -> SiteAuthenticator | None:
        """Message signer chosen by the tenant's auth_mode (contract §7.1).

        A linked operator tenant (docs/OPERATOR-LINK.md) signs ``/m/<host_key>`` messages with its
        confirmed shared-secret credential; ``/t/`` (and ``/m/`` before the first confirm) keeps the
        legacy file secret.
        """
        if (
            tenant.operator_linked and ref is not None and ref.host_key is not None
            and ref.host_key == tenant.host_key
        ):
            linked = self.credentials.authenticator(tenant.site_id, tenant.moodle_url)
            if linked is not None:
                return linked
        if tenant.auth_mode == "legacy_file":
            secret = self.secret(tenant.site_id)
            return FileSecretAuthenticator(secret) if secret is not None else None
        if tenant.auth_mode == "shared_secret":
            return self.credentials.authenticator(tenant.site_id, tenant.moodle_url)
        return None  # signature: option 2, not implemented

    def transport_for(self, tenant: Tenant) -> httpx.AsyncBaseTransport | None:
        return self.pinned_transport if tenant.self_registered else self.transport

    def tenant(self, site: str, ref: TenantRef | None = None) -> tuple[Tenant, SiteAuthenticator] | None:
        """Active tenant with a usable message signer, else None (OAuth off for that site)."""
        if not SITE_ID_RE.fullmatch(site):
            return None
        tenant = self.registry.get(site)
        if tenant is None or tenant.status != "active":
            return None
        auth = self.authenticator(tenant, ref)
        return (tenant, auth) if auth is not None else None

    def enabled(self, site: str, ref: TenantRef | None = None) -> bool:
        return self.tenant(site, ref) is not None

    def challenge(self, ref: TenantRef | str, error: str | None = None) -> bytes:
        value = f'Bearer resource_metadata="{self.prm_url(ref)}", scope="{" ".join(SCOPES)}"'
        if error:
            value += f', error="{error}"'
        return value.encode()

    def _ref(self, request: Request) -> TenantRef:
        ref = request.scope.get("ubionai.ref")
        return ref if isinstance(ref, TenantRef) else TenantRef.legacy(request.path_params["site"])

    def _found(self, request: Request) -> tuple[TenantRef, Tenant, SiteAuthenticator] | None:
        ref = self._ref(request)
        found = self.tenant(ref.site_id, ref)
        if found is None:
            return None
        if ref.host_key is None and found[0].self_registered and not self.legacy_self_registered:
            return None
        if ref.host_key is not None and found[0].host_key != ref.host_key:
            return None
        return ref, found[0], found[1]

    def _ref_for_grant(self, grant: Grant) -> TenantRef:
        return self._ref_for_resource(grant.site_id, grant.resource)

    def _ref_for_resource(self, site: str, resource: str) -> TenantRef:
        base = resource[len(self.public_url):] if resource.startswith(self.public_url) else ""
        base = base[: -len("/mcp")] if base.endswith("/mcp") else ""
        return TenantRef(site, base) if base else TenantRef.legacy(site)

    def _revoke_code(self, code: PendingCode) -> None:
        """Burn an unredeemed code's Moodle token, signed for the URL family it was issued on."""
        ref = self._ref_for_resource(code.site, code.resource)
        self._spawn(self._revoke_moodle(code.site, code.moodle_userid, code.moodle_tokenid, ref))

    # --- RS -------------------------------------------------------------------------------
    def authenticate(self, ref: TenantRef | str, bearer: str) -> Grant | None:
        """Access token -> live grant for this site (audience = the MCP URL it was issued for)."""
        ref = _as_ref(ref)
        site = ref.site_id
        now = _now()
        with self.registry._connect() as conn:
            row = conn.execute(
                "SELECT g.grant_id, g.site_id, g.moodle_userid, g.client_id, g.scope, g.resource,"
                " g.wstoken_ct, g.moodle_tokenid, g.valid_until"
                " FROM oauth_tokens t JOIN oauth_grants g ON g.grant_id = t.grant_id"
                " WHERE t.token_hash = ? AND t.kind = 'access' AND t.used_at IS NULL"
                " AND t.expires_at > ? AND g.revoked_at IS NULL AND g.valid_until > ?"
                " AND g.kek_id = ?",
                (_hash(bearer), now, now, self.kek.kek_id),
            ).fetchone()
        if row is None:
            return None
        grant = Grant(*row)
        if grant.site_id != site or grant.resource != self.resource(ref):
            return None  # RFC 8707 audience; no token passthrough across tenants or URL families
        return grant

    def teacher_limit_reached(self, tenant: Tenant, userid: int) -> bool:
        """A new teacher would exceed the tier's limit. Teachers already holding a live grant
        (reconnecting, a second client) are always allowed."""
        if tenant.tier != "limited":
            return False
        now = _now()
        with self.registry._connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT moodle_userid FROM oauth_grants"
                " WHERE site_id = ? AND revoked_at IS NULL AND valid_until > ?",
                (tenant.site_id, now),
            ).fetchall()
        teachers = {row[0] for row in rows}
        return userid not in teachers and len(teachers) >= self.limits.max_teachers

    def user_token(self, tenant: Tenant, grant: Grant) -> bytearray:
        return open_(
            self.kek,
            grant.wstoken_ct,
            tenant.site_id,
            _user_field(grant.grant_id, grant.moodle_userid),
            moodle_url=tenant.moodle_url,
        )

    # --- ASGI -----------------------------------------------------------------------------
    def handles(self, path: str) -> bool:
        return path.startswith("/.well-known/") or bool(
            re.fullmatch(r"/t/[a-z0-9][a-z0-9-]{1,62}/(oauth/[a-z]+|\.well-known/openid-configuration)", path)
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self.router(scope, receive, send)

    def host_ready(self, tenant: Tenant | None) -> bool:
        """The tenant behind /m/<host_key> can run OAuth (active + message signer)."""
        return tenant is not None and tenant.host_key is not None and self.enabled(
            tenant.site_id, TenantRef.host(tenant.site_id, tenant.host_key)
        )

    async def serve_host_route(
        self, scope: Scope, receive: Receive, send: Send, kind: str, endpoint: str, host_key: str, tenant: Tenant | None
    ) -> None:
        """``/m/<host_key>`` OAuth + metadata (contract §5.1, §6).

        A ready tenant is served by the normal handlers with a ``/m/`` TenantRef (path rewritten
        to the ``/t/`` route internally). Otherwise metadata and DCR answer statically (nothing is
        fetched or stored for an arbitrary host) and authorize shows the "ask your administrator" page.
        """
        if self.host_ready(tenant):
            assert tenant is not None
            site = tenant.site_id
            path = {
                "prm": f"/.well-known/oauth-protected-resource/t/{site}/mcp",
                "as_metadata": f"/.well-known/oauth-authorization-server/t/{site}",
                "oauth": f"/t/{site}/oauth/{endpoint}",
            }[kind]
            inner = dict(scope, path=path, raw_path=path.encode())
            inner["ubionai.ref"] = TenantRef.host(site, host_key)
            await self.router(inner, receive, send)
            return
        ref = TenantRef("", f"/m/{host_key}")
        request = Request(scope, receive)
        response: Response
        if kind == "prm":
            response = JSONResponse(self._prm_doc(ref))
        elif kind == "as_metadata":
            response = JSONResponse(self._as_doc(ref))
        elif kind == "oauth" and endpoint == "register" and request.method == "POST":
            response = await self.stateless_register(request, host_key)
        elif kind == "oauth" and endpoint == "authorize" and request.method == "GET":
            response = self.site_page(request, ref, tenant)
        else:
            response = _oauth_error("invalid_request", "site not registered", 404)
        await response(scope, receive, send)

    def site_page(self, request: Request, ref: TenantRef, tenant: Tenant | None) -> Response:
        if self.page_limit is not None:
            wait = self.page_limit(request)
            if wait is not None:
                return _page("too many requests", 429)
        if tenant is None:
            kind = "unregistered"
        elif tenant.status == "disabled":
            kind = "disabled"
        else:
            kind = "pending"  # pending review, or not yet confirmed / no signer
        redirect_uri = request.query_params.get("redirect_uri", "")
        back = None
        if redirect_uri and redirect_allowed(redirect_uri):
            params = {"error": "access_denied", "error_description": "site_not_registered", "iss": self.issuer(ref)}
            state = request.query_params.get("state")
            if state is not None:
                params["state"] = state
            back = redirect_uri + ("&" if "?" in redirect_uri else "?") + urlencode(params)
        return render_site_page(
            kind, ref.host_key or "", page_language(request.headers.get("accept-language")), back
        )

    def _routes(self) -> list[Route]:
        return [
            Route("/.well-known/oauth-protected-resource/t/{site}/mcp", self.prm),
            Route("/.well-known/oauth-authorization-server/t/{site}", self.as_metadata),
            Route("/.well-known/openid-configuration/t/{site}", self.as_metadata),
            Route("/t/{site}/.well-known/openid-configuration", self.as_metadata),
            Route("/t/{site}/oauth/register", self.register, methods=["POST"]),
            Route("/t/{site}/oauth/authorize", self.authorize, methods=["GET"]),
            Route("/t/{site}/oauth/callback", self.callback, methods=["GET"]),
            Route("/t/{site}/oauth/token", self.token, methods=["POST"]),
            Route("/t/{site}/oauth/revoke", self.revoke, methods=["POST"]),
        ]

    def _site(self, request: Request) -> TenantRef | None:
        found = self._found(request)
        return found[0] if found is not None else None

    # --- metadata -------------------------------------------------------------------------
    def _prm_doc(self, ref: TenantRef) -> dict[str, Any]:
        return {
            "resource": self.resource(ref),
            "authorization_servers": [self.issuer(ref)],
            "scopes_supported": SCOPES,
            "bearer_methods_supported": ["header"],
        }

    def _as_doc(self, ref: TenantRef) -> dict[str, Any]:
        iss = self.issuer(ref)
        return {
            "issuer": iss,
            "authorization_endpoint": f"{iss}/oauth/authorize",
            "token_endpoint": f"{iss}/oauth/token",
            "registration_endpoint": f"{iss}/oauth/register",
            "revocation_endpoint": f"{iss}/oauth/revoke",
            "scopes_supported": SCOPES + ["offline_access"],
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "revocation_endpoint_auth_methods_supported": ["none"],
            "client_id_metadata_document_supported": True,
            "authorization_response_iss_parameter_supported": True,
        }

    async def prm(self, request: Request) -> Response:
        ref = self._site(request)
        if not ref:
            return JSONResponse({"error": "not found"}, status_code=404)
        return JSONResponse(self._prm_doc(ref))

    async def as_metadata(self, request: Request) -> Response:
        ref = self._site(request)
        if not ref:
            return JSONResponse({"error": "not found"}, status_code=404)
        return JSONResponse(self._as_doc(ref))

    # --- clients --------------------------------------------------------------------------
    async def _client_metadata(self, request: Request) -> tuple[list[str], str | None, list[str]] | Response:
        """Validated DCR body -> (redirect_uris, client_name, grant_types), or an error response."""
        try:
            body = await request.json()
        except (ValueError, json.JSONDecodeError):
            return _oauth_error("invalid_client_metadata", "body must be JSON")
        if not isinstance(body, dict):
            return _oauth_error("invalid_client_metadata", "body must be a JSON object")
        uris = body.get("redirect_uris")
        if not isinstance(uris, list) or not uris or not all(isinstance(u, str) for u in uris):
            return _oauth_error("invalid_redirect_uri", "redirect_uris required")
        bad = [u for u in uris if not redirect_allowed(u)]
        if bad:
            return _oauth_error("invalid_redirect_uri", f"redirect_uri not allowed: {bad[0]}")
        if body.get("token_endpoint_auth_method", "none") != "none":
            return _oauth_error("invalid_client_metadata", "only public clients (none)")
        grants = body.get("grant_types") or ["authorization_code", "refresh_token"]
        if not isinstance(grants, list) or not set(grants) <= {"authorization_code", "refresh_token"}:
            return _oauth_error("invalid_client_metadata", "unsupported grant_types")
        name = body.get("client_name")
        name = name[:200] if isinstance(name, str) else None
        return list(uris), name, grants

    @staticmethod
    def _dcr_response(client: Client, grants: list[str]) -> Response:
        return JSONResponse(
            {
                "client_id": client.client_id,
                "client_id_issued_at": _now(),
                "redirect_uris": client.redirect_uris,
                "client_name": client.client_name,
                "token_endpoint_auth_method": "none",
                "grant_types": grants,
                "response_types": ["code"],
            },
            status_code=201,
        )

    async def register(self, request: Request) -> Response:
        ref = self._site(request)
        if not ref:
            return JSONResponse({"error": "not found"}, status_code=404)
        meta = await self._client_metadata(request)
        if isinstance(meta, Response):
            return meta
        uris, name, grants = meta
        client = Client("dcr_" + secrets.token_urlsafe(16), uris, name, "dcr")
        self._save_client(ref.site_id, client)
        return self._dcr_response(client, grants)

    # Stateless DCR for /m/<host_key> before (or regardless of) registration (contract §5.1): the
    # client_id carries its redirect URIs and is MACed with a KEK-derived key, so arbitrary hosts
    # cannot fill the database, and the id stays valid once the site registers.
    def _dcr_key(self) -> bytes:
        return derive_key(self.kek, PURPOSE_DCR_STATELESS, "hub")

    def stateless_client_id(self, host_key: str, uris: list[str], name: str | None) -> str:
        body = b64url(
            json.dumps({"h": host_key, "r": uris, "n": name, "iat": _now()}, separators=(",", ":"), sort_keys=True).encode()
        )
        mac = hmac.new(self._dcr_key(), (STATELESS_DCR_PREFIX + body).encode(), hashlib.sha256).digest()
        return f"{STATELESS_DCR_PREFIX}{body}.{b64url(mac)}"

    def _stateless_client(self, client_id: str, host_key: str | None) -> Client | None:
        if host_key is None or not client_id.startswith(STATELESS_DCR_PREFIX) or len(client_id) > 4096:
            return None
        body, _, mac = client_id[len(STATELESS_DCR_PREFIX):].partition(".")
        expected = hmac.new(self._dcr_key(), (STATELESS_DCR_PREFIX + body).encode(), hashlib.sha256).digest()
        try:
            if not hmac.compare_digest(unb64url(mac), expected):
                return None
            data = json.loads(unb64url(body))
        except (ValueError, json.JSONDecodeError):
            return None
        if not isinstance(data, dict) or data.get("h") != host_key:
            return None
        uris = data.get("r")
        if not isinstance(uris, list) or not uris or not all(isinstance(u, str) and redirect_allowed(u) for u in uris):
            return None
        name = data.get("n") if isinstance(data.get("n"), str) else None
        return Client(client_id, uris, name, "dcr")

    def _host_key_of(self, ref: TenantRef) -> str | None:
        if ref.host_key is not None:
            return ref.host_key
        tenant = self.registry.get(ref.site_id)
        return tenant.host_key if tenant is not None else None

    def _known_client(self, ref: TenantRef, client_id: str) -> Client | None:
        """Registered (DB) or stateless DCR client usable at this ref (token / revoke endpoints)."""
        if client_id.startswith(STATELESS_DCR_PREFIX):
            return self._stateless_client(client_id, self._host_key_of(ref))
        return self._load_client(ref.site_id, client_id)

    async def stateless_register(self, request: Request, host_key: str) -> Response:
        meta = await self._client_metadata(request)
        if isinstance(meta, Response):
            return meta
        uris, name, grants = meta
        client = Client(self.stateless_client_id(host_key, uris, name and name[:100]), uris, name and name[:100], "dcr")
        return self._dcr_response(client, grants)

    def _save_client(self, site: str, client: Client) -> None:
        with self.registry._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO oauth_clients"
                " (site_id, client_id, redirect_uris, client_name, source, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (site, client.client_id, json.dumps(client.redirect_uris), client.client_name, client.source, _now()),
            )

    def _load_client(self, site: str, client_id: str) -> Client | None:
        with self.registry._connect() as conn:
            row = conn.execute(
                "SELECT client_id, redirect_uris, client_name, source FROM oauth_clients"
                " WHERE site_id = ? AND client_id = ?",
                (site, client_id),
            ).fetchone()
        return Client(row[0], json.loads(row[1]), row[2], row[3]) if row else None

    async def _client(self, ref: TenantRef, client_id: str) -> Client | None:
        site = ref.site_id
        if not client_id:
            return None
        if client_id.startswith(STATELESS_DCR_PREFIX):
            return self._stateless_client(client_id, self._host_key_of(ref))
        if "://" not in client_id:
            client = self._load_client(site, client_id)
            return client if client is not None and client.source == "dcr" else None
        if not cimd_url_ok(client_id):
            logger.warning("CIMD client_id rejected (not an https URL with a path) site=%s", site)
            return None
        try:
            doc = await self.cimd_fetcher(client_id)
        except CimdError as exc:
            logger.warning("CIMD fetch failed site=%s host=%s: %s", site, urlsplit(client_id).hostname, exc)
            return None
        problem = cimd_problem(client_id, doc)
        if problem:
            logger.warning("CIMD document rejected site=%s host=%s: %s", site, urlsplit(client_id).hostname, problem)
            return None
        uris = [u for u in doc["redirect_uris"] if isinstance(u, str)]
        client = Client(client_id, uris, _display_name(doc.get("client_name")), "cimd")
        self._save_client(site, client)
        return client

    # --- authorize ------------------------------------------------------------------------
    def _purge(self) -> None:
        now = time.time()
        for key in [k for k, r in self.requests.items() if r.exp < now]:
            del self.requests[key]
        for key in [k for k, c in self.codes.items() if c.exp < now]:
            code = self.codes.pop(key)
            self._revoke_code(code)

    def _spawn(self, coro: Awaitable[Any]) -> None:
        try:
            task = asyncio.get_running_loop().create_task(coro)  # type: ignore[arg-type]
        except RuntimeError:
            return
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def authorize(self, request: Request) -> Response:
        self._purge()
        found = self._found(request)
        if not found:
            return _page("unknown site", 404)
        ref, tenant, auth = found
        site = ref.site_id
        q = request.query_params
        client = await self._client(ref, q.get("client_id", ""))
        if client is None:
            return _page("invalid client_id", 400)
        redirect_uri = q.get("redirect_uri", "")
        if not redirect_uri or not redirect_allowed(redirect_uri) or not redirect_matches(client.redirect_uris, redirect_uri):
            return _page("invalid redirect_uri", 400)
        client_state = q.get("state")

        def fail(error: str, desc: str) -> Response:
            return self._to_client(redirect_uri, ref, client_state, error=error, error_description=desc)

        if q.get("response_type") != "code":
            return fail("unsupported_response_type", "response_type must be code")
        challenge = q.get("code_challenge", "")
        if q.get("code_challenge_method") != "S256" or not re.fullmatch(r"[A-Za-z0-9_-]{43}", challenge):
            return fail("invalid_request", "PKCE S256 code_challenge required")
        if q.get("resource") != self.resource(ref):
            return fail("invalid_target", "resource must be " + self.resource(ref))
        requested = (q.get("scope") or " ".join(SCOPES)).split()
        if not set(requested) <= set(SCOPES) | {"offline_access"}:
            return fail("invalid_scope", "unknown scope")

        state = secrets.token_urlsafe(24)
        bind = secrets.token_urlsafe(24)
        req = AuthRequest(
            site=site,
            client_id=client.client_id,
            client_name=self._consent_name(client, redirect_uri),
            redirect_uri=redirect_uri,
            client_state=client_state,
            code_challenge=challenge,
            resource=self.resource(ref),
            scope=" ".join(requested),
            bind=bind,
            exp=time.time() + REQUEST_TTL,
            base_path=ref.base_path,
        )
        self.requests[state] = req
        signed = auth.sign(
            {
                "typ": "authz_req",
                "iss": self.issuer(ref),
                "aud": tenant.moodle_url,
                "site": site,
                "state": state,
                "client_name": req.client_name,
                "client_host": urlsplit(client.client_id).hostname if client.source == "cimd" else None,
                "redirect_host": urlsplit(redirect_uri).hostname,
                "scope": req.scope,
                "callback": f"{self.issuer(ref)}/oauth/callback",
                "exp": int(req.exp),
            },
        )
        target = f"{tenant.moodle_url}/local/ubionai/oauth/authorize.php?" + urlencode({"req": signed})
        response = RedirectResponse(target, 302)
        # Binds the callback to the browser that started the flow (login CSRF / code injection).
        response.set_cookie(
            COOKIE,
            bind,
            max_age=REQUEST_TTL,
            path=f"{ref.base_path}/oauth/",
            secure=self.public_url.startswith("https://"),
            httponly=True,
            samesite="lax",
        )
        return response

    @staticmethod
    def _consent_name(client: Client, redirect_uri: str) -> str:
        """Name shown on the Moodle consent page (escaped there with s()).

        A CIMD name is self-asserted by whoever hosts the document, so the document's host is
        part of the label: "Claude (claude.ai)" cannot be impersonated from another domain.
        """
        if client.source == "cimd":
            host = urlsplit(client.client_id).hostname or "unknown"
            return f"{client.client_name or host} — {host}" if client.client_name else host
        return client.client_name or urlsplit(redirect_uri).hostname or "client"

    def _to_client(self, redirect_uri: str, ref: TenantRef | str, state: str | None, **params: str) -> Response:
        ref = _as_ref(ref)
        params = {**params, "iss": self.issuer(ref)}
        if state is not None:
            params["state"] = state
        sep = "&" if "?" in redirect_uri else "?"
        response = RedirectResponse(redirect_uri + sep + urlencode(params), 302)
        response.delete_cookie(COOKIE, path=f"{ref.base_path}/oauth/")
        return response

    async def _post(self, tenant: Tenant, url: str, assertion: str) -> httpx.Response | None:
        try:
            async with httpx.AsyncClient(
                timeout=10, follow_redirects=False, transport=self.transport_for(tenant), trust_env=False
            ) as client:
                return await client.post(url, data={"assertion": assertion})
        except httpx.HTTPError as exc:
            logger.warning("back channel failed site=%s: %s", tenant.site_id, type(exc).__name__)
            return None

    async def callback(self, request: Request) -> Response:
        self._purge()
        found = self._found(request)
        req = self.requests.pop(request.query_params.get("state", ""), None)
        if not found or req is None or req.site != found[0].site_id or req.exp < time.time():
            return _page("unknown or expired request; start again from Claude", 400)
        ref, tenant, auth = found
        site = ref.site_id
        if req.base_path != ref.base_path:
            return _page("unknown or expired request; start again from Claude", 400)
        if not hmac.compare_digest(request.cookies.get(COOKIE, ""), req.bind):
            return _page("this sign-in was started in another browser; start again from Claude", 400)
        if request.query_params.get("error"):
            return self._to_client(req.redirect_uri, ref, req.client_state, error="access_denied",
                                   error_description="the user denied the request in Moodle")
        code = request.query_params.get("code", "")
        assertion = auth.sign(
            {
                "typ": "exchange",
                "iss": self.issuer(ref),
                "aud": tenant.moodle_url,
                "site": site,
                "code": code,
                "state": request.query_params.get("state", ""),
                "jti": secrets.token_urlsafe(12),
                "exp": _now() + BACKCHANNEL_TTL,
            },
        )
        resp = await self._post(tenant, f"{tenant.moodle_url}/local/ubionai/oauth/exchange.php", assertion)
        try:
            data = resp.json() if resp is not None and resp.status_code == 200 else None
        except ValueError:
            data = None
        if (
            not isinstance(data, dict)
            or not isinstance(data.get("userid"), int)
            or not isinstance(data.get("tokenid"), int)
            or not isinstance(data.get("wstoken"), str)
            or not isinstance(data.get("validuntil"), int)
        ):
            reason = None
            if resp is not None:
                try:
                    reason = resp.json().get("reason")
                except (ValueError, AttributeError):
                    reason = None
            logger.warning("exchange failed site=%s status=%s reason=%s", site,
                           resp.status_code if resp is not None else None, reason)
            return self._to_client(req.redirect_uri, ref, req.client_state, error="access_denied",
                                   error_description="Moodle did not issue a token")
        userid, tokenid = data["userid"], data["tokenid"]
        problem = await self._check_user_token(tenant, data["wstoken"], userid)
        if problem:
            logger.warning("user token refused site=%s userid=%s: %s", site, userid, problem)
            await self._revoke_moodle(site, userid, tokenid, ref)
            return self._to_client(req.redirect_uri, ref, req.client_state, error="access_denied",
                                   error_description=problem)
        if self.teacher_limit_reached(tenant, userid):
            logger.warning("teacher limit reached site=%s limit=%s", site, self.limits.max_teachers)
            await self._revoke_moodle(site, userid, tokenid, ref)
            return self._to_client(req.redirect_uri, ref, req.client_state, error="access_denied",
                                   error_description=TEACHER_LIMIT_ERROR)
        grant_id = secrets.token_urlsafe(16)
        ct = seal(self.kek, data["wstoken"].encode(), site, _user_field(grant_id, userid), moodle_url=tenant.moodle_url)
        code_out = secrets.token_urlsafe(32)
        self.codes[_hash(code_out)] = PendingCode(
            site=site,
            client_id=req.client_id,
            redirect_uri=req.redirect_uri,
            code_challenge=req.code_challenge,
            resource=req.resource,
            scope=req.scope,
            grant_id=grant_id,
            moodle_userid=userid,
            moodle_tokenid=tokenid,
            wstoken_ct=ct,
            valid_until=min(data["validuntil"], _now() + self.refresh_ttl),
            exp=time.time() + CODE_TTL,
        )
        return self._to_client(req.redirect_uri, ref, req.client_state, code=code_out)

    async def _check_user_token(self, tenant: Tenant, wstoken: str, userid: int) -> str | None:
        """G8: refuse site-admin tokens and tokens of any service other than ubionai_user."""
        client = MoodleClient(
            ws_endpoint(tenant.moodle_url), wstoken, timeout=10, transport=self.transport_for(tenant)
        )
        try:
            info = await client.call("core_webservice_get_site_info")
        except MoodleError as exc:
            return f"site_info failed ({exc.errorcode or 'error'})"
        if not isinstance(info, dict):
            return "site_info returned no data"
        if info.get("userid") != userid:
            return "token belongs to another user"
        if info.get("userissiteadmin"):
            return "site administrator tokens are not accepted"
        functions = info.get("functions")
        names = {f.get("name") for f in functions if isinstance(f, dict)} if isinstance(functions, list) else None
        if not names or not names <= USER_SERVICE_FUNCTIONS:
            return "token is not limited to the ubionai_user service"
        return None

    async def _revoke_moodle(self, site: str, userid: int, tokenid: int, ref: TenantRef | None = None) -> bool:
        found = self.tenant(site, ref)
        if not found:
            return False
        tenant, auth = found
        assertion = auth.sign(
            {
                "typ": "revoke",
                "iss": self.issuer(ref or site),
                "aud": tenant.moodle_url,
                "site": site,
                "userid": userid,
                "tokenid": tokenid,
                "jti": secrets.token_urlsafe(12),
                "exp": _now() + BACKCHANNEL_TTL,
            },
        )
        resp = await self._post(tenant, f"{tenant.moodle_url}/local/ubionai/oauth/revoke.php", assertion)
        ok = resp is not None and resp.status_code == 200
        if not ok:
            logger.warning("moodle revoke failed site=%s userid=%s", site, userid)
        return ok

    # --- token ----------------------------------------------------------------------------
    def _issue(self, grant_id: str, scope: str) -> dict[str, Any]:
        access = secrets.token_urlsafe(32)
        refresh = secrets.token_urlsafe(32)
        now = _now()
        with self.registry._connect() as conn:
            conn.execute(
                "INSERT INTO oauth_tokens (token_hash, kind, grant_id, expires_at) VALUES (?, 'access', ?, ?)",
                (_hash(access), grant_id, now + self.access_ttl),
            )
            conn.execute(
                "INSERT INTO oauth_tokens (token_hash, kind, grant_id, expires_at) VALUES (?, 'refresh', ?, ?)",
                (_hash(refresh), grant_id, now + self.refresh_ttl),
            )
        return {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": self.access_ttl,
            "refresh_token": refresh,
            "scope": scope,
        }

    def _grant(self, grant_id: str) -> tuple[Grant, int | None] | None:
        with self.registry._connect() as conn:
            row = conn.execute(
                "SELECT grant_id, site_id, moodle_userid, client_id, scope, resource, wstoken_ct,"
                " moodle_tokenid, valid_until, revoked_at FROM oauth_grants WHERE grant_id = ?",
                (grant_id,),
            ).fetchone()
        return (Grant(*row[:9]), row[9]) if row else None

    async def revoke_grant(self, grant: Grant) -> None:
        with self.registry._connect() as conn:
            cur = conn.execute(
                "UPDATE oauth_grants SET revoked_at = ? WHERE grant_id = ? AND revoked_at IS NULL",
                (_now(), grant.grant_id),
            )
            conn.execute("UPDATE oauth_tokens SET used_at = ? WHERE grant_id = ? AND used_at IS NULL",
                         (_now(), grant.grant_id))
        if cur.rowcount:
            await self._revoke_moodle(grant.site_id, grant.moodle_userid, grant.moodle_tokenid, self._ref_for_grant(grant))

    async def token(self, request: Request) -> Response:
        self._purge()
        ref = self._site(request)
        if not ref:
            return _oauth_error("invalid_request", "unknown site", 404)
        site = ref.site_id
        if not request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
            return _oauth_error("invalid_request", "form-urlencoded body required")
        form = await request.form()
        grant_type = form.get("grant_type")
        client_id = str(form.get("client_id") or "")
        if not client_id or self._known_client(ref, client_id) is None:
            return _oauth_error("invalid_client", "unknown client", 401)
        resource = form.get("resource")
        if resource is not None and resource != self.resource(ref):
            return _oauth_error("invalid_target", "resource mismatch")

        if grant_type == "authorization_code":
            code = self.codes.pop(_hash(str(form.get("code") or "")), None)
            if (
                code is None
                or code.site != site
                or code.exp < time.time()
                or code.client_id != client_id
                or code.resource != self.resource(ref)
            ):
                if code is not None:
                    self._revoke_code(code)
                return _oauth_error("invalid_grant", "invalid code")
            verifier = str(form.get("code_verifier") or "")
            if (
                form.get("redirect_uri") != code.redirect_uri
                or not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier)
                or not hmac.compare_digest(_b64(hashlib.sha256(verifier.encode()).digest()), code.code_challenge)
            ):
                # The code is burnt either way; its Moodle token must not linger.
                self._revoke_code(code)
                return _oauth_error("invalid_grant", "redirect_uri or PKCE verification failed")
            tenant = self.registry.get(site)
            if tenant is not None and self.teacher_limit_reached(tenant, code.moodle_userid):
                # Another new teacher got the last seat between callback and token.
                self._revoke_code(code)
                return _oauth_error("invalid_grant", TEACHER_LIMIT_ERROR)
            with self.registry._connect() as conn:
                conn.execute(
                    "INSERT INTO oauth_grants (grant_id, site_id, moodle_userid, client_id, scope, resource,"
                    " wstoken_ct, moodle_tokenid, valid_until, kek_id, created_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (code.grant_id, site, code.moodle_userid, client_id, code.scope, code.resource,
                     code.wstoken_ct, code.moodle_tokenid, code.valid_until, self.kek.kek_id, _now()),
                )
            logger.info("oauth grant created site=%s userid=%s", site, code.moodle_userid)
            return JSONResponse(self._issue(code.grant_id, code.scope), headers={"Cache-Control": "no-store"})

        if grant_type == "refresh_token":
            now = _now()
            token_hash = _hash(str(form.get("refresh_token") or ""))
            with self.registry._connect() as conn:
                row = conn.execute(
                    "SELECT grant_id, expires_at FROM oauth_tokens WHERE token_hash = ? AND kind = 'refresh'",
                    (token_hash,),
                ).fetchone()
            found = self._grant(row[0]) if row else None
            if found is None:
                return _oauth_error("invalid_grant", "invalid refresh token")
            grant, revoked_at = found
            if grant.site_id != site or grant.client_id != client_id or grant.resource != self.resource(ref):
                return _oauth_error("invalid_grant", "invalid refresh token")
            with self.registry._connect() as conn:
                claimed = conn.execute(
                    "UPDATE oauth_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL",
                    (now, token_hash),
                ).rowcount
            if not claimed or revoked_at is not None:
                await self.revoke_grant(grant)  # reuse detected -> revoke the grant and its Moodle token
                return _oauth_error("invalid_grant", "refresh token reused or revoked")
            if row[1] < now or grant.valid_until < now:
                await self.revoke_grant(grant)
                return _oauth_error("invalid_grant", "refresh token or Moodle token expired")
            return JSONResponse(self._issue(grant.grant_id, grant.scope), headers={"Cache-Control": "no-store"})

        return _oauth_error("unsupported_grant_type", "authorization_code or refresh_token")

    async def revoke(self, request: Request) -> Response:
        ref = self._site(request)
        if not ref:
            return _oauth_error("invalid_request", "unknown site", 404)
        site = ref.site_id
        form = await request.form()
        token_hash = _hash(str(form.get("token") or ""))
        with self.registry._connect() as conn:
            row = conn.execute("SELECT grant_id, kind FROM oauth_tokens WHERE token_hash = ?", (token_hash,)).fetchone()
        found = self._grant(row[0]) if row else None
        if found is not None:
            grant, _ = found
            if grant.site_id == site and grant.client_id == form.get("client_id"):
                if row[1] == "refresh":
                    await self.revoke_grant(grant)
                else:
                    with self.registry._connect() as conn:
                        conn.execute("UPDATE oauth_tokens SET used_at = ? WHERE token_hash = ?", (_now(), token_hash))
        return Response(status_code=200, headers={"Cache-Control": "no-store"})  # RFC 7009 §2.2
