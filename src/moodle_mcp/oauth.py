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

Hub <-> plugin messages are signed with the tenant shared secret read from
``$UBIONAI_HUB_TENANT_SECRETS_DIR/<site>/oauth.secret``. A tenant without that file keeps working
with its static bearer only; the static bearer keeps working for tenants that have it.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
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

from .crypto import Kek, open_, seal
from .moodle import MoodleClient, MoodleError
from .registry import SITE_ID_RE, Registry, Tenant, ws_endpoint

logger = logging.getLogger(__name__)

SCOPES = ["moodle:read", "moodle:write"]
ALLOWED_REDIRECTS = (
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
)
TRUSTED_CIMD = ("https://claude.ai/oauth/claude-code-client-metadata",)
SECRET_FILE = "oauth.secret"
MIN_SECRET_LEN = 32
CODE_TTL = 60
REQUEST_TTL = 600
BACKCHANNEL_TTL = 60
ACCESS_TTL = 3600
REFRESH_TTL = 30 * 86400
COOKIE = "ubionai_oauth"
MAC_PREFIX = b"ubionai-oauth-v1."
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


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def sign_message(secret: bytes, claims: dict[str, Any]) -> str:
    """``base64url(json) "." base64url(HMAC-SHA256(secret, "ubionai-oauth-v1." + body))``."""
    body = _b64(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    return body + "." + _b64(hmac.new(secret, MAC_PREFIX + body.encode(), hashlib.sha256).digest())


def verify_message(secret: bytes, token: str, typ: str) -> dict[str, Any] | None:
    try:
        body, mac = token.split(".", 1)
        expected = hmac.new(secret, MAC_PREFIX + body.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_unb64(mac), expected):
            return None
        claims = json.loads(_unb64(body))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(claims, dict) or claims.get("typ") != typ or claims.get("exp", 0) < _now():
        return None
    return claims


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


CimdFetcher = Callable[[str], Awaitable[dict[str, Any]]]


async def default_cimd_fetcher(url: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=5, follow_redirects=False) as client:
        resp = await client.get(url, headers={"Accept": "application/json"})
    if resp.status_code != 200 or len(resp.content) > 5 * 1024:
        raise ValueError(f"CIMD fetch failed: HTTP {resp.status_code}")
    return resp.json()


def _oauth_error(error: str, description: str, status: int = 400) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status,
        headers={"Cache-Control": "no-store"},
    )


def _page(message: str, status: int) -> HTMLResponse:
    return HTMLResponse(
        f"<!doctype html><title>UBION AI</title><p>{message}</p>",
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
    cimd_fetcher: CimdFetcher = default_cimd_fetcher
    trusted_cimd: tuple[str, ...] = TRUSTED_CIMD
    access_ttl: int = ACCESS_TTL
    refresh_ttl: int = REFRESH_TTL
    requests: dict[str, AuthRequest] = field(default_factory=dict)
    codes: dict[bytes, PendingCode] = field(default_factory=dict)
    _tasks: set[asyncio.Task[Any]] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.public_url = validate_public_url(self.public_url)
        with self.registry._connect() as conn:
            conn.executescript(_SCHEMA)
            conn.execute("UPDATE meta SET schema_version = 5 WHERE schema_version < 5")
        self.router = Starlette(routes=self._routes())

    # --- tenancy / urls -------------------------------------------------------------------
    def issuer(self, site: str) -> str:
        return f"{self.public_url}/t/{site}"

    def resource(self, site: str) -> str:
        return f"{self.public_url}/t/{site}/mcp"

    def prm_url(self, site: str) -> str:
        return f"{self.public_url}/.well-known/oauth-protected-resource/t/{site}/mcp"

    def secret(self, site: str) -> bytes | None:
        return load_tenant_secret(self.secrets_dir, site)

    def tenant(self, site: str) -> tuple[Tenant, bytes] | None:
        """Active tenant with a usable shared secret, else None (OAuth off for that site)."""
        if not SITE_ID_RE.fullmatch(site):
            return None
        tenant = self.registry.get(site)
        if tenant is None or tenant.status != "active":
            return None
        secret = self.secret(site)
        return (tenant, secret) if secret is not None else None

    def enabled(self, site: str) -> bool:
        return self.tenant(site) is not None

    def challenge(self, site: str, error: str | None = None) -> bytes:
        value = f'Bearer resource_metadata="{self.prm_url(site)}", scope="{" ".join(SCOPES)}"'
        if error:
            value += f', error="{error}"'
        return value.encode()

    # --- RS -------------------------------------------------------------------------------
    def authenticate(self, site: str, bearer: str) -> Grant | None:
        """Access token -> live grant for this site (audience = this tenant's MCP URL)."""
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
        if grant.site_id != site or grant.resource != self.resource(site):
            return None  # RFC 8707 audience; no token passthrough across tenants
        return grant

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

    def _site(self, request: Request) -> str | None:
        site = request.path_params["site"]
        return site if self.enabled(site) else None

    # --- metadata -------------------------------------------------------------------------
    async def prm(self, request: Request) -> Response:
        site = self._site(request)
        if not site:
            return JSONResponse({"error": "not found"}, status_code=404)
        return JSONResponse(
            {
                "resource": self.resource(site),
                "authorization_servers": [self.issuer(site)],
                "scopes_supported": SCOPES,
                "bearer_methods_supported": ["header"],
            }
        )

    async def as_metadata(self, request: Request) -> Response:
        site = self._site(request)
        if not site:
            return JSONResponse({"error": "not found"}, status_code=404)
        iss = self.issuer(site)
        return JSONResponse(
            {
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
        )

    # --- clients --------------------------------------------------------------------------
    async def register(self, request: Request) -> Response:
        site = self._site(request)
        if not site:
            return JSONResponse({"error": "not found"}, status_code=404)
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
        client = Client("dcr_" + secrets.token_urlsafe(16), list(uris), name, "dcr")
        self._save_client(site, client)
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

    async def _client(self, site: str, client_id: str) -> Client | None:
        if not client_id:
            return None
        if not client_id.startswith("https://"):
            return self._load_client(site, client_id)
        if client_id not in self.trusted_cimd:
            logger.warning("CIMD client not on trusted list site=%s", site)
            return None
        try:
            doc = await self.cimd_fetcher(client_id)
        except Exception as exc:  # noqa: BLE001 - any fetch/parse failure rejects the client
            logger.warning("CIMD fetch failed: %s", type(exc).__name__)
            return None
        uris = doc.get("redirect_uris")
        if doc.get("client_id") != client_id or not isinstance(uris, list) or not uris:
            return None
        if doc.get("token_endpoint_auth_method", "none") != "none":
            return None
        name = doc.get("client_name")
        client = Client(client_id, [u for u in uris if isinstance(u, str)], name if isinstance(name, str) else None, "cimd")
        self._save_client(site, client)
        return client

    # --- authorize ------------------------------------------------------------------------
    def _purge(self) -> None:
        now = time.time()
        for key in [k for k, r in self.requests.items() if r.exp < now]:
            del self.requests[key]
        for key in [k for k, c in self.codes.items() if c.exp < now]:
            code = self.codes.pop(key)
            self._spawn(self._revoke_moodle(code.site, code.moodle_userid, code.moodle_tokenid))

    def _spawn(self, coro: Awaitable[Any]) -> None:
        try:
            task = asyncio.get_running_loop().create_task(coro)  # type: ignore[arg-type]
        except RuntimeError:
            return
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def authorize(self, request: Request) -> Response:
        self._purge()
        site = request.path_params["site"]
        found = self.tenant(site)
        if not found:
            return _page("unknown site", 404)
        tenant, secret = found
        q = request.query_params
        client = await self._client(site, q.get("client_id", ""))
        if client is None:
            return _page("invalid client_id", 400)
        redirect_uri = q.get("redirect_uri", "")
        if not redirect_uri or not redirect_allowed(redirect_uri) or not redirect_matches(client.redirect_uris, redirect_uri):
            return _page("invalid redirect_uri", 400)
        client_state = q.get("state")

        def fail(error: str, desc: str) -> Response:
            return self._to_client(redirect_uri, site, client_state, error=error, error_description=desc)

        if q.get("response_type") != "code":
            return fail("unsupported_response_type", "response_type must be code")
        challenge = q.get("code_challenge", "")
        if q.get("code_challenge_method") != "S256" or not re.fullmatch(r"[A-Za-z0-9_-]{43}", challenge):
            return fail("invalid_request", "PKCE S256 code_challenge required")
        if q.get("resource") != self.resource(site):
            return fail("invalid_target", "resource must be " + self.resource(site))
        requested = (q.get("scope") or " ".join(SCOPES)).split()
        if not set(requested) <= set(SCOPES) | {"offline_access"}:
            return fail("invalid_scope", "unknown scope")

        state = secrets.token_urlsafe(24)
        bind = secrets.token_urlsafe(24)
        req = AuthRequest(
            site=site,
            client_id=client.client_id,
            client_name=client.client_name or urlsplit(redirect_uri).hostname or "client",
            redirect_uri=redirect_uri,
            client_state=client_state,
            code_challenge=challenge,
            resource=self.resource(site),
            scope=" ".join(requested),
            bind=bind,
            exp=time.time() + REQUEST_TTL,
        )
        self.requests[state] = req
        signed = sign_message(
            secret,
            {
                "typ": "authz_req",
                "iss": self.issuer(site),
                "aud": tenant.moodle_url,
                "site": site,
                "state": state,
                "client_name": req.client_name,
                "redirect_host": urlsplit(redirect_uri).hostname,
                "scope": req.scope,
                "callback": f"{self.issuer(site)}/oauth/callback",
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
            path=f"/t/{site}/oauth/",
            secure=self.public_url.startswith("https://"),
            httponly=True,
            samesite="lax",
        )
        return response

    def _to_client(self, redirect_uri: str, site: str, state: str | None, **params: str) -> Response:
        params = {**params, "iss": self.issuer(site)}
        if state is not None:
            params["state"] = state
        sep = "&" if "?" in redirect_uri else "?"
        response = RedirectResponse(redirect_uri + sep + urlencode(params), 302)
        response.delete_cookie(COOKIE, path=f"/t/{site}/oauth/")
        return response

    async def _post(self, url: str, assertion: str) -> httpx.Response | None:
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=False, transport=self.transport) as client:
                return await client.post(url, data={"assertion": assertion})
        except httpx.HTTPError as exc:
            logger.warning("back channel failed: %s", type(exc).__name__)
            return None

    async def callback(self, request: Request) -> Response:
        self._purge()
        site = request.path_params["site"]
        found = self.tenant(site)
        req = self.requests.pop(request.query_params.get("state", ""), None)
        if not found or req is None or req.site != site or req.exp < time.time():
            return _page("unknown or expired request; start again from Claude", 400)
        if not hmac.compare_digest(request.cookies.get(COOKIE, ""), req.bind):
            return _page("this sign-in was started in another browser; start again from Claude", 400)
        tenant, secret = found
        if request.query_params.get("error"):
            return self._to_client(req.redirect_uri, site, req.client_state, error="access_denied",
                                   error_description="the user denied the request in Moodle")
        code = request.query_params.get("code", "")
        assertion = sign_message(
            secret,
            {
                "typ": "exchange",
                "iss": self.issuer(site),
                "aud": tenant.moodle_url,
                "site": site,
                "code": code,
                "state": request.query_params.get("state", ""),
                "jti": secrets.token_urlsafe(12),
                "exp": _now() + BACKCHANNEL_TTL,
            },
        )
        resp = await self._post(f"{tenant.moodle_url}/local/ubionai/oauth/exchange.php", assertion)
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
            return self._to_client(req.redirect_uri, site, req.client_state, error="access_denied",
                                   error_description="Moodle did not issue a token")
        userid, tokenid = data["userid"], data["tokenid"]
        problem = await self._check_user_token(tenant, data["wstoken"], userid)
        if problem:
            logger.warning("user token refused site=%s userid=%s: %s", site, userid, problem)
            await self._revoke_moodle(site, userid, tokenid)
            return self._to_client(req.redirect_uri, site, req.client_state, error="access_denied",
                                   error_description=problem)
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
        return self._to_client(req.redirect_uri, site, req.client_state, code=code_out)

    async def _check_user_token(self, tenant: Tenant, wstoken: str, userid: int) -> str | None:
        """G8: refuse site-admin tokens and tokens of any service other than ubionai_user."""
        client = MoodleClient(ws_endpoint(tenant.moodle_url), wstoken, timeout=10, transport=self.transport)
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

    async def _revoke_moodle(self, site: str, userid: int, tokenid: int) -> bool:
        found = self.tenant(site)
        if not found:
            return False
        tenant, secret = found
        assertion = sign_message(
            secret,
            {
                "typ": "revoke",
                "iss": self.issuer(site),
                "aud": tenant.moodle_url,
                "site": site,
                "userid": userid,
                "tokenid": tokenid,
                "jti": secrets.token_urlsafe(12),
                "exp": _now() + BACKCHANNEL_TTL,
            },
        )
        resp = await self._post(f"{tenant.moodle_url}/local/ubionai/oauth/revoke.php", assertion)
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
            await self._revoke_moodle(grant.site_id, grant.moodle_userid, grant.moodle_tokenid)

    async def token(self, request: Request) -> Response:
        self._purge()
        site = self._site(request)
        if not site:
            return _oauth_error("invalid_request", "unknown site", 404)
        if not request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
            return _oauth_error("invalid_request", "form-urlencoded body required")
        form = await request.form()
        grant_type = form.get("grant_type")
        client_id = str(form.get("client_id") or "")
        if not client_id or self._load_client(site, client_id) is None:
            return _oauth_error("invalid_client", "unknown client", 401)
        resource = form.get("resource")
        if resource is not None and resource != self.resource(site):
            return _oauth_error("invalid_target", "resource mismatch")

        if grant_type == "authorization_code":
            code = self.codes.pop(_hash(str(form.get("code") or "")), None)
            if code is None or code.site != site or code.exp < time.time() or code.client_id != client_id:
                if code is not None:
                    self._spawn(self._revoke_moodle(code.site, code.moodle_userid, code.moodle_tokenid))
                return _oauth_error("invalid_grant", "invalid code")
            verifier = str(form.get("code_verifier") or "")
            if (
                form.get("redirect_uri") != code.redirect_uri
                or not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier)
                or not hmac.compare_digest(_b64(hashlib.sha256(verifier.encode()).digest()), code.code_challenge)
            ):
                # The code is burnt either way; its Moodle token must not linger.
                self._spawn(self._revoke_moodle(code.site, code.moodle_userid, code.moodle_tokenid))
                return _oauth_error("invalid_grant", "redirect_uri or PKCE verification failed")
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
            if grant.site_id != site or grant.client_id != client_id:
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
        site = self._site(request)
        if not site:
            return _oauth_error("invalid_request", "unknown site", 404)
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
