"""Phase 0 spike: minimal MCP OAuth 2.1 authorization + resource server (DO NOT DEPLOY).

Self-contained prototype for DESIGN-easy-connect.md §5.1. It is not wired into
``server.create_app`` and keeps everything in memory.

Implements, per tenant ``/t/<site>``:

- RS: ``/t/<site>/mcp`` -> 401 ``WWW-Authenticate: Bearer resource_metadata=..., scope=...``;
  bearer must be an access token whose ``aud`` is exactly this resource (RFC 8707)
- RFC 9728 PRM: ``/.well-known/oauth-protected-resource/t/<site>/mcp``
- RFC 8414 AS metadata (issuer ``<base>/t/<site>``): path-insert, OIDC path-insert and
  OIDC path-append variants serve the same document
- RFC 7591 DCR ``/t/<site>/oauth/register`` (redirect_uri allowlist)
- CIMD: ``client_id`` that is an https URL on the trusted list is fetched and validated
- ``/t/<site>/oauth/authorize``: PKCE S256 required, exact ``resource``, exact redirect_uri
  (loopback: any port, RFC 8252 §7.3), ``iss`` in the response (RFC 9207)
- ``/t/<site>/oauth/token``: authorization_code + refresh_token, refresh rotation with reuse
  detection (whole family revoked), ``resource`` check
- ``/t/<site>/oauth/revoke`` (RFC 7009)

User authentication is delegated to Moodle (§3.2). ``StubMoodleDelegate`` stands in for the
plugin's ``oauth/authorize.php`` + ``oauth/exchange.php``: authorize redirects the browser to
the delegate with a signed request, the delegate redirects back to ``/t/<site>/oauth/callback``
with a one-time ``mcode``, and the hub redeems it over a back channel for the Moodle user.

Run: ``python -m moodle_mcp.oauth_spike --port 8799 --sites demo`` (binds 127.0.0.1 only).
"""

from __future__ import annotations

import argparse
import base64
import contextvars
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable
from urllib.parse import urlencode, urlsplit

import httpx
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger("moodle_mcp.oauth_spike")

SCOPES = ["moodle:read", "moodle:write"]
SITE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
MCP_PATH_RE = re.compile(r"^/t/([a-z0-9][a-z0-9-]{0,62})/mcp/?$")
ALLOWED_REDIRECTS = (
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
)
TRUSTED_CIMD = ("https://claude.ai/oauth/claude-code-client-metadata",)
CODE_TTL = 60
REQUEST_TTL = 600


def _now() -> float:
    return time.time()


def _h(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def sign(key: bytes, claims: dict[str, Any]) -> str:
    body = _b64(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    return body + "." + _b64(hmac.new(key, body.encode(), hashlib.sha256).digest())


def verify(key: bytes, token: str) -> dict[str, Any] | None:
    try:
        body, mac = token.split(".", 1)
        if not hmac.compare_digest(_unb64(mac), hmac.new(key, body.encode(), hashlib.sha256).digest()):
            return None
        claims = json.loads(_unb64(body))
    except (ValueError, json.JSONDecodeError):
        return None
    if claims.get("exp", 0) < _now():
        return None
    return claims


def _is_loopback(uri: str) -> bool:
    parts = urlsplit(uri)
    if parts.scheme != "http" or not parts.hostname:
        return False
    if parts.hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(parts.hostname).is_loopback
    except ValueError:
        return False


def redirect_allowed(uri: str) -> bool:
    """Hub-wide allowlist (§5.1, decision 3): Claude callbacks + loopback for Claude Code."""
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


@dataclass
class Client:
    client_id: str
    redirect_uris: list[str]
    client_name: str | None
    source: str  # dcr | cimd
    created: float = field(default_factory=_now)


@dataclass
class AuthRequest:
    req_id: str
    site: str
    client_id: str
    redirect_uri: str
    state: str | None
    code_challenge: str
    resource: str
    scope: str
    exp: float


@dataclass
class AuthCode:
    site: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    resource: str
    scope: str
    subject: str
    exp: float
    used: bool = False
    family: str | None = None


@dataclass
class TokenRecord:
    kind: str  # access | refresh
    site: str
    client_id: str
    subject: str
    resource: str
    scope: str
    family: str
    exp: float
    used: bool = False


@dataclass
class Store:
    clients: dict[str, Client] = field(default_factory=dict)
    requests: dict[str, AuthRequest] = field(default_factory=dict)
    codes: dict[str, AuthCode] = field(default_factory=dict)
    tokens: dict[str, TokenRecord] = field(default_factory=dict)
    revoked_families: set[str] = field(default_factory=set)

    def revoke_family(self, family: str) -> None:
        self.revoked_families.add(family)
        for rec in self.tokens.values():
            if rec.family == family:
                rec.used = True
                rec.exp = 0


# --- Moodle delegation -------------------------------------------------------------------


class MoodleDelegate:
    """Contract for the Moodle side (plugin ``oauth/authorize.php`` + ``oauth/exchange.php``)."""

    def authorize_url(self, site: str, signed_request: str) -> str:
        raise NotImplementedError

    async def exchange(self, site: str, req_id: str, mcode: str) -> dict[str, Any] | None:
        """Back channel: redeem a one-time mcode -> ``{"userid": ..., "wstoken"?: ...}``."""
        raise NotImplementedError


class StubMoodleDelegate(MoodleDelegate):
    """In-process stand-in: ``/_stub/moodle/authorize`` auto-approves as ``user_id``."""

    def __init__(self, base_url: str, user_id: int = 3) -> None:
        self.base_url = base_url
        self.user_id = user_id
        self.codes: dict[str, dict[str, Any]] = {}

    def authorize_url(self, site: str, signed_request: str) -> str:
        return f"{self.base_url}/_stub/moodle/authorize?" + urlencode({"req": signed_request})

    def issue(self, req_id: str, site: str) -> str:
        mcode = secrets.token_urlsafe(24)
        self.codes[_h(mcode)] = {"req_id": req_id, "site": site, "userid": self.user_id, "exp": _now() + 120}
        return mcode

    async def exchange(self, site: str, req_id: str, mcode: str) -> dict[str, Any] | None:
        rec = self.codes.pop(_h(mcode), None)
        if not rec or rec["exp"] < _now() or rec["req_id"] != req_id or rec["site"] != site:
            return None
        return {"userid": rec["userid"]}


class HttpMoodleDelegate(MoodleDelegate):
    """Untested sketch for wiring a real Moodle: signed POST to the plugin's exchange endpoint."""

    def __init__(self, authorize_url: str, exchange_url: str, secret: bytes) -> None:
        self._authorize = authorize_url
        self._exchange = exchange_url
        self._secret = secret

    def authorize_url(self, site: str, signed_request: str) -> str:
        return self._authorize + "?" + urlencode({"req": signed_request})

    async def exchange(self, site: str, req_id: str, mcode: str) -> dict[str, Any] | None:
        assertion = sign(self._secret, {"aud": site, "req_id": req_id, "mcode": mcode, "exp": _now() + 60})
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            resp = await client.post(self._exchange, data={"assertion": assertion})
        if resp.status_code != 200:
            return None
        return resp.json()


# --- CIMD --------------------------------------------------------------------------------

CimdFetcher = Callable[[str], Awaitable[dict[str, Any]]]


async def default_cimd_fetcher(url: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=5, follow_redirects=False) as client:
        resp = await client.get(url, headers={"Accept": "application/json"})
    if resp.status_code != 200 or len(resp.content) > 5 * 1024:
        raise ValueError(f"CIMD fetch failed: HTTP {resp.status_code}")
    return resp.json()


# --- application -------------------------------------------------------------------------


@dataclass
class Config:
    base_url: str
    sites: set[str]
    access_ttl: int = 3600
    refresh_ttl: int = 30 * 86400
    trusted_cimd: tuple[str, ...] = TRUSTED_CIMD


_subject: contextvars.ContextVar[TokenRecord | None] = contextvars.ContextVar("oauth_spike_subject", default=None)


def _oauth_error(error: str, description: str, status: int = 400) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status,
        headers={"Cache-Control": "no-store"},
    )


class OAuthSpike:
    def __init__(
        self,
        config: Config,
        delegate: MoodleDelegate | None = None,
        cimd_fetcher: CimdFetcher | None = None,
    ) -> None:
        self.config = config
        self.store = Store()
        self.request_key = secrets.token_bytes(32)
        self.delegate = delegate or StubMoodleDelegate(config.base_url)
        self.cimd_fetcher = cimd_fetcher or default_cimd_fetcher
        self.request_log: list[str] = []
        self.mcp = self._build_mcp()
        self.mcp_app = self.mcp.streamable_http_app()
        self.router = Starlette(routes=self._routes())

    # urls
    def issuer(self, site: str) -> str:
        return f"{self.config.base_url}/t/{site}"

    def resource(self, site: str) -> str:
        return f"{self.config.base_url}/t/{site}/mcp"

    def prm_url(self, site: str) -> str:
        return f"{self.config.base_url}/.well-known/oauth-protected-resource/t/{site}/mcp"

    # MCP
    def _build_mcp(self) -> FastMCP:
        mcp = FastMCP("moodle-oauth-spike", streamable_http_path="/mcp", stateless_http=True, json_response=True)

        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
        def whoami() -> dict[str, Any]:
            """Return the delegated Moodle subject bound to the access token."""
            rec = _subject.get()
            if rec is None:
                raise ValueError("no subject")
            return {
                "site": rec.site,
                "moodle_userid": rec.subject,
                "client_id": rec.client_id,
                "scope": rec.scope,
                "aud": rec.resource,
            }

        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
        def echo(text: str) -> str:
            """Echo text back."""
            return text

        return mcp

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self.mcp_app(scope, receive, send)
            return
        if scope["type"] != "http":
            return
        path = scope["path"]
        query = scope.get("query_string", b"").decode()
        query = re.sub(r"\b(code|mcode|req|state|code_challenge)=[^&]*", r"\1=***", query)
        entry = f"{scope['method']} {path}" + (f"?{query}" if query else "")
        self.request_log.append(entry)
        logger.info("%s", entry)
        m = MCP_PATH_RE.match(path)
        if m:
            await self._mcp_entry(m.group(1), scope, receive, send)
            return
        await self.router(scope, receive, send)

    async def _mcp_entry(self, site: str, scope: Scope, receive: Receive, send: Send) -> None:
        if site not in self.config.sites:
            await JSONResponse({"error": "unknown site"}, status_code=404)(scope, receive, send)
            return
        auth = ""
        for name, value in scope.get("headers", []):
            if name == b"authorization":
                auth = value.decode("latin-1")
        challenge = f'Bearer resource_metadata="{self.prm_url(site)}", scope="{" ".join(SCOPES)}"'
        if not auth.lower().startswith("bearer "):
            await JSONResponse(
                {"error": "unauthorized"}, status_code=401, headers={"WWW-Authenticate": challenge}
            )(scope, receive, send)
            return
        rec = self.store.tokens.get(_h(auth[7:].strip()))
        valid = (
            rec is not None
            and rec.kind == "access"
            and not rec.used
            and rec.exp > _now()
            and rec.family not in self.store.revoked_families
            and rec.site == site
            and rec.resource == self.resource(site)  # RFC 8707 audience; no token passthrough
        )
        if not valid:
            await JSONResponse(
                {"error": "invalid_token"},
                status_code=401,
                headers={"WWW-Authenticate": challenge + ', error="invalid_token"'},
            )(scope, receive, send)
            return
        scope = dict(scope, path="/mcp", raw_path=b"/mcp")
        token = _subject.set(rec)
        try:
            await self.mcp_app(scope, receive, send)
        finally:
            _subject.reset(token)

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
            Route("/_stub/moodle/authorize", self.stub_moodle_authorize, methods=["GET"]),
            Route("/health", lambda r: JSONResponse({"status": "ok"})),
        ]

    def _site(self, request: Request) -> str | None:
        site = request.path_params["site"]
        return site if SITE_RE.match(site) and site in self.config.sites else None

    # metadata
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

    # clients
    async def register(self, request: Request) -> Response:
        if not self._site(request):
            return JSONResponse({"error": "not found"}, status_code=404)
        try:
            body = await request.json()
        except (ValueError, json.JSONDecodeError):
            return _oauth_error("invalid_client_metadata", "body must be JSON")
        uris = body.get("redirect_uris")
        if not isinstance(uris, list) or not uris or not all(isinstance(u, str) for u in uris):
            return _oauth_error("invalid_redirect_uri", "redirect_uris required")
        bad = [u for u in uris if not redirect_allowed(u)]
        if bad:
            return _oauth_error("invalid_redirect_uri", f"redirect_uri not allowed: {bad[0]}")
        method = body.get("token_endpoint_auth_method", "none")
        if method != "none":
            return _oauth_error("invalid_client_metadata", "only public clients (none)")
        grants = body.get("grant_types") or ["authorization_code", "refresh_token"]
        if not set(grants) <= {"authorization_code", "refresh_token"}:
            return _oauth_error("invalid_client_metadata", "unsupported grant_types")
        client = Client(
            client_id="dcr_" + secrets.token_urlsafe(16),
            redirect_uris=list(uris),
            client_name=body.get("client_name"),
            source="dcr",
        )
        self.store.clients[client.client_id] = client
        return JSONResponse(
            {
                "client_id": client.client_id,
                "client_id_issued_at": int(client.created),
                "redirect_uris": client.redirect_uris,
                "client_name": client.client_name,
                "token_endpoint_auth_method": "none",
                "grant_types": grants,
                "response_types": ["code"],
            },
            status_code=201,
        )

    async def _client(self, client_id: str) -> Client | None:
        if client_id in self.store.clients:
            return self.store.clients[client_id]
        if not client_id.startswith("https://"):
            return None
        if client_id not in self.config.trusted_cimd:
            logger.warning("CIMD client not on trusted list: %s", client_id)
            return None
        try:
            doc = await self.cimd_fetcher(client_id)
        except Exception as exc:  # noqa: BLE001 - any fetch/parse failure rejects the client
            logger.warning("CIMD fetch failed %s: %s", client_id, exc)
            return None
        uris = doc.get("redirect_uris")
        if doc.get("client_id") != client_id or not isinstance(uris, list) or not uris:
            return None
        if doc.get("token_endpoint_auth_method", "none") != "none":
            return None
        client = Client(client_id, [u for u in uris if isinstance(u, str)], doc.get("client_name"), "cimd")
        self.store.clients[client_id] = client
        return client

    # authorize
    async def authorize(self, request: Request) -> Response:
        site = self._site(request)
        if not site:
            return HTMLResponse("unknown site", status_code=404)
        q = request.query_params
        client = await self._client(q.get("client_id", ""))
        if client is None:
            return HTMLResponse("invalid client_id", status_code=400)
        redirect_uri = q.get("redirect_uri", "")
        if not redirect_uri or not redirect_allowed(redirect_uri) or not redirect_matches(
            client.redirect_uris, redirect_uri
        ):
            return HTMLResponse("invalid redirect_uri", status_code=400)
        state = q.get("state")

        def fail(error: str, desc: str) -> Response:
            params = {"error": error, "error_description": desc, "iss": self.issuer(site)}
            if state is not None:
                params["state"] = state
            return RedirectResponse(redirect_uri + ("&" if "?" in redirect_uri else "?") + urlencode(params), 302)

        if q.get("response_type") != "code":
            return fail("unsupported_response_type", "response_type must be code")
        challenge = q.get("code_challenge", "")
        if q.get("code_challenge_method") != "S256" or not re.fullmatch(r"[A-Za-z0-9_-]{43}", challenge):
            return fail("invalid_request", "PKCE S256 code_challenge required")
        resource = q.get("resource")
        if resource != self.resource(site):
            return fail("invalid_target", "resource must be " + self.resource(site))
        requested = (q.get("scope") or " ".join(SCOPES)).split()
        if not set(requested) <= set(SCOPES) | {"offline_access"}:
            return fail("invalid_scope", "unknown scope")
        req = AuthRequest(
            req_id=secrets.token_urlsafe(16),
            site=site,
            client_id=client.client_id,
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=challenge,
            resource=resource,
            scope=" ".join(requested),
            exp=_now() + REQUEST_TTL,
        )
        self.store.requests[req.req_id] = req
        signed = sign(
            self.request_key,
            {
                "req_id": req.req_id,
                "site": site,
                "client_name": client.client_name or client.client_id,
                "redirect_host": urlsplit(redirect_uri).hostname,
                "scope": req.scope,
                "callback": f"{self.issuer(site)}/oauth/callback",
                "exp": int(req.exp),
            },
        )
        return RedirectResponse(self.delegate.authorize_url(site, signed), 302)

    async def stub_moodle_authorize(self, request: Request) -> Response:
        """Stand-in for Moodle ``local/ubionai/oauth/authorize.php`` (login + consent auto-approved)."""
        if not isinstance(self.delegate, StubMoodleDelegate):
            return HTMLResponse("stub disabled", status_code=404)
        claims = verify(self.request_key, request.query_params.get("req", ""))
        if not claims:
            return HTMLResponse("bad request", status_code=400)
        mcode = self.delegate.issue(claims["req_id"], claims["site"])
        return RedirectResponse(
            claims["callback"] + "?" + urlencode({"req_id": claims["req_id"], "mcode": mcode}), 302
        )

    async def callback(self, request: Request) -> Response:
        site = self._site(request)
        req = self.store.requests.pop(request.query_params.get("req_id", ""), None)
        if not site or req is None or req.site != site or req.exp < _now():
            return HTMLResponse("unknown or expired request", status_code=400)
        user = await self.delegate.exchange(site, req.req_id, request.query_params.get("mcode", ""))
        if not user or "userid" not in user:
            return HTMLResponse("delegated login failed", status_code=400)
        code = secrets.token_urlsafe(32)
        self.store.codes[_h(code)] = AuthCode(
            site=site,
            client_id=req.client_id,
            redirect_uri=req.redirect_uri,
            code_challenge=req.code_challenge,
            resource=req.resource,
            scope=req.scope,
            subject=str(user["userid"]),
            exp=_now() + CODE_TTL,
        )
        params = {"code": code, "iss": self.issuer(site)}
        if req.state is not None:
            params["state"] = req.state
        sep = "&" if "?" in req.redirect_uri else "?"
        return RedirectResponse(req.redirect_uri + sep + urlencode(params), 302)

    # token
    def _issue(self, site: str, client_id: str, subject: str, resource: str, scope: str, family: str) -> dict:
        access = secrets.token_urlsafe(32)
        refresh = secrets.token_urlsafe(32)
        now = _now()
        self.store.tokens[_h(access)] = TokenRecord(
            "access", site, client_id, subject, resource, scope, family, now + self.config.access_ttl
        )
        self.store.tokens[_h(refresh)] = TokenRecord(
            "refresh", site, client_id, subject, resource, scope, family, now + self.config.refresh_ttl
        )
        return {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": self.config.access_ttl,
            "refresh_token": refresh,
            "scope": scope,
        }

    async def token(self, request: Request) -> Response:
        site = self._site(request)
        if not site:
            return _oauth_error("invalid_request", "unknown site", 404)
        if not request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
            return _oauth_error("invalid_request", "form-urlencoded body required")
        form = await request.form()
        grant = form.get("grant_type")
        client_id = str(form.get("client_id") or "")
        if client_id not in self.store.clients:
            return _oauth_error("invalid_client", "unknown client", 401)
        resource = form.get("resource")
        if resource is not None and resource != self.resource(site):
            return _oauth_error("invalid_target", "resource mismatch")

        if grant == "authorization_code":
            code = self.store.codes.get(_h(str(form.get("code") or "")))
            if code is None or code.site != site or code.exp < _now() or code.client_id != client_id:
                return _oauth_error("invalid_grant", "invalid code")
            if code.used:
                if code.family:
                    self.store.revoke_family(code.family)  # code replay: kill what it minted
                return _oauth_error("invalid_grant", "code already used")
            if form.get("redirect_uri") != code.redirect_uri:
                return _oauth_error("invalid_grant", "redirect_uri mismatch")
            verifier = str(form.get("code_verifier") or "")
            if not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier) or not hmac.compare_digest(
                _b64(hashlib.sha256(verifier.encode()).digest()), code.code_challenge
            ):
                return _oauth_error("invalid_grant", "PKCE verification failed")
            if resource is not None and resource != code.resource:
                return _oauth_error("invalid_target", "resource differs from authorization request")
            code.used = True
            code.family = secrets.token_urlsafe(12)
            body = self._issue(site, client_id, code.subject, code.resource, code.scope, code.family)
            return JSONResponse(body, headers={"Cache-Control": "no-store"})

        if grant == "refresh_token":
            rec = self.store.tokens.get(_h(str(form.get("refresh_token") or "")))
            if rec is None or rec.kind != "refresh" or rec.site != site or rec.client_id != client_id:
                return _oauth_error("invalid_grant", "invalid refresh token")
            if rec.used or rec.family in self.store.revoked_families:
                self.store.revoke_family(rec.family)  # reuse detected -> revoke whole family
                return _oauth_error("invalid_grant", "refresh token reused or revoked")
            if rec.exp < _now():
                return _oauth_error("invalid_grant", "refresh token expired")
            rec.used = True
            body = self._issue(site, client_id, rec.subject, rec.resource, rec.scope, rec.family)
            return JSONResponse(body, headers={"Cache-Control": "no-store"})

        return _oauth_error("unsupported_grant_type", "authorization_code or refresh_token")

    async def revoke(self, request: Request) -> Response:
        site = self._site(request)
        if not site:
            return _oauth_error("invalid_request", "unknown site", 404)
        form = await request.form()
        rec = self.store.tokens.get(_h(str(form.get("token") or "")))
        if rec is not None and rec.site == site and rec.client_id == form.get("client_id"):
            if rec.kind == "refresh":
                self.store.revoke_family(rec.family)
            else:
                rec.used = True
                rec.exp = 0
        return Response(status_code=200)  # RFC 7009 §2.2: 200 even for unknown tokens


def create_spike_app(
    base_url: str,
    sites: set[str],
    delegate: MoodleDelegate | None = None,
    cimd_fetcher: CimdFetcher | None = None,
    access_ttl: int = 3600,
) -> OAuthSpike:
    return OAuthSpike(Config(base_url=base_url.rstrip("/"), sites=sites, access_ttl=access_ttl), delegate, cimd_fetcher)


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase 0 OAuth spike (127.0.0.1 only)")
    parser.add_argument("--port", type=int, default=8799)
    parser.add_argument("--sites", default="demo", help="comma separated site ids")
    parser.add_argument("--stub-user", type=int, default=3, help="Moodle user id the stub approves as")
    parser.add_argument("--moodle-authorize-url", help="real Moodle delegate authorize URL (disables stub)")
    parser.add_argument("--moodle-exchange-url", help="real Moodle delegate exchange URL")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    base = f"http://127.0.0.1:{args.port}"
    delegate: MoodleDelegate | None = None
    if args.moodle_authorize_url:
        secret = os.environ.get("OAUTH_SPIKE_DELEGATE_SECRET", "").encode()
        if not secret or not args.moodle_exchange_url:
            parser.error("--moodle-exchange-url and OAUTH_SPIKE_DELEGATE_SECRET are required with a real delegate")
        delegate = HttpMoodleDelegate(args.moodle_authorize_url, args.moodle_exchange_url, secret)
    else:
        delegate = StubMoodleDelegate(base, args.stub_user)
    app = create_spike_app(base, set(args.sites.split(",")), delegate)

    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
