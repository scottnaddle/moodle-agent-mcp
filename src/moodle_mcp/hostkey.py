"""Canonical ``host_key`` for self-registered sites and ``/m/<host_key>/…`` routes.

Registration (``site_url``) and routing (``/m/<host_key>/mcp``) both go through
``normalize_host_key`` so the stored key and the routed key cannot drift apart
(registration contract §6.2).
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import idna

MAX_SITE_URL = 255
MAX_HOST_KEY = 255
MAX_PATH = 100
MAX_SEGMENTS = 4
DEFAULT_PORTS = frozenset({443})

# Host names that only make sense inside a private network (§4.3). v1 does not serve them.
INTERNAL_NAMES = frozenset({"localhost"})
INTERNAL_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa", ".intranet")

_SEGMENT_RE = re.compile(r"[A-Za-z0-9._~-]+")
_LABEL_RE = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")
_NUMERIC_RE = re.compile(r"(0x[0-9a-f]*|[0-9]+)")


class HostKeyError(Exception):
    """``code`` is a registration error code (§4.1): invalid_site_url, unsupported_scheme,
    port_not_allowed or private_address_not_supported."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code


def parse_ports(value: str | None) -> frozenset[int]:
    """``UBIONAI_HUB_REG_ALLOWED_PORTS`` (comma list, default 443). Raises ValueError."""
    if value is None or not value.strip():
        return DEFAULT_PORTS
    ports: set[int] = set()
    for raw in value.split(","):
        entry = raw.strip()
        if not entry.isdigit() or not 0 < int(entry) < 65536:
            raise ValueError(f"invalid port '{entry}'")
        ports.add(int(entry))
    return frozenset(ports | {443})


def allowed_ports_from_env() -> frozenset[int]:
    try:
        return parse_ports(os.environ.get("UBIONAI_HUB_REG_ALLOWED_PORTS"))
    except ValueError:
        return DEFAULT_PORTS


def normalize_hostname(raw: str) -> str:
    """Lower-case, drop one trailing dot, UTS #46 + IDNA 2008 to A-labels, refuse internal names."""
    host = raw.strip()
    if not host or host != raw:
        raise HostKeyError("invalid_site_url", "empty host")
    if host.startswith("[") or ":" in host:
        raise HostKeyError("private_address_not_supported", "IP literal hosts are not supported")
    host = host.lower()
    if host.endswith("."):
        host = host[:-1]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise HostKeyError("private_address_not_supported", "IP literal hosts are not supported")
    try:
        ascii_host = idna.encode(host, uts46=True, transitional=False).decode("ascii")
    except (idna.IDNAError, UnicodeError, ValueError):
        raise HostKeyError("invalid_site_url", "host is not a valid domain name") from None
    labels = ascii_host.split(".")
    if len(ascii_host) > 253 or not all(_LABEL_RE.fullmatch(label) for label in labels):
        raise HostKeyError("invalid_site_url", "host is not a valid domain name")
    if len(labels) < 2:
        raise HostKeyError("private_address_not_supported", "single-label hosts are not supported")
    # 2130706433, 0177.0.0.1, 0x7f.1 … are IP literals to many resolvers; a numeric TLD is never valid.
    if _NUMERIC_RE.fullmatch(labels[-1]):
        raise HostKeyError("private_address_not_supported", "IP literal hosts are not supported")
    if ascii_host in INTERNAL_NAMES or ascii_host.endswith(INTERNAL_SUFFIXES):
        raise HostKeyError("private_address_not_supported", "internal host names are not supported")
    return ascii_host


def _normalize_port(raw: str | None, allowed_ports: frozenset[int]) -> int:
    if raw is None:
        return 443
    if not raw.isdigit() or len(raw) > 5:
        raise HostKeyError("invalid_site_url", "invalid port")
    port = int(raw)
    if not 0 < port < 65536:
        raise HostKeyError("invalid_site_url", "invalid port")
    if port != 443 and port not in allowed_ports:
        raise HostKeyError("port_not_allowed", "port not allowed")
    return port


def _normalize_path(raw: str) -> str:
    path = raw.rstrip("/")
    if not path:
        return ""
    if not path.startswith("/") or len(path) > MAX_PATH:
        raise HostKeyError("invalid_site_url", "invalid path")
    segments = path[1:].split("/")
    if len(segments) > MAX_SEGMENTS:
        raise HostKeyError("invalid_site_url", "too many path segments")
    for seg in segments:
        if seg in ("", ".", "..") or not _SEGMENT_RE.fullmatch(seg):
            raise HostKeyError("invalid_site_url", "invalid path segment")
    return path


def normalize_host_key(raw: str, allowed_ports: frozenset[int] = DEFAULT_PORTS) -> str:
    """``<host>[:<port>][/<path>]`` -> canonical host_key (§6.2). Raises HostKeyError."""
    if not raw or any(ord(c) <= 0x20 or ord(c) == 0x7F for c in raw) or "\\" in raw:
        raise HostKeyError("invalid_site_url", "invalid host key")
    if any(c in raw for c in "?#@%"):
        raise HostKeyError("invalid_site_url", "query, fragment, userinfo and percent-encoding are not allowed")
    authority, slash, path = raw.partition("/")
    if authority.startswith("["):
        raise HostKeyError("private_address_not_supported", "IP literal hosts are not supported")
    host, colon, port_text = authority.rpartition(":") if ":" in authority else (authority, "", "")
    if colon and ":" in host:
        raise HostKeyError("private_address_not_supported", "IP literal hosts are not supported")
    hostname = normalize_hostname(host)
    port = _normalize_port(port_text if colon else None, allowed_ports)
    norm_path = _normalize_path(slash + path)
    key = hostname + ("" if port == 443 else f":{port}") + norm_path
    if len(key) > MAX_HOST_KEY:
        raise HostKeyError("invalid_site_url", "host key too long")
    return key


@dataclass(frozen=True)
class SiteUrl:
    url: str  # canonical https URL (no trailing slash)
    host_key: str
    host: str  # canonical host name (A-labels, no port)


def normalize_site_url(site_url: str, allowed_ports: frozenset[int] = DEFAULT_PORTS) -> SiteUrl:
    """Moodle ``$CFG->wwwroot`` -> canonical URL + host_key. https only (§1.3, §2.2)."""
    if not isinstance(site_url, str) or not site_url or len(site_url) > MAX_SITE_URL:
        raise HostKeyError("invalid_site_url", "site_url missing or too long")
    try:
        parts = urlsplit(site_url)
    except ValueError:
        raise HostKeyError("invalid_site_url", "site_url does not parse") from None
    scheme = parts.scheme.lower()
    if scheme != "https":
        if scheme and parts.netloc:
            raise HostKeyError("unsupported_scheme", "site_url must be https")
        raise HostKeyError("invalid_site_url", "site_url must be an absolute https URL")
    if "@" in parts.netloc or "?" in site_url or "#" in site_url:
        raise HostKeyError("invalid_site_url", "userinfo, query and fragment are not allowed")
    key = normalize_host_key(parts.netloc + parts.path, allowed_ports)
    host = key.split("/", 1)[0].split(":", 1)[0]
    return SiteUrl(url="https://" + key, host=host, host_key=key)


def site_key_for(host_key: str, hash_len: int = 6) -> str:
    """``slug(host_key)[:48] + "-" + sha256(host_key)[:n]`` — the tenant's public site_id (§3.1)."""
    slug = re.sub(r"[^a-z0-9]+", "-", host_key.lower()).strip("-")[:48].strip("-")
    return f"{slug}-{hashlib.sha256(host_key.encode()).hexdigest()[:hash_len]}"


# --- /m/<host_key>/… routes -----------------------------------------------------------------

_WELL_KNOWN_PRM = "/.well-known/oauth-protected-resource/m/"
_WELL_KNOWN_AS = ("/.well-known/oauth-authorization-server/m/", "/.well-known/openid-configuration/m/")
_OAUTH_SUFFIX_RE = re.compile(r"^(.+)/oauth/([a-z]+)$")


@dataclass(frozen=True)
class HostRoute:
    raw_host_key: str
    kind: str  # "mcp", "prm", "as_metadata", "oauth"
    endpoint: str = ""  # oauth endpoint name for kind == "oauth"


def is_host_route(path: str) -> bool:
    return path.startswith("/m/") or path.startswith(_WELL_KNOWN_PRM) or path.startswith(_WELL_KNOWN_AS)


def parse_host_route(path: str) -> HostRoute | None:
    """Split ``/m/<host_key><fixed suffix>``; the suffix is taken from the end, so a wwwroot path
    containing ``mcp`` or ``oauth`` stays unambiguous (``/m/ex.com/mcp/mcp`` -> ``ex.com/mcp``)."""
    if path.startswith(_WELL_KNOWN_PRM):
        rest = path[len(_WELL_KNOWN_PRM):]
        if rest.endswith("/mcp") and len(rest) > 4:
            return HostRoute(rest[:-4], "prm")
        return None
    for prefix in _WELL_KNOWN_AS:
        if path.startswith(prefix):
            rest = path[len(prefix):]
            return HostRoute(rest, "as_metadata") if rest else None
    if not path.startswith("/m/"):
        return None
    rest = path[3:]
    if rest.endswith("/mcp") and len(rest) > 4:
        return HostRoute(rest[:-4], "mcp")
    if rest.endswith("/.well-known/openid-configuration"):
        host = rest[: -len("/.well-known/openid-configuration")]
        return HostRoute(host, "as_metadata") if host else None
    match = _OAUTH_SUFFIX_RE.match(rest)
    if match:
        return HostRoute(match.group(1), "oauth", match.group(2))
    return None
