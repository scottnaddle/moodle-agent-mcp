"""Network-related helpers shared by the hub: IP lists, public-address policy, pinned connections."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Iterable

import httpx

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
Resolver = Callable[[str, int], Awaitable[list[str]]]

_NAT64 = ipaddress.ip_network("64:ff9b::/96")

# Registration contract §4.3. Most of these already fail ``is_global``; they are listed so the
# policy does not depend on the Python version's special-purpose registry, and so the public
# platform addresses that do pass ``is_global`` (Azure WireServer) are refused too.
DENY_NETWORKS: tuple[IPNetwork, ...] = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
        "168.63.129.16/32",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
        "2001:db8::/32",
        "2001::/32",
        "100::/64",
    )
)


def parse_ip_list(value: str | None) -> str | None:
    """Normalise a comma-separated IP/CIDR list.

    Args:
        value: raw value, or None / "" / whitespace-only for "no restriction".

    Returns:
        Canonical comma-joined string, or None when value is empty/whitespace-only.

    Raises:
        ValueError: with a message naming the offending entry, e.g.
            "invalid IP entry '1.2.3.4 # office'".
    """
    if value is None or not value.strip():
        return None

    canonical: list[str] = []
    seen: set[str] = set()
    for raw in value.split(","):
        entry = raw.strip()
        if entry == "":
            raise ValueError("empty entry in IP list")
        if "#" in entry or "%" in entry or any(ch.isspace() for ch in entry):
            raise ValueError(f"invalid IP entry '{entry}'")
        try:
            if "/" in entry:
                normalised = str(ipaddress.ip_network(entry, strict=True))
            else:
                normalised = str(ipaddress.ip_address(entry))
        except ValueError:
            raise ValueError(f"invalid IP entry '{entry}'") from None
        if normalised not in seen:
            seen.add(normalised)
            canonical.append(normalised)

    result = ",".join(canonical)
    if len(result) > 255:
        raise ValueError("IP list exceeds 255 characters")
    return result


def parse_networks(value: str | None) -> tuple[IPNetwork, ...]:
    """Comma-separated IPs/CIDRs -> networks (a bare IP becomes a /32 or /128)."""
    if value is None or not value.strip():
        return ()
    nets: list[IPNetwork] = []
    for raw in value.split(","):
        entry = raw.strip()
        if not entry:
            raise ValueError("empty entry in CIDR list")
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            raise ValueError(f"invalid CIDR entry '{entry}'") from None
    return tuple(nets)


def ip_allowed(ip: IPAddress) -> bool:
    """Only globally routable unicast addresses (IPv4-mapped / 6to4 / NAT64 checked as their IPv4)."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip_allowed(ip.ipv4_mapped)
        if ip.sixtofour is not None:
            return ip_allowed(ip.sixtofour)
        if ip.teredo is not None:
            return False
        if ip in _NAT64:
            return ip_allowed(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return ip.is_global and not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _embedded(ip: IPAddress) -> list[IPAddress]:
    out: list[IPAddress] = [ip]
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            out.append(ip.ipv4_mapped)
        if ip.sixtofour is not None:
            out.append(ip.sixtofour)
        if ip in _NAT64:
            out.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return out


@dataclass
class AddressPolicy:
    """``ip_allowed`` + the §4.3 deny list + operator CIDRs + the hub's own addresses."""

    extra_deny: tuple[IPNetwork, ...] = ()
    self_addresses: set[IPAddress] = field(default_factory=set)

    def allowed(self, ip: IPAddress) -> bool:
        if not ip_allowed(ip):
            return False
        for candidate in _embedded(ip):
            if candidate in self.self_addresses:
                return False
            for net in DENY_NETWORKS + self.extra_deny:
                if candidate.version == net.version and candidate in net:
                    return False
        return True


async def system_resolve(host: str, port: int) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [str(info[4][0]).split("%", 1)[0] for info in infos]


class ResolveError(Exception):
    """The host did not resolve."""


class BlockedAddress(Exception):
    """The host is (or resolves to) a non-public address."""


async def vet_host(
    host: str,
    port: int,
    resolve: Resolver,
    policy: AddressPolicy | None = None,
    *,
    allow_literal: bool = True,
) -> str:
    """Resolve once; every address must pass the policy; return the first one to connect to."""
    try:
        literal: IPAddress | None = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        literal = None
    if literal is not None and not allow_literal:
        raise BlockedAddress("IP literal host")
    try:
        addresses = [str(literal)] if literal is not None else await resolve(host, port)
    except OSError as exc:
        raise ResolveError("host did not resolve") from exc
    if not addresses:
        raise ResolveError("host did not resolve")
    try:
        ips = [ipaddress.ip_address(a) for a in addresses]
    except ValueError as exc:
        raise ResolveError("resolver returned a malformed address") from exc
    check = policy.allowed if policy is not None else ip_allowed
    if not all(check(ip) for ip in ips):
        raise BlockedAddress("host resolves to a non-public address")
    return str(ips[0])


class BlockedAddressError(httpx.TransportError):
    """Raised by PinnedPublicTransport when the destination is not a public address."""


class PinnedPublicTransport(httpx.AsyncBaseTransport):
    """httpx transport that resolves the host itself and connects only to a vetted public IP.

    Every request re-resolves and re-vets (a tenant whose DNS later points inside fails from then
    on); the TCP connection goes to the vetted IP while TLS SNI, certificate verification and the
    ``Host`` header keep the host name, so DNS rebinding between check and connect is impossible.
    Use it with ``trust_env=False`` clients; proxies would defeat the pinning.
    """

    def __init__(
        self,
        inner: httpx.AsyncBaseTransport | None = None,
        *,
        resolve: Resolver = system_resolve,
        policy: AddressPolicy | None = None,
        https_only: bool = True,
        allow_literal: bool = False,
    ) -> None:
        self.inner = inner if inner is not None else httpx.AsyncHTTPTransport(trust_env=False)
        self.resolve = resolve
        self.policy = policy if policy is not None else AddressPolicy()
        self.https_only = https_only
        self.allow_literal = allow_literal
        self.targets: list[tuple[str, str]] = []  # (host, ip) of recent requests, for tests/logs

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        if self.https_only and url.scheme != "https":
            raise BlockedAddressError("only https destinations are allowed", request=request)
        host = url.host
        port = url.port or (443 if url.scheme == "https" else 80)
        try:
            ip = await vet_host(host, port, self.resolve, self.policy, allow_literal=self.allow_literal)
        except BlockedAddress as exc:
            raise BlockedAddressError(str(exc), request=request) from None
        except ResolveError as exc:
            raise httpx.ConnectError(str(exc), request=request) from None
        self.targets.append((host, ip))
        del self.targets[:-20]
        pinned = httpx.Request(
            request.method,
            url.copy_with(host=ip),
            headers=request.headers,  # already carries Host: <name>
            stream=request.stream,
            extensions={**request.extensions, "sni_hostname": host},
        )
        return await self.inner.handle_async_request(pinned)

    async def aclose(self) -> None:
        await self.inner.aclose()


class FetchError(Exception):
    """A pinned fetch failed. ``kind``: blocked, unreachable, redirected, status, too_large, timeout."""

    def __init__(self, kind: str, detail: str = "", status: int | None = None) -> None:
        super().__init__(f"{kind}: {detail}" if detail else kind)
        self.kind = kind
        self.status = status


@dataclass
class SafeFetcher:
    """GET a small JSON document from an untrusted https URL with SSRF protection.

    One resolution per request, every address public, connection pinned to the vetted IP, no
    redirects, environment proxies ignored, bounded size and time. ``transport`` is the inner
    transport below the pinning layer (``httpx.MockTransport`` in tests).
    """

    transport: httpx.AsyncBaseTransport | None = None
    resolve: Resolver = system_resolve
    policy: AddressPolicy = field(default_factory=AddressPolicy)
    connect_timeout: float = 3.0
    timeout: float = 5.0
    max_bytes: int = 8192
    headers: dict[str, str] = field(default_factory=dict)

    def pinned_transport(self) -> PinnedPublicTransport:
        return PinnedPublicTransport(self.transport, resolve=self.resolve, policy=self.policy)

    async def get_json(self, url: str) -> Any:
        transport = self.pinned_transport()
        try:
            async with asyncio.timeout(self.timeout):
                async with httpx.AsyncClient(
                    transport=transport,
                    timeout=httpx.Timeout(self.timeout, connect=self.connect_timeout),
                    follow_redirects=False,
                    trust_env=False,
                ) as client:
                    async with client.stream("GET", url, headers=self.headers) as resp:
                        if 300 <= resp.status_code < 400:
                            raise FetchError("redirected", status=resp.status_code)
                        if resp.status_code != 200:
                            raise FetchError("status", f"HTTP {resp.status_code}", resp.status_code)
                        ctype = resp.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                        if ctype != "application/json":
                            raise FetchError("status", "not application/json", resp.status_code)
                        declared = resp.headers.get("content-length")
                        if declared and declared.isdigit() and int(declared) > self.max_bytes:
                            raise FetchError("too_large")
                        body = bytearray()
                        async for chunk in resp.aiter_bytes():
                            body += chunk
                            if len(body) > self.max_bytes:
                                raise FetchError("too_large")
        except FetchError:
            raise
        except BlockedAddressError as exc:
            raise FetchError("blocked", str(exc)) from None
        except (TimeoutError, httpx.TimeoutException):
            raise FetchError("timeout") from None
        except (httpx.HTTPError, OSError) as exc:
            raise FetchError("unreachable", type(exc).__name__) from None
        try:
            return json.loads(bytes(body))
        except (ValueError, UnicodeDecodeError):
            raise FetchError("status", "body is not JSON", 200) from None


def client_ip_key(ip: str, v6_prefix: int = 64) -> str:
    """Rate-limit key for a client address: IPv4 as is, IPv6 by /64 (or the given prefix)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
        return str(ipaddress.ip_network(f"{addr}/{v6_prefix}", strict=False))
    return str(addr)


def client_prefix_key(ip: str) -> str:
    """IPv4 /24, IPv6 /56 (registration contract §3.2 / §4.2)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    bits = 24 if addr.version == 4 else 56
    return str(ipaddress.ip_network(f"{addr}/{bits}", strict=False))


def trusted_client_ip(peer: str | None, forwarded_for: str | None, trusted: Iterable[IPNetwork]) -> str:
    """Client IP: the peer, or the right-most untrusted X-Forwarded-For hop behind trusted proxies."""
    nets = tuple(trusted)
    if not peer:
        return ""

    def is_trusted(value: str) -> bool:
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return False
        return any(addr.version == n.version and addr in n for n in nets)

    if not nets or not forwarded_for or not is_trusted(peer):
        return peer
    hops = [h.strip() for h in forwarded_for.split(",") if h.strip()]
    for hop in reversed(hops):
        if not is_trusted(hop):
            try:
                return str(ipaddress.ip_address(hop))
            except ValueError:
                return peer
    return peer
