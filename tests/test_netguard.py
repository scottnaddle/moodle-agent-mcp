"""Public-address policy, pinned transport and SafeFetcher (contract §2.2, §4.3). No network."""

import asyncio
import ipaddress

import httpx
import pytest

from moodle_mcp.netutil import (
    AddressPolicy,
    BlockedAddress,
    FetchError,
    PinnedPublicTransport,
    ResolveError,
    SafeFetcher,
    client_ip_key,
    client_prefix_key,
    parse_networks,
    trusted_client_ip,
    vet_host,
)

DENIED = [
    "0.1.2.3", "10.1.2.3", "100.64.0.1", "100.100.100.200", "127.0.0.1", "169.254.169.254",
    "172.16.5.4", "192.0.0.8", "192.0.2.1", "192.168.1.1", "198.18.0.1", "198.51.100.1",
    "203.0.113.9", "224.0.0.1", "240.0.0.1", "255.255.255.255", "168.63.129.16",
    "::", "::1", "fc00::1", "fd00:ec2::254", "fe80::1", "ff02::1", "2001:db8::1", "2001::1", "100::1",
    "::ffff:10.0.0.1", "::ffff:169.254.169.254", "2002:a9fe:a9fe::1", "64:ff9b::a9fe:a9fe",
    "2001:0:4136:e378:8000:63bf:3fff:fdd2",  # Teredo
]
ALLOWED = ["1.2.3.4", "8.8.8.8", "2606:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808"]


@pytest.mark.parametrize("address", DENIED)
def test_policy_denies(address):
    assert not AddressPolicy().allowed(ipaddress.ip_address(address))


@pytest.mark.parametrize("address", ALLOWED)
def test_policy_allows(address):
    assert AddressPolicy().allowed(ipaddress.ip_address(address))


def test_policy_extra_cidrs_and_hub_self():
    policy = AddressPolicy(extra_deny=parse_networks("8.8.4.0/24"), self_addresses={ipaddress.ip_address("1.1.1.1")})
    assert not policy.allowed(ipaddress.ip_address("8.8.4.4"))
    assert not policy.allowed(ipaddress.ip_address("1.1.1.1"))
    assert not policy.allowed(ipaddress.ip_address("::ffff:1.1.1.1"))
    assert policy.allowed(ipaddress.ip_address("8.8.8.8"))


async def test_vet_host_requires_every_address_public():
    async def mixed(host, port):
        return ["1.2.3.4", "10.0.0.1"]

    async def empty(host, port):
        return []

    async def nx(host, port):
        raise OSError("nx")

    with pytest.raises(BlockedAddress):
        await vet_host("a.example", 443, mixed, AddressPolicy())
    with pytest.raises(ResolveError):
        await vet_host("a.example", 443, empty, AddressPolicy())
    with pytest.raises(ResolveError):
        await vet_host("a.example", 443, nx, AddressPolicy())
    with pytest.raises(BlockedAddress):
        await vet_host("8.8.8.8", 443, mixed, AddressPolicy(), allow_literal=False)


class Rebinder:
    """First answer public, every later answer the cloud metadata address."""

    def __init__(self):
        self.calls = 0

    async def __call__(self, host, port):
        self.calls += 1
        return ["1.2.3.4"] if self.calls == 1 else ["169.254.169.254"]


async def test_pinned_transport_connects_to_the_vetted_ip_and_revets_each_request():
    seen = []

    def handler(request):
        seen.append((request.url.host, request.headers["host"], request.extensions.get("sni_hostname")))
        return httpx.Response(200, json={})

    resolve = Rebinder()
    transport = PinnedPublicTransport(httpx.MockTransport(handler), resolve=resolve)
    async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
        assert (await client.get("https://moodle.example/x")).status_code == 200
        # DNS now points inside: the next request fails before any connection is made.
        with pytest.raises(httpx.TransportError):
            await client.get("https://moodle.example/x")
    assert seen == [("1.2.3.4", "moodle.example", "moodle.example")]
    assert transport.targets == [("moodle.example", "1.2.3.4")]


async def test_pinned_transport_refuses_http_and_literals():
    async def resolve(host, port):
        return ["1.2.3.4"]

    transport = PinnedPublicTransport(httpx.MockTransport(lambda r: httpx.Response(200)), resolve=resolve)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(httpx.TransportError):
            await client.get("http://moodle.example/")
        with pytest.raises(httpx.TransportError):
            await client.get("https://1.2.3.4/")


async def _public(host, port):
    return ["1.2.3.4"]


def _fetcher(handler, **kw):
    return SafeFetcher(transport=httpx.MockTransport(handler), resolve=_public, **kw)


async def test_safe_fetcher_ok_and_failures():
    assert await _fetcher(lambda r: httpx.Response(200, json={"a": 1})).get_json("https://s.example/cb") == {"a": 1}
    cases = [
        (lambda r: httpx.Response(302, headers={"location": "https://www.s.example/"}), "redirected"),
        (lambda r: httpx.Response(404, json={}), "status"),
        (lambda r: httpx.Response(500, json={}), "status"),
        (lambda r: httpx.Response(200, text="<html>", headers={"content-type": "text/html"}), "status"),
        (lambda r: httpx.Response(200, content=b"not json", headers={"content-type": "application/json"}), "status"),
        (lambda r: httpx.Response(200, content=b"{" + b" " * 9000 + b"}", headers={"content-type": "application/json"}), "too_large"),
    ]
    for handler, kind in cases:
        with pytest.raises(FetchError) as exc:
            await _fetcher(handler).get_json("https://s.example/cb")
        assert exc.value.kind == kind


async def test_safe_fetcher_size_limit_without_content_length():
    async def stream():
        for _ in range(10):
            yield b" " * 1000

    def handler(request):
        return httpx.Response(200, content=stream(), headers={"content-type": "application/json"})

    with pytest.raises(FetchError) as exc:
        await _fetcher(handler).get_json("https://s.example/cb")
    assert exc.value.kind == "too_large"


async def test_safe_fetcher_timeout_and_unreachable_and_blocked():
    async def slow(request):
        await asyncio.sleep(1)
        return httpx.Response(200, json={})

    with pytest.raises(FetchError) as exc:
        await _fetcher(slow, timeout=0.05).get_json("https://s.example/cb")
    assert exc.value.kind == "timeout"

    def refuse(request):
        raise httpx.ConnectError("refused", request=request)

    with pytest.raises(FetchError) as exc:
        await _fetcher(refuse).get_json("https://s.example/cb")
    assert exc.value.kind == "unreachable"

    async def private(host, port):
        return ["192.168.0.10"]

    fetcher = SafeFetcher(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})), resolve=private)
    with pytest.raises(FetchError) as exc:
        await fetcher.get_json("https://s.example/cb")
    assert exc.value.kind == "blocked"


async def test_safe_fetcher_ignores_env_proxies(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://10.0.0.1:3128")
    seen = []

    def handler(request):
        seen.append(request.url.host)
        return httpx.Response(200, json={})

    await _fetcher(handler).get_json("https://s.example/cb")
    assert seen == ["1.2.3.4"]


def test_client_ip_keys():
    assert client_ip_key("1.2.3.4") == "1.2.3.4"
    assert client_ip_key("2001:db8:1:2:3::9") == "2001:db8:1:2::/64"
    assert client_prefix_key("1.2.3.4") == "1.2.3.0/24"
    assert client_prefix_key("2001:db8:1:2:3::9") == "2001:db8:1::/56"


def test_trusted_client_ip():
    proxies = parse_networks("10.0.0.0/8")
    assert trusted_client_ip("1.2.3.4", "9.9.9.9", proxies) == "1.2.3.4"  # peer not a proxy
    assert trusted_client_ip("10.0.0.2", "9.9.9.9, 8.8.8.8", proxies) == "8.8.8.8"
    assert trusted_client_ip("10.0.0.2", "9.9.9.9", ()) == "10.0.0.2"  # no trusted proxies configured
