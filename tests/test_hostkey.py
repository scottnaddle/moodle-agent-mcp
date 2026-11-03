"""host_key normalisation shared by registration and /m/ routing (contract §6.2, §4.3)."""

import pytest

from moodle_mcp.hostkey import (
    HostKeyError,
    normalize_host_key,
    normalize_site_url,
    parse_host_route,
    parse_ports,
    site_key_for,
)
from moodle_mcp.registry import SITE_ID_RE

PORTS = frozenset({443, 8443})


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("lms.school.ac.kr", "lms.school.ac.kr"),
        ("LMS.School.AC.kr", "lms.school.ac.kr"),
        ("lms.school.ac.kr.", "lms.school.ac.kr"),
        ("lms.school.ac.kr:443", "lms.school.ac.kr"),
        ("lms.school.ac.kr:8443", "lms.school.ac.kr:8443"),
        ("example.com/moodle", "example.com/moodle"),
        ("example.com/Moodle/", "example.com/Moodle"),  # path case kept, trailing / dropped
        ("example.com/a/b/c/d", "example.com/a/b/c/d"),
        ("한국.kr", "xn--3e0b707e.kr"),  # IDN -> A-label
        ("faß.de", "xn--fa-hia.de"),  # IDNA 2008 keeps ß (IDNA 2003 would map it to "fass")
        ("example.com/mcp", "example.com/mcp"),
    ],
)
def test_normalize_host_key(raw, expected):
    assert normalize_host_key(raw, PORTS) == expected


@pytest.mark.parametrize(
    "raw, code",
    [
        ("example.com/../x", "invalid_site_url"),
        ("example.com/./x", "invalid_site_url"),
        ("example.com//x", "invalid_site_url"),
        ("example.com/a%2Fb", "invalid_site_url"),
        ("example.com/a b", "invalid_site_url"),
        ("example.com/a/b/c/d/e", "invalid_site_url"),
        ("example.com/" + "a" * 100, "invalid_site_url"),
        ("a" * 64 + ".com", "invalid_site_url"),
        ("-bad.example.com", "invalid_site_url"),
        ("ex_ample.com", "invalid_site_url"),
        ("example.com:9443", "port_not_allowed"),
        ("example.com:0", "invalid_site_url"),
        ("localhost", "private_address_not_supported"),
        ("moodle", "private_address_not_supported"),
        ("moodle.local", "private_address_not_supported"),
        ("lms.school.internal", "private_address_not_supported"),
        ("lms.lan", "private_address_not_supported"),
        ("router.home.arpa", "private_address_not_supported"),
        ("a.localhost", "private_address_not_supported"),
        ("intra.school.intranet", "private_address_not_supported"),
        ("10.0.0.5", "private_address_not_supported"),
        ("8.8.8.8", "private_address_not_supported"),  # public IP literals are not supported in v1 either
        ("[::1]", "private_address_not_supported"),
        ("2130706433", "private_address_not_supported"),
        ("0177.0.0.1", "private_address_not_supported"),
        ("0x7f.1", "private_address_not_supported"),
    ],
)
def test_normalize_host_key_rejects(raw, code):
    with pytest.raises(HostKeyError) as exc:
        normalize_host_key(raw, PORTS)
    assert exc.value.code == code


def test_length_boundaries():
    label = "a" * 63
    host = ".".join([label, label, label, "b" * 58, "kr"])  # 253 chars
    assert len(host) == 253
    assert normalize_host_key(host) == host
    with pytest.raises(HostKeyError):
        normalize_host_key("c" + host)
    path = "/" + "/".join(["p" * 24] * 4)  # 99 chars, 4 segments
    assert normalize_host_key("example.com" + path) == "example.com" + path
    with pytest.raises(HostKeyError):
        normalize_host_key("example.com" + path + "pp")


def test_site_url_rules():
    site = normalize_site_url("https://LMS.School.ac.kr/moodle/")
    assert (site.url, site.host_key, site.host) == (
        "https://lms.school.ac.kr/moodle",
        "lms.school.ac.kr/moodle",
        "lms.school.ac.kr",
    )
    for url, code in [
        ("http://lms.school.ac.kr", "unsupported_scheme"),
        ("ftp://lms.school.ac.kr", "unsupported_scheme"),
        ("https://user:pw@lms.school.ac.kr", "invalid_site_url"),
        ("https://lms.school.ac.kr/?x=1", "invalid_site_url"),
        ("https://lms.school.ac.kr/#f", "invalid_site_url"),
        ("lms.school.ac.kr", "invalid_site_url"),
        ("https://lms.school.ac.kr/" + "m" * 250, "invalid_site_url"),
        ("https://127.0.0.1/moodle", "private_address_not_supported"),
        ("https://lms.school.ac.kr:8443", "port_not_allowed"),
    ]:
        with pytest.raises(HostKeyError) as exc:
            normalize_site_url(url)
        assert exc.value.code == code, url


def test_site_key_derivation():
    key = site_key_for("lms.school.ac.kr/moodle")
    assert key.startswith("lms-school-ac-kr-moodle-") and len(key.rsplit("-", 1)[1]) == 6
    assert SITE_ID_RE.fullmatch(key)
    long_key = site_key_for("a" * 60 + ".example.com/" + "B" * 40, 14)
    assert SITE_ID_RE.fullmatch(long_key) and len(long_key) <= 63
    assert site_key_for("x.example/A") != site_key_for("x.example/a")


def test_parse_host_route_takes_suffix_from_the_end():
    assert parse_host_route("/m/ex.com/mcp/mcp").raw_host_key == "ex.com/mcp"
    r = parse_host_route("/m/ex.com/oauth/oauth/authorize")
    assert (r.raw_host_key, r.kind, r.endpoint) == ("ex.com/oauth", "oauth", "authorize")
    assert parse_host_route("/.well-known/oauth-protected-resource/m/ex.com/moodle/mcp").raw_host_key == "ex.com/moodle"
    assert parse_host_route("/.well-known/oauth-authorization-server/m/ex.com").kind == "as_metadata"
    assert parse_host_route("/m/ex.com/.well-known/openid-configuration").kind == "as_metadata"
    assert parse_host_route("/m/ex.com/other") is None
    assert parse_host_route("/m//mcp") is None


def test_parse_ports():
    assert parse_ports(None) == frozenset({443})
    assert parse_ports("8443") == frozenset({443, 8443})
    with pytest.raises(ValueError):
        parse_ports("http")
