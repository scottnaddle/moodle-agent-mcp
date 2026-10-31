import base64
import os

import pytest

from moodle_mcp.netutil import parse_ip_list
from moodle_mcp.server import create_app


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("203.0.113.10", "203.0.113.10"),
        ("2001:DB8::1", "2001:db8::1"),
        ("::ffff:192.0.2.1", "::ffff:192.0.2.1"),
        ("2001:DB8::/32", "2001:db8::/32"),
        (" 203.0.113.10 , 198.51.100.0/24 ", "203.0.113.10,198.51.100.0/24"),
        ("203.0.113.10,203.0.113.10", "203.0.113.10"),
        ("2001:db8::2,203.0.113.10,2001:db8::1", "2001:db8::2,203.0.113.10,2001:db8::1"),
        (None, None),
        ("", None),
        ("   ", None),
    ],
)
def test_parse_ip_list_valid(value, expected):
    assert parse_ip_list(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "1.2.3.4 # office",
        "1.2.3.4,",
        ",1.2.3.4",
        "1.2.3.4,,5.6.7.8",
        "1.2.3.4;5.6.7.8",
        "1.2.3.4 5.6.7.8",
        "999.1.1.1",
        "10.0.0.1/24",
        "fe80::1%eth0",
        "1.2.3.4-9",
        "10.1.",
        "host.example",
    ],
)
def test_parse_ip_list_invalid_names_entry(value):
    with pytest.raises(ValueError) as excinfo:
        parse_ip_list(value)
    assert "invalid IP entry" in str(excinfo.value) or "empty entry" in str(excinfo.value)


def test_parse_ip_list_invalid_rejects_hash_before_parsing():
    with pytest.raises(ValueError, match=r"invalid IP entry '1\.2\.3\.4 # office'"):
        parse_ip_list("1.2.3.4 # office")


def test_parse_ip_list_invalid_rejects_too_long_result():
    entries = [f"2001:db8::{index:x}" for index in range(1, 32)]
    with pytest.raises(ValueError, match="255 characters"):
        parse_ip_list(",".join(entries))


def test_create_app_rejects_invalid_egress_ip(tmp_path, monkeypatch):
    monkeypatch.delenv("MOODLE_TOKEN", raising=False)
    monkeypatch.delenv("MCP_BEARER_TOKEN", raising=False)
    monkeypatch.setenv("UBIONAI_HUB_EGRESS_IP", "1.2.3.4 #bad")
    kek_file = tmp_path / "kek"
    kek_file.write_bytes(base64.b64encode(os.urandom(32)) + b"\n")
    os.chmod(kek_file, 0o600)
    with pytest.raises(RuntimeError, match="UBIONAI_HUB_EGRESS_IP"):
        create_app(hub_db=str(tmp_path / "hub.sqlite3"), kek_file=str(kek_file))
