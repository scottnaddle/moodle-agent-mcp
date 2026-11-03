"""tests/vectors/registration-v1.json is the interop contract with local_ubionai (PHPUnit uses it too)."""

import base64
import hashlib
import hmac
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from moodle_mcp.hostkey import normalize_site_url, site_key_for
from moodle_mcp.siteauth import SharedSecretAuthenticator, derive_mac_key, secret_hash, verify_message

V = json.loads((Path(__file__).parent / "vectors" / "registration-v1.json").read_text())


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def test_identifiers():
    site = normalize_site_url(V["site_url"])
    assert site.url == V["canonical_site_url"] and site.host_key == V["host_key"]
    assert site_key_for(V["host_key"]) == V["site_key"]


def test_secret_hash_and_hkdf_independently():
    secret = V["site_secret"]
    assert len(_unb64(secret)) == 32
    assert hashlib.sha256(secret.encode()).hexdigest() == V["secret_hash_hex"] == secret_hash(secret).hex()
    hk = V["hkdf"]
    expected = HKDF(algorithm=hashes.SHA256(), length=hk["length"], salt=hk["salt"].encode(),
                    info=hk["info"].encode()).derive(secret.encode())
    assert expected.hex() == V["mac_key_hex"]
    assert derive_mac_key(secret, V["site_key"], V["secret_version"]).hex() == V["mac_key_hex"]


def test_challenge_rule():
    c = V["callback_challenge"]
    assert _b64(hashlib.sha256(_unb64(c["challenge_b64url"])).digest()) == c["challenge_sha256"]


def test_message_signature():
    key = bytes.fromhex(V["mac_key_hex"])
    msg = V["message"]
    body = _b64(json.dumps(msg["claims"], separators=(",", ":"), sort_keys=True).encode())
    mac = _b64(hmac.new(key, b"ubionai-oauth-v1." + body.encode(), hashlib.sha256).digest())
    assert f"{body}.{mac}" == msg["token"]
    claims = {k: v for k, v in msg["claims"].items() if k != "kv"}
    signer = SharedSecretAuthenticator(site_key=V["site_key"], version=V["secret_version"], mac_key=key)
    assert signer.sign(claims) == msg["token"]
    assert verify_message(bytes(32), msg["token"], "authz_req") is None  # wrong key never verifies
