"""KEK storage and envelope encryption for tenant secrets."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import stat
from typing import Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

FIELD_MOODLE_TOKEN = "moodle_token"
FIELD_LITELLM_KEY = "litellm_key"

PURPOSE_PSEUDONYM_HMAC = "pseudonym-hmac"
PURPOSE_PSEUDONYM_MAP = "pseudonym-map"

_HKDF_SALT = b"ubionai-hub/hkdf/v1"

_VERSION = b"\x01"
_NONCE_LEN = 12
_WRAPPED_DEK_LEN = 48
_TAG_LEN = 16
_MIN_BLOB_LEN = 1 + _NONCE_LEN + _WRAPPED_DEK_LEN + _NONCE_LEN + _TAG_LEN


class KekError(Exception):
    """Raised when the key-encryption key cannot be loaded."""


class DecryptError(Exception):
    """Raised when a sealed value cannot be opened."""


class Kek:
    """A 256-bit key-encryption key."""

    def __init__(self, raw: bytes) -> None:
        if len(raw) != 32:
            raise KekError("KEK file invalid")
        self._raw = bytes(raw)

    @property
    def kek_id(self) -> str:
        return hashlib.sha256(self._raw).hexdigest()[:8]

    def __repr__(self) -> str:
        return f"Kek(kek_id={self.kek_id!r})"


def derive_key(kek: Kek, purpose: str, site_id: str) -> bytes:
    """Derive a 32-byte tenant- and purpose-specific key from the KEK."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=purpose.encode("ascii") + b"\x00" + site_id.encode("utf-8"),
    )
    return hkdf.derive(kek._raw)


def load_kek(path: Union[str, os.PathLike[str]]) -> Kek:
    """Load a base64-encoded 32-byte KEK from a regular, private file."""
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:
            raise KekError("KEK file invalid")
        with open(path, "rb") as handle:
            text = handle.read().strip()
        if not text:
            raise KekError("KEK file invalid")
        raw = base64.b64decode(text, validate=True)
        if len(raw) != 32:
            raise KekError("KEK file invalid")
        return Kek(raw)
    except KekError:
        raise
    except (OSError, ValueError, binascii.Error, TypeError):
        raise KekError("KEK file invalid") from None


def _aad(site_id: str, field: str, moodle_url: str | None = None) -> bytes:
    aad = b"ubionai-hub/v1\x00" + site_id.encode() + b"\x00" + field.encode()
    if moodle_url is not None:
        aad += b"\x00" + moodle_url.encode()
    return aad


def seal(
    kek: Kek,
    plaintext: bytes | bytearray,
    site_id: str,
    field: str,
    *,
    moodle_url: str | None = None,
) -> bytes:
    """Encrypt plaintext with a fresh DEK, wrapped by the KEK."""
    dek = os.urandom(32)
    n1 = os.urandom(_NONCE_LEN)
    n2 = os.urandom(_NONCE_LEN)
    aad = _aad(site_id, field, moodle_url)
    wrapped = AESGCM(kek._raw).encrypt(n1, dek, aad)
    ct = AESGCM(dek).encrypt(n2, bytes(plaintext), aad)
    return _VERSION + n1 + wrapped + n2 + ct


def open_(
    kek: Kek,
    blob: bytes,
    site_id: str,
    field: str,
    *,
    moodle_url: str | None = None,
) -> bytearray:
    """Open an envelope and return the plaintext as a bytearray."""
    try:
        if len(blob) < _MIN_BLOB_LEN or blob[:1] != _VERSION:
            raise DecryptError("decrypt failed")
        n1 = blob[1 : 1 + _NONCE_LEN]
        wrapped_start = 1 + _NONCE_LEN
        wrapped = blob[wrapped_start : wrapped_start + _WRAPPED_DEK_LEN]
        n2_start = wrapped_start + _WRAPPED_DEK_LEN
        n2 = blob[n2_start : n2_start + _NONCE_LEN]
        ct = blob[n2_start + _NONCE_LEN :]
        aad = _aad(site_id, field, moodle_url)
        dek = AESGCM(kek._raw).decrypt(n1, wrapped, aad)
        plaintext = AESGCM(dek).decrypt(n2, ct, aad)
        return bytearray(plaintext)
    except DecryptError:
        raise
    except (InvalidTag, ValueError, TypeError, OverflowError):
        raise DecryptError("decrypt failed") from None
