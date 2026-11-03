"""Hub <-> plugin message protection per tenant (registration contract §3, §7).

``auth_mode`` of a tenant picks the ``SiteAuthenticator``:

- ``legacy_file``: HMAC with ``$UBIONAI_HUB_TENANT_SECRETS_DIR/<site>/oauth.secret`` (hub-staging).
- ``shared_secret``: HMAC with ``mac_key = HKDF(site_secret, "ubionai-site-v1",
  "oauth-mac|<site_key>|v<n>")`` of the ``current`` site credential, claim ``kv`` = n. The hub
  stores only ``sha256(site_secret)`` (API authentication) and ``mac_key`` sealed with the KEK.
- ``signature``: hub Ed25519 JWS (option 2). Reserved; not implemented, no keys are generated.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypto import DecryptError, Kek, open_, seal

MAC_PREFIX = b"ubionai-oauth-v1."
MAC_SALT = b"ubionai-site-v1"
SECRET_BYTES = 32
PENDING_TTL = 3600
RETIRED_GRACE = 600

AuthMode = Literal["legacy_file", "shared_secret", "signature"]


def _now() -> int:
    return int(time.time())


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64url(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def sign_message(secret: bytes, claims: dict[str, Any]) -> str:
    """``base64url(json) "." base64url(HMAC-SHA256(secret, "ubionai-oauth-v1." + body))``."""
    body = b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    return body + "." + b64url(hmac.new(secret, MAC_PREFIX + body.encode(), hashlib.sha256).digest())


def verify_message(secret: bytes, token: str, typ: str) -> dict[str, Any] | None:
    try:
        body, mac = token.split(".", 1)
        expected = hmac.new(secret, MAC_PREFIX + body.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(unb64url(mac), expected):
            return None
        claims = json.loads(unb64url(body))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(claims, dict) or claims.get("typ") != typ or claims.get("exp", 0) < _now():
        return None
    return claims


def mac_info(site_key: str, version: int) -> str:
    return f"oauth-mac|{site_key}|v{version}"


def derive_mac_key(site_secret: str, site_key: str, version: int) -> bytes:
    """Plugin side: ``hash_hkdf('sha256', $site_secret, 32, $info, 'ubionai-site-v1')``.

    ``ikm`` is the base64url string exactly as transmitted (UTF-8 bytes), not its decoding.
    """
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=MAC_SALT, info=mac_info(site_key, version).encode()
    ).derive(site_secret.encode())


def secret_hash(site_secret: str) -> bytes:
    return hashlib.sha256(site_secret.encode()).digest()


def mac_field(version: int) -> str:
    return f"site_mac_key:v{version}"


class SiteAuthenticator(Protocol):
    """Hub <-> plugin message protection for one tenant."""

    mode: AuthMode

    def sign(self, claims: dict[str, Any]) -> str:
        """Hub -> plugin message (authz_req, exchange, revoke). Adds kid/kv as needed."""

    def verify(self, token: str, typ: str) -> dict[str, Any] | None:
        """Plugin -> hub signed message, if a mode defines one (v1: none; reserved)."""

    def describe(self) -> dict[str, Any]:
        """Public parameters for registration/status responses (no secrets)."""


@dataclass
class FileSecretAuthenticator:
    secret: bytes
    mode: AuthMode = "legacy_file"

    def sign(self, claims: dict[str, Any]) -> str:
        return sign_message(self.secret, claims)

    def verify(self, token: str, typ: str) -> dict[str, Any] | None:
        return verify_message(self.secret, token, typ)

    def describe(self) -> dict[str, Any]:
        return {"auth_mode": self.mode}


@dataclass
class SharedSecretAuthenticator:
    site_key: str
    version: int
    mac_key: bytes
    mode: AuthMode = "shared_secret"

    def sign(self, claims: dict[str, Any]) -> str:
        return sign_message(self.mac_key, {**claims, "kv": self.version})

    def verify(self, token: str, typ: str) -> dict[str, Any] | None:
        claims = verify_message(self.mac_key, token, typ)
        if claims is None or claims.get("kv") != self.version:
            return None
        return claims

    def describe(self) -> dict[str, Any]:
        return {
            "auth_mode": self.mode,
            "mac": {
                "alg": "HMAC-SHA256",
                "kdf": "HKDF-SHA256",
                "salt": MAC_SALT.decode(),
                "info": mac_info(self.site_key, self.version),
            },
        }


@dataclass
class SignatureAuthenticator:
    """Option 2 placeholder: hub Ed25519 JWS with ``kid``. Not implemented in v1."""

    kid: str = ""
    mode: AuthMode = "signature"

    def sign(self, claims: dict[str, Any]) -> str:
        raise NotImplementedError("signature auth_mode is reserved for option 2")

    def verify(self, token: str, typ: str) -> dict[str, Any] | None:
        raise NotImplementedError("signature auth_mode is reserved for option 2")

    def describe(self) -> dict[str, Any]:
        raise NotImplementedError("signature auth_mode is reserved for option 2")


@dataclass(frozen=True)
class IssuedCredential:
    site_id: str
    version: int
    site_secret: str  # plaintext, returned once to the plugin and never stored
    expires_at: int


@dataclass(frozen=True)
class Credential:
    site_id: str
    version: int
    secret_hash: bytes
    mac_key_ct: bytes
    kek_id: str
    state: str
    created_at: int
    confirmed_at: int | None
    expires_at: int | None


class SiteCredentialStore(Protocol):
    """Issue / confirm / rotate / retire site credentials (registration API side)."""

    def issue(self, site_id: str) -> IssuedCredential: ...

    def confirm(self, site_id: str, version: int, presented: str) -> bool: ...

    def authenticate(self, site_id: str, presented: str) -> int | None: ...

    def retire_all(self, site_id: str) -> None: ...


class ConfirmError(Exception):
    """``code``: invalid_site_credentials, nothing_to_confirm, pending_secret_expired."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class SharedSecretCredentialStore:
    """``site_credentials`` rows: hash of the secret + KEK-sealed derived MAC key (§3.1, §3.2)."""

    def __init__(self, registry: Any, kek: Kek, clock: Any = None) -> None:
        self.registry = registry
        self.kek = kek
        self.clock = clock or _now

    def _connect(self) -> Any:
        return self.registry._connect()

    def _tenant_url(self, conn: sqlite3.Connection, site_id: str) -> str:
        row = conn.execute("SELECT moodle_url FROM tenants WHERE site_id = ?", (site_id,)).fetchone()
        if row is None:
            raise KeyError(site_id)
        return row[0]

    def _purge(self, conn: sqlite3.Connection, site_id: str, now: int) -> None:
        conn.execute(
            "DELETE FROM site_credentials WHERE site_id = ? AND state = 'retired' AND expires_at <= ?",
            (site_id, now),
        )

    def issue(self, site_id: str) -> IssuedCredential:
        """New ``pending`` version (an older pending one is retired at once; ``current`` stays)."""
        now = int(self.clock())
        site_secret = b64url(secrets.token_bytes(SECRET_BYTES))
        with self._connect() as conn:
            moodle_url = self._tenant_url(conn, site_id)
            self._purge(conn, site_id, now)
            conn.execute(
                "UPDATE site_credentials SET state = 'retired', expires_at = ?"
                " WHERE site_id = ? AND state = 'pending'",
                (now, site_id),
            )
            conn.execute("UPDATE tenants SET secret_seq = secret_seq + 1 WHERE site_id = ?", (site_id,))
            version = conn.execute("SELECT secret_seq FROM tenants WHERE site_id = ?", (site_id,)).fetchone()[0]
            mac_key = derive_mac_key(site_secret, site_id, version)
            conn.execute(
                "INSERT INTO site_credentials (site_id, version, kind, secret_hash, mac_key_ct, kek_id,"
                " state, created_at, confirmed_at, expires_at)"
                " VALUES (?, ?, 'shared_secret', ?, ?, ?, 'pending', ?, NULL, ?)",
                (
                    site_id,
                    version,
                    secret_hash(site_secret),
                    seal(self.kek, mac_key, site_id, mac_field(version), moodle_url=moodle_url),
                    self.kek.kek_id,
                    now,
                    now + PENDING_TTL,
                ),
            )
        return IssuedCredential(site_id, version, site_secret, now + PENDING_TTL)

    def credentials(self, site_id: str) -> list[Credential]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT site_id, version, secret_hash, mac_key_ct, kek_id, state, created_at,"
                " confirmed_at, expires_at FROM site_credentials WHERE site_id = ? ORDER BY version",
                (site_id,),
            ).fetchall()
        return [Credential(*row) for row in rows]

    def _matches(self, cred: Credential, presented: str) -> bool:
        return hmac.compare_digest(cred.secret_hash, secret_hash(presented))

    def authenticate(self, site_id: str, presented: str) -> int | None:
        """Version of the ``current`` credential when ``presented`` is its secret, else None."""
        for cred in self.credentials(site_id):
            if cred.state == "current" and self._matches(cred, presented):
                return cred.version
        return None

    def confirm(self, site_id: str, version: int, presented: str) -> bool:
        """pending -> current (old current -> retired with a grace period). Idempotent."""
        now = int(self.clock())
        creds = self.credentials(site_id)
        target = next((c for c in creds if c.version == version and c.state != "retired"), None)
        if target is None:
            if any(c.state != "retired" and self._matches(c, presented) for c in creds):
                raise ConfirmError("nothing_to_confirm")
            raise ConfirmError("invalid_site_credentials")
        if not self._matches(target, presented):
            raise ConfirmError("invalid_site_credentials")
        if target.state == "current":
            return True
        if target.expires_at is not None and target.expires_at <= now:
            with self._connect() as conn:
                conn.execute(
                    "DELETE FROM site_credentials WHERE site_id = ? AND version = ? AND state = 'pending'",
                    (site_id, version),
                )
            raise ConfirmError("pending_secret_expired")
        with self._connect() as conn:
            conn.execute(
                "UPDATE site_credentials SET state = 'retired', expires_at = ?"
                " WHERE site_id = ? AND state = 'current'",
                (now + RETIRED_GRACE, site_id),
            )
            cur = conn.execute(
                "UPDATE site_credentials SET state = 'current', confirmed_at = ?, expires_at = NULL"
                " WHERE site_id = ? AND version = ? AND state = 'pending'",
                (now, site_id, version),
            )
            if cur.rowcount != 1:
                raise ConfirmError("nothing_to_confirm")
            self._purge(conn, site_id, now)
        return True

    def retire_all(self, site_id: str) -> None:
        now = int(self.clock())
        with self._connect() as conn:
            conn.execute(
                "UPDATE site_credentials SET state = 'retired', expires_at = ?"
                " WHERE site_id = ? AND state != 'retired'",
                (now + RETIRED_GRACE, site_id),
            )

    def current_version(self, site_id: str) -> int | None:
        return next((c.version for c in self.credentials(site_id) if c.state == "current"), None)

    def authenticator(self, site_id: str, moodle_url: str) -> SharedSecretAuthenticator | None:
        """Signer for the ``current`` credential; None until the first confirm."""
        cred = next((c for c in self.credentials(site_id) if c.state == "current"), None)
        if cred is None or cred.kek_id != self.kek.kek_id:
            return None
        try:
            key = open_(self.kek, cred.mac_key_ct, site_id, mac_field(cred.version), moodle_url=moodle_url)
        except DecryptError:
            return None
        return SharedSecretAuthenticator(site_key=site_id, version=cred.version, mac_key=bytes(key))
