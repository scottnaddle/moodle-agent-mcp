"""SQLite-backed tenant registry with encrypted tenant secrets."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator
from urllib.parse import urlsplit, urlunsplit

from .crypto import (
    FIELD_LITELLM_KEY,
    FIELD_MOODLE_TOKEN,
    DecryptError,
    Kek,
    open_,
    seal,
)

SITE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  schema_version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tenants (
  site_id      TEXT PRIMARY KEY CHECK (site_id GLOB '[a-z0-9]*'
                 AND length(site_id) BETWEEN 2 AND 63),
  moodle_url   TEXT NOT NULL,
  token_ct     BLOB NOT NULL,
  litellm_ct   BLOB,
  bearer_hash  BLOB NOT NULL UNIQUE,
  kek_id       TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'active'
               CHECK (status IN ('active','disabled')),
  pseudonymize INTEGER NOT NULL DEFAULT 1
               CHECK (pseudonymize IN (0,1)),
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS reg_codes (
  code_hash  BLOB PRIMARY KEY,
  site_id    TEXT NOT NULL,
  moodle_url TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at    INTEGER
);
INSERT INTO meta(schema_version) SELECT 3 WHERE NOT EXISTS (SELECT 1 FROM meta);
"""


class TenantError(Exception):
    """Base error for tenant registry operations."""


class TenantNotFound(TenantError):
    """Raised when a tenant does not exist."""


class DuplicateSite(TenantError):
    """Raised when a site id or bearer is already registered."""


class RegCodeError(TenantError):
    """Raised for invalid registration-code operations."""


@dataclass(frozen=True)
class Tenant:
    site_id: str
    moodle_url: str
    bearer_hash: bytes
    token_ct: bytes
    litellm_ct: bytes | None
    kek_id: str
    status: str
    created_at: int
    updated_at: int
    pseudonymize: bool = True


def normalize_moodle_url(url: str, allow_http: bool = False) -> str:
    """Validate and normalize a Moodle base URL (no trailing slash)."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise TenantError("invalid Moodle URL") from None
    scheme = parts.scheme.lower()
    if scheme != "https" and not (allow_http and scheme == "http"):
        raise TenantError("invalid Moodle URL")
    if not parts.hostname or parts.username is not None or parts.password is not None:
        raise TenantError("invalid Moodle URL")
    if parts.query or parts.fragment:
        raise TenantError("invalid Moodle URL")
    netloc = parts.netloc.lower()
    if port is not None:
        host = parts.hostname.lower()
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = f"{host}:{port}"
    path = parts.path.rstrip("/")
    return urlunsplit((scheme, netloc, path, "", ""))


def ws_endpoint(moodle_url: str) -> str:
    return moodle_url + "/webservice/rest/server.php"


def _hash_bearer(bearer: str) -> bytes:
    return hashlib.sha256(bearer.encode()).digest()


def _now() -> int:
    return int(time.time())


class Registry:
    def __init__(self, db_path: str, kek: Kek) -> None:
        self._path = db_path
        self._kek = kek

    @classmethod
    def open(cls, db_path: str, kek: Kek) -> "Registry":
        fd = os.open(db_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        registry = cls(db_path, kek)
        with registry._connect() as conn:
            conn.executescript(_SCHEMA)
            columns = {info[1] for info in conn.execute("PRAGMA table_info(tenants)")}
            if "pseudonymize" not in columns:
                conn.execute(
                    "ALTER TABLE tenants ADD COLUMN pseudonymize INTEGER NOT NULL DEFAULT 1"
                )
            row = conn.execute("SELECT schema_version FROM meta").fetchone()
            if row is None:
                conn.execute("INSERT INTO meta(schema_version) VALUES (3)")
            elif row[0] < 3:
                registry._migrate_aad(conn)
                conn.execute("UPDATE meta SET schema_version = 3")
        return registry

    def _migrate_aad(self, conn: sqlite3.Connection) -> None:
        """Re-seal legacy rows so the tenant Moodle URL is bound into the token AAD."""
        rows = conn.execute(
            "SELECT site_id, moodle_url, token_ct, litellm_ct FROM tenants"
        ).fetchall()
        for site_id, moodle_url, token_ct, litellm_ct in rows:
            new_token = self._migrate_blob(
                token_ct, site_id, moodle_url, FIELD_MOODLE_TOKEN
            )
            new_litellm = self._migrate_blob(
                litellm_ct, site_id, moodle_url, FIELD_LITELLM_KEY
            )
            if new_token != token_ct or new_litellm != litellm_ct:
                conn.execute(
                    "UPDATE tenants SET token_ct = ?, litellm_ct = ? WHERE site_id = ?",
                    (new_token, new_litellm, site_id),
                )

    def _migrate_blob(
        self, blob: bytes | None, site_id: str, moodle_url: str, field: str
    ) -> bytes | None:
        if blob is None:
            return None
        try:
            plaintext = open_(self._kek, blob, site_id, field)
        except DecryptError:
            try:
                open_(self._kek, blob, site_id, field, moodle_url=moodle_url)
            except DecryptError:
                return blob
            return blob
        return seal(self._kek, plaintext, site_id, field, moodle_url=moodle_url)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._path, timeout=5)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("PRAGMA secure_delete=ON")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _tenant(row: sqlite3.Row | tuple) -> Tenant:
        return Tenant(
            site_id=row[0],
            moodle_url=row[1],
            token_ct=row[2],
            litellm_ct=row[3],
            bearer_hash=row[4],
            kek_id=row[5],
            status=row[6],
            created_at=row[7],
            updated_at=row[8],
            pseudonymize=bool(row[9]),
        )

    @staticmethod
    def _select_columns() -> str:
        return (
            "site_id, moodle_url, token_ct, litellm_ct, bearer_hash, kek_id, "
            "status, created_at, updated_at, pseudonymize"
        )

    def add(
        self,
        site_id: str,
        moodle_url: str,
        moodle_token: bytes,
        litellm_key: bytes | None,
        bearer: str,
        pseudonymize: bool = True,
    ) -> None:
        if not SITE_ID_RE.fullmatch(site_id):
            raise TenantError("invalid site_id")
        url = normalize_moodle_url(moodle_url, os.environ.get("UBIONAI_HUB_ALLOW_HTTP") == "1")
        now = _now()
        token_ct = seal(
            self._kek, moodle_token, site_id, FIELD_MOODLE_TOKEN, moodle_url=url
        )
        litellm_ct = (
            seal(self._kek, litellm_key, site_id, FIELD_LITELLM_KEY, moodle_url=url)
            if litellm_key is not None
            else None
        )
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO tenants (site_id, moodle_url, token_ct, litellm_ct, bearer_hash,"
                    " kek_id, status, pseudonymize, created_at, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)",
                    (
                        site_id,
                        url,
                        token_ct,
                        litellm_ct,
                        _hash_bearer(bearer),
                        self._kek.kek_id,
                        int(pseudonymize),
                        now,
                        now,
                    ),
                )
        except sqlite3.IntegrityError:
            raise DuplicateSite("site already exists") from None

    def get(self, site_id: str) -> Tenant | None:
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT {self._select_columns()} FROM tenants WHERE site_id = ?", (site_id,)
            ).fetchone()
        return self._tenant(row) if row is not None else None

    def verify_bearer(self, site_id: str, bearer: str) -> Tenant | None:
        tenant = self.get(site_id)
        if tenant is None or tenant.status != "active":
            return None
        if not hmac.compare_digest(tenant.bearer_hash, _hash_bearer(bearer)):
            return None
        return tenant

    def set_status(self, site_id: str, status: str) -> None:
        if status not in ("active", "disabled"):
            raise TenantError("invalid status")
        self._update(site_id, "status = ?, updated_at = ?", (status, _now()))

    def rotate_token(self, site_id: str, token: bytes) -> None:
        tenant = self._require(site_id)
        token_ct = seal(
            self._kek, token, tenant.site_id, FIELD_MOODLE_TOKEN, moodle_url=tenant.moodle_url
        )
        self._update(site_id, "token_ct = ?, updated_at = ?", (token_ct, _now()))

    def rotate_litellm(self, site_id: str, key: bytes | None) -> None:
        tenant = self._require(site_id)
        litellm_ct = (
            seal(
                self._kek,
                key,
                tenant.site_id,
                FIELD_LITELLM_KEY,
                moodle_url=tenant.moodle_url,
            )
            if key is not None
            else None
        )
        self._update(site_id, "litellm_ct = ?, updated_at = ?", (litellm_ct, _now()))

    def rotate_bearer(self, site_id: str, bearer: str) -> None:
        self._update(site_id, "bearer_hash = ?, updated_at = ?", (_hash_bearer(bearer), _now()))

    def rotate_pseudonymize(self, site_id: str, enabled: bool) -> None:
        self._update(site_id, "pseudonymize = ?, updated_at = ?", (int(enabled), _now()))

    def delete(self, site_id: str) -> None:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM tenants WHERE site_id = ?", (site_id,))
            if cur.rowcount == 0:
                raise TenantNotFound("site not found")

    def list(self) -> list[Tenant]:
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT {self._select_columns()} FROM tenants ORDER BY site_id"
            ).fetchall()
        return [self._tenant(row) for row in rows]

    def kek_ids(self) -> set[str]:
        with self._connect() as conn:
            rows = conn.execute("SELECT DISTINCT kek_id FROM tenants").fetchall()
        return {row[0] for row in rows}

    def moodle_token(self, tenant: Tenant) -> bytearray:
        return open_(
            self._kek,
            tenant.token_ct,
            tenant.site_id,
            FIELD_MOODLE_TOKEN,
            moodle_url=tenant.moodle_url,
        )

    def litellm_key(self, tenant: Tenant) -> bytearray | None:
        if tenant.litellm_ct is None:
            return None
        return open_(
            self._kek,
            tenant.litellm_ct,
            tenant.site_id,
            FIELD_LITELLM_KEY,
            moodle_url=tenant.moodle_url,
        )

    def issue_code(self, site_id: str, moodle_url: str, ttl_seconds: int) -> str:
        if not SITE_ID_RE.fullmatch(site_id):
            raise TenantError("invalid site_id")
        if ttl_seconds <= 0:
            raise RegCodeError("invalid TTL")
        url = normalize_moodle_url(moodle_url, os.environ.get("UBIONAI_HUB_ALLOW_HTTP") == "1")
        code = secrets.token_urlsafe(24)
        now = _now()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO reg_codes (code_hash, site_id, moodle_url, expires_at, used_at)"
                " VALUES (?, ?, ?, ?, NULL)",
                (hashlib.sha256(code.encode()).digest(), site_id, url, now + int(ttl_seconds)),
            )
        return code

    def lookup_code(self, code: str, now: int) -> tuple[str, str] | None:
        code_hash = hashlib.sha256(code.encode()).digest()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT site_id, moodle_url FROM reg_codes WHERE code_hash = ?"
                " AND used_at IS NULL AND expires_at > ?",
                (code_hash, now),
            ).fetchone()
        return (row[0], row[1]) if row is not None else None

    def consume_code(self, code: str, now: int) -> bool:
        code_hash = hashlib.sha256(code.encode()).digest()
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE reg_codes SET used_at = ? WHERE code_hash = ? AND used_at IS NULL"
                " AND expires_at > ?",
                (now, code_hash, now),
            )
        return cur.rowcount > 0

    def claim_code(self, code: str, now: int) -> tuple[str, str] | None:
        code_hash = hashlib.sha256(code.encode()).digest()
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE reg_codes SET used_at = ? WHERE code_hash = ? AND used_at IS NULL"
                " AND expires_at > ?",
                (now, code_hash, now),
            )
            if cur.rowcount == 0:
                return None
            row = conn.execute(
                "SELECT site_id, moodle_url FROM reg_codes WHERE code_hash = ?", (code_hash,)
            ).fetchone()
        return (row[0], row[1]) if row is not None else None

    def _require(self, site_id: str) -> Tenant:
        tenant = self.get(site_id)
        if tenant is None:
            raise TenantNotFound("site not found")
        return tenant

    def _update(self, site_id: str, assignments: str, params: tuple[object, ...]) -> None:
        with self._connect() as conn:
            cur = conn.execute(
                f"UPDATE tenants SET {assignments} WHERE site_id = ?", (*params, site_id)
            )
            if cur.rowcount == 0:
                raise TenantNotFound("site not found")
