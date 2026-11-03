"""SQLite-backed tenant registry with encrypted tenant secrets."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import secrets
import sqlite3
import time
import unicodedata
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator
from urllib.parse import urlsplit, urlunsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import (
    FIELD_ADMIN_CONTACT,
    FIELD_LITELLM_KEY,
    FIELD_MOODLE_TOKEN,
    PURPOSE_PSEUDONYM_MAP,
    DecryptError,
    Kek,
    derive_key,
    open_,
    seal,
)
from .hostkey import HostKeyError, allowed_ports_from_env, normalize_site_url

logger = logging.getLogger(__name__)

SITE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")


def _parse_pseudonym_ttl() -> int:
    try:
        return int(os.environ.get("UBIONAI_HUB_PSEUDONYM_TTL", "86400"))
    except ValueError:
        return 86_400


PSEUDONYM_TTL = _parse_pseudonym_ttl()

_PMAP_AAD_PREFIX = b"ubionai-hub/pmap/v1\x00"
_PMAP_NONCE_LEN = 12

# Assignment-title name heuristic per tenant (see pseudonym.HEURISTIC_MODES).
ASSIGNMENT_TITLE_HEURISTICS = ("full", "title", "off")

SCHEMA_VERSION = 6
TENANT_STATUSES = ("active", "pending", "disabled")

_TENANTS_V6_COLUMNS = """
  site_id      TEXT PRIMARY KEY CHECK (site_id GLOB '[a-z0-9]*'
                 AND length(site_id) BETWEEN 2 AND 63),
  moodle_url   TEXT NOT NULL,
  token_ct     BLOB,
  litellm_ct   BLOB,
  bearer_hash  BLOB UNIQUE,
  kek_id       TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'active'
               CHECK (status IN ('active','pending','disabled')),
  pseudonymize INTEGER NOT NULL DEFAULT 1
               CHECK (pseudonymize IN (0,1)),
  assignment_title_heuristic TEXT NOT NULL DEFAULT 'title'
               CHECK (assignment_title_heuristic IN ('full','title','off')),
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL,
  host_key     TEXT UNIQUE,
  origin       TEXT NOT NULL DEFAULT 'operator'
               CHECK (origin IN ('operator','self_registered')),
  tier         TEXT NOT NULL DEFAULT 'standard' CHECK (tier IN ('limited','standard')),
  auth_mode    TEXT NOT NULL DEFAULT 'legacy_file'
               CHECK (auth_mode IN ('legacy_file','shared_secret','signature')),
  site_identifier_hash BLOB,
  plugin_version INTEGER,
  moodle_release TEXT,
  contact_ct   BLOB,
  consent_version TEXT,
  consent_at   INTEGER,
  last_verified_at INTEGER,
  secret_seq   INTEGER NOT NULL DEFAULT 0,
  CHECK (origin = 'operator' OR (token_ct IS NULL AND bearer_hash IS NULL)),
  CHECK (origin = 'self_registered' OR (token_ct IS NOT NULL AND bearer_hash IS NOT NULL))
"""

# Columns that exist before v6, copied by the v6 table rebuild.
_TENANTS_V5_COLUMNS = (
    "site_id, moodle_url, token_ct, litellm_ct, bearer_hash, kek_id, status, pseudonymize,"
    " assignment_title_heuristic, created_at, updated_at"
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  schema_version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tenants (""" + _TENANTS_V6_COLUMNS + """);
CREATE TABLE IF NOT EXISTS reg_codes (
  code_hash  BLOB PRIMARY KEY,
  site_id    TEXT NOT NULL,
  moodle_url TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at    INTEGER
);
CREATE TABLE IF NOT EXISTS pseudonym_map (
  site_id     TEXT NOT NULL,
  placeholder TEXT NOT NULL,
  category    TEXT NOT NULL,
  value_ct    BLOB NOT NULL,
  kek_id      TEXT NOT NULL,
  expires_at  INTEGER NOT NULL,
  PRIMARY KEY (site_id, placeholder)
);
INSERT INTO meta(schema_version) SELECT 6 WHERE NOT EXISTS (SELECT 1 FROM meta);
"""

# Schema v6 (registration contract §3.2): tenants without a site token / static bearer
# (self-registered), host_key routing, tier, auth_mode. Operator rows keep their token + bearer.
_SCHEMA_V6_EXTRA = """
CREATE TABLE IF NOT EXISTS site_credentials (
  site_id      TEXT NOT NULL,
  version      INTEGER NOT NULL,
  kind         TEXT NOT NULL CHECK (kind IN ('shared_secret')),
  secret_hash  BLOB NOT NULL,
  mac_key_ct   BLOB NOT NULL,
  kek_id       TEXT NOT NULL,
  state        TEXT NOT NULL CHECK (state IN ('pending','current','retired')),
  created_at   INTEGER NOT NULL,
  confirmed_at INTEGER,
  expires_at   INTEGER,
  PRIMARY KEY (site_id, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS site_credentials_one_current
  ON site_credentials(site_id) WHERE state = 'current';
CREATE UNIQUE INDEX IF NOT EXISTS site_credentials_one_pending
  ON site_credentials(site_id) WHERE state = 'pending';
CREATE TABLE IF NOT EXISTS site_registrations (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  host_key         TEXT NOT NULL,
  site_id          TEXT,
  nonce_hash       BLOB UNIQUE,
  client_ip_prefix TEXT,
  outcome          TEXT NOT NULL,
  error            TEXT,
  plugin_version   INTEGER,
  created_at       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS site_registrations_host ON site_registrations(host_key, created_at);
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
    bearer_hash: bytes | None
    token_ct: bytes | None
    litellm_ct: bytes | None
    kek_id: str
    status: str
    created_at: int
    updated_at: int
    pseudonymize: bool = True
    assignment_title_heuristic: str = "title"
    host_key: str | None = None
    origin: str = "operator"
    tier: str = "standard"
    auth_mode: str = "legacy_file"
    site_identifier_hash: bytes | None = None
    plugin_version: int | None = None
    moodle_release: str | None = None
    consent_version: str | None = None
    consent_at: int | None = None
    last_verified_at: int | None = None

    @property
    def self_registered(self) -> bool:
        return self.origin == "self_registered"


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


def operator_host_key(moodle_url: str) -> str | None:
    """host_key of an operator tenant's Moodle URL, or None (http, IP literal, internal name…)."""
    try:
        return normalize_site_url(moodle_url, allowed_ports_from_env()).host_key
    except HostKeyError:
        return None


def ws_endpoint(moodle_url: str) -> str:
    return moodle_url + "/webservice/rest/server.php"


def _hash_bearer(bearer: str) -> bytes:
    return hashlib.sha256(bearer.encode()).digest()


def _now() -> int:
    return int(time.time())


def _normalize_original(category: str, original: str) -> str:
    text = unicodedata.normalize("NFC", original).strip()
    if category == "email":
        return text.lower()
    if category in ("phone", "resident_id"):
        return re.sub(r"[- ]", "", text)
    return text


class Registry:
    def __init__(self, db_path: str, kek: Kek) -> None:
        self._path = db_path
        self._kek = kek
        self._last_purge = 0.0

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
            if "assignment_title_heuristic" not in columns:
                conn.execute(
                    "ALTER TABLE tenants ADD COLUMN assignment_title_heuristic TEXT NOT NULL"
                    " DEFAULT 'title'"
                    " CHECK (assignment_title_heuristic IN ('full','title','off'))"
                )
            row = conn.execute("SELECT schema_version FROM meta").fetchone()
            if row is None:
                conn.execute("INSERT INTO meta(schema_version) VALUES (?)", (SCHEMA_VERSION,))
            else:
                if row[0] < 3:
                    registry._migrate_aad(conn)
                    conn.execute("UPDATE meta SET schema_version = 3")
                if row[0] < 4:
                    conn.execute("UPDATE meta SET schema_version = 4")
            conn.commit()
            columns = {info[1] for info in conn.execute("PRAGMA table_info(tenants)")}
            if "host_key" not in columns:
                registry._migrate_v6(conn)
            conn.executescript(_SCHEMA_V6_EXTRA)
            conn.execute(
                "UPDATE meta SET schema_version = ? WHERE schema_version < ?",
                (SCHEMA_VERSION, SCHEMA_VERSION),
            )
        return registry

    def _migrate_v6(self, conn: sqlite3.Connection) -> None:
        """Rebuild ``tenants`` (SQLite cannot drop NOT NULL with ALTER) in one transaction.

        Existing rows become ``origin='operator'``, ``tier='standard'``, ``auth_mode='legacy_file'``;
        ``host_key`` is computed from ``moodle_url`` and left NULL when it is not a valid public
        https host key or when two tenants would share it (logged for the operator).
        """
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("CREATE TABLE tenants_v6 (" + _TENANTS_V6_COLUMNS + ")")
            conn.execute(
                f"INSERT INTO tenants_v6 ({_TENANTS_V5_COLUMNS}) SELECT {_TENANTS_V5_COLUMNS} FROM tenants"
            )
            conn.execute("DROP TABLE tenants")
            conn.execute("ALTER TABLE tenants_v6 RENAME TO tenants")
            keys: dict[str, list[str]] = {}
            for site_id, moodle_url in conn.execute("SELECT site_id, moodle_url FROM tenants").fetchall():
                host_key = operator_host_key(moodle_url)
                if host_key is None:
                    logger.warning("schema v6: no host_key for site=%s (not a public https URL)", site_id)
                    continue
                keys.setdefault(host_key, []).append(site_id)
            for host_key, sites in keys.items():
                if len(sites) > 1:
                    logger.warning("schema v6: host_key %s shared by %s; left NULL", host_key, ",".join(sites))
                    continue
                conn.execute("UPDATE tenants SET host_key = ? WHERE site_id = ?", (host_key, sites[0]))
            conn.execute("UPDATE meta SET schema_version = ?", (SCHEMA_VERSION,))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

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
            assignment_title_heuristic=row[10],
            host_key=row[11],
            origin=row[12],
            tier=row[13],
            auth_mode=row[14],
            site_identifier_hash=row[15],
            plugin_version=row[16],
            moodle_release=row[17],
            consent_version=row[18],
            consent_at=row[19],
            last_verified_at=row[20],
        )

    @staticmethod
    def _select_columns() -> str:
        return (
            "site_id, moodle_url, token_ct, litellm_ct, bearer_hash, kek_id, "
            "status, created_at, updated_at, pseudonymize, assignment_title_heuristic, "
            "host_key, origin, tier, auth_mode, site_identifier_hash, plugin_version, "
            "moodle_release, consent_version, consent_at, last_verified_at"
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
        host_key = operator_host_key(url)
        try:
            with self._connect() as conn:
                if host_key is not None and conn.execute(
                    "SELECT 1 FROM tenants WHERE host_key = ?", (host_key,)
                ).fetchone():
                    logger.warning("host_key %s already used; site=%s gets none", host_key, site_id)
                    host_key = None
                conn.execute(
                    "INSERT INTO tenants (site_id, moodle_url, token_ct, litellm_ct, bearer_hash,"
                    " kek_id, status, pseudonymize, created_at, updated_at, host_key)"
                    " VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)",
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
                        host_key,
                    ),
                )
        except sqlite3.IntegrityError:
            raise DuplicateSite("site already exists") from None

    def add_self_registered(
        self,
        site_id: str,
        moodle_url: str,
        host_key: str,
        *,
        status: str,
        site_identifier_hash: bytes | None,
        plugin_version: int,
        moodle_release: str,
        consent_version: str,
        consent_at: int,
        contact: bytes | None = None,
    ) -> Tenant:
        """Self-registered tenant: tier limited, no site token, no static bearer (contract §3.2)."""
        if not SITE_ID_RE.fullmatch(site_id):
            raise TenantError("invalid site_id")
        if status not in ("active", "pending"):
            raise TenantError("invalid status")
        now = _now()
        contact_ct = (
            seal(self._kek, contact, site_id, FIELD_ADMIN_CONTACT, moodle_url=moodle_url)
            if contact is not None
            else None
        )
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO tenants (site_id, moodle_url, token_ct, litellm_ct, bearer_hash, kek_id,"
                    " status, pseudonymize, created_at, updated_at, host_key, origin, tier, auth_mode,"
                    " site_identifier_hash, plugin_version, moodle_release, contact_ct,"
                    " consent_version, consent_at, last_verified_at)"
                    " VALUES (?, ?, NULL, NULL, NULL, ?, ?, 1, ?, ?, ?, 'self_registered', 'limited',"
                    " 'shared_secret', ?, ?, ?, ?, ?, ?, ?)",
                    (
                        site_id, moodle_url, self._kek.kek_id, status, now, now, host_key,
                        site_identifier_hash, plugin_version, moodle_release, contact_ct,
                        consent_version, consent_at, now,
                    ),
                )
        except sqlite3.IntegrityError:
            raise DuplicateSite("site or host already exists") from None
        return self._require(site_id)

    def record_verification(
        self,
        site_id: str,
        *,
        plugin_version: int,
        moodle_release: str,
        site_identifier_hash: bytes | None,
        consent_version: str,
        consent_at: int,
        contact: bytes | None = None,
    ) -> None:
        """A re-registration proved control of the site again (callback verified)."""
        tenant = self._require(site_id)
        now = _now()
        contact_ct = (
            seal(self._kek, contact, site_id, FIELD_ADMIN_CONTACT, moodle_url=tenant.moodle_url)
            if contact is not None
            else None
        )
        self._update(
            site_id,
            "plugin_version = ?, moodle_release = ?, site_identifier_hash = ?, consent_version = ?,"
            " consent_at = ?, contact_ct = COALESCE(?, contact_ct), last_verified_at = ?, updated_at = ?",
            (plugin_version, moodle_release, site_identifier_hash, consent_version, consent_at,
             contact_ct, now, now),
        )

    def get_by_host_key(self, host_key: str) -> Tenant | None:
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT {self._select_columns()} FROM tenants WHERE host_key = ?", (host_key,)
            ).fetchone()
        return self._tenant(row) if row is not None else None

    def site_identifier_elsewhere(self, site_identifier_hash: bytes, host_key: str) -> bool:
        """Another host already registered with the same Moodle siteidentifier (cloned DB?)."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM tenants WHERE site_identifier_hash = ? AND host_key IS NOT ?",
                (site_identifier_hash, host_key),
            ).fetchone()
        return row is not None

    def count_self_registered_since(self, since: int) -> int:
        with self._connect() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM tenants WHERE origin = 'self_registered' AND created_at >= ?",
                (since,),
            ).fetchone()[0]

    def get(self, site_id: str) -> Tenant | None:
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT {self._select_columns()} FROM tenants WHERE site_id = ?", (site_id,)
            ).fetchone()
        return self._tenant(row) if row is not None else None

    def verify_bearer(self, site_id: str, bearer: str) -> Tenant | None:
        tenant = self.get(site_id)
        if tenant is None or tenant.status != "active" or tenant.bearer_hash is None:
            return None
        if not hmac.compare_digest(tenant.bearer_hash, _hash_bearer(bearer)):
            return None
        return tenant

    def revoke_grants(self, site_id: str) -> int:
        """Revoke every teacher OAuth grant (and its tokens) of a tenant; returns the count.

        The Moodle-side user tokens are not contacted here: callers use this when the site behind
        the tenant can no longer be trusted to be the one that issued them.
        """
        now = _now()
        with self._connect() as conn:
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'oauth_grants'"
            ).fetchone()
            if exists is None:
                return 0
            conn.execute(
                "UPDATE oauth_tokens SET used_at = ? WHERE used_at IS NULL AND grant_id IN"
                " (SELECT grant_id FROM oauth_grants WHERE site_id = ? AND revoked_at IS NULL)",
                (now, site_id),
            )
            cur = conn.execute(
                "UPDATE oauth_grants SET revoked_at = ? WHERE site_id = ? AND revoked_at IS NULL",
                (now, site_id),
            )
            return cur.rowcount

    def set_status(self, site_id: str, status: str) -> None:
        if status not in TENANT_STATUSES:
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

    def set_assignment_title_heuristic(self, site_id: str, mode: str) -> None:
        if mode not in ASSIGNMENT_TITLE_HEURISTICS:
            raise TenantError("invalid assignment_title_heuristic")
        self._update(
            site_id, "assignment_title_heuristic = ?, updated_at = ?", (mode, _now())
        )

    def _pmap_aad(self, site_id: str, placeholder: str) -> bytes:
        return (
            _PMAP_AAD_PREFIX
            + site_id.encode("utf-8")
            + b"\x00"
            + placeholder.encode("utf-8")
        )

    def _pmap_encrypt(self, site_id: str, placeholder: str, original: str) -> bytes:
        nonce = os.urandom(_PMAP_NONCE_LEN)
        key = derive_key(self._kek, PURPOSE_PSEUDONYM_MAP, site_id)
        ciphertext = AESGCM(key).encrypt(
            nonce, original.encode("utf-8"), self._pmap_aad(site_id, placeholder)
        )
        return nonce + ciphertext

    def _pmap_decrypt(self, site_id: str, placeholder: str, blob: bytes) -> str | None:
        try:
            nonce = blob[:_PMAP_NONCE_LEN]
            ciphertext = blob[_PMAP_NONCE_LEN:]
            key = derive_key(self._kek, PURPOSE_PSEUDONYM_MAP, site_id)
            plaintext = AESGCM(key).decrypt(
                nonce, ciphertext, self._pmap_aad(site_id, placeholder)
            )
            return plaintext.decode("utf-8")
        except (InvalidTag, ValueError, UnicodeDecodeError, TypeError):
            return None

    def pmap_get(
        self, site_id: str, placeholder: str, now: int, ttl: int | None = None
    ) -> tuple[str, str] | None:
        now = int(now)
        ttl = PSEUDONYM_TTL if ttl is None else int(ttl)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT category, value_ct, kek_id, expires_at FROM pseudonym_map"
                " WHERE site_id = ? AND placeholder = ?",
                (site_id, placeholder),
            ).fetchone()
            if row is None:
                return None
            category, blob, kek_id, expires_at = row
            if kek_id != self._kek.kek_id:
                conn.execute(
                    "DELETE FROM pseudonym_map WHERE site_id = ? AND placeholder = ?",
                    (site_id, placeholder),
                )
                return None
            if expires_at <= now:
                return None
            original = self._pmap_decrypt(site_id, placeholder, blob)
            if original is None:
                return None
            conn.execute(
                "UPDATE pseudonym_map SET expires_at = ?"
                " WHERE site_id = ? AND placeholder = ?",
                (now + ttl, site_id, placeholder),
            )
        return category, original

    def pmap_put(
        self,
        site_id: str,
        placeholder: str,
        category: str,
        original: str,
        ttl: int,
        now: int,
    ) -> None:
        now = int(now)
        ttl = int(ttl)
        monotonic_now = time.monotonic()
        if monotonic_now - self._last_purge >= 60:
            self._last_purge = monotonic_now
            self.pmap_purge(now=now)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT category, value_ct, kek_id, expires_at FROM pseudonym_map"
                " WHERE site_id = ? AND placeholder = ?",
                (site_id, placeholder),
            ).fetchone()
            if row is not None:
                existing_category, blob, kek_id, expires_at = row
                if expires_at > now and kek_id == self._kek.kek_id:
                    existing = self._pmap_decrypt(site_id, placeholder, blob)
                    if existing is not None:
                        if _normalize_original(category, existing) != _normalize_original(
                            category, original
                        ):
                            conn.execute(
                                "UPDATE pseudonym_map SET expires_at = ?"
                                " WHERE site_id = ? AND placeholder = ?",
                                (now + ttl, site_id, placeholder),
                            )
                            return
                        conn.execute(
                            "UPDATE pseudonym_map SET expires_at = ?"
                            " WHERE site_id = ? AND placeholder = ?",
                            (now + ttl, site_id, placeholder),
                        )
                        return
            value_ct = self._pmap_encrypt(site_id, placeholder, original)
            conn.execute(
                "INSERT INTO pseudonym_map"
                " (site_id, placeholder, category, value_ct, kek_id, expires_at)"
                " VALUES (?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(site_id, placeholder) DO UPDATE SET"
                " category = excluded.category, value_ct = excluded.value_ct,"
                " kek_id = excluded.kek_id, expires_at = excluded.expires_at",
                (site_id, placeholder, category, value_ct, self._kek.kek_id, now + ttl),
            )

    def pmap_norm(self, site_id: str, placeholder: str, now: int) -> str | None:
        now = int(now)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT category, value_ct, kek_id, expires_at FROM pseudonym_map"
                " WHERE site_id = ? AND placeholder = ?",
                (site_id, placeholder),
            ).fetchone()
            if row is None:
                return None
            category, blob, kek_id, expires_at = row
            if kek_id != self._kek.kek_id:
                conn.execute(
                    "DELETE FROM pseudonym_map WHERE site_id = ? AND placeholder = ?",
                    (site_id, placeholder),
                )
                return None
            if expires_at <= now:
                return None
            original = self._pmap_decrypt(site_id, placeholder, blob)
            if original is None:
                return None
        return _normalize_original(category, original)

    def pmap_purge(self, site_id: str | None = None, now: int | None = None) -> int:
        now = _now() if now is None else int(now)
        with self._connect() as conn:
            if site_id is None:
                cur = conn.execute(
                    "DELETE FROM pseudonym_map WHERE expires_at <= ?", (now,)
                )
            else:
                cur = conn.execute(
                    "DELETE FROM pseudonym_map WHERE site_id = ? AND expires_at <= ?",
                    (site_id, now),
                )
            return cur.rowcount

    def delete(self, site_id: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM pseudonym_map WHERE site_id = ?", (site_id,))
            conn.execute("DELETE FROM site_credentials WHERE site_id = ?", (site_id,))
            conn.execute("DELETE FROM site_registrations WHERE site_id = ?", (site_id,))
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
        if tenant.token_ct is None:
            raise DecryptError("tenant has no site token")
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
