"""Usage limits of the lowest tier (``tier=limited``, every self-registered tenant).

Decided 2026-11-03 (Scott, contract §8.3 #2): provisional values of 5 teachers and 200 requests
per day, set by configuration only (never hard-coded at the call sites):

- ``UBIONAI_HUB_LIMITED_MAX_TEACHERS`` (default 5): distinct Moodle users with a live OAuth
  grant. A new teacher beyond the limit gets no grant; teachers already connected keep working.
- ``UBIONAI_HUB_LIMITED_DAILY_REQUESTS`` (default 200): authenticated MCP requests per tenant per
  UTC day. Beyond it the MCP endpoint answers ``429 daily_limit_exceeded`` (contract §4.1 format).

The daily counter lives in sqlite so a restart does not reset it.
"""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

DEFAULT_MAX_TEACHERS = 5
DEFAULT_DAILY_REQUESTS = 200
USAGE_RETENTION_DAYS = 7

_SCHEMA = """
CREATE TABLE IF NOT EXISTS usage_daily (
  site_id TEXT NOT NULL,
  day TEXT NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (site_id, day)
);
"""


def _positive_int(name: str, default: int) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    if not raw.isdigit() or int(raw) < 1:
        raise ValueError(f"{name} must be a positive integer")
    return int(raw)


@dataclass(frozen=True)
class TierLimits:
    """Limits applied to ``tier=limited`` tenants (operator tenants are not limited here)."""

    max_teachers: int = DEFAULT_MAX_TEACHERS
    daily_requests: int = DEFAULT_DAILY_REQUESTS
    concurrency: int = 1  # advertised only; not enforced yet
    llm_proxy: bool = False

    @classmethod
    def from_env(cls) -> "TierLimits":
        return cls(
            max_teachers=_positive_int("UBIONAI_HUB_LIMITED_MAX_TEACHERS", DEFAULT_MAX_TEACHERS),
            daily_requests=_positive_int("UBIONAI_HUB_LIMITED_DAILY_REQUESTS", DEFAULT_DAILY_REQUESTS),
        )

    def describe(self) -> dict[str, Any]:
        """``tenant.limits`` in registration / status responses."""
        return {
            "max_teachers": self.max_teachers,
            "daily_requests": self.daily_requests,
            "concurrency": self.concurrency,
            "llm_proxy": self.llm_proxy,
        }


def _utc_day(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")


def seconds_to_utc_midnight(ts: float) -> int:
    return max(1, 86_400 - int(ts) % 86_400)


class DailyUsage:
    """Per-tenant request counter per UTC day (sqlite, shared by every worker on the same DB)."""

    def __init__(self, registry: Any, clock: Callable[[], float] = time.time) -> None:
        self.registry = registry
        self.clock = clock
        self._purged_day: str | None = None
        with self.registry._connect() as conn:
            conn.executescript(_SCHEMA)

    def hit(self, site_id: str, limit: int) -> int | None:
        """Count one request. Returns seconds until the next UTC day when the limit is used up
        (the refused request is not counted), else None."""
        now = self.clock()
        day = _utc_day(now)
        with self.registry._connect() as conn:
            if self._purged_day != day:
                cutoff = _utc_day(now - USAGE_RETENTION_DAYS * 86_400)
                conn.execute("DELETE FROM usage_daily WHERE day < ?", (cutoff,))
                self._purged_day = day
            cur = conn.execute(
                "INSERT INTO usage_daily (site_id, day, count) VALUES (?, ?, 1)"
                " ON CONFLICT (site_id, day) DO UPDATE SET count = count + 1 WHERE count < ?",
                (site_id, day, limit),
            )
            allowed = cur.rowcount > 0
        return None if allowed else seconds_to_utc_midnight(now)

    def count(self, site_id: str) -> int:
        with self.registry._connect() as conn:
            try:
                row = conn.execute(
                    "SELECT count FROM usage_daily WHERE site_id = ? AND day = ?",
                    (site_id, _utc_day(self.clock())),
                ).fetchone()
            except sqlite3.OperationalError:
                return 0
        return int(row[0]) if row else 0
