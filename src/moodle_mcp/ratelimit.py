"""In-process rate limits for the registration API and the unregistered-site page (contract §4.2).

Single uvicorn process assumed (as deployed today); counters are lost on restart, which only
ever makes the limits more lenient for a moment.
"""

from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable

HOUR = 3600
DAY = 86400


@dataclass(frozen=True)
class Rule:
    key: str
    limit: int
    window: int


@dataclass
class RateLimiter:
    clock: Callable[[], float] = time.monotonic
    max_keys: int = 50_000
    _hits: dict[tuple[str, int], deque[float]] = field(default_factory=dict)
    _negative: dict[str, tuple[int, float]] = field(default_factory=dict)

    def _window(self, rule: Rule, now: float) -> deque[float]:
        hits = self._hits.get((rule.key, rule.window))
        if hits is None:
            if len(self._hits) >= self.max_keys:
                self._gc(now)
            hits = self._hits.setdefault((rule.key, rule.window), deque())
        while hits and hits[0] <= now - rule.window:
            hits.popleft()
        return hits

    def _gc(self, now: float) -> None:
        for key in [k for k, v in self._hits.items() if not v or v[-1] <= now - k[1]]:
            del self._hits[key]
        if len(self._hits) >= self.max_keys:
            self._hits.clear()

    def check(self, *rules: Rule) -> int | None:
        """Seconds to wait when any rule is exhausted, else None (nothing recorded)."""
        now = self.clock()
        wait = 0.0
        for rule in rules:
            hits = self._window(rule, now)
            if len(hits) >= rule.limit:
                wait = max(wait, hits[len(hits) - rule.limit] + rule.window - now)
        return max(1, math.ceil(wait)) if wait > 0 else None

    def record(self, *rules: Rule) -> None:
        now = self.clock()
        for rule in rules:
            self._window(rule, now).append(now)

    def hit(self, *rules: Rule) -> int | None:
        """check + record when allowed."""
        wait = self.check(*rules)
        if wait is None:
            self.record(*rules)
        return wait

    # Negative cache: a target host that keeps failing verification is not called again for a
    # while (1 min, doubling, at most 1 h) so the hub cannot be used to hammer someone's site.
    def negative_wait(self, key: str) -> int | None:
        entry = self._negative.get(key)
        if entry is None:
            return None
        remaining = entry[1] - self.clock()
        return max(1, math.ceil(remaining)) if remaining > 0 else None

    def negative_fail(self, key: str, base: int = 60, cap: int = HOUR) -> int:
        count = self._negative.get(key, (0, 0.0))[0] + 1
        delay = min(cap, base * 2 ** (count - 1))
        if len(self._negative) >= self.max_keys:
            now = self.clock()
            self._negative = {k: v for k, v in self._negative.items() if v[1] > now}
        self._negative[key] = (count, self.clock() + delay)
        return delay

    def negative_clear(self, key: str) -> None:
        self._negative.pop(key, None)
