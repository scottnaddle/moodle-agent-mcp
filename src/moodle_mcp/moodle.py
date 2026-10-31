"""Minimal async client for the Moodle REST web service (server.php)."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

import httpx

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 180.0


class MoodleError(Exception):
    """Raised when Moodle returns an exception payload or the call fails."""

    def __init__(self, message: str, errorcode: str | None = None) -> None:
        super().__init__(message)
        self.errorcode = errorcode


def _scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value)


def flatten_params(params: Mapping[str, Any], prefix: str = "") -> dict[str, str]:
    """Flatten nested dicts/lists into Moodle's PHP-style array syntax.

    {"courseids": [5, 6]}              -> {"courseids[0]": "5", "courseids[1]": "6"}
    {"grades": [{"userid": 3}]}        -> {"grades[0][userid]": "3"}
    Booleans become "1"/"0"; None values are omitted.
    """
    out: dict[str, str] = {}
    for key, value in params.items():
        name = f"{prefix}[{key}]" if prefix else str(key)
        _flatten_into(out, name, value)
    return out


def _flatten_into(out: dict[str, str], name: str, value: Any) -> None:
    if value is None:
        return
    if isinstance(value, Mapping):
        out.update(flatten_params(value, name))
    elif isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            _flatten_into(out, f"{name}[{i}]", item)
    else:
        out[name] = _scalar(value)


class MoodleClient:
    def __init__(
        self,
        endpoint: str,
        token: str,
        *,
        timeout: httpx.Timeout | float = DEFAULT_TIMEOUT,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.endpoint = endpoint
        self._token = token
        self._timeout = timeout
        self._transport = transport

    def __repr__(self) -> str:  # never expose the token
        return f"MoodleClient(endpoint={self.endpoint!r})"

    async def call(self, wsfunction: str, **params: Any) -> Any:
        if not self.endpoint or not self._token:
            raise MoodleError("Moodle is not configured (MOODLE_WS_ENDPOINT / MOODLE_TOKEN missing)")

        data = flatten_params(params)
        data.update(
            {
                "wstoken": self._token,
                "wsfunction": wsfunction,
                "moodlewsrestformat": "json",
            }
        )
        logger.debug("Moodle call %s (%d params)", wsfunction, len(data) - 3)

        try:
            async with httpx.AsyncClient(timeout=self._timeout, transport=self._transport) as client:
                resp = await client.post(self.endpoint, data=data)
                resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise MoodleError(f"{wsfunction}: HTTP {exc.response.status_code} from Moodle") from None
        except httpx.HTTPError as exc:
            raise MoodleError(f"{wsfunction}: request failed ({type(exc).__name__})") from None

        if not resp.content.strip():
            return None  # some void functions return an empty body
        try:
            result = resp.json()
        except ValueError:
            raise MoodleError(f"{wsfunction}: Moodle returned a non-JSON response") from None

        if isinstance(result, dict) and "exception" in result:
            errorcode = result.get("errorcode")
            message = result.get("message", "")
            raise MoodleError(f"{wsfunction}: [{errorcode}] {message}".replace(self._token, "***"), errorcode)
        return result
