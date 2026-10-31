"""Network-related parsing helpers shared by the hub."""

from __future__ import annotations

import ipaddress


def parse_ip_list(value: str | None) -> str | None:
    """Normalise a comma-separated IP/CIDR list.

    Args:
        value: raw value, or None / "" / whitespace-only for "no restriction".

    Returns:
        Canonical comma-joined string, or None when value is empty/whitespace-only.

    Raises:
        ValueError: with a message naming the offending entry, e.g.
            "invalid IP entry '1.2.3.4 # office'".
    """
    if value is None or not value.strip():
        return None

    canonical: list[str] = []
    seen: set[str] = set()
    for raw in value.split(","):
        entry = raw.strip()
        if entry == "":
            raise ValueError("empty entry in IP list")
        if "#" in entry or "%" in entry or any(ch.isspace() for ch in entry):
            raise ValueError(f"invalid IP entry '{entry}'")
        try:
            if "/" in entry:
                normalised = str(ipaddress.ip_network(entry, strict=True))
            else:
                normalised = str(ipaddress.ip_address(entry))
        except ValueError:
            raise ValueError(f"invalid IP entry '{entry}'") from None
        if normalised not in seen:
            seen.add(normalised)
            canonical.append(normalised)

    result = ",".join(canonical)
    if len(result) > 255:
        raise ValueError("IP list exceeds 255 characters")
    return result
