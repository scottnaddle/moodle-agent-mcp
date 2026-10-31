"""Administrative CLI for the multi-tenant hub registry."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import secrets
import stat
import sys
from datetime import datetime, timezone

from .crypto import KekError, load_kek
from .registry import Registry, TenantError


def _read_secret(path: str) -> bytes:
    if path == "-":
        if sys.stdin.isatty():
            data = getpass.getpass("").encode()
        else:
            stream = getattr(sys.stdin, "buffer", sys.stdin)
            data = stream.read()
            if isinstance(data, str):
                data = data.encode()
    else:
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode):
            raise OSError("secret source is not a regular file")
        if st.st_mode & 0o077:
            print(f"warning: {path} is group/world-readable", file=sys.stderr)
        with open(path, "rb") as handle:
            data = handle.read()
    data = data.strip()
    if not data:
        raise ValueError("secret is empty")
    return data


def _write_once(path: str, data: str | bytes) -> None:
    payload = data.encode() if isinstance(data, str) else data
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def _parse_ttl(text: str | None) -> int:
    if text is None or not str(text).strip():
        return 86_400
    match = re.fullmatch(r"(\d+)([smhd]?)", str(text).strip())
    if match is None:
        raise ValueError("invalid TTL")
    amount = int(match.group(1))
    if amount <= 0:
        raise ValueError("invalid TTL")
    unit = match.group(2)
    factor = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86_400}[unit]
    return amount * factor


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="moodle-hub-admin")
    sub = parser.add_subparsers(dest="command", required=True)

    add = sub.add_parser("add", help="add a tenant")
    add.add_argument("--site-id", required=True)
    add.add_argument("--moodle-url", required=True)
    add.add_argument("--moodle-token-file", required=True)
    add.add_argument("--litellm-key-file")
    add.add_argument("--bearer-out", required=True)
    add_flags = add.add_mutually_exclusive_group()
    add_flags.add_argument("--pseudonymize", dest="pseudonymize", action="store_true")
    add_flags.add_argument("--no-pseudonymize", dest="pseudonymize", action="store_false")
    add.set_defaults(pseudonymize=True)

    rotate = sub.add_parser("rotate", help="rotate tenant credentials")
    rotate.add_argument("--site-id", required=True)
    rotate.add_argument("--moodle-token-file")
    rotate.add_argument("--litellm-key-file")
    rotate.add_argument("--new-bearer", dest="rotate_auth", action="store_true")
    rotate.add_argument("--bearer-out")
    rotate_flags = rotate.add_mutually_exclusive_group()
    rotate_flags.add_argument("--pseudonymize", dest="pseudonymize", action="store_true")
    rotate_flags.add_argument("--no-pseudonymize", dest="pseudonymize", action="store_false")
    rotate.set_defaults(pseudonymize=None)

    disable = sub.add_parser("disable", help="disable a tenant")
    disable.add_argument("--site-id", required=True)

    enable = sub.add_parser("enable", help="enable a tenant")
    enable.add_argument("--site-id", required=True)

    listing = sub.add_parser("list", help="list tenants (metadata only)")
    listing.add_argument("--json", action="store_true")

    delete = sub.add_parser("delete", help="delete a tenant")
    delete.add_argument("--site-id", required=True)
    delete.add_argument("--yes", action="store_true")

    issue = sub.add_parser("issue-code", help="issue a one-time registration code")
    issue.add_argument("--site-id", required=True)
    issue.add_argument("--moodle-url", required=True)
    issue.add_argument("--ttl", default=None)
    issue.add_argument("--out", required=True)

    purge = sub.add_parser("purge-pseudonyms", help="delete expired pseudonym map rows")
    purge.add_argument("--site-id")

    return parser


def _metadata(tenant) -> dict[str, object]:
    return {
        "site_id": tenant.site_id,
        "moodle_url": tenant.moodle_url,
        "status": tenant.status,
        "has_litellm": tenant.litellm_ct is not None,
        "kek_id": tenant.kek_id,
        "pseudonymize": tenant.pseudonymize,
        "created_at": tenant.created_at,
        "updated_at": tenant.updated_at,
    }


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    db_path = os.environ.get("UBIONAI_HUB_DB")
    kek_path = os.environ.get("UBIONAI_HUB_KEK_FILE")
    if not db_path or not kek_path:
        parser.print_usage(sys.stderr)
        print("UBIONAI_HUB_DB and UBIONAI_HUB_KEK_FILE are required", file=sys.stderr)
        return 2

    try:
        kek = load_kek(kek_path)
        registry = Registry.open(db_path, kek)
    except (KekError, OSError, ValueError):
        print("cannot open registry", file=sys.stderr)
        return 1

    try:
        if args.command == "add":
            if os.path.exists(args.bearer_out):
                print("bearer output already exists", file=sys.stderr)
                return 1
            token = _read_secret(args.moodle_token_file)
            litellm = _read_secret(args.litellm_key_file) if args.litellm_key_file else None
            bearer = secrets.token_urlsafe(32)
            registry.add(args.site_id, args.moodle_url, token, litellm, bearer, args.pseudonymize)
            _write_once(args.bearer_out, bearer)
            print(f"added site={args.site_id}")
            return 0

        if args.command == "rotate":
            changed = False
            if args.moodle_token_file:
                registry.rotate_token(args.site_id, _read_secret(args.moodle_token_file))
                changed = True
            if args.litellm_key_file:
                registry.rotate_litellm(args.site_id, _read_secret(args.litellm_key_file))
                changed = True
            if args.pseudonymize is not None:
                registry.rotate_pseudonymize(args.site_id, args.pseudonymize)
                changed = True
            if args.rotate_auth:
                if not args.bearer_out:
                    print("--bearer-out is required with --new-bearer", file=sys.stderr)
                    return 1
                if os.path.exists(args.bearer_out):
                    print("bearer output already exists", file=sys.stderr)
                    return 1
                bearer = secrets.token_urlsafe(32)
                registry.rotate_bearer(args.site_id, bearer)
                _write_once(args.bearer_out, bearer)
                changed = True
            if not changed:
                print("nothing to rotate", file=sys.stderr)
                return 1
            print(f"rotated site={args.site_id}")
            return 0

        if args.command == "disable":
            registry.set_status(args.site_id, "disabled")
            print(f"disabled site={args.site_id}")
            return 0

        if args.command == "enable":
            registry.set_status(args.site_id, "active")
            print(f"enabled site={args.site_id}")
            return 0

        if args.command == "list":
            tenants = registry.list()
            if args.json:
                print(json.dumps([_metadata(tenant) for tenant in tenants]))
            else:
                for tenant in tenants:
                    meta = _metadata(tenant)
                    print(
                        f"{meta['site_id']}\t{meta['moodle_url']}\t{meta['status']}\t"
                        f"has_litellm={meta['has_litellm']}\tpseudonymize={meta['pseudonymize']}\t"
                        f"kek_id={meta['kek_id']}\tcreated_at={meta['created_at']}\t"
                        f"updated_at={meta['updated_at']}"
                    )
            return 0

        if args.command == "delete":
            if not args.yes:
                print("refusing to delete without --yes", file=sys.stderr)
                return 1
            registry.delete(args.site_id)
            stamp = datetime.now(timezone.utc).isoformat()
            print(f"deleted site={args.site_id} at={stamp}")
            return 0

        if args.command == "issue-code":
            if os.path.exists(args.out):
                print("output file already exists", file=sys.stderr)
                return 1
            ttl = _parse_ttl(args.ttl)
            code = registry.issue_code(args.site_id, args.moodle_url, ttl)
            _write_once(args.out, code)
            print(f"issued code for site={args.site_id}")
            return 0

        if args.command == "purge-pseudonyms":
            print(f"purged {registry.pmap_purge(args.site_id)}")
            return 0
    except (TenantError, OSError, ValueError, KekError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    parser.print_usage(sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
