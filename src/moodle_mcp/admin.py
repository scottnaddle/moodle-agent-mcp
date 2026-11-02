"""Administrative CLI for the multi-tenant hub registry."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import os
import re
import secrets
import stat
import sys
import time
from datetime import datetime, timezone

from . import oauth
from .crypto import KekError, load_kek
from .registry import (
    ASSIGNMENT_TITLE_HEURISTICS,
    OAuthClientInfo,
    OAuthGrantInfo,
    Registry,
    Tenant,
    TenantError,
)


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
    parser = argparse.ArgumentParser(
        prog="moodle-hub-admin",
        epilog="oauth-revoke: default is dry-run; pass --yes to apply the changes.",
    )
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
    rotate.add_argument(
        "--assignment-title-heuristic", choices=ASSIGNMENT_TITLE_HEURISTICS
    )

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

    oauth_list = sub.add_parser(
        "oauth-list", help="list a tenant's OAuth clients and grants (metadata only)"
    )
    oauth_list.add_argument("--site-id", required=True)
    oauth_list.add_argument("--json", action="store_true")
    oauth_list.add_argument("--include-revoked", action="store_true")

    oauth_revoke = sub.add_parser(
        "oauth-revoke",
        help="revoke a tenant's OAuth grants and delete clients (default is dry-run)",
    )
    oauth_revoke.add_argument("--site-id", required=True)
    target = oauth_revoke.add_mutually_exclusive_group(required=True)
    target.add_argument("--client-id", help="target one OAuth client")
    target.add_argument("--grant-id", help="target one teacher grant")
    target.add_argument("--user-id", type=int, help="target every grant of one teacher")
    target.add_argument("--all", action="store_true", help="target every grant and client")
    oauth_revoke.add_argument(
        "--delete-client", action="store_true", help="also delete the targeted client(s)"
    )
    mode = oauth_revoke.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="explicit dry-run (the default)")
    mode.add_argument("--yes", action="store_true", help="apply the changes (not a dry-run)")
    oauth_revoke.add_argument(
        "--skip-moodle", action="store_true", help="do not ask Moodle to revoke the tokens"
    )

    return parser


def _metadata(tenant) -> dict[str, object]:
    return {
        "site_id": tenant.site_id,
        "moodle_url": tenant.moodle_url,
        "status": tenant.status,
        "has_litellm": tenant.litellm_ct is not None,
        "kek_id": tenant.kek_id,
        "pseudonymize": tenant.pseudonymize,
        "assignment_title_heuristic": tenant.assignment_title_heuristic,
        "created_at": tenant.created_at,
        "updated_at": tenant.updated_at,
    }


# --- OAuth (per-tenant clients and teacher grants) -----------------------------------------
# Only public metadata is ever printed: no access/refresh token, no sealed Moodle token,
# no token hash and no shared secret.


def _client_meta(info: OAuthClientInfo) -> dict[str, object]:
    return {
        "client_id": info.client_id,
        "source": info.source,
        "client_name": info.client_name,
        "created_at": info.created_at,
        "active_grants": info.active_grants,
    }


def _grant_meta(info: OAuthGrantInfo) -> dict[str, object]:
    return {
        "grant_id": info.grant_id,
        "moodle_userid": info.moodle_userid,
        "client_id": info.client_id,
        "scope": info.scope,
        "created_at": info.created_at,
        "valid_until": info.valid_until,
        "revoked_at": info.revoked_at,
        "live_tokens": info.live_tokens,
    }


async def _moodle_revoke(
    tenant: Tenant, secret: bytes, issuer: str, userid: int, tokenid: int
) -> bool:
    """Ask the tenant's Moodle plugin to revoke one teacher token (back channel)."""
    return await oauth.revoke_moodle_token(tenant, secret, issuer, userid, tokenid)


def _oauth_list(
    registry: Registry, site_id: str, as_json: bool, include_revoked: bool
) -> int:
    clients = registry.oauth_clients(site_id)
    grants = registry.oauth_grants(site_id, include_revoked=include_revoked)
    if as_json:
        print(
            json.dumps(
                {
                    "site_id": site_id,
                    "clients": [_client_meta(client) for client in clients],
                    "grants": [_grant_meta(grant) for grant in grants],
                }
            )
        )
        return 0
    print(f"site={site_id}")
    print("clients:")
    if not clients:
        print("  (none)")
    for client in clients:
        print(
            f"  client_id={client.client_id} source={client.source} "
            f"client_name={client.client_name or '-'} created_at={client.created_at} "
            f"active_grants={client.active_grants}"
        )
    print("grants:")
    if not grants:
        print("  (none)")
    for grant in grants:
        revoked_at = "-" if grant.revoked_at is None else grant.revoked_at
        print(
            f"  grant_id={grant.grant_id} moodle_userid={grant.moodle_userid} "
            f"client_id={grant.client_id} scope={grant.scope} created_at={grant.created_at} "
            f"valid_until={grant.valid_until} revoked_at={revoked_at} "
            f"live_tokens={grant.live_tokens}"
        )
    return 0


def _oauth_targets(
    registry: Registry, site_id: str, args
) -> tuple[list[OAuthGrantInfo], list[str]]:
    """Active grants to revoke and clients to delete for the given target selection."""
    if args.all:
        grants = registry.oauth_grants(site_id)
        return grants, [client.client_id for client in registry.oauth_clients(site_id)]
    if args.client_id:
        grants = registry.oauth_grants(site_id, client_id=args.client_id)
        return grants, [args.client_id] if args.delete_client else []
    if args.grant_id:
        grants = registry.oauth_grants(site_id, grant_id=args.grant_id)
        clients = sorted({grant.client_id for grant in grants})
        return grants, clients if args.delete_client else []
    grants = registry.oauth_grants(site_id, moodle_userid=args.user_id)
    clients = sorted({grant.client_id for grant in grants})
    return grants, clients if args.delete_client else []


def _oauth_revoke(registry: Registry, site_id: str, args) -> int:
    tenant = registry.get(site_id)
    if tenant is None:
        print("error: site not found", file=sys.stderr)
        return 1
    grants, clients = _oauth_targets(registry, site_id, args)

    if not args.yes:
        for grant in grants:
            print(
                f"DRY-RUN would revoke grant={grant.grant_id} "
                f"userid={grant.moodle_userid} client={grant.client_id}"
            )
        for client_id in clients:
            print(f"DRY-RUN would delete client={client_id}")
        print(f"grants={len(grants)} clients={len(clients)}")
        return 0

    changed = registry.oauth_revoke_grants(
        site_id, [grant.grant_id for grant in grants], int(time.time())
    )
    revoked = {grant.grant_id for grant in grants} & set(changed)

    issuer = None
    public_url = (os.environ.get("UBIONAI_HUB_PUBLIC_URL") or "").strip()
    if public_url:
        try:
            issuer = f"{oauth.validate_public_url(public_url)}/t/{site_id}"
        except oauth.OAuthConfigError:
            issuer = None
    secrets_dir = (os.environ.get("UBIONAI_HUB_TENANT_SECRETS_DIR") or "").strip()
    secret = oauth.load_tenant_secret(secrets_dir, site_id) if secrets_dir else None

    partial = False
    for grant in grants:
        if grant.grant_id not in revoked:
            continue
        if args.skip_moodle or secret is None or issuer is None:
            partial = True
            print(
                f"warning: moodle token not revoked grant={grant.grant_id} "
                f"(expires {grant.valid_until})",
                file=sys.stderr,
            )
            print(f"revoked grant={grant.grant_id} moodle=skipped")
            continue
        ok = asyncio.run(
            _moodle_revoke(
                tenant, secret, issuer, grant.moodle_userid, grant.moodle_tokenid
            )
        )
        if not ok:
            partial = True
        print(f"revoked grant={grant.grant_id} moodle={'ok' if ok else 'failed'}")

    if clients:
        registry.oauth_delete_clients(site_id, clients)
        for client_id in clients:
            print(f"deleted client={client_id}")

    return 3 if partial else 0


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
            if args.assignment_title_heuristic is not None:
                registry.set_assignment_title_heuristic(
                    args.site_id, args.assignment_title_heuristic
                )
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

        if args.command == "oauth-list":
            if registry.get(args.site_id) is None:
                print("error: site not found", file=sys.stderr)
                return 1
            return _oauth_list(
                registry, args.site_id, args.json, args.include_revoked
            )

        if args.command == "oauth-revoke":
            return _oauth_revoke(registry, args.site_id, args)
    except (TenantError, OSError, ValueError, KekError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    parser.print_usage(sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
