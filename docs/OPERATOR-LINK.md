# Operator link: self-registration for an operator tenant (decision #4)

Contract decision #4 (2026-11-03, `REGISTRATION.md`): when a self-registering host collides with an
operator-created tenant the hub answers `409 site_managed_by_operator`; nothing is absorbed
automatically, the operator links the host by hand. This page specifies that manual link.

## Model

- An operator tenant (`origin=operator`, `auth_mode=legacy_file`, site token + static bearer) gains
  an optional **link approval**: `tenants.link_approved_at` (schema v7). `NULL` = not linked.
- `link-host` sets the tenant's `host_key` (the same `normalize_site_url` / `normalize_host_key`
  used for registration and `/m/` routing) and the approval. `unlink-host` removes the approval.
- Linking never changes `origin`, `tier`, `auth_mode`, the site token, the static bearer, the
  `oauth.secret` file or anything on `/t/<site_id>`. The legacy credentials stay authoritative for
  `/t/`.
- A linked tenant additionally accepts the shared-secret credential family (`site_credentials`,
  `sha256(site_secret)` + KEK-sealed `mac_key = HKDF-SHA256(site_secret, "ubionai-site-v1",
  "oauth-mac|<site_id>|v<n>")`) — used **only** for `/m/<host_key>/…`.

## CLI

```
moodle-hub-admin link-host   --site <site_id> --url <site_url>
moodle-hub-admin unlink-host --site <site_id>
```

`link-host`:

1. The tenant must exist and be `origin=operator` (self-registered tenants are refused: they are
   already self-managed).
2. `--url` is normalised (`UBIONAI_HUB_REG_ALLOWED_PORTS` applies). Invalid / IP literal / internal
   names are refused.
3. Another tenant already holding that `host_key` → refused (exit 1, names the other site_id).
4. The tenant already has a *different* `host_key` → refused (the operator must fix the tenant;
   silently re-routing `/m/` would orphan its grants).
5. `--url` whose host_key differs from the tenant's `moodle_url` host_key → allowed with a warning
   (e.g. an internal `moodle_url`); OAuth redirects still go to `moodle_url`.
6. Sets `host_key`, `link_approved_at = now`. Idempotent (re-link keeps the first approval time).

`unlink-host`:

1. Clears `link_approved_at` (`host_key` is kept: `/m/` falls back to the operator's legacy signer,
   if any, exactly as before linking).
2. Deletes the tenant's `site_credentials` (the plugin's `site_secret` / `mac_key` stop working at
   once) and revokes teacher grants issued on `/m/<host_key>/mcp` (`/t/` grants untouched). This
   is hub-side only (the CLI is offline): the teachers' Moodle `ubionai_user` tokens are not
   revoked in Moodle; the site administrator can remove them there.
3. Re-registration from that host is `409 site_managed_by_operator` again.

Both commands write one row to `operator_link_audit` (site_id, host_key, action, OS user, time) and
print/log a line. No secret is read, written or printed.

## Registration of a linked host

`POST /api/v1/sites/register` runs policy, rate limits and the callback verification unchanged.
Then, for a host whose tenant is an operator tenant:

| Tenant state | Result |
|---|---|
| not linked | `409 site_managed_by_operator` (unchanged) |
| linked, `UBIONAI_HUB_HOST_ROUTES=0` | `409 site_managed_by_operator` (nothing to route to) |
| linked, `status=disabled` | `403 host_blocked` |
| linked, > 3 registrations / 24 h | `429 rate_limited` (status is **not** changed: the operator tenant keeps serving `/t/`) |
| linked | `200`, same tenant, new pending shared secret (`site_key` = operator `site_id`); audit outcome `linked` |

The `200` body is the normal register result with `tenant.tier = standard` (operator tiers are not
limited), `mcp_url = /m/<host_key>/mcp`, `legacy_mcp_url = null` and `oauth.issuers` /
`allowed_callbacks` listing only `/m/<host_key>` (the `/t/` family keeps the legacy file secret).
`grants_kept`: `true` on the first registration (no site identity recorded yet, the operator vouched
for the link) and when `site_identifier_hash` matches; otherwise `/m/` grants are revoked (never
`/t/` grants) and it is `false`. `confirm`, `rotate` and `status` work for linked tenants as for
self-registered ones (`status` → `legacy_mcp_url: null`).

## Signer selection on `/m/`

For a linked tenant with a `current` shared-secret credential, OAuth messages on `/m/<host_key>`
(authorize request, exchange, revoke) are signed with that `mac_key` (`kv` claim). Before the first
confirm, or after unlink, `/m/` uses the legacy signer as before. `/t/` always uses the legacy
signer. Hub → Moodle traffic of an operator tenant uses the normal (operator-trusted) transport.

## Unknown hosts on `/m/` (behaviour change)

`/m/<host_key>/…`, `/.well-known/oauth-protected-resource/m/<host_key>/…`,
`/.well-known/oauth-authorization-server/m/<host_key>` and `/.well-known/openid-configuration/m/…`
answer `404 {"error":"not found"}` when **no tenant** has that host_key (canonical or not); a
browser `GET …/oauth/authorize` keeps the static "ask your administrator" HTML page, which is also
`404`. This
replaces the static surface (401 + metadata, stateless DCR, "ask your administrator" page) for
unknown hosts: an arbitrary host no longer gets an OAuth face. Hosts with a tenant row (active,
pending, unconfirmed or disabled; self-registered or operator) behave as before (200 metadata / 401
/ pages). Consequence: a client cannot pre-register (stateless DCR) before the site registers; it
adds the connector after the site administrator finishes registration.

## Schema v7

Idempotent on every open: `ALTER TABLE tenants ADD COLUMN link_approved_at INTEGER` when missing,
`CREATE TABLE IF NOT EXISTS operator_link_audit (...)`, `meta.schema_version = 7`.
