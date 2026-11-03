# Site self-registration (contract v1, shared secret)

Design: `../registration-contract-2026-11-03.md` (option 1). This page is the operator/developer
summary of what the hub implements.

## Flow

1. `local_ubionai` (after the site admin consents) calls `POST /api/v1/sites/register` with the
   wwwroot, plugin/Moodle versions, consent record, a fresh `callback_nonce` and
   `challenge_sha256`. Never a Moodle token (`wstoken`/`token`/`password` keys → 400).
2. The hub normalises `site_url` to a `host_key` (same function as `/m/` routing), applies policy
   (https, port allowlist, no IP literals / internal names, blocklist, minimum plugin and terms
   versions, consent), rate limits, then calls
   `GET {wwwroot}/local/ubionai/register_callback.php?nonce=…`:
   one DNS resolution, every address public, TCP pinned to the vetted IP (SNI/Host keep the name),
   no redirects, no env proxies, 3 s connect / 5 s total, 8 KiB.
3. The callback must echo the nonce, a `challenge` whose SHA-256 equals `challenge_sha256`, the
   same wwwroot (normalised) and plugin version.
4. New host → tenant `origin=self_registered`, `tier=limited`, `auth_mode=shared_secret`, no site
   token, no static bearer (enforced by a DB CHECK), `status=active` at once. Known self-registered
   host → re-registration (same tenant, new pending secret; the current secret keeps working until
   confirm). Teacher grants are kept only when `site_identifier_hash` equals the recorded one
   (same Moodle); otherwise every grant and its hub tokens are revoked. The `200` response carries
   `grants_kept: true|false`. A host that belongs to an operator-created tenant → `409
   site_managed_by_operator`; nothing is absorbed automatically. The operator may link it by hand
   (`moodle-hub-admin link-host`, [OPERATOR-LINK.md](OPERATOR-LINK.md)): a linked host's
   registration (callback still verified) reuses the operator tenant (`200`, `site_key` = its
   site_id) and gets a shared secret for `/m/<host_key>` only; `/t/`, the site token, the static
   bearer and `oauth.secret` are untouched.
5. The response carries `site_secret` once (`201` new, `200` re-registration). The plugin stores it
   encrypted and calls `POST /api/v1/sites/{site_key}/confirm` with it as Bearer → `current`.
   `rotate` (Bearer = current secret) issues a new pending secret; `status` reports.

The hub stores `sha256(site_secret)` (API authentication) and
`mac_key = HKDF-SHA256(ikm=site_secret as transmitted, salt="ubionai-site-v1",
info="oauth-mac|<site_key>|v<n>")` sealed with the KEK (OAuth message signing, claim `kv`).
`tests/vectors/registration-v1.json` holds fake interop vectors for the plugin's PHPUnit tests.

## Routes

| Path | Notes |
|---|---|
| `POST /api/v1/sites/register` | `UBIONAI_HUB_SELF_REGISTRATION=1`, else `503 registration_disabled` |
| `POST /api/v1/sites/{site_key}/confirm` · `/rotate`, `GET …/status` | Bearer site secret |
| `GET /.well-known/ubionai-hub.json` · `/.well-known/ubionai-hub-keys.json` | keys: `[]` unless `UBIONAI_HUB_PUBLIC_KEYS_FILE` lists public Ed25519 JWKs (option 2; no key generation) |
| `/m/<host_key>/mcp`, `/m/<host_key>/oauth/*`, `/.well-known/…/m/<host_key>` | `UBIONAI_HUB_HOST_ROUTES=1`, else 404. OAuth only |
| `/t/<site_key>/mcp` | legacy family; self-registered tenants use OAuth here too (`UBIONAI_HUB_LEGACY_TENANT_ROUTES=0` hides them) |

For a host that **no tenant** holds (neither self-registered nor an operator tenant with that
host_key), every `/m/<host_key>/…` and `/.well-known/…/m/<host_key>…` path answers
`404 {"error":"not found"}` (canonical or not), except a browser `GET …/oauth/authorize`, which gets
the static "ask your Moodle administrator" page — also `404` (escaped host only, strict CSP,
no-store, KO/EN, 60/min per IP). Nothing is fetched or stored for such hosts.

For a known host that is pending/disabled or not yet confirmed (no signer), `/m/` answers
statically: `401` + `resource_metadata`, PRM/AS metadata, stateless DCR (`dcr_s1.` client ids,
MACed with a KEK-derived key, nothing stored) and the pending/disabled page on `/oauth/authorize`.
Non-canonical URLs of a known host get `400 non_canonical_url` with `canonical_url`. Clients
therefore add the connector after the site has registered (earlier, the URL is a 404).

## Decisions of 2026-11-03 (Scott, contract §8.3)

| # | Decision | Where |
|---|---|---|
| 1 | New sites active at once, lowest tier (`limited`). Operator switches: `UBIONAI_HUB_REG_AUTO_ACTIVATE=0` (new sites `pending`), `moodle-hub-admin disable --site-id <key>` or `--host <host_key>` per site (re-registration cannot re-enable: `403 host_blocked`) | `registration.py`, `admin.py` |
| 2 | Provisional limits from configuration: 5 teachers, 200 requests/day | `limits.py`, `oauth.py`, `server.py` |
| 3 | Re-registration keeps grants only for the same site (`site_identifier_hash`), else revokes all | `registration.py`, `Registry.revoke_grants` |
| 4 | Host collision with an operator tenant → `409`; linking is manual: `moodle-hub-admin link-host --site <id> --url <wwwroot>` / `unlink-host --site <id>` ([OPERATOR-LINK.md](OPERATOR-LINK.md)) | `registration.py`, `admin.py`, `Registry.link_host` |
| 5 | HKDF / hash design unchanged; tests assert that `site_secret`, `mac_key` and tokens never reach logs | `tests/test_reg_decisions.py` |

## Operator link (decision #4)

```sh
moodle-hub-admin link-host   --site school-op --url https://lms.school.ac.kr/moodle
moodle-hub-admin unlink-host --site school-op
moodle-hub-admin list --json   # "linked": true|false
```

- `link-host`: operator tenants only; the host_key (same normalisation as registration) must not
  belong to another tenant, and a tenant already routed under a different host_key is refused.
  Idempotent. Warns when `--url` differs from the tenant's `moodle_url` (OAuth still redirects to
  `moodle_url`).
- Linked + `UBIONAI_HUB_HOST_ROUTES=1` → registration `200` with `tier=standard`,
  `legacy_mcp_url: null`, `oauth.issuers` = `/m/<host_key>` only. Not linked, or host routes off →
  `409 site_managed_by_operator`. Disabled → `403 host_blocked`. More than 3 registrations in 24 h →
  `429` (the operator tenant's status is never changed).
- `grants_kept`: true on the first linked registration and for the same `site_identifier_hash`;
  a different Moodle revokes `/m/` grants only.
- `unlink-host`: deletes the shared-secret credentials, revokes `/m/` grants (hub side; Moodle user
  tokens are not contacted), keeps `host_key`; registration is `409` again.
- Every link/unlink → `operator_link_audit` row (site_id, host_key, action, OS user, time) + a
  WARNING log line. No secrets. Schema v7 (`tenants.link_approved_at`), applied idempotently at open.

## Limits (`tier=limited`)

| Limit | Setting (default) | Enforcement |
|---|---|---|
| Teachers per site | `UBIONAI_HUB_LIMITED_MAX_TEACHERS` (`5`) | Distinct Moodle users with a live grant. A new teacher beyond the limit gets no grant: the OAuth callback redirects to the client with `error=access_denied&error_description=teacher_limit_reached` (the just-issued Moodle token is revoked); the token endpoint re-checks (`400 invalid_grant`, `teacher_limit_reached`). Teachers already connected keep working and may reconnect. |
| Requests per day | `UBIONAI_HUB_LIMITED_DAILY_REQUESTS` (`200`) | Authenticated MCP HTTP requests (`/m/…/mcp`, `/t/…/mcp`) per tenant per UTC day, counted in sqlite (`usage_daily`, survives restarts). Beyond it: `429 {"error":"daily_limit_exceeded","error_description":…,"retry_after":<s to 00:00 UTC>}` + `Retry-After`. |

Values must be positive integers (otherwise the hub refuses to start). They are reported in
`tenant.limits` of the register/rotate responses and in `status`
(`{"max_teachers", "daily_requests", "concurrency", "llm_proxy"}`; `concurrency` is advertised but
not enforced yet). Operator tenants (`tier=standard`) are not limited.

## Settings

| Variable | Default |
|---|---|
| `UBIONAI_HUB_SELF_REGISTRATION` | `0` |
| `UBIONAI_HUB_HOST_ROUTES` | `0` |
| `UBIONAI_HUB_LEGACY_TENANT_ROUTES` | `1` |
| `UBIONAI_HUB_REG_DEFAULT_TIER` | `limited` (anything else refuses to start) |
| `UBIONAI_HUB_REG_AUTO_ACTIVATE` | `1` (`0` → new tenants `pending`) |
| `UBIONAI_HUB_LIMITED_MAX_TEACHERS` | `5` (provisional) |
| `UBIONAI_HUB_LIMITED_DAILY_REQUESTS` | `200` (provisional) |
| `UBIONAI_HUB_REG_ALLOWED_PORTS` | `443` |
| `UBIONAI_HUB_REG_DENY_CIDRS` | empty (added to the built-in private/metadata deny list) |
| `UBIONAI_HUB_REG_BLOCKED_HOSTS` | empty (host or host_key list → `403 host_blocked`) |
| `UBIONAI_HUB_REG_MIN_PLUGIN_VERSION` | `2026110300` |
| `UBIONAI_HUB_REG_MIN_TERMS_VERSION` | `2026-11-01` |
| `UBIONAI_HUB_TRUSTED_PROXIES` | empty (only then is `X-Forwarded-For` used for rate limits) |
| `UBIONAI_HUB_PUBLIC_KEYS_FILE` | empty |
| `UBIONAI_HUB_SELF_ADDRESSES` | empty (hub origin IPs, comma-separated; when set, only these + `UBIONAI_HUB_EGRESS_IP` are blocked as "self" and the public URL is not resolved) |
| `UBIONAI_HUB_SELF_VET_DNS` | `1` (`0` → do not resolve the public URL for self-vetting) |

`UBIONAI_HUB_PUBLIC_URL` is required when self-registration or host routes are on.
Rate limits are in-process (single uvicorn worker assumed).

Self-vetting: by default the hub resolves the host of `UBIONAI_HUB_PUBLIC_URL` and refuses
callbacks to those addresses (and to `UBIONAI_HUB_EGRESS_IP`). Behind a CDN/proxy (e.g. Cloudflare)
that host resolves to shared anycast IPs, which would refuse every Moodle site behind the same CDN
with `403 private_address_not_supported`. There, set `UBIONAI_HUB_SELF_ADDRESSES` to the real
origin IPs (or `UBIONAI_HUB_SELF_VET_DNS=0` if egress IPs cover it). Refusals caused by a self
address are logged as `reason=self_address` (others `reason=non_public`).

## Security notes

- Every hub → Moodle connection of a self-registered tenant (OAuth exchange/revoke, token check,
  MCP tool calls) goes through `PinnedPublicTransport`: re-resolved and re-vetted per request, so a
  site whose DNS later points at `169.254.169.254` or a private range simply fails.
- Secrets: the hub logs site keys, host keys, user ids and outcomes, never `site_secret`, the
  derived `mac_key`, hub access/refresh tokens or teacher Moodle tokens
  (`test_site_secret_and_mac_key_never_logged` exercises register, confirm, rotate, status, OAuth,
  both limits and a revoking re-registration with DEBUG logging).
- Self-registration never grants course creation or any site-level Moodle token; teachers still
  connect with their own `ubionai_user` token, checked against the hub's function whitelist.
- Development: a single-worker `php -S` Moodle deadlocks (the registration request waits for the
  callback request). Use a multi-worker web server.
