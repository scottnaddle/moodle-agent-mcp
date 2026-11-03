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
   token, no static bearer (enforced by a DB CHECK). Known self-registered host → re-registration
   (same tenant, grants kept, new pending secret; the current secret keeps working until confirm).
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

For a host that is not registered (or pending/disabled, or not yet confirmed), `/m/` answers
statically: `401` + `resource_metadata`, PRM/AS metadata, stateless DCR (`dcr_s1.` client ids,
MACed with a KEK-derived key, nothing stored) and an "ask your Moodle administrator" page on
`/oauth/authorize` (escaped host only, strict CSP, no-store, KO/EN, 60/min per IP). Non-canonical
URLs get `400 non_canonical_url` with `canonical_url`.

## Settings

| Variable | Default |
|---|---|
| `UBIONAI_HUB_SELF_REGISTRATION` | `0` |
| `UBIONAI_HUB_HOST_ROUTES` | `0` |
| `UBIONAI_HUB_LEGACY_TENANT_ROUTES` | `1` |
| `UBIONAI_HUB_REG_DEFAULT_TIER` | `limited` (anything else refuses to start) |
| `UBIONAI_HUB_REG_AUTO_ACTIVATE` | `1` (`0` → new tenants `pending`) |
| `UBIONAI_HUB_REG_ALLOWED_PORTS` | `443` |
| `UBIONAI_HUB_REG_DENY_CIDRS` | empty (added to the built-in private/metadata deny list) |
| `UBIONAI_HUB_REG_BLOCKED_HOSTS` | empty (host or host_key list → `403 host_blocked`) |
| `UBIONAI_HUB_REG_MIN_PLUGIN_VERSION` | `2026110300` |
| `UBIONAI_HUB_REG_MIN_TERMS_VERSION` | `2026-11-01` |
| `UBIONAI_HUB_TRUSTED_PROXIES` | empty (only then is `X-Forwarded-For` used for rate limits) |
| `UBIONAI_HUB_PUBLIC_KEYS_FILE` | empty |

`UBIONAI_HUB_PUBLIC_URL` is required when self-registration or host routes are on.
Rate limits are in-process (single uvicorn worker assumed).

## Security notes

- Every hub → Moodle connection of a self-registered tenant (OAuth exchange/revoke, token check,
  MCP tool calls) goes through `PinnedPublicTransport`: re-resolved and re-vetted per request, so a
  site whose DNS later points at `169.254.169.254` or a private range simply fails.
- Self-registration never grants course creation or any site-level Moodle token; teachers still
  connect with their own `ubionai_user` token, checked against the hub's function whitelist.
- Development: a single-worker `php -S` Moodle deadlocks (the registration request waits for the
  callback request). Use a multi-worker web server.
