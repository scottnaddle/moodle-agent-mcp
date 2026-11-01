# Phase 0 spike — minimal OAuth 2.1 AS/RS (do not merge, do not deploy)

Prototype for `DESIGN-easy-connect.md` §5.1. In-memory, separate from `server.create_app` (production path unchanged).

## Run (127.0.0.1 only)

```sh
PYTHONPATH=src .venv/bin/python -m moodle_mcp.oauth_spike --port 8799 --sites demo --stub-user 3
# MCP URL: http://127.0.0.1:8799/t/demo/mcp
```

- Default: built-in stub Moodle (`/_stub/moodle/authorize`) auto-approves as `--stub-user`.
- Real Moodle (untested sketch): `--moodle-authorize-url <moodle>/local/ubionai/oauth/authorize.php --moodle-exchange-url <moodle>/local/ubionai/oauth/exchange.php` with `OAUTH_SPIKE_DELEGATE_SECRET` in the environment.

## Endpoints

| Path | Spec |
|---|---|
| `POST /t/<site>/mcp` without/with bad token | 401 `WWW-Authenticate: Bearer resource_metadata="…", scope="moodle:read moodle:write"` (+ `error="invalid_token"`) |
| `GET /.well-known/oauth-protected-resource/t/<site>/mcp` | RFC 9728 PRM, `authorization_servers=["<base>/t/<site>"]` |
| `GET /.well-known/oauth-authorization-server/t/<site>`, `/.well-known/openid-configuration/t/<site>`, `/t/<site>/.well-known/openid-configuration` | RFC 8414 / OIDC, `issuer=<base>/t/<site>`, S256, `none`, CIMD flag, `iss` flag |
| `POST /t/<site>/oauth/register` | RFC 7591 DCR, redirect allowlist: claude.ai / claude.com callbacks + loopback (any port) |
| `GET /t/<site>/oauth/authorize` | PKCE S256 required, `resource` must equal `<base>/t/<site>/mcp`, redirect exact (loopback port-agnostic), CIMD for trusted `https://` client_ids |
| `GET /t/<site>/oauth/callback` | delegate returns `mcode` → back-channel exchange → code (60 s) + `iss` |
| `POST /t/<site>/oauth/token` | form only; `authorization_code`, `refresh_token` (rotation, reuse → family revoked), `resource` check |
| `POST /t/<site>/oauth/revoke` | RFC 7009 |

## Tests

`.venv/bin/python -m pytest tests/test_oauth_spike.py -s` — MCP SDK `OAuthClientProvider` E2E (DCR and CIMD), refresh on expiry, plus raw negative tests.
