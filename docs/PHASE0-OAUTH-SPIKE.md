# Phase 0 OAuth spike — superseded

The in-memory prototype (`oauth_spike.py`, stub Moodle login) was replaced by the tenant-wired
implementation in `src/moodle_mcp/oauth.py`, which delegates login to the real `local_ubionai`
plugin (0.6.0-spike2: `oauth/authorize.php`, `oauth/exchange.php`, `oauth/revoke.php`).

- Deploy / env / migration / rollback: `deploy/hub/SPIKE-OAUTH.md`
- Tests: `tests/test_oauth.py` (MCP SDK `OAuthClientProvider` against uvicorn on 127.0.0.1 with a fake plugin)
- Local E2E with a real Moodle: `scripts/e2e_moodle_oauth.py`
