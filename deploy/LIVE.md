
## Live: moodle-mcp:p0 (2026-10-31 swap)
Source: /workspace/moodle-mcp on Grok Bot box (local git). Image `moodle-mcp:p0` (Python, mcp SDK, Streamable HTTP, 14 tools).
Endpoint: https://mcp.example.com/mcp, header `Authorization: Bearer <MCP_BEARER_TOKEN>`. `/health` is open.

Run / update:
    # build from source tarball: docker build -t moodle-mcp:p0 <src-dir>
    cd /opt/moodle-mcp && docker compose up -d
    curl -s http://127.0.0.1:8791/health

Rollback to placeholder:
    cd /opt/moodle-mcp && cp -p docker-compose.yml.bak-20261031-placeholder docker-compose.yml && docker compose up -d
