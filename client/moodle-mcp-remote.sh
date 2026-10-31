#!/usr/bin/env bash
# stdio wrapper: lets Grok Bot (or any stdio MCP client) talk to the remote Moodle MCP server via mcp-remote.
# The bearer token is read from a mode-600 file and passed through an env var, never on the command line,
# so it does not show up in `ps` output.
#   MCP_URL=https://mcp.example.com/mcp MCP_TOKEN_FILE=~/.config/moodle-mcp/token ./moodle-mcp-remote.sh
set -euo pipefail
MCP_URL="${MCP_URL:-https://mcp.example.com/mcp}"
MCP_TOKEN_FILE="${MCP_TOKEN_FILE:-$HOME/.config/moodle-mcp/token}"
if [ ! -r "$MCP_TOKEN_FILE" ]; then echo "token file not readable: $MCP_TOKEN_FILE" >&2; exit 1; fi
perm=$(stat -c %a "$MCP_TOKEN_FILE" 2>/dev/null || stat -f %Lp "$MCP_TOKEN_FILE")
if [ "$perm" != "600" ] && [ "$perm" != "400" ]; then echo "refusing: $MCP_TOKEN_FILE must be chmod 600 (is $perm)" >&2; exit 1; fi
AUTH_HEADER="Bearer $(tr -d '\r\n' < "$MCP_TOKEN_FILE")"
export AUTH_HEADER
# mcp-remote expands ${AUTH_HEADER} itself; the literal string below is what appears in argv.
exec npx -y mcp-remote@latest "$MCP_URL" --transport http-only --header 'Authorization:${AUTH_HEADER}'
