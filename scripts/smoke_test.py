#!/usr/bin/env python3
"""Smoke test for a deployed Moodle MCP server.

Usage:
  MCP_URL=https://mcp.example.com/mcp MCP_BEARER_TOKEN_FILE=~/.config/moodle-mcp/token \
      python3 scripts/smoke_test.py [--write]

Read-only by default. --write also creates a throwaway course "MCP-SMOKE-<ts>" with a section and a page
(delete it afterwards). Requires: pip install "mcp>=1.26,<2".
"""
import asyncio, json, os, sys, time
from pathlib import Path
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

URL = os.environ.get("MCP_URL", "http://127.0.0.1:8791/mcp")
tf = os.environ.get("MCP_BEARER_TOKEN_FILE")
TOKEN = Path(os.path.expanduser(tf)).read_text().strip() if tf else os.environ.get("MCP_BEARER_TOKEN", "")
WRITE = "--write" in sys.argv
ok = fail = 0


def data(res):
    txt = "".join(getattr(c, "text", "") for c in res.content)
    try:
        return json.loads(txt)
    except Exception:
        return txt


async def step(s, name, tool, args, check=lambda d: not (isinstance(d, dict) and d.get("error")), expect_fail=False):
    global ok, fail
    try:
        r = await s.call_tool(tool, args)
        d = data(r)
        good = (not r.isError) and check(d)
    except Exception as e:  # noqa: BLE001
        d, good = str(e), False
    if expect_fail:
        good = not good
    ok += good; fail += not good
    print(f"[{'PASS' if good else 'FAIL'}] {name}: {str(d)[:160]}")
    return d


async def main():
    global ok, fail
    async with streamablehttp_client(URL, headers={"Authorization": f"Bearer {TOKEN}"}) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = (await s.list_tools()).tools
            n = len(tools); good = n == 39; ok += good; fail += not good
            print(f"[{'PASS' if good else 'FAIL'}] list_tools: {n} tools")
            await step(s, "site_info", "site_info", {}, lambda d: "release" in str(d))
            await step(s, "list_categories", "list_categories", {})
            await step(s, "list_courses", "list_courses", {})
            if WRITE:
                sn = f"MCP-SMOKE-{int(time.time())}"
                await step(s, "create_course preview", "create_course", {"fullname": sn, "shortname": sn, "confirm": False})
                d = await step(s, "create_course", "create_course", {"fullname": sn, "shortname": sn, "numsections": 1, "confirm": True})
                cid = d.get("courseid") if isinstance(d, dict) else None
                if isinstance(d, dict) and d.get("enrol_error"):
                    fail += 1; print("[FAIL] bot enrolment as editingteacher:", d["enrol_error"][:120])
                if cid:
                    await step(s, "get_course_outline", "get_course_outline", {"course_id": cid})
                    await step(s, "add_sections (local_grokbot)", "add_sections", {"course_id": cid, "names": ["Smoke"], "confirm": True})
                    await step(s, "create_page (local_grokbot)", "create_page", {"course_id": cid, "section": 1, "name": "Hello", "content_html": "<p>hi</p>", "confirm": True})
                    await step(s, "create_assignment", "create_assignment", {"course_id": cid, "section": 1, "name": "Task", "confirm": True})
                    await step(s, "list_assignments", "list_assignments", {"course_ids": [cid]})
                    await step(s, "list_students", "list_students", {"course_id": cid})
    print(f"\n{ok} passed, {fail} failed")
    sys.exit(1 if fail else 0)


asyncio.run(main())
