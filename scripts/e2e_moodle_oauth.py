"""Local E2E: hub OAuth + real Moodle (local_ubionai 0.6.0-spike2) + official MCP SDK OAuth client.

Runs the hub in-process on 127.0.0.1 with a throwaway registry and KEK, logs in to Moodle as a
real browser would (login form, consent form with sesskey), and drives the SDK through
discovery -> DCR -> PKCE -> Moodle consent -> token -> tools. Never prints secrets.

Environment (all local, fake data only):
  E2E_MOODLE_URL       e.g. http://127.0.0.1:8081 (Moodle wwwroot)
  E2E_SITE             hub site id configured in the plugin (local_ubionai/hub_site_id)
  E2E_SECRET_FILE      file with the shared secret configured in the plugin (local_ubionai/oauth_secret)
  E2E_HUB_PORT         hub port; the plugin's local_ubionai/hub_url must be http://127.0.0.1:<port>
  E2E_TEACHER_USER / E2E_TEACHER_PW_FILE   a teacher account (editing teacher in a course)
  E2E_ADMIN_USER / E2E_ADMIN_PW_FILE       a site administrator account (must be refused)
  E2E_COURSE_ID        a course of the teacher (expected in list_courses)

Run: PYTHONPATH=src .venv/bin/python scripts/e2e_moodle_oauth.py
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import secrets
import shutil
import sys
import tempfile
import threading
import time
from html import unescape
from urllib.parse import parse_qs, urljoin, urlsplit

import logging

import httpx
import uvicorn
from mcp import ClientSession
from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import OAuthClientMetadata
from pydantic import AnyUrl

from moodle_mcp.oauth import USER_SERVICE_FUNCTIONS

REDIRECT = "http://127.0.0.1:53682/callback"
logging.basicConfig(level=logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read().strip()


class MemStorage(TokenStorage):
    def __init__(self):
        self.tokens = None
        self.client = None

    async def get_tokens(self):
        return self.tokens

    async def set_tokens(self, tokens):
        self.tokens = tokens

    async def get_client_info(self):
        return self.client

    async def set_client_info(self, client_info):
        self.client = client_info


class MoodleBrowser:
    """Cookie-keeping browser: Moodle login form, consent form, redirects back to the client."""

    def __init__(self, moodle: str, username: str, password: str):
        self.moodle, self.username, self.password = moodle, username, password
        self.http = httpx.AsyncClient(follow_redirects=False, timeout=30)
        self.result: dict[str, str] = {}
        self.error_page = ""
        self.steps: list[str] = []

    async def login(self) -> None:
        page = await self.http.get(f"{self.moodle}/login/index.php")
        token = re.search(r'name="logintoken" value="([^"]+)"', page.text)
        resp = await self.http.post(
            f"{self.moodle}/login/index.php",
            data={"username": self.username, "password": self.password, "logintoken": token.group(1) if token else ""},
        )
        if resp.status_code != 303 or "testsession" not in resp.headers.get("location", ""):
            raise RuntimeError(f"Moodle login failed for {self.username}")
        await self.http.get(resp.headers["location"])

    def _log(self, method: str, url: str) -> None:
        parts = urlsplit(url)
        query = re.sub(r"\b(code|req|state|code_challenge)=[^&]*", r"\1=***", parts.query)
        self.steps.append(f"{method} {parts.netloc}{parts.path}" + (f"?{query[:80]}" if query else ""))

    async def redirect(self, url: str) -> None:
        method, data = "GET", None
        for _ in range(12):
            if url.startswith(REDIRECT):
                self.result = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
                return
            self._log(method, url)
            resp = await (self.http.post(url, data=data) if method == "POST" else self.http.get(url))
            method, data = "GET", None
            if resp.status_code in (301, 302, 303):
                url = urljoin(url, resp.headers["location"])
                continue
            text = resp.text
            if 'name="approve"' in text:
                sesskey = re.search(r'name="sesskey" value="([^"]+)"', text).group(1)
                action = unescape(re.search(r'<form method="post" action="([^"]+)"', text).group(1))
                consent = re.sub(r"<[^>]+>", " ", text.split("<table", 1)[1].split("</table>", 1)[0])
                self.steps.append("consent page: " + " ".join(consent.split())[:300])
                method, data, url = "POST", {"sesskey": sesskey, "approve": "Allow"}, action
                continue
            self.error_page = " ".join(re.sub(r"<[^>]+>", " ", text).split())
            return
        raise RuntimeError("too many redirects")

    async def callback(self):
        if "code" not in self.result:
            raise RuntimeError(f"no authorization code: {self.result or 'stopped in Moodle'}")
        return self.result["code"], self.result.get("state")


def _provider(server_url: str, storage: MemStorage, browser: MoodleBrowser) -> OAuthClientProvider:
    return OAuthClientProvider(
        server_url=server_url,
        client_metadata=OAuthClientMetadata(
            client_name="e2e-sdk-client",
            redirect_uris=[AnyUrl(REDIRECT)],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            token_endpoint_auth_method="none",
        ),
        storage=storage,
        redirect_handler=browser.redirect,
        callback_handler=browser.callback,
    )


async def _tools(server_url: str, auth, calls):
    out = []
    async with httpx.AsyncClient(auth=auth, follow_redirects=False, timeout=60) as http, streamable_http_client(
        server_url, http_client=http
    ) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            for name, args in calls:
                result = await session.call_tool(name, args)
                out.append(json.loads(result.content[0].text))
    return out


def _start_hub(tmp: str, moodle: str, site: str, secret_file: str, port: int):
    from moodle_mcp.crypto import load_kek
    from moodle_mcp.registry import Registry
    from moodle_mcp.server import create_app

    kek = os.path.join(tmp, "kek.key")
    with open(os.open(kek, os.O_CREAT | os.O_WRONLY, 0o600), "wb") as handle:
        handle.write(base64.b64encode(os.urandom(32)))
    os.makedirs(os.path.join(tmp, "tenants", site), mode=0o700)
    target = os.path.join(tmp, "tenants", site, "oauth.secret")
    shutil.copyfile(secret_file, target)
    os.chmod(target, 0o600)
    os.environ.update(
        UBIONAI_HUB_ALLOW_HTTP="1",
        UBIONAI_HUB_PUBLIC_URL=f"http://127.0.0.1:{port}",
        UBIONAI_HUB_TENANT_SECRETS_DIR=os.path.join(tmp, "tenants"),
    )
    for name in ("MOODLE_TOKEN", "MCP_BEARER_TOKEN"):
        os.environ.pop(name, None)
    db = os.path.join(tmp, "hub.sqlite3")
    static_bearer = secrets.token_urlsafe(24)
    Registry.open(db, load_kek(kek)).add(site, moodle, b"e2e-unused-static-token", None, static_bearer)
    app = create_app(hub_db=db, kek_file=kek)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    return server, thread, db, static_bearer


async def main() -> int:
    moodle = os.environ["E2E_MOODLE_URL"].rstrip("/")
    site = os.environ["E2E_SITE"]
    port = int(os.environ.get("E2E_HUB_PORT", "8799"))
    course_id = int(os.environ["E2E_COURSE_ID"])
    base = f"http://127.0.0.1:{port}"
    server_url = f"{base}/t/{site}/mcp"
    tmp = tempfile.mkdtemp(prefix="ubionai-e2e-")
    server, thread, db, static_bearer = _start_hub(tmp, moodle, site, os.environ["E2E_SECRET_FILE"], port)
    failures = 0

    def check(name: str, ok: bool, detail: str = "") -> None:
        nonlocal failures
        failures += 0 if ok else 1
        print(f"{'PASS' if ok else 'FAIL'} {name}" + (f" — {detail}" if detail else ""))

    try:
        # 1) teacher: full SDK flow, tools run with the teacher's own token
        teacher = MoodleBrowser(moodle, os.environ["E2E_TEACHER_USER"], _read(os.environ["E2E_TEACHER_PW_FILE"]))
        await teacher.login()
        storage = MemStorage()
        info, courses, outline, preview = await _tools(
            server_url,
            _provider(server_url, storage, teacher),
            [
                ("site_info", {}),
                ("list_courses", {}),
                ("get_course_outline", {"course_id": course_id}),
                ("create_assignment", {"course_id": course_id, "section": 0, "name": "E2E essay (preview)"}),
            ],
        )
        print("browser steps:\n  " + "\n  ".join(teacher.steps))
        functions = {f.get("name") for f in info.get("functions", [])}
        check("teacher site_info (own token, not admin, ubionai_user functions only)",
              info.get("userissiteadmin") is False and 0 < len(functions) and functions <= USER_SERVICE_FUNCTIONS,
              f"userid={info.get('userid')} functions={len(functions)}")
        ids = [c.get("id") for c in courses.get("courses", [])]
        check("teacher list_courses (core_enrol_get_users_courses)", course_id in ids and "error" not in courses, f"course ids={ids}")
        check("teacher get_course_outline", "error" not in outline, f"sections={len(outline.get('sections', []))}")
        check("teacher create_assignment preview", preview.get("preview") is True and preview["module"]["course_id"] == course_id)
        check("iss returned with code", teacher.result.get("iss") == f"{base}/t/{site}")

        # 2) static bearer of the same tenant still authenticates (tenant token is a dummy here)
        async with httpx.AsyncClient() as http:
            r = await http.post(server_url, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                                headers={"Authorization": f"Bearer {static_bearer}", "Accept": "application/json, text/event-stream"})
        check("static tenant bearer still accepted", r.status_code == 200, f"HTTP {r.status_code}")

        # 3) profile page lists the connection; RFC 7009 revoke at the hub deletes the Moodle token
        page = await teacher.http.get(f"{moodle}/local/ubionai/connections.php")
        check("profile connections page lists the token", "Revoke" in page.text)
        async with httpx.AsyncClient() as http:
            r = await http.post(f"{base}/t/{site}/oauth/revoke",
                                data={"token": storage.tokens.refresh_token, "client_id": storage.client.client_id})
            dead = await http.post(server_url, json={}, headers={"Authorization": f"Bearer {storage.tokens.access_token}"})
        page = await teacher.http.get(f"{moodle}/local/ubionai/connections.php")
        check("hub revoke -> Moodle token deleted", r.status_code == 200 and "no Claude connections" in page.text)
        check("revoked access token -> 401", dead.status_code == 401)

        # 4) site administrator: Moodle refuses before any code is issued
        admin = MoodleBrowser(moodle, os.environ["E2E_ADMIN_USER"], _read(os.environ["E2E_ADMIN_PW_FILE"]))
        await admin.login()
        refused = False
        try:
            await _tools(server_url, _provider(server_url, MemStorage(), admin), [("site_info", {})])
        except Exception:  # noqa: BLE001 - the SDK raises once the callback has no code
            refused = True
        check("site admin refused", refused and "Site administrators cannot connect" in admin.error_page and not admin.result,
              admin.error_page[admin.error_page.find("Site administrators"):][:90])
        import sqlite3

        with sqlite3.connect(db) as conn:
            grants = conn.execute("SELECT moodle_userid, revoked_at IS NOT NULL FROM oauth_grants").fetchall()
        check("hub grants: teacher only, revoked", len(grants) == 1 and grants[0][1] == 1, f"{len(grants)} grant(s)")
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"{'OK' if not failures else 'FAILED'}: {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
