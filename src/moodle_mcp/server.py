"""FastMCP server exposing Moodle read/write tools over Streamable HTTP."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hmac
import html
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import threading
import time
from contextvars import ContextVar
from typing import Any, Literal
from urllib.parse import urljoin, urlsplit

import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field
from starlette.types import ASGIApp, Receive, Scope, Send

from .crypto import (
    PURPOSE_PSEUDONYM_HMAC,
    DecryptError,
    Kek,
    KekError,
    derive_key,
    load_kek,
)
from .moodle import MoodleClient, MoodleError
from .netutil import parse_ip_list
from .oauth import OAuthConfigError, OAuthServer
from .pseudonym import (
    DEFAULT_ASSIGNMENT_TITLE_HEURISTIC,
    Pseudonymizer,
    RegistryPseudonymMap,
)
from .registry import DuplicateSite, Registry, TenantError, normalize_moodle_url, ws_endpoint

logger = logging.getLogger(__name__)

_current_client: ContextVar[MoodleClient | None] = ContextVar("moodle_mcp_client", default=None)
_current_pseudonymizer: ContextVar[Pseudonymizer | None] = ContextVar(
    "moodle_mcp_pseudonymizer", default=None
)
# Moodle user id of an OAuth (per-teacher) request; None for the tenant/service token.
_current_userid: ContextVar[int | None] = ContextVar("moodle_mcp_userid", default=None)


class BodyTooLarge(Exception):
    """Raised when a request body exceeds its configured limit."""


class _PseudonymizerStore:
    """Process-local per-tenant pseudonymizer objects sharing the registry map."""

    def __init__(
        self,
        registry: Registry,
        kek: Kek,
        ttl_seconds: int = 3600,
        max_entries: int = 512,
    ) -> None:
        self._registry = registry
        self._kek = kek
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._items: dict[str, tuple[Pseudonymizer, float]] = {}
        self._lock = threading.Lock()

    def get(
        self,
        site_id: str,
        enabled: bool = True,
        assignment_title_heuristic: str = DEFAULT_ASSIGNMENT_TITLE_HEURISTIC,
    ) -> Pseudonymizer | None:
        if not enabled:
            return None
        now = time.monotonic()
        with self._lock:
            for key, (_, seen) in list(self._items.items()):
                if now - seen > self._ttl:
                    del self._items[key]
            item = self._items.get(site_id)
            if item is not None:
                self._items[site_id] = (item[0], now)
                item[0].assignment_title_heuristic = assignment_title_heuristic
                return item[0]
            if len(self._items) >= self._max_entries:
                oldest = min(self._items, key=lambda key: self._items[key][1])
                del self._items[oldest]
            pseudonymizer = Pseudonymizer(
                derive_key(self._kek, PURPOSE_PSEUDONYM_HMAC, site_id),
                RegistryPseudonymMap(self._registry, site_id, self._kek),
                assignment_title_heuristic=assignment_title_heuristic,
            )
            self._items[site_id] = (pseudonymizer, now)
            return pseudonymizer
TENANT_PATH_RE = re.compile(r"^/t/([a-z0-9][a-z0-9-]{1,62})/mcp/?$")
CHAT_PATH_RE = re.compile(r"^/t/([a-z0-9][a-z0-9-]{1,62})/v1/chat/completions/?$")
MAX_REGISTER_BYTES = 16_384
MAX_CHAT_BYTES = 1024 * 1024

OPTIONAL_HINT = (
    "This tool needs the optional Moodle plugin {plugin}. If it is not installed (or its web service functions "
    "are not in the external service), this tool cannot work; all other tools are unaffected."
)
EDITINGTEACHER_ROLE_ID = int(os.environ.get("MOODLE_EDITINGTEACHER_ROLE_ID") or "3")  # blank in .env -> default
WRITE_NOTE = "WRITE - only call after the teacher confirmed."
CONFIRM_NOTE = "Call first with confirm=false to get a preview; call again with confirm=true after the teacher agrees."
PREVIEW_NOTE = "Nothing changed. Re-call with confirm=true."
MAX_UPLOAD_BYTES = 200 * 1024 * 1024
SUBMISSION_TYPES = {"onlinetext", "file"}
FORUM_TYPES = {"general", "qanda", "single", "eachuser", "blog"}
COMPLETION_MODES = {"none", "manual", "view", "submit", "pass", "grade", "posts"}
WORKSHOP_STRATEGIES = {"accumulative", "comments", "numerrors", "rubric"}
WORKSHOP_SUBMISSION_TYPES = {"text", "file"}
WIKI_MODES = {"collaborative", "individual"}
SETTINGS_NOTE = "settings: extra module fields passed to Moodle as is (advanced; override the other arguments)."
YOUTUBE_RE = re.compile(
    r"(?:youtube(?:-nocookie)?\.com/(?:watch\?(?:.*&)?v=|embed/|shorts/|live/)|youtu\.be/)([\w-]{6,})"
)
VIMEO_RE = re.compile(r"vimeo\.com/(?:video/)?(\d+)")
WRITE_FUNCTIONS = frozenset(
    {
        "core_course_create_courses",
        "enrol_manual_enrol_users",
        "mod_assign_save_grade",
        "mod_assign_save_grades",
        "core_files_upload",
        "core_course_edit_module",
        "mod_forum_add_discussion",
    }
)
# Name seeding for assignment titles: fetch only name fields (no email or id
# numbers) and seed a few courses at a time. onlyactive stays at Moodle's
# default (0) so suspended enrolments are seeded too.
SEED_USER_OPTIONS = [{"name": "userfields", "value": "id,firstname,lastname,fullname"}]
SEED_CONCURRENCY = 5
_LOCAL_WRITE_PREFIX = "local_ubionai_"
_LOCAL_READ_FUNCTIONS = frozenset({
    "local_ubionai_get_course_assignments",
    "local_ubionai_list_course_assignments",
})


def _is_write(wsfunction: str) -> bool:
    return (
        wsfunction in WRITE_FUNCTIONS
        or (
            wsfunction.startswith(_LOCAL_WRITE_PREFIX)
            and wsfunction not in _LOCAL_READ_FUNCTIONS
        )
    )


class GradeEntry(BaseModel):
    user_id: int = Field(description="Moodle user id of the student")
    grade: float = Field(description="Grade value")
    feedback_text: str = Field(default="", description="Feedback comment (HTML allowed)")


class QuizAnswer(BaseModel):
    text: str = Field(description="Answer text (HTML for multichoice, plain for shortanswer)")
    fraction: float = Field(default=0, description="Grade fraction -1..1; 1 = fully correct")
    feedback: str = Field(default="", description="Feedback shown for this answer")


class QuizQuestion(BaseModel):
    type: Literal["multichoice", "truefalse", "shortanswer", "essay"]
    text: str = Field(description="Question text (HTML)")
    name: str | None = Field(default=None, description="Question name (defaults to the start of the text)")
    mark: float = Field(default=1, description="Default mark / slot mark")
    generalfeedback: str = ""
    answers: list[QuizAnswer] | None = Field(default=None, description="multichoice (>=2) / shortanswer (>=1)")
    single: bool | None = Field(default=None, description="multichoice: one correct answer (default true)")
    shuffleanswers: bool | None = None
    correct: bool | None = Field(default=None, description="truefalse: the correct answer")
    feedbacktrue: str | None = None
    feedbackfalse: str | None = None
    usecase: bool | None = Field(default=None, description="shortanswer: case sensitive")
    graderinfo: str | None = Field(default=None, description="essay: information for graders")
    responseformat: Literal["editor", "editorfilepicker", "plain", "monospaced", "noinline"] | None = None
    responsefieldlines: int | None = None


class RubricLevel(BaseModel):
    definition: str = Field(description="What this level looks like")
    score: float = Field(description="Points for this level (>= 0, distinct within the criterion)")


class RubricCriterion(BaseModel):
    description: str = Field(description="Criterion, e.g. 'Learning-goal alignment'")
    levels: list[RubricLevel] = Field(description="At least 2 levels")


class GradeItemRef(BaseModel):
    cmid: int
    itemnumber: int = Field(description="Grade item number; workshop: 0 = submission, 1 = assessment")


class GradeCategory(BaseModel):
    name: str = Field(description="Category name (an existing category with this name is reused)")
    weight: float | None = Field(
        default=None, description="weighted_mean: weight; natural: percent; ignored for mean"
    )
    cmids: list[int | GradeItemRef] = Field(
        default=[], description="Activities to move in: a cmid moves all its grade items, {cmid, itemnumber} one"
    )


def _video_embed(url: str) -> str:
    """HTML embedding a video: responsive iframe for YouTube/Vimeo links, otherwise a <video> tag."""
    embed = None
    if m := YOUTUBE_RE.search(url):
        embed = f"https://www.youtube.com/embed/{m.group(1)}"
    elif m := VIMEO_RE.search(url):
        embed = f"https://player.vimeo.com/video/{m.group(1)}"
    if embed:
        return (
            '<div style="position:relative;padding-bottom:56.25%;height:0;overflow:hidden;max-width:100%;">'
            f'<iframe src="{html.escape(embed)}" '
            'style="position:absolute;top:0;left:0;width:100%;height:100%;border:0;" '
            'allow="autoplay; clipboard-write; encrypted-media; picture-in-picture; fullscreen" '
            "allowfullscreen></iframe></div>"
        )
    return f'<video controls preload="metadata" style="max-width:100%;" src="{html.escape(url)}"></video>'


def _availability(required_cmids: list[int], open_from: int | None) -> str:
    """core_availability JSON: all listed activities completed AND (optionally) date >= open_from."""
    conditions: list[dict[str, Any]] = [{"type": "completion", "cm": cmid, "e": 1} for cmid in required_cmids]
    if open_from is not None:
        conditions.append({"type": "date", "d": ">=", "t": open_from})
    if not conditions:
        return ""  # no restrictions
    return json.dumps({"op": "&", "c": conditions, "showc": [True] * len(conditions)})


def _blocked_ip(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return not ip.is_global or ip.is_private or ip.is_loopback or ip.is_link_local


def _resolve_host(host: str, port: int) -> list[tuple[Any, ...]]:
    """DNS indirection point so tests can avoid touching the network."""
    return socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)


async def _assert_public_url(url: str, resolver: Any = None) -> None:
    parts = urlsplit(url)
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise ValueError("file_url must be an http(s) URL")
    if parts.username is not None or parts.password is not None:
        raise ValueError("file_url must not contain credentials")
    try:
        port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    except ValueError:
        raise ValueError("file_url must be an http(s) URL") from None
    try:
        infos = await asyncio.to_thread(
            resolver or _resolve_host, parts.hostname, port
        )
    except socket.gaierror:
        return
    for info in infos:
        if _blocked_ip(info[4][0]):
            raise ValueError("file_url host is not allowed")


async def _download(url: str, limit: int = MAX_UPLOAD_BYTES, resolver: Any = None) -> bytes:
    timeout = httpx.Timeout(120.0, connect=10.0)
    current = url
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        for _ in range(6):
            await _assert_public_url(current, resolver)
            async with client.stream("GET", current) as resp:
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location")
                    if not location:
                        raise ValueError("file_url redirect has no location")
                    current = urljoin(str(resp.url), location)
                    continue
                resp.raise_for_status()
                if int(resp.headers.get("content-length") or 0) > limit:
                    raise ValueError(f"file is larger than {limit} bytes")
                chunks, size = [], 0
                async for chunk in resp.aiter_bytes():
                    size += len(chunk)
                    if size > limit:
                        raise ValueError(f"file is larger than {limit} bytes")
                    chunks.append(chunk)
                return b"".join(chunks)
    raise ValueError("file_url redirected too many times")


def _check_file(filename: str, file_url: str | None, file_base64: str | None) -> tuple[bytes | None, str | None]:
    """Validate an upload request; returns (decoded base64 data or None, error or None)."""
    if (file_url is None) == (file_base64 is None):
        return None, "give exactly one of file_url or file_base64"
    if not filename.strip() or "/" in filename or "\\" in filename:
        return None, "filename must be a plain file name"
    if file_base64 is None:
        return None, None
    try:
        data = base64.b64decode(file_base64, validate=True)
    except (binascii.Error, ValueError):
        return None, "file_base64 is not valid base64"
    if len(data) > MAX_UPLOAD_BYTES:
        return None, f"file is larger than {MAX_UPLOAD_BYTES} bytes"
    return data, None


def _wrap(result: Any, key: str = "result") -> dict[str, Any]:
    return result if isinstance(result, dict) else {key: result}


def _map_strings(value: Any, transform: Any) -> Any:
    """Recursively apply transform to every string value (keys are untouched)."""
    if isinstance(value, str):
        return transform(value)
    if isinstance(value, list):
        return [_map_strings(item, transform) for item in value]
    if isinstance(value, dict):
        return {key: _map_strings(item, transform) for key, item in value.items()}
    return value


def create_mcp(client: MoodleClient | None) -> FastMCP:
    mcp = FastMCP(
        "moodle",
        instructions=(
            "Read and write Moodle data (courses, students, assignments, quizzes, grades, attendance). "
            "Tools marked WRITE change Moodle data: preview first (confirm=false where available) and only "
            "call them for real after the teacher explicitly confirmed."
        ),
        host="0.0.0.0",  # disables localhost-only DNS-rebinding host checks; bearer auth guards access
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
    )

    def _request_client() -> MoodleClient | None:
        try:
            ctx = mcp.get_context()
            request = ctx.request_context.request
            if request is not None:
                scoped = request.scope.get("state", {}).get("moodle_client")
                if scoped is not None:
                    return scoped
        except (LookupError, ValueError, AttributeError, KeyError):
            pass
        return _current_client.get()

    def _request_pseudonymizer() -> Pseudonymizer | None:
        try:
            ctx = mcp.get_context()
            request = ctx.request_context.request
            if request is not None:
                scoped = request.scope.get("state", {}).get("pseudonymizer")
                if scoped is not None:
                    return scoped
        except (LookupError, ValueError, AttributeError, KeyError):
            pass
        return _current_pseudonymizer.get()

    def _request_userid() -> int | None:
        try:
            ctx = mcp.get_context()
            request = ctx.request_context.request
            if request is not None:
                state = request.scope.get("state", {})
                if "moodle_userid" in state:
                    return state["moodle_userid"]
        except (LookupError, ValueError, AttributeError, KeyError):
            pass
        return _current_userid.get()

    async def _user_courses(userid: int) -> dict[str, Any]:
        """Courses of a teacher token: core_course_get_courses needs moodle/course:view (admin-only)."""
        return await call("core_enrol_get_users_courses", key="courses", userid=userid)

    def _dumps(obj: Any) -> str:
        pseudonymizer = _request_pseudonymizer()
        if pseudonymizer is not None:
            obj = pseudonymizer.restore_value(obj)
        return json.dumps(obj, ensure_ascii=False)

    async def _seed_course_users(
        active: MoodleClient, pseudonymizer: Pseudonymizer, result: Any
    ) -> bool:
        """Seed enrolled-user names for every course in the result.

        Returns False when any seeding call fails, so the caller can fail closed:
        with incomplete seeding, assignment titles must keep the heuristic on.
        """
        courses = result.get("courses") if isinstance(result, dict) else None
        if not isinstance(courses, list):
            return True
        courseids = [
            course["id"]
            for course in courses
            if isinstance(course, dict)
            and course.get("assignments")
            and isinstance(course.get("id"), int)
        ]
        limit = asyncio.Semaphore(SEED_CONCURRENCY)

        async def seed_one(courseid: int) -> bool:
            async with limit:
                try:
                    users = await active.call(
                        "core_enrol_get_enrolled_users",
                        courseid=courseid,
                        options=SEED_USER_OPTIONS,
                    )
                except MoodleError:
                    return False
            pseudonymizer.seed(_wrap(users, "users"))
            return True

        results = await asyncio.gather(*(seed_one(cid) for cid in courseids))
        return all(results)

    async def call(
        wsfunction: str,
        key: str = "result",
        *,
        assignment_listing: bool = False,
        **params: Any,
    ) -> dict[str, Any]:
        active = client or _request_client()
        if active is None:
            raise MoodleError("no tenant context")
        pseudonymizer = _request_pseudonymizer()
        if pseudonymizer is not None:
            params = pseudonymizer.restore_value(params)
            if _is_write(wsfunction):
                leftover = pseudonymizer.unresolved(params)
                if leftover:
                    return {
                        "error": "unresolved placeholders",
                        "placeholders": sorted(leftover),
                    }
        try:
            result = _wrap(await active.call(wsfunction, **params), key)
        except MoodleError as exc:
            result = {"error": str(exc)}
        if pseudonymizer is not None:
            # Seeded names are the only masking for assignment titles, so fail
            # closed (heuristic on) if seeding any course failed.
            assignment_titles = assignment_listing
            if assignment_listing:
                assignment_titles = await _seed_course_users(
                    active, pseudonymizer, result
                )
            result = pseudonymizer.pseudonymize_value(
                result, assignment_titles=assignment_titles
            )
        return result

    @mcp.tool()
    async def site_info() -> dict[str, Any]:
        """Get Moodle site info and the identity of the web service user."""
        return await call("core_webservice_get_site_info")

    @mcp.tool()
    async def list_courses(ids: list[int] | None = None) -> dict[str, Any]:
        """List courses. Pass course ids to restrict, or omit for all visible courses."""
        userid = _request_userid()
        if userid is not None:
            res = await _user_courses(userid)
            if ids and isinstance(res.get("courses"), list):
                wanted = set(ids)
                res["courses"] = [c for c in res["courses"] if isinstance(c, dict) and c.get("id") in wanted]
            return res
        options = {"ids": ids} if ids else None
        return await call("core_course_get_courses", key="courses", options=options)

    @mcp.tool()
    async def get_course_outline(course_id: int) -> dict[str, Any]:
        """Get the sections and activities/modules of a course."""
        return await call("core_course_get_contents", key="sections", courseid=course_id)

    @mcp.tool()
    async def list_students(course_id: int) -> dict[str, Any]:
        """List users enrolled in a course (with roles and groups)."""
        return await call("core_enrol_get_enrolled_users", key="users", courseid=course_id)

    @mcp.tool()
    async def list_assignments(
        course_ids: list[int] | None = None,
        offset: int = 0,
        limit: int = 25,
    ) -> dict[str, Any]:
        """List assignments, grouped by course. Omit course_ids for all accessible courses.

        offset/limit page through all courses that have assignments and apply only
        when course_ids is omitted. Courses the service user is not enrolled in come
        from the local_ubionai plugin (tagged source=local_ubionai); results include
        a paging block with next_offset.
        """
        offset = max(0, int(offset))
        limit = min(100, max(1, int(limit)))

        # Without course_ids, core results are only shown on the first page; later
        # pages need just their course ids, so skip name seeding for them.
        res = await call(
            "mod_assign_get_assignments",
            courseids=course_ids or None,
            assignment_listing=bool(course_ids) or offset == 0,
        )
        if not isinstance(res, dict) or "error" in res:
            return res

        fallback_errors: list[dict[str, Any]] = []
        seen: set[int] = set()
        if isinstance(res.get("courses"), list):
            seen = {int(c["id"]) for c in res["courses"] if isinstance(c, dict) and "id" in c}

        if course_ids:
            for courseid in [cid for cid in course_ids if cid not in seen]:
                extra = await call(
                    "local_ubionai_get_course_assignments",
                    courseid=courseid,
                    assignment_listing=True,
                )
                if isinstance(extra, dict) and "error" not in extra:
                    for course in extra.get("courses", []):
                        if isinstance(course, dict):
                            course["source"] = "local_ubionai"
                            res.setdefault("courses", []).append(course)
                    res.setdefault("warnings", []).extend(extra.get("warnings", []))
                else:
                    error = extra.get("error") if isinstance(extra, dict) else str(extra)
                    fallback_errors.append({"courseid": courseid, "error": str(error)})
                    res["hint"] = OPTIONAL_HINT.format(plugin="local_ubionai")
            if fallback_errors:
                res["fallback_errors"] = fallback_errors
            return res

        # No course_ids: primary paged enumeration through the plugin.
        page = await call(
            "local_ubionai_list_course_assignments",
            offset=offset,
            limit=limit,
            assignment_listing=True,
        )
        page_error = page.get("error") if isinstance(page, dict) else str(page)
        if isinstance(page, dict) and "error" not in page:
            # Core mod_assign results are only included on the first page; later pages
            # come entirely from the plugin so enrolled courses do not repeat.
            if offset != 0:
                res["courses"] = []
            for course in page.get("courses", []):
                if isinstance(course, dict) and int(course.get("id", 0)) not in seen:
                    course["source"] = "local_ubionai"
                    res.setdefault("courses", []).append(course)
                    seen.add(int(course["id"]))
            res.setdefault("warnings", []).extend(page.get("warnings", []))
            total = int(page.get("total", 0))
            res["paging"] = {
                "offset": offset,
                "limit": limit,
                "total": total,
                "next_offset": offset + limit if offset + limit < total else None,
            }
            return res

        # Degraded fallback (0.4.x plugin or Connect not re-run after upgrade).
        userid = _request_userid()
        cc = await (_user_courses(userid) if userid is not None else call("core_course_get_courses", key="courses"))
        if not isinstance(cc, dict) or "error" in cc or not isinstance(cc.get("courses"), list):
            res["hint"] = OPTIONAL_HINT.format(plugin="local_ubionai")
            return res

        # Read id/format first: both are pseudonymisation-safe (ints are never masked;
        # format values like "site" are ASCII and untouched by the name detectors).
        ids = sorted(
            int(c["id"])
            for c in cc["courses"]
            if isinstance(c, dict) and int(c.get("id", 0)) != 1 and c.get("format") != "site"
        )
        ids = [cid for cid in ids if cid not in seen]
        window = ids[offset:offset + limit]

        # As in the plugin path, core mod_assign results belong to the first page only.
        if offset != 0:
            res["courses"] = []

        degraded_errors: list[dict[str, Any]] = []
        for courseid in window:
            extra = await call(
                "local_ubionai_get_course_assignments",
                courseid=courseid,
                assignment_listing=True,
            )
            if isinstance(extra, dict) and "error" not in extra:
                for course in extra.get("courses", []):
                    if isinstance(course, dict) and course.get("assignments"):
                        course["source"] = "local_ubionai"
                        res.setdefault("courses", []).append(course)
                res.setdefault("warnings", []).extend(extra.get("warnings", []))
            else:
                error = extra.get("error") if isinstance(extra, dict) else str(extra)
                degraded_errors.append({"courseid": courseid, "error": str(error)})

        res["paging"] = {
            "offset": offset,
            "limit": limit,
            "total": len(ids),
            "next_offset": offset + limit if offset + limit < len(ids) else None,
        }
        res["degraded"] = (
            "local_ubionai_list_course_assignments unavailable; re-run Connect in the plugin"
        )
        if page_error:
            res["plugin_error"] = str(page_error)
            res["degraded"] += f" (plugin error: {page_error})"
        if degraded_errors:
            res["fallback_errors"] = degraded_errors
        if (not window and offset == 0) or (degraded_errors and not res.get("courses")):
            res["hint"] = OPTIONAL_HINT.format(plugin="local_ubionai")
        if not ids and not seen and not res.get("courses"):
            res["hint"] = (
                "No courses returned; the service user is not enrolled in any course. "
                "Pass course_ids to list assignments for specific courses."
            )
        return res

    @mcp.tool()
    async def get_submissions(assignment_ids: list[int], status: str = "") -> dict[str, Any]:
        """Get submissions for assignments. Optional status filter (e.g. 'submitted', 'draft')."""
        return await call("mod_assign_get_submissions", assignmentids=assignment_ids, status=status)

    @mcp.tool()
    async def get_assignment_grades(assignment_ids: list[int]) -> dict[str, Any]:
        """Get grades already given for assignments (mod_assign_get_grades)."""
        return await call("mod_assign_get_grades", assignmentids=assignment_ids)

    @mcp.tool()
    async def gradebook_overview(course_id: int, user_id: int | None = None) -> dict[str, Any]:
        """Get gradebook items and grades for a course, optionally for a single user."""
        return await call("gradereport_user_get_grade_items", courseid=course_id, userid=user_id)

    @mcp.tool()
    async def list_quizzes(course_ids: list[int] | None = None) -> dict[str, Any]:
        """List quizzes in the given courses (omit for all accessible courses)."""
        return await call("mod_quiz_get_quizzes_by_courses", courseids=course_ids or None)

    @mcp.tool()
    async def list_quiz_attempts(quiz_id: int, user_id: int, status: str = "all") -> dict[str, Any]:
        """List a user's attempts on a quiz. status: all, finished or unfinished."""
        return await call(
            "mod_quiz_get_user_attempts",
            quizid=quiz_id,
            userid=user_id,
            status=status,
            includepreviews=False,
        )

    @mcp.tool()
    async def review_attempt(attempt_id: int) -> dict[str, Any]:
        """Get the full review (questions, responses, marks) of a quiz attempt."""
        return await call("mod_quiz_get_attempt_review", attemptid=attempt_id)

    @mcp.tool()
    async def attendance_sessions(attendance_id: int) -> dict[str, Any]:
        """List sessions (and attendance logs) of an attendance activity instance."""
        res = await call("mod_attendance_get_sessions", key="sessions", attendanceid=attendance_id)
        if isinstance(res, dict) and "error" in res:
            res["hint"] = OPTIONAL_HINT.format(plugin="mod_attendance")
        return res

    @mcp.tool()
    async def list_categories() -> dict[str, Any]:
        """List course categories (id, name, parent, coursecount)."""
        return await call("core_course_get_categories", key="categories")

    @mcp.tool(
        description=f"{WRITE_NOTE} Create a course (core_course_create_courses) and enrol the bot as editingteacher. "
        "Call first with confirm=false to get a preview; call again with confirm=true after the teacher agrees. "
        "format: topics|weeks|singleactivity|social. startdate: unix timestamp."
    )
    async def create_course(
        fullname: str,
        shortname: str,
        categoryid: int = 1,
        format: str = "topics",
        numsections: int | None = None,
        visible: int = 1,
        startdate: int | None = None,
        summary: str = "",
        confirm: bool = False,
    ) -> dict[str, Any]:
        course: dict[str, Any] = {
            "fullname": fullname,
            "shortname": shortname,
            "categoryid": categoryid,
            "format": format,
            "visible": visible,
            "summary": summary,
            "summaryformat": 1,
        }
        if numsections is not None:
            course["courseformatoptions"] = [{"name": "numsections", "value": str(numsections)}]
        if startdate is not None:
            course["startdate"] = startdate
        if not confirm:
            return {"preview": True, "course": course, "note": "Not created. Re-call with confirm=true."}
        created = await call("core_course_create_courses", key="courses", courses=[course])
        if "error" in created:
            return created
        courseid = created["courses"][0]["id"]
        info = await call("core_webservice_get_site_info")
        if "error" in info:
            return {"ok": True, "courseid": courseid, "enrol_error": info["error"]}
        enrol = await call(
            "enrol_manual_enrol_users",
            enrolments=[{"roleid": EDITINGTEACHER_ROLE_ID, "userid": info["userid"], "courseid": courseid}],
        )
        out: dict[str, Any] = {"ok": True, "courseid": courseid, "shortname": created["courses"][0].get("shortname")}
        if "error" in enrol:
            out["enrol_error"] = enrol["error"]
        else:
            out["enrolled_userid"] = info["userid"]
        return out

    @mcp.tool(description=f"{WRITE_NOTE} Save a grade and feedback comment for one student's assignment submission.")
    async def grade_submission(
        assignment_id: int,
        user_id: int,
        grade: float,
        feedback_text: str = "",
        attempt_number: int = -1,
        workflow_state: str = "",
    ) -> dict[str, Any]:
        result = await call(
            "mod_assign_save_grade",
            assignmentid=assignment_id,
            userid=user_id,
            grade=grade,
            attemptnumber=attempt_number,
            addattempt=0,
            workflowstate=workflow_state,
            applytoall=1,
            plugindata={"assignfeedbackcomments_editor": {"text": feedback_text, "format": 1}},
        )
        return result if "error" in result else {"ok": True, **result}

    @mcp.tool(description=f"{WRITE_NOTE} Save grades and feedback for several students of one assignment at once.")
    async def bulk_grade(assignment_id: int, grades: list[GradeEntry]) -> dict[str, Any]:
        entries = [
            {
                "userid": g.user_id,
                "grade": g.grade,
                "attemptnumber": -1,
                "addattempt": 0,
                "workflowstate": "",
                "plugindata": {"assignfeedbackcomments_editor": {"text": g.feedback_text, "format": 1}},
            }
            for g in grades
        ]
        result = await call("mod_assign_save_grades", assignmentid=assignment_id, applytoall=1, grades=entries)
        return result if "error" in result else {"ok": True, "graded": len(entries), **result}

    async def write(wsfunction: str, preview: dict[str, Any], confirm: bool, **params: Any) -> dict[str, Any]:
        """Preview (no Moodle call) unless confirmed; then call and report ok."""
        if not confirm:
            result = {"preview": True, **preview, "note": PREVIEW_NOTE}
            pseudonymizer = _request_pseudonymizer()
            if pseudonymizer is not None:
                leftover = pseudonymizer.unresolved(params)
                if leftover:
                    result["unresolved_placeholders"] = sorted(leftover)
            return result
        result = await call(wsfunction, **params)
        return result if "error" in result else {"ok": True, **result}

    async def create_module(
        course_id: int, section: int, modname: str, name: str, intro: str, visible: int,
        settings: dict[str, Any], confirm: bool,
    ) -> dict[str, Any]:  # fmt: skip
        module = {"course_id": course_id, "section": section, "modname": modname, "name": name,
                  "intro": intro, "visible": visible, "settings": settings}  # fmt: skip
        return await write(
            "local_ubionai_create_module", {"module": module}, confirm,
            courseid=course_id, section=section, modname=modname, name=name, intro=intro, visible=visible,
            settings=_dumps(settings),
        )  # fmt: skip

    @mcp.tool(
        description=f"{WRITE_NOTE} Create an assignment in a course section. {CONFIRM_NOTE} "
        "Dates are unix timestamps. submission_types: onlinetext and/or file."
    )
    async def create_assignment(
        course_id: int,
        section: int,
        name: str,
        intro: str = "",
        duedate: int | None = None,
        cutoffdate: int | None = None,
        allowsubmissionsfromdate: int | None = None,
        grade: float = 100,
        submission_types: list[str] = ["onlinetext"],  # noqa: B006 - never mutated
        max_files: int = 1,
        visible: int = 1,
        completion_submit: bool = False,
        confirm: bool = False,
    ) -> dict[str, Any]:
        if bad := set(submission_types) - SUBMISSION_TYPES:
            return {"error": f"unknown submission_types: {sorted(bad)} (allowed: onlinetext, file)"}
        settings: dict[str, Any] = {
            "grade": grade,
            "assignsubmission_onlinetext_enabled": int("onlinetext" in submission_types),
            "assignsubmission_file_enabled": int("file" in submission_types),
            "assignsubmission_file_maxfiles": max_files,
        }
        dates = {"duedate": duedate, "cutoffdate": cutoffdate, "allowsubmissionsfromdate": allowsubmissionsfromdate}
        settings.update({k: v for k, v in dates.items() if v is not None})
        if completion_submit:
            settings.update(completion=2, completionsubmit=1)
        return await create_module(course_id, section, "assign", name, intro, visible, settings, confirm)

    @mcp.tool(
        description=f"{WRITE_NOTE} Create a quiz in a course section. {CONFIRM_NOTE} "
        "timeopen/timeclose: unix timestamps; timelimit: seconds; attempts 0 = unlimited; "
        "grademethod 1 highest, 2 average, 3 first, 4 last. completion_pass_grade: passing grade that "
        "completes the quiz. Add questions afterwards with add_quiz_questions (quiz instance id)."
    )
    async def create_quiz(
        course_id: int,
        section: int,
        name: str,
        intro: str = "",
        timeopen: int | None = None,
        timeclose: int | None = None,
        timelimit: int | None = None,
        attempts: int = 0,
        grademethod: int = 1,
        grade: float = 10,
        visible: int = 1,
        completion_pass_grade: float | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        settings: dict[str, Any] = {"attempts": attempts, "grademethod": grademethod, "grade": grade}
        times = {"timeopen": timeopen, "timeclose": timeclose, "timelimit": timelimit}
        settings.update({k: v for k, v in times.items() if v is not None})
        if completion_pass_grade is not None:
            settings.update(completion=2, completionusegrade=1, completionpassgrade=1, gradepass=completion_pass_grade)
        return await create_module(course_id, section, "quiz", name, intro, visible, settings, confirm)

    @mcp.tool(
        description=f"{WRITE_NOTE} Create a forum in a course section. {CONFIRM_NOTE} "
        "type: general|qanda|single|eachuser|blog. max_grade > 0 enables whole-forum grading out of max_grade. "
        "completion_posts > 0 completes the forum after that many posts."
    )
    async def create_forum(
        course_id: int,
        section: int,
        name: str,
        intro: str = "",
        type: str = "general",
        max_grade: int = 0,
        duedate: int | None = None,
        completion_posts: int = 0,
        visible: int = 1,
        confirm: bool = False,
    ) -> dict[str, Any]:
        if type not in FORUM_TYPES:
            return {"error": f"type must be one of {sorted(FORUM_TYPES)}"}
        settings: dict[str, Any] = {"type": type}
        if max_grade > 0:
            settings["grade_forum"] = max_grade
        if duedate is not None:
            settings["duedate"] = duedate
        if completion_posts > 0:
            settings.update(completion=2, completionposts=completion_posts)
        return await create_module(course_id, section, "forum", name, intro, visible, settings, confirm)

    @mcp.tool(
        description=f"{WRITE_NOTE} Create a page (HTML content) in a course section. {CONFIRM_NOTE} "
        "video_url: YouTube/Vimeo links are embedded as a responsive player, other URLs as a <video> tag."
    )
    async def create_page(
        course_id: int,
        section: int,
        name: str,
        content_html: str,
        intro: str = "",
        video_url: str | None = None,
        completion_view: bool = True,
        visible: int = 1,
        confirm: bool = False,
    ) -> dict[str, Any]:
        content = content_html + (_video_embed(video_url) if video_url else "")
        settings: dict[str, Any] = {"content": content}
        if completion_view:
            settings.update(completion=2, completionview=1)
        return await create_module(course_id, section, "page", name, intro, visible, settings, confirm)

    @mcp.tool(
        description=f"{WRITE_NOTE} Upload a file and create a file resource in a course section. {CONFIRM_NOTE} "
        "Give exactly one of file_url (downloaded by the server, max 200 MB) or file_base64."
    )
    async def create_resource(
        course_id: int,
        section: int,
        name: str,
        filename: str,
        file_url: str | None = None,
        file_base64: str | None = None,
        intro: str = "",
        completion_view: bool = True,
        visible: int = 1,
        confirm: bool = False,
    ) -> dict[str, Any]:
        settings: dict[str, Any] = {"completion": 2, "completionview": 1} if completion_view else {}
        return await create_with_file(
            course_id, section, "resource", name, intro, visible, settings, "files", filename, file_url, file_base64,
            confirm,
        )  # fmt: skip

    async def create_with_file(
        course_id: int, section: int, modname: str, name: str, intro: str, visible: int, settings: dict[str, Any],
        file_setting: str, filename: str, file_url: str | None, file_base64: str | None, confirm: bool,
    ) -> dict[str, Any]:  # fmt: skip
        """Preview, or upload the file to the user's draft area and create the module with settings[file_setting]."""
        data, error = _check_file(filename, file_url, file_base64)
        if error:
            return {"error": error}
        if not confirm:
            module = {"course_id": course_id, "section": section, "modname": modname, "name": name,
                      "intro": intro, "visible": visible, "settings": settings}  # fmt: skip
            file = {"filename": filename, "source": file_url or "base64"}
            if data is not None:
                file["size_bytes"] = len(data)
            return {"preview": True, "module": module, "file": file, "note": PREVIEW_NOTE}
        if data is None:
            try:
                data = await _download(file_url or "")
            except (httpx.HTTPError, ValueError) as exc:
                return {"error": f"download failed: {exc}"}
        info = await call("core_webservice_get_site_info")
        if "error" in info:
            return info
        upload = await call(
            "core_files_upload",
            contextlevel="user", instanceid=info["userid"], component="user", filearea="draft", itemid=0,
            filepath="/", filename=filename, filecontent=base64.b64encode(data).decode("ascii"),
        )  # fmt: skip
        if "error" in upload:
            return upload
        settings = {**settings, file_setting: upload["itemid"]}
        out = await create_module(course_id, section, modname, name, intro, visible, settings, True)
        return out if "error" in out else {**out, "size_bytes": len(data)}

    @mcp.tool(
        description=f"{WRITE_NOTE} Create a workshop (peer assessment) in a course section. {CONFIRM_NOTE} "
        "strategy: accumulative|comments|numerrors|rubric (define a rubric afterwards with set_rubric). "
        "grade = submission max, gradinggrade = assessment max. submission_types: text and/or file. "
        "Dates are unix timestamps. The workshop starts in the setup phase. " + SETTINGS_NOTE
    )
    async def create_workshop(
        course_id: int,
        section: int,
        name: str,
        intro: str = "",
        strategy: str = "rubric",
        grade: float = 80,
        gradinggrade: float = 20,
        instructions_submission: str = "",
        instructions_assessment: str = "",
        submission_types: list[str] = ["text", "file"],  # noqa: B006 - never mutated
        submission_start: int | None = None,
        submission_end: int | None = None,
        assessment_start: int | None = None,
        assessment_end: int | None = None,
        self_assessment: bool = False,
        visible: int = 1,
        settings: dict[str, Any] = {},  # noqa: B006 - never mutated
        confirm: bool = False,
    ) -> dict[str, Any]:
        if strategy not in WORKSHOP_STRATEGIES:
            return {"error": f"strategy must be one of {sorted(WORKSHOP_STRATEGIES)}"}
        if not submission_types or set(submission_types) - WORKSHOP_SUBMISSION_TYPES:
            return {"error": "submission_types must be a non-empty subset of ['file', 'text']"}
        module: dict[str, Any] = {
            "strategy": strategy,
            "grade": grade,
            "gradinggrade": gradinggrade,
            "submissiontypetext": int("text" in submission_types),
            "submissiontypefile": int("file" in submission_types),
            "useselfassessment": int(self_assessment),
        }
        if instructions_submission:
            module["instructauthors"] = instructions_submission
        if instructions_assessment:
            module["instructreviewers"] = instructions_assessment
        dates = {"submissionstart": submission_start, "submissionend": submission_end,
                 "assessmentstart": assessment_start, "assessmentend": assessment_end}  # fmt: skip
        module.update({k: v for k, v in dates.items() if v is not None})
        settings = {**module, **settings}
        return await create_module(course_id, section, "workshop", name, intro, visible, settings, confirm)

    @mcp.tool(
        description=f"{WRITE_NOTE} Create a wiki in a course section. {CONFIRM_NOTE} mode: collaborative|individual. "
        "group_mode: 0 none, 1 separate groups, 2 visible groups. " + SETTINGS_NOTE
    )
    async def create_wiki(
        course_id: int,
        section: int,
        name: str,
        intro: str = "",
        mode: str = "collaborative",
        first_page_title: str = "",
        group_mode: int = 0,
        visible: int = 1,
        settings: dict[str, Any] = {},  # noqa: B006 - never mutated
        confirm: bool = False,
    ) -> dict[str, Any]:
        if mode not in WIKI_MODES:
            return {"error": f"mode must be one of {sorted(WIKI_MODES)}"}
        if group_mode not in (0, 1, 2):
            return {"error": "group_mode must be 0, 1 or 2"}
        module: dict[str, Any] = {"wikimode": mode, "groupmode": group_mode}
        if first_page_title:
            module["firstpagetitle"] = first_page_title
        settings = {**module, **settings}
        return await create_module(course_id, section, "wiki", name, intro, visible, settings, confirm)

    @mcp.tool(
        description=f"{WRITE_NOTE} Create a glossary in a course section. {CONFIRM_NOTE} "
        "default_approval=false makes student entries wait for teacher approval. completion_entries > 0 completes "
        "the glossary after that many entries. " + SETTINGS_NOTE
    )
    async def create_glossary(
        course_id: int,
        section: int,
        name: str,
        intro: str = "",
        display_format: str = "dictionary",
        default_approval: bool = True,
        allow_comments: bool = False,
        completion_entries: int = 0,
        visible: int = 1,
        settings: dict[str, Any] = {},  # noqa: B006 - never mutated
        confirm: bool = False,
    ) -> dict[str, Any]:
        module: dict[str, Any] = {
            "displayformat": display_format,
            "defaultapproval": int(default_approval),
            "allowcomments": int(allow_comments),
        }
        if completion_entries > 0:
            module.update(completion=2, completionentries=completion_entries)
        settings = {**module, **settings}
        return await create_module(course_id, section, "glossary", name, intro, visible, settings, confirm)

    @mcp.tool(
        description=f"{WRITE_NOTE} Create a feedback (survey) activity in a course section. {CONFIRM_NOTE} "
        "Questions are added in Moodle afterwards. timeopen/timeclose: unix timestamps. completion_submit "
        "completes it on submission. " + SETTINGS_NOTE
    )
    async def create_feedback(
        course_id: int,
        section: int,
        name: str,
        intro: str = "",
        anonymous: bool = True,
        multiple_submit: bool = False,
        timeopen: int | None = None,
        timeclose: int | None = None,
        page_after_submit: str = "",
        completion_submit: bool = False,
        visible: int = 1,
        settings: dict[str, Any] = {},  # noqa: B006 - never mutated
        confirm: bool = False,
    ) -> dict[str, Any]:
        module: dict[str, Any] = {"anonymous": 1 if anonymous else 2, "multiple_submit": int(multiple_submit)}
        times = {"timeopen": timeopen, "timeclose": timeclose}
        module.update({k: v for k, v in times.items() if v is not None})
        if page_after_submit:
            module["page_after_submit"] = page_after_submit
        if completion_submit:
            module.update(completion=2, completionsubmit=1)
        settings = {**module, **settings}
        return await create_module(course_id, section, "feedback", name, intro, visible, settings, confirm)

    @mcp.tool(
        description=f"{WRITE_NOTE} Upload a .h5p package and create an H5P activity in a course section. "
        f"{CONFIRM_NOTE} Give exactly one of file_url (downloaded by the server, max 200 MB) or file_base64. "
        "completion_pass_grade: passing grade (out of grade) that completes the activity. " + SETTINGS_NOTE
    )
    async def create_h5pactivity(
        course_id: int,
        section: int,
        name: str,
        filename: str,
        file_url: str | None = None,
        file_base64: str | None = None,
        intro: str = "",
        grade: float = 100,
        completion_pass_grade: float | None = None,
        completion_view: bool = False,
        visible: int = 1,
        settings: dict[str, Any] = {},  # noqa: B006 - never mutated
        confirm: bool = False,
    ) -> dict[str, Any]:
        if not filename.lower().endswith(".h5p"):
            return {"error": "filename must end with .h5p"}
        module: dict[str, Any] = {"grade": grade}
        if completion_pass_grade is not None:
            module.update(completion=2, completionusegrade=1, completionpassgrade=1, gradepass=completion_pass_grade)
        if completion_view:
            module.update(completion=2, completionview=1)
        return await create_with_file(
            course_id, section, "h5pactivity", name, intro, visible, {**module, **settings}, "packagefile", filename,
            file_url, file_base64, confirm,
        )  # fmt: skip

    @mcp.tool(
        description=f"{WRITE_NOTE} Create an OpenMAIC multi-agent lecture activity in a course section. "
        f"{CONFIRM_NOTE} prompt: lecture manuscript / generation prompt (generation is started on the activity "
        "page); lecture_id links an existing OpenMAIC lecture instead. completion_min_progress: percent watched "
        "that completes the activity (0 = no completion rule). " + SETTINGS_NOTE
    )
    async def create_openmaic(
        course_id: int,
        section: int,
        name: str,
        intro: str = "",
        prompt: str = "",
        lecture_id: str | None = None,
        completion_min_progress: int = 80,
        grade: int = 100,
        visible: int = 1,
        settings: dict[str, Any] = {},  # noqa: B006 - never mutated
        confirm: bool = False,
    ) -> dict[str, Any]:
        if not 0 <= completion_min_progress <= 100:
            return {"error": "completion_min_progress must be between 0 and 100"}
        module: dict[str, Any] = {"grade": grade}
        if prompt:
            module["manuscript"] = prompt
        if lecture_id:
            module["lectureid"] = lecture_id
        if completion_min_progress > 0:
            module.update(completion=2, completionminprogress=completion_min_progress)
        settings = {**module, **settings}
        res = await create_module(course_id, section, "openmaic", name, intro, visible, settings, confirm)
        if isinstance(res, dict) and "error" in res:
            res["hint"] = OPTIONAL_HINT.format(plugin="mod_openmaic")
        return res

    @mcp.tool(
        description=f"{WRITE_NOTE} Define (or replace) the rubric of an activity. {CONFIRM_NOTE} "
        "Assignments (area 'submissions') and other advanced-grading areas get a ready rubric shown to students; "
        "a workshop with strategy 'rubric' gets its assessment form replaced (whole-number scores 0-100; area "
        "ignored). Each criterion needs >= 2 levels with distinct scores. Fails once the rubric was used."
    )
    async def set_rubric(
        cmid: int,
        name: str,
        criteria: list[RubricCriterion],
        description: str = "",
        area: str = "submissions",
        confirm: bool = False,
    ) -> dict[str, Any]:
        if not criteria:
            return {"error": "criteria must not be empty"}
        if any(len(c.levels) < 2 for c in criteria):
            return {"error": "every criterion needs at least 2 levels"}
        payload = [c.model_dump() for c in criteria]
        preview = {"cmid": cmid, "name": name, "area": area, "criteria": payload,
                   "max_score": sum(max(lv.score for lv in c.levels) for c in criteria)}  # fmt: skip
        return await write(
            "local_ubionai_set_rubric", preview, confirm,
            cmid=cmid, name=name, criteria=_dumps(payload), description=description, areaname=area,
        )  # fmt: skip

    @mcp.tool(
        description=f"{WRITE_NOTE} Organise the gradebook into weighted categories under the course total and move "
        f"activities' grade items into them. {CONFIRM_NOTE} aggregation (course total and new categories): "
        "weighted_mean (weight = coefficient, e.g. percent) | natural (weight = percent) | mean (weights ignored). "
        "Categories are reused by name."
    )
    async def set_grade_categories(
        course_id: int,
        categories: list[GradeCategory],
        aggregation: Literal["weighted_mean", "natural", "mean"] = "weighted_mean",
        confirm: bool = False,
    ) -> dict[str, Any]:
        if not categories:
            return {"error": "categories must not be empty"}
        if aggregation != "mean" and any(c.weight is None for c in categories):
            return {"error": f"every category needs a weight for {aggregation}"}
        payload = [c.model_dump(exclude_none=True) for c in categories]
        preview = {"course_id": course_id, "aggregation": aggregation, "categories": payload}
        if aggregation != "mean":
            preview["total_weight"] = sum(c.weight or 0 for c in categories)
        return await write(
            "local_ubionai_set_grade_categories", preview, confirm,
            courseid=course_id, categories=_dumps(payload), aggregation=aggregation,
        )  # fmt: skip

    @mcp.tool(
        description=f"{WRITE_NOTE} Create a course badge awarded when all activity_cmids are completed and/or the "
        f"course is completed with at least min_course_grade. {CONFIRM_NOTE} The activities need completion "
        "tracking; the course-grade criterion needs course completion configured. enable=true activates it "
        "(it can no longer be edited freely once awarded)."
    )
    async def create_badge(
        course_id: int,
        name: str,
        description: str,
        activity_cmids: list[int] = [],  # noqa: B006 - never mutated
        min_course_grade: float | None = None,
        enable: bool = False,
        confirm: bool = False,
    ) -> dict[str, Any]:
        if not activity_cmids and min_course_grade is None:
            return {"error": "give activity_cmids and/or min_course_grade"}
        if not description.strip():
            return {"error": "description must not be empty"}
        criteria = {"activities": activity_cmids, "min_course_grade": min_course_grade}
        preview = {"course_id": course_id, "name": name, "description": description, "criteria": criteria,
                   "enable": enable}  # fmt: skip
        return await write(
            "local_ubionai_create_badge", preview, confirm,
            courseid=course_id, name=name, description=description, criteria=_dumps(criteria), enable=enable,
        )  # fmt: skip

    @mcp.tool(
        description=f"{WRITE_NOTE} Update an activity (local_ubionai_update_module). {CONFIRM_NOTE} "
        "Empty name/intro and visible=-1 mean unchanged. settings: module fields to change, e.g. "
        '{"duedate": 1767225600} or {"timeclose": ...}; other settings are kept.'
    )
    async def update_activity(
        cmid: int,
        name: str = "",
        intro: str = "",
        visible: int = -1,
        settings: dict[str, Any] = {},  # noqa: B006 - never mutated
        confirm: bool = False,
    ) -> dict[str, Any]:
        change = {"cmid": cmid, "name": name, "intro": intro, "visible": visible, "settings": settings}
        return await write(
            "local_ubionai_update_module", {"change": change}, confirm,
            cmid=cmid, name=name, intro=intro, visible=visible, settings=_dumps(settings),
        )  # fmt: skip

    @mcp.tool(description=f"{WRITE_NOTE} Show or hide an activity on the course page. {CONFIRM_NOTE}")
    async def set_activity_visibility(cmid: int, visible: bool, confirm: bool = False) -> dict[str, Any]:
        action = "show" if visible else "hide"
        preview = {"cmid": cmid, "action": action}
        result = await write("core_course_edit_module", preview, confirm, action=action, id=cmid)
        # Moodle answers with the re-rendered activity HTML; report just the outcome.
        return {"ok": True, "cmid": cmid, "visible": visible} if result.get("ok") else result

    @mcp.tool(
        description=f"{WRITE_NOTE} Set the completion rule of an activity. {CONFIRM_NOTE} "
        "mode: none | manual | view | submit (assignment) | grade (receive a grade) | "
        "pass (passing grade; pass_grade sets it) | posts (forum; posts = number of posts). "
        "Completion must be enabled in the course settings."
    )
    async def set_completion(
        cmid: int, mode: str, posts: int = 1, pass_grade: float | None = None, confirm: bool = False
    ) -> dict[str, Any]:
        settings: dict[str, Any]
        match mode:
            case "none":
                settings = {"completion": 0}
            case "manual":
                settings = {"completion": 1}
            case "view":
                settings = {"completion": 2, "completionview": 1}
            case "submit":
                settings = {"completion": 2, "completionsubmit": 1}
            case "grade":
                settings = {"completion": 2, "completionusegrade": 1}
            case "pass":
                settings = {"completion": 2, "completionusegrade": 1, "completionpassgrade": 1}
                if pass_grade is not None:
                    settings["gradepass"] = pass_grade
            case "posts":
                if posts < 1:
                    return {"error": "posts must be >= 1"}
                settings = {"completion": 2, "completionposts": posts}
            case _:
                return {"error": f"mode must be one of {sorted(COMPLETION_MODES)}"}
        return await write(
            "local_ubionai_update_module", {"cmid": cmid, "settings": settings}, confirm,
            cmid=cmid, settings=_dumps(settings),
        )  # fmt: skip

    @mcp.tool(
        description=f"{WRITE_NOTE} Restrict access to an activity (target = cmid) or a section (target = section "
        f"number): require completion of required_cmids and/or a start date open_from (unix timestamp). "
        f"Replaces existing restrictions; empty required_cmids and no open_from removes them. {CONFIRM_NOTE}"
    )
    async def set_access_restriction(
        target_type: str,
        course_id: int,
        target: int,
        required_cmids: list[int] = [],  # noqa: B006 - never mutated
        open_from: int | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        availability = _availability(required_cmids, open_from)
        preview = {"target_type": target_type, "course_id": course_id, "target": target, "availability": availability}
        if target_type == "activity":
            return await write(
                "local_ubionai_update_module", preview, confirm,
                cmid=target, settings=_dumps({"availability": availability}),
            )  # fmt: skip
        if target_type == "section":
            return await write(
                "local_ubionai_set_section_availability", preview, confirm,
                courseid=course_id, section=target, availability=availability,
            )  # fmt: skip
        return {"error": "target_type must be 'activity' or 'section'"}

    @mcp.tool(
        description=f"{WRITE_NOTE} Create questions and add them to a quiz (quiz_id = quiz instance id, not cmid). "
        f"Fails if the quiz already has attempts. {CONFIRM_NOTE}"
    )
    async def add_quiz_questions(quiz_id: int, questions: list[QuizQuestion], confirm: bool = False) -> dict[str, Any]:
        payload = [q.model_dump(exclude_none=True) for q in questions]
        return await write(
            "local_ubionai_add_quiz_questions", {"quiz_id": quiz_id, "questions": payload}, confirm,
            quizid=quiz_id, questions=_dumps(payload),
        )  # fmt: skip

    @mcp.tool(
        description=f"{WRITE_NOTE} Append sections to a course. summaries (HTML) are matched to names by position. "
        f"{CONFIRM_NOTE}"
    )
    async def add_sections(
        course_id: int, names: list[str], summaries: list[str] | None = None, confirm: bool = False
    ) -> dict[str, Any]:
        if summaries and len(summaries) > len(names):
            return {"error": "summaries must not have more items than names"}
        return await write(
            "local_ubionai_add_sections", {"course_id": course_id, "names": names, "summaries": summaries or []},
            confirm, courseid=course_id, names=names, summaries=summaries or None,
        )  # fmt: skip

    @mcp.tool(
        description=f"{WRITE_NOTE} Rename a course section and/or change its summary (HTML). Omitted values stay "
        f"unchanged; name='' restores the default name. {CONFIRM_NOTE}"
    )
    async def update_section(
        course_id: int, section: int, name: str | None = None, summary: str | None = None, confirm: bool = False
    ) -> dict[str, Any]:
        if name is None and summary is None:
            return {"error": "give name and/or summary"}
        return await write(
            "local_ubionai_update_section",
            {"course_id": course_id, "section": section, "name": name, "summary": summary}, confirm,
            courseid=course_id, section=section, name=name, summary=summary,
        )  # fmt: skip

    @mcp.tool(
        description=f"{WRITE_NOTE} Post a new discussion to a forum (forum_id = forum instance id). {CONFIRM_NOTE}"
    )
    async def post_forum_discussion(forum_id: int, subject: str, message: str, confirm: bool = False) -> dict[str, Any]:
        return await write(
            "mod_forum_add_discussion", {"forum_id": forum_id, "subject": subject, "message": message}, confirm,
            forumid=forum_id, subject=subject, message=message,
        )  # fmt: skip

    @mcp.tool()
    async def list_forum_discussions(forum_id: int) -> dict[str, Any]:
        """List the discussions of a forum (forum instance id) with all their posts."""
        listing = await call("mod_forum_get_forum_discussions", key="discussions", forumid=forum_id)
        if "error" in listing:
            return listing
        discussions = []
        for d in listing.get("discussions") or []:
            discussion_id = d.get("discussion") or d.get("id")
            posts_reply = await call("mod_forum_get_discussion_posts", key="posts", discussionid=discussion_id)
            entry = {
                "id": discussion_id,
                "name": d.get("name") or d.get("subject"),
                "author": d.get("userfullname"),
                "timecreated": d.get("created"),
                "timemodified": d.get("timemodified"),
                "numreplies": d.get("numreplies"),
                "pinned": d.get("pinned"),
            }
            if "error" in posts_reply:
                entry["posts_error"] = posts_reply["error"]
            else:
                entry["posts"] = [_post(p) for p in posts_reply.get("posts") or []]
            discussions.append(entry)
        return {"discussions": discussions}

    return mcp


def _post(p: dict[str, Any]) -> dict[str, Any]:
    author = p.get("author")
    return {
        "id": p.get("id"),
        "parentid": p.get("parentid", p.get("parent")),
        "subject": p.get("subject"),
        "message": p.get("message"),
        "author": author.get("fullname") if isinstance(author, dict) else (author or p.get("userfullname")),
        "timecreated": p.get("timecreated", p.get("created")),
    }


class BearerAuthMiddleware:
    """Require `Authorization: Bearer <token>` on every request except GET /health."""

    def __init__(self, app: ASGIApp, token: str) -> None:
        if not token:
            raise ValueError("bearer token must not be empty")
        self.app = app
        self._expected = f"Bearer {token}".encode()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return

        if scope["path"] in ("/health", "/healthz") and scope["method"] in ("GET", "HEAD"):
            await _json(send, 200, {"status": "ok"})
            return

        provided = b""
        for name, value in scope.get("headers", []):
            if name == b"authorization":
                provided = value
                break
        if not hmac.compare_digest(provided, self._expected):
            await _json(send, 401, {"error": "unauthorized"}, [(b"www-authenticate", b"Bearer")])
            return
        await self.app(scope, receive, send)


async def _json(send: Send, status: int, body: dict[str, Any], extra: list[tuple[bytes, bytes]] | None = None) -> None:
    payload = json.dumps(body).encode()
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode())]
    await send({"type": "http.response.start", "status": status, "headers": headers + (extra or [])})
    await send({"type": "http.response.body", "body": payload})


def _bearer_from_scope(scope: Scope) -> str | None:
    provided: bytes | None = None
    for name, value in scope.get("headers", []):
        if name.lower() == b"authorization":
            provided = value
            break
    if provided is None:
        return None
    try:
        text = provided.decode("latin-1")
    except UnicodeDecodeError:  # pragma: no cover - latin-1 never fails
        return None
    scheme, separator, token = text.partition(" ")
    if scheme != "Bearer" or not separator or not token:
        return None
    if token.strip() != token or any(char.isspace() for char in token):
        return None
    return token


async def _read_body(receive: Receive, limit: int | None = None) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            break
        if message["type"] != "http.request":
            continue
        chunk = message.get("body", b"")
        size += len(chunk)
        if limit is not None and size > limit:
            raise BodyTooLarge
        chunks.append(chunk)
        if not message.get("more_body", False):
            break
    return b"".join(chunks)


async def _handle_register(
    scope: Scope,
    receive: Receive,
    send: Send,
    registry: Registry,
    public_url: str,
    egress_ip: str | None,
) -> None:
    if scope.get("method") != "POST":
        await _json(send, 404, {"error": "not found"})
        return

    headers = {name.lower(): value for name, value in scope.get("headers", [])}
    content_type = headers.get(b"content-type", b"").split(b";", 1)[0].strip().lower()
    if content_type != b"application/json":
        await _json(send, 415, {"error": "unsupported media type"})
        return
    try:
        content_length = int(headers.get(b"content-length", b"0"))
    except ValueError:
        content_length = 0
    if content_length > MAX_REGISTER_BYTES:
        await _json(send, 413, {"error": "request too large"})
        return

    try:
        body = await _read_body(receive, MAX_REGISTER_BYTES)
    except BodyTooLarge:
        await _json(send, 413, {"error": "request too large"})
        return
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        await _json(send, 400, {"error": "invalid request"})
        return
    required = {"registration_code", "site_url", "wstoken"}
    if not isinstance(payload, dict) or set(payload) != required:
        await _json(send, 400, {"error": "invalid request"})
        return
    code = payload["registration_code"]
    site_url = payload["site_url"]
    wstoken = payload["wstoken"]
    if not all(isinstance(value, str) and value for value in (code, site_url, wstoken)):
        await _json(send, 400, {"error": "invalid request"})
        return

    claimed = registry.lookup_code(code, int(time.time()))
    if claimed is None:
        await _json(send, 403, {"error": "forbidden"})
        return
    site_id, bound_url = claimed
    allow_http = os.environ.get("UBIONAI_HUB_ALLOW_HTTP") == "1"
    try:
        normalized = normalize_moodle_url(site_url, allow_http)
    except TenantError:
        await _json(send, 403, {"error": "forbidden"})
        return
    if normalized != bound_url:
        await _json(send, 403, {"error": "forbidden"})
        return
    if registry.get(site_id) is not None:
        await _json(send, 409, {"error": "conflict"})
        return

    try:
        info = await MoodleClient(ws_endpoint(bound_url), wstoken).call("core_webservice_get_site_info")
    except MoodleError:
        await _json(send, 400, {"error": "registration failed"})
        return
    siteurl = info.get("siteurl") if isinstance(info, dict) else None
    try:
        if not isinstance(siteurl, str) or normalize_moodle_url(siteurl, allow_http) != bound_url:
            await _json(send, 400, {"error": "registration failed"})
            return
    except TenantError:
        await _json(send, 400, {"error": "registration failed"})
        return

    bearer = secrets.token_urlsafe(32)
    try:
        registry.add(site_id, bound_url, wstoken.encode(), None, bearer)
    except DuplicateSite:
        await _json(send, 409, {"error": "conflict"})
        return
    except TenantError:
        await _json(send, 400, {"error": "registration failed"})
        return

    if not registry.consume_code(code, int(time.time())):
        try:
            registry.delete(site_id)
        except TenantError:
            pass
        await _json(send, 403, {"error": "forbidden"})
        return

    await _json(
        send,
        200,
        {
            "site_id": site_id,
            "mcp_endpoint": f"{public_url}/t/{site_id}/mcp",
            "mcp_bearer": bearer,
            "egress_ip": egress_ip,
        },
    )


def _pseudonymize_content(content: Any, pseudonymizer: Pseudonymizer) -> Any:
    if isinstance(content, str):
        return pseudonymizer.pseudonymize(content)
    parts = []
    for part in content:
        if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
            part = {**part, "text": pseudonymizer.pseudonymize(part["text"])}
        parts.append(part)
    return parts


def _restore_chat_response(data: Any, pseudonymizer: Pseudonymizer) -> Any:
    if not isinstance(data, dict):
        return data
    choices = data.get("choices")
    if not isinstance(choices, list):
        return data
    for choice in choices:
        if not isinstance(choice, dict):
            continue
        message = choice.get("message")
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, str):
            message["content"] = pseudonymizer.restore(content)
        elif isinstance(content, list):
            for part in content:
                if (
                    isinstance(part, dict)
                    and part.get("type") == "text"
                    and isinstance(part.get("text"), str)
                ):
                    part["text"] = pseudonymizer.restore(part["text"])
        tool_calls = message.get("tool_calls")
        if not isinstance(tool_calls, list):
            continue
        for call in tool_calls:
            function = call.get("function") if isinstance(call, dict) else None
            arguments = function.get("arguments") if isinstance(function, dict) else None
            if not isinstance(arguments, str):
                continue
            try:
                parsed = json.loads(arguments)
            except (ValueError, TypeError):
                continue
            if isinstance(parsed, (dict, list)):
                function["arguments"] = json.dumps(
                    pseudonymizer.restore_value(parsed), ensure_ascii=False
                )
    return data


def _valid_chat_messages(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    messages = payload.get("messages")
    if not isinstance(messages, list):
        return False
    for message in messages:
        if not isinstance(message, dict) or not isinstance(message.get("role"), str):
            return False
        content = message.get("content")
        if isinstance(content, str):
            continue
        if content is None and isinstance(message.get("tool_calls"), list):
            continue
        if not isinstance(content, list):
            return False
        for part in content:
            if (
                not isinstance(part, dict)
                or part.get("type") != "text"
                or not isinstance(part.get("text"), str)
            ):
                return False
    return True


async def _handle_chat_proxy(
    scope: Scope,
    receive: Receive,
    send: Send,
    registry: Registry,
    tenant: Any,
    pseudonymizer: Pseudonymizer | None,
) -> None:
    if scope.get("method") != "POST":
        await _json(send, 404, {"error": "not found"})
        return

    headers = {name.lower(): value for name, value in scope.get("headers", [])}
    try:
        content_length = int(headers.get(b"content-length", b"0"))
    except ValueError:
        content_length = 0
    if content_length > MAX_CHAT_BYTES:
        await _json(send, 413, {"error": "request too large"})
        return

    try:
        body = await _read_body(receive, MAX_CHAT_BYTES)
    except BodyTooLarge:
        await _json(send, 413, {"error": "request too large"})
        return
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        await _json(send, 400, {"error": "invalid request"})
        return
    if not _valid_chat_messages(payload):
        await _json(send, 400, {"error": "invalid request"})
        return

    key_buf: bytearray | None = None
    try:
        try:
            key_buf = registry.litellm_key(tenant)
        except DecryptError:
            logger.error("decrypt failed site=%s", tenant.site_id)
            await _json(send, 500, {"error": "internal error"})
            return
        if key_buf is None:
            await _json(send, 403, {"error": "forbidden"})
            return

        if pseudonymizer is not None:
            payload = pseudonymizer.pseudonymize_chat_payload(payload)
        if payload.get("stream") is True:
            payload["stream"] = False

        base_url = (os.environ.get("UBIONAI_HUB_LITELLM_URL") or "http://litellm:4000").rstrip("/")
        try:
            key = bytes(key_buf).decode()
            async with httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=10.0)) as http:
                upstream = await http.post(
                    base_url + "/v1/chat/completions",
                    json=payload,
                    headers={"Authorization": f"Bearer {key}"},
                )
        except (httpx.HTTPError, UnicodeDecodeError):
            await _json(send, 502, {"error": "upstream error"})
            return

        try:
            data = upstream.json()
        except ValueError:
            text = upstream.text
            if pseudonymizer is not None:
                text = pseudonymizer.restore(text)
            await _send_raw(send, upstream.status_code, text.encode(), b"text/plain")
            return
        if pseudonymizer is not None:
            data = _restore_chat_response(data, pseudonymizer)
        await _json(send, upstream.status_code, data)
    finally:
        if key_buf is not None:
            key_buf[:] = b"\x00" * len(key_buf)


async def _send_raw(send: Send, status: int, payload: bytes, content_type: bytes) -> None:
    headers = [(b"content-type", content_type), (b"content-length", str(len(payload)).encode())]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": payload})


class RegisterEndpoint:
    """ASGI wrapper that serves POST /register in multi-tenant mode."""

    def __init__(
        self,
        app: ASGIApp,
        registry: Registry,
        kek: Kek,
        public_url: str,
        egress_ip: str | None,
    ) -> None:
        self.app = app
        self.registry = registry
        self.kek = kek
        self.public_url = public_url
        self.egress_ip = egress_ip

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if scope.get("path") == "/register":
            await _handle_register(
                scope, receive, send, self.registry, self.public_url, self.egress_ip
            )
            return
        await self.app(scope, receive, send)


class TenantRouterMiddleware:
    """Authenticate a tenant, then route /t/<site_id>/mcp to the MCP app."""

    def __init__(
        self,
        app: ASGIApp,
        registry: Registry,
        kek: Kek,
        pseudonymizers: _PseudonymizerStore | None = None,
        oauth: OAuthServer | None = None,
        moodle_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.app = app
        self.registry = registry
        self.pseudonymizers = pseudonymizers or _PseudonymizerStore(registry, kek)
        self.oauth = oauth
        self.moodle_transport = moodle_transport

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return

        path = scope.get("path", "")
        method = scope.get("method", "")
        if path in ("/health", "/healthz") and method in ("GET", "HEAD"):
            await _json(send, 200, {"status": "ok"})
            return
        if path == "/register":
            await self.app(scope, receive, send)
            return

        match = TENANT_PATH_RE.fullmatch(path)
        chat_match = CHAT_PATH_RE.fullmatch(path)
        raw_path = scope.get("raw_path")
        if raw_path:
            try:
                raw_text = raw_path.decode("latin-1")
            except UnicodeDecodeError:  # pragma: no cover - latin-1 never fails
                raw_text = ""
            if TENANT_PATH_RE.fullmatch(raw_text) is None:
                match = None
            if CHAT_PATH_RE.fullmatch(raw_text) is None:
                chat_match = None
        if match is None and chat_match is None:
            raw_ok = not raw_path or raw_path.decode("latin-1") == path
            if self.oauth is not None and raw_ok and self.oauth.handles(path):
                await self.oauth(scope, receive, send)
                return
            await _json(send, 404, {"error": "not found"})
            return

        if chat_match is not None:
            site_id = chat_match.group(1)
            bearer = _bearer_from_scope(scope)
            verified = (
                self.registry.verify_bearer(site_id, bearer)
                if bearer is not None
                else None
            )
            if verified is None or verified.litellm_ct is None:
                await _json(send, 403, {"error": "forbidden"})
                return
            pseudonymizer = self.pseudonymizers.get(
                site_id, verified.pseudonymize, verified.assignment_title_heuristic
            )
            await _handle_chat_proxy(
                scope, receive, send, self.registry, verified, pseudonymizer
            )
            return

        site_id = match.group(1)

        oauth_on = self.oauth is not None and self.oauth.enabled(site_id)
        bearer = _bearer_from_scope(scope)
        if bearer is None:
            challenge = self.oauth.challenge(site_id) if oauth_on and self.oauth else b"Bearer"
            await _json(send, 401, {"error": "unauthorized"}, [(b"www-authenticate", challenge)])
            return
        # The tenant's static bearer keeps working; otherwise an OAuth access token of a teacher.
        tenant = self.registry.verify_bearer(site_id, bearer)
        grant = None
        if tenant is None and oauth_on and self.oauth is not None:
            grant = self.oauth.authenticate(site_id, bearer)
            tenant = self.registry.get(site_id) if grant is not None else None
            if grant is None or tenant is None or tenant.status != "active":
                await _json(
                    send,
                    401,
                    {"error": "invalid_token"},
                    [(b"www-authenticate", self.oauth.challenge(site_id, "invalid_token"))],
                )
                return
        if tenant is None:
            await _json(send, 403, {"error": "forbidden"})
            return

        token_buf: bytearray | None = None
        try:
            try:
                if grant is not None and self.oauth is not None:
                    token_buf = self.oauth.user_token(tenant, grant)
                else:
                    token_buf = self.registry.moodle_token(tenant)
            except DecryptError:
                logger.error("decrypt failed site=%s", site_id)
                await _json(send, 500, {"error": "internal error"})
                return
            client = MoodleClient(ws_endpoint(tenant.moodle_url), token_buf, transport=self.moodle_transport)
            pseudonymizer = self.pseudonymizers.get(
                site_id, tenant.pseudonymize, tenant.assignment_title_heuristic
            )
            state = scope.setdefault("state", {})
            state["moodle_client"] = client
            state["pseudonymizer"] = pseudonymizer
            userid = grant.moodle_userid if grant is not None else None
            state["moodle_userid"] = userid
            scope["path"] = "/mcp"
            scope["raw_path"] = b"/mcp"
            context_token = _current_client.set(client)
            pseudonymizer_token = _current_pseudonymizer.set(pseudonymizer)
            userid_token = _current_userid.set(userid)
            try:
                await self.app(scope, receive, send)
            finally:
                _current_userid.reset(userid_token)
                _current_pseudonymizer.reset(pseudonymizer_token)
                _current_client.reset(context_token)
        finally:
            if token_buf is not None:
                token_buf[:] = b"\x00" * len(token_buf)


def create_app(
    *,
    moodle_endpoint: str | None = None,
    moodle_token: str | None = None,
    bearer_token: str | None = None,
    hub_db: str | None = None,
    kek_file: str | None = None,
    tenant_secrets_dir: str | None = None,
    moodle_transport: httpx.AsyncBaseTransport | None = None,
) -> ASGIApp:
    """Build the full ASGI app. Values default to env vars."""
    db_path = hub_db if hub_db is not None else os.environ.get("UBIONAI_HUB_DB", "")
    if not db_path:
        endpoint = moodle_endpoint if moodle_endpoint is not None else os.environ.get("MOODLE_WS_ENDPOINT", "")
        token = moodle_token if moodle_token is not None else os.environ.get("MOODLE_TOKEN", "")
        bearer = bearer_token if bearer_token is not None else os.environ.get("MCP_BEARER_TOKEN", "")
        if not bearer.strip():
            raise RuntimeError("MCP_BEARER_TOKEN is empty; refusing to start")
        if not endpoint or not token:
            logger.warning("MOODLE_WS_ENDPOINT or MOODLE_TOKEN not set; tool calls will return errors")

        mcp = create_mcp(MoodleClient(endpoint, token))
        return BearerAuthMiddleware(mcp.streamable_http_app(), bearer.strip())

    kek_path = kek_file if kek_file is not None else os.environ.get("UBIONAI_HUB_KEK_FILE", "")
    if not kek_path:
        raise RuntimeError("KEK file invalid")
    try:
        kek = load_kek(kek_path)
    except KekError:
        raise RuntimeError("KEK file invalid") from None

    registry = Registry.open(db_path, kek)
    kek_ids = registry.kek_ids()
    if kek_ids and kek.kek_id not in kek_ids:
        raise RuntimeError("KEK file invalid")

    if (
        moodle_token
        or bearer_token
        or os.environ.get("MOODLE_TOKEN")
        or os.environ.get("MCP_BEARER_TOKEN")
    ):
        raise RuntimeError("global Moodle credentials are not allowed in multi-tenant mode")

    public_url = (os.environ.get("UBIONAI_HUB_PUBLIC_URL") or "").rstrip("/")
    try:
        egress_ip = parse_ip_list(os.environ.get("UBIONAI_HUB_EGRESS_IP"))
    except ValueError as exc:
        raise RuntimeError(f"UBIONAI_HUB_EGRESS_IP invalid: {exc}") from None

    # Per-teacher OAuth (Easy Connect trial): on when a tenant secrets directory is configured;
    # per site only when <dir>/<site>/oauth.secret exists. Off -> static bearers only, as before.
    secrets_dir = (
        tenant_secrets_dir
        if tenant_secrets_dir is not None
        else os.environ.get("UBIONAI_HUB_TENANT_SECRETS_DIR", "")
    )
    oauth: OAuthServer | None = None
    if secrets_dir:
        if not public_url:
            raise RuntimeError("UBIONAI_HUB_PUBLIC_URL is required with UBIONAI_HUB_TENANT_SECRETS_DIR")
        try:
            oauth = OAuthServer(registry, kek, public_url, secrets_dir, transport=moodle_transport)
        except OAuthConfigError as exc:
            raise RuntimeError(str(exc)) from None

    mcp = create_mcp(None)
    inner = RegisterEndpoint(
        mcp.streamable_http_app(), registry, kek, public_url, egress_ip
    )
    return TenantRouterMiddleware(inner, registry, kek, oauth=oauth, moodle_transport=moodle_transport)
