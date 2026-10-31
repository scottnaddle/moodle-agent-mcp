"""FastMCP server exposing Moodle read/write tools over Streamable HTTP."""

from __future__ import annotations

import hmac
import json
import logging
import os
from typing import Any

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field
from starlette.types import ASGIApp, Receive, Scope, Send

from .moodle import MoodleClient, MoodleError

logger = logging.getLogger(__name__)

WRITE_NOTE = "WRITE - only call after the teacher confirmed."


class GradeEntry(BaseModel):
    user_id: int = Field(description="Moodle user id of the student")
    grade: float = Field(description="Grade value")
    feedback_text: str = Field(default="", description="Feedback comment (HTML allowed)")


def _wrap(result: Any, key: str = "result") -> dict[str, Any]:
    return result if isinstance(result, dict) else {key: result}


def create_mcp(client: MoodleClient) -> FastMCP:
    mcp = FastMCP(
        "moodle",
        instructions=(
            "Read and write Moodle data (courses, students, assignments, quizzes, grades, attendance). "
            "Tools marked WRITE change grades: only call them after the teacher explicitly confirmed."
        ),
        host="0.0.0.0",  # disables localhost-only DNS-rebinding host checks; bearer auth guards access
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
    )

    async def call(wsfunction: str, key: str = "result", **params: Any) -> dict[str, Any]:
        try:
            return _wrap(await client.call(wsfunction, **params), key)
        except MoodleError as exc:
            return {"error": str(exc)}

    @mcp.tool()
    async def site_info() -> dict[str, Any]:
        """Get Moodle site info and the identity of the web service user."""
        return await call("core_webservice_get_site_info")

    @mcp.tool()
    async def list_courses(ids: list[int] | None = None) -> dict[str, Any]:
        """List courses. Pass course ids to restrict, or omit for all visible courses."""
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
    async def list_assignments(course_ids: list[int] | None = None) -> dict[str, Any]:
        """List assignments, grouped by course. Omit course_ids for all accessible courses."""
        return await call("mod_assign_get_assignments", courseids=course_ids or None)

    @mcp.tool()
    async def get_submissions(assignment_ids: list[int], status: str = "") -> dict[str, Any]:
        """Get submissions for assignments. Optional status filter (e.g. 'submitted', 'draft')."""
        return await call("mod_assign_get_submissions", assignmentids=assignment_ids, status=status)

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
        return await call("mod_attendance_get_sessions", key="sessions", attendanceid=attendance_id)

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

    return mcp


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

        if scope["path"] == "/health" and scope["method"] in ("GET", "HEAD"):
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


def create_app(
    *,
    moodle_endpoint: str | None = None,
    moodle_token: str | None = None,
    bearer_token: str | None = None,
) -> ASGIApp:
    """Build the full ASGI app (auth middleware + MCP). Values default to env vars."""
    endpoint = moodle_endpoint if moodle_endpoint is not None else os.environ.get("MOODLE_WS_ENDPOINT", "")
    token = moodle_token if moodle_token is not None else os.environ.get("MOODLE_TOKEN", "")
    bearer = bearer_token if bearer_token is not None else os.environ.get("MCP_BEARER_TOKEN", "")
    if not bearer.strip():
        raise RuntimeError("MCP_BEARER_TOKEN is empty; refusing to start")
    if not endpoint or not token:
        logger.warning("MOODLE_WS_ENDPOINT or MOODLE_TOKEN not set; tool calls will return errors")

    mcp = create_mcp(MoodleClient(endpoint, token))
    return BearerAuthMiddleware(mcp.streamable_http_app(), bearer.strip())
