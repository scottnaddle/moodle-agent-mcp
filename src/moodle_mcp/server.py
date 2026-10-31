"""FastMCP server exposing Moodle read/write tools over Streamable HTTP."""

from __future__ import annotations

import base64
import binascii
import hmac
import html
import json
import logging
import os
import re
from typing import Any, Literal

import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field
from starlette.types import ASGIApp, Receive, Scope, Send

from .moodle import MoodleClient, MoodleError

logger = logging.getLogger(__name__)

EDITINGTEACHER_ROLE_ID = int(os.environ.get("MOODLE_EDITINGTEACHER_ROLE_ID", "3"))
WRITE_NOTE = "WRITE - only call after the teacher confirmed."
CONFIRM_NOTE = "Call first with confirm=false to get a preview; call again with confirm=true after the teacher agrees."
PREVIEW_NOTE = "Nothing changed. Re-call with confirm=true."
MAX_UPLOAD_BYTES = 200 * 1024 * 1024
SUBMISSION_TYPES = {"onlinetext", "file"}
FORUM_TYPES = {"general", "qanda", "single", "eachuser", "blog"}
COMPLETION_MODES = {"none", "manual", "view", "submit", "pass", "grade", "posts"}
YOUTUBE_RE = re.compile(
    r"(?:youtube(?:-nocookie)?\.com/(?:watch\?(?:.*&)?v=|embed/|shorts/|live/)|youtu\.be/)([\w-]{6,})"
)
VIMEO_RE = re.compile(r"vimeo\.com/(?:video/)?(\d+)")


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


async def _download(url: str, limit: int = MAX_UPLOAD_BYTES) -> bytes:
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError("file_url must be an http(s) URL")
    timeout = httpx.Timeout(120.0, connect=10.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        async with client.stream("GET", url) as resp:
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


def _wrap(result: Any, key: str = "result") -> dict[str, Any]:
    return result if isinstance(result, dict) else {key: result}


def create_mcp(client: MoodleClient) -> FastMCP:
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
        return await call("mod_attendance_get_sessions", key="sessions", attendanceid=attendance_id)

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
            return {"preview": True, **preview, "note": PREVIEW_NOTE}
        result = await call(wsfunction, **params)
        return result if "error" in result else {"ok": True, **result}

    async def create_module(
        course_id: int, section: int, modname: str, name: str, intro: str, visible: int,
        settings: dict[str, Any], confirm: bool,
    ) -> dict[str, Any]:  # fmt: skip
        module = {"course_id": course_id, "section": section, "modname": modname, "name": name,
                  "intro": intro, "visible": visible, "settings": settings}  # fmt: skip
        return await write(
            "local_grokbot_create_module", {"module": module}, confirm,
            courseid=course_id, section=section, modname=modname, name=name, intro=intro, visible=visible,
            settings=json.dumps(settings),
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
        if (file_url is None) == (file_base64 is None):
            return {"error": "give exactly one of file_url or file_base64"}
        if not filename.strip() or "/" in filename or "\\" in filename:
            return {"error": "filename must be a plain file name"}
        data: bytes | None = None
        if file_base64 is not None:
            try:
                data = base64.b64decode(file_base64, validate=True)
            except (binascii.Error, ValueError):
                return {"error": "file_base64 is not valid base64"}
            if len(data) > MAX_UPLOAD_BYTES:
                return {"error": f"file is larger than {MAX_UPLOAD_BYTES} bytes"}
        settings: dict[str, Any] = {"completion": 2, "completionview": 1} if completion_view else {}
        if not confirm:
            module = {"course_id": course_id, "section": section, "modname": "resource", "name": name,
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
        settings["files"] = upload["itemid"]
        out = await create_module(course_id, section, "resource", name, intro, visible, settings, True)
        return out if "error" in out else {**out, "size_bytes": len(data)}

    @mcp.tool(
        description=f"{WRITE_NOTE} Update an activity (local_grokbot_update_module). {CONFIRM_NOTE} "
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
            "local_grokbot_update_module", {"change": change}, confirm,
            cmid=cmid, name=name, intro=intro, visible=visible, settings=json.dumps(settings),
        )  # fmt: skip

    @mcp.tool(description=f"{WRITE_NOTE} Show or hide an activity on the course page. {CONFIRM_NOTE}")
    async def set_activity_visibility(cmid: int, visible: bool, confirm: bool = False) -> dict[str, Any]:
        action = "show" if visible else "hide"
        return await write("core_course_edit_module", {"cmid": cmid, "action": action}, confirm, action=action, id=cmid)

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
            "local_grokbot_update_module", {"cmid": cmid, "settings": settings}, confirm,
            cmid=cmid, settings=json.dumps(settings),
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
                "local_grokbot_update_module", preview, confirm,
                cmid=target, settings=json.dumps({"availability": availability}),
            )  # fmt: skip
        if target_type == "section":
            return await write(
                "local_grokbot_set_section_availability", preview, confirm,
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
            "local_grokbot_add_quiz_questions", {"quiz_id": quiz_id, "questions": payload}, confirm,
            quizid=quiz_id, questions=json.dumps(payload),
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
            "local_grokbot_add_sections", {"course_id": course_id, "names": names, "summaries": summaries or []},
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
            "local_grokbot_update_section",
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
