"""Teacher (OAuth) course listing.

A teacher token has no moodle/course:view, so core_course_get_courses is denied
even for the teacher's own courses. The teacher path therefore uses
core_enrol_get_users_courses(userid=own id); the static bearer path is unchanged.
"""

import json
from urllib.parse import parse_qs

import httpx
import respx

from moodle_mcp.moodle import MoodleClient
from moodle_mcp.server import _current_userid, create_mcp

from .conftest import ENDPOINT, MOODLE_TOKEN

ACCESS_ERROR = {
    "exception": "webservice_access_exception",
    "errorcode": "accessexception",
    "message": "Access control exception",
}


def form(request: httpx.Request) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(request.content.decode(), keep_blank_values=True).items()}


def make_handler(replies):
    calls: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        data = form(request)
        calls.append(data)
        payload = replies[data["wsfunction"]]
        if callable(payload):
            payload = payload(data)
        return httpx.Response(200, json=payload)

    return handler, calls


def mcp():
    return create_mcp(MoodleClient(ENDPOINT, MOODLE_TOKEN))


async def call_tool(replies, name, args, userid=None):
    """Run a tool with userid in the request context (None = static bearer)."""
    handler, calls = make_handler(replies)
    token = _current_userid.set(userid)
    try:
        with respx.mock as router:
            router.post(ENDPOINT).mock(side_effect=handler)
            _content, result = await mcp().call_tool(name, args)
    finally:
        _current_userid.reset(token)
    return result, calls


def wsfunctions(calls):
    return [call["wsfunction"] for call in calls]


async def test_teacher_list_courses_uses_enrol_function():
    courses = [{"id": 2, "shortname": "Two"}, {"id": 5, "shortname": "Five"}]
    result, calls = await call_tool(
        {"core_enrol_get_users_courses": courses}, "list_courses", {}, userid=3
    )
    assert wsfunctions(calls) == ["core_enrol_get_users_courses"]
    assert calls[0]["userid"] == "3"
    assert result == {"courses": courses}


async def test_teacher_list_courses_ids_filter():
    result, calls = await call_tool(
        {"core_enrol_get_users_courses": [{"id": 2}, {"id": 5}]},
        "list_courses",
        {"ids": [2, 7]},
        userid=3,
    )
    assert wsfunctions(calls) == ["core_enrol_get_users_courses"]
    # Course 7 is not enrolled: it is dropped silently, not reported as missing.
    assert result == {"courses": [{"id": 2}]}


async def test_teacher_list_assignments_fallback_uses_enrol():
    result, calls = await call_tool(
        {
            "mod_assign_get_assignments": {"courses": [], "warnings": []},
            "local_ubionai_list_course_assignments": ACCESS_ERROR,
            "core_enrol_get_users_courses": [
                {"id": 2, "format": "topics"},
                {"id": 5, "format": "topics"},
            ],
            "local_ubionai_get_course_assignments": ACCESS_ERROR,
        },
        "list_assignments",
        {},
        userid=3,
    )
    functions = wsfunctions(calls)
    assert "core_enrol_get_users_courses" in functions
    assert "core_course_get_courses" not in functions
    enrol = next(c for c in calls if c["wsfunction"] == "core_enrol_get_users_courses")
    assert enrol["userid"] == "3"
    assert result["degraded"]


async def test_static_bearer_list_courses_unchanged():
    result, calls = await call_tool(
        {"core_course_get_courses": [{"id": 5}]}, "list_courses", {}, userid=None
    )
    assert wsfunctions(calls) == ["core_course_get_courses"]
    assert result == {"courses": [{"id": 5}]}

    result, calls = await call_tool(
        {"core_course_get_courses": [{"id": 5}]},
        "list_courses",
        {"ids": [5, 6]},
        userid=None,
    )
    assert wsfunctions(calls) == ["core_course_get_courses"]
    assert calls[0]["options[ids][0]"] == "5"
    assert calls[0]["options[ids][1]"] == "6"


async def test_teacher_list_courses_moodle_error():
    result, calls = await call_tool(
        {"core_enrol_get_users_courses": ACCESS_ERROR}, "list_courses", {}, userid=3
    )
    assert wsfunctions(calls) == ["core_enrol_get_users_courses"]
    assert set(result) == {"error"}
    assert "accessexception" in result["error"]
    assert MOODLE_TOKEN not in json.dumps(result)
