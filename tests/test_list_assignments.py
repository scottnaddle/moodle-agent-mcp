import json
from urllib.parse import parse_qs

import httpx
import respx

from moodle_mcp.moodle import MoodleClient
from moodle_mcp.pseudonym import PLACEHOLDER_RE, Pseudonymizer
from moodle_mcp.server import (
    OPTIONAL_HINT,
    _current_pseudonymizer,
    _is_write,
    create_mcp,
)

from .conftest import ENDPOINT, MOODLE_TOKEN


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


async def call_list_assignments(replies, course_ids=None):
    handler, calls = make_handler(replies)
    with respx.mock as router:
        router.post(ENDPOINT).mock(side_effect=handler)
        args = {} if course_ids is None else {"course_ids": course_ids}
        _content, result = await mcp().call_tool("list_assignments", args)
    return result, calls


async def test_enrolled_course_does_not_fall_back():
    primary = {"courses": [{"id": 5, "fullname": "Course", "assignments": []}], "warnings": []}
    result, calls = await call_list_assignments(
        {"mod_assign_get_assignments": primary}, course_ids=[5]
    )
    assert result["courses"] == primary["courses"]
    assert [call["wsfunction"] for call in calls] == ["mod_assign_get_assignments"]
    assert "source" not in result["courses"][0]


async def test_non_enrolled_course_uses_fallback_and_tags_source():
    fallback = {
        "courses": [
            {"id": 5, "fullname": "Course", "shortname": "C", "assignments": [{"id": 9}]}
        ],
        "warnings": [],
    }
    result, calls = await call_list_assignments(
        {
            "mod_assign_get_assignments": {"courses": [], "warnings": []},
            "local_ubionai_get_course_assignments": fallback,
        },
        course_ids=[5],
    )
    assert [call["wsfunction"] for call in calls] == [
        "mod_assign_get_assignments",
        "local_ubionai_get_course_assignments",
    ]
    assert calls[1]["courseid"] == "5"
    assert result["courses"] == [
        {**fallback["courses"][0], "source": "local_ubionai"}
    ]


async def test_only_missing_ids_fall_back():
    primary = {"courses": [{"id": 5, "fullname": "Five", "assignments": []}], "warnings": []}
    fallback = {"courses": [{"id": 6, "fullname": "Six", "assignments": []}], "warnings": []}
    result, calls = await call_list_assignments(
        {
            "mod_assign_get_assignments": primary,
            "local_ubionai_get_course_assignments": fallback,
        },
        course_ids=[5, 6],
    )
    fallback_calls = [
        call for call in calls if call["wsfunction"] == "local_ubionai_get_course_assignments"
    ]
    assert [call["courseid"] for call in fallback_calls] == ["6"]
    assert result["courses"] == [
        primary["courses"][0],
        {**fallback["courses"][0], "source": "local_ubionai"},
    ]


async def test_fallback_error_reports_error_and_hint():
    error = {
        "exception": "webservice_access_exception",
        "errorcode": "accessexception",
        "message": "Access control exception",
    }
    result, _calls = await call_list_assignments(
        {
            "mod_assign_get_assignments": {"courses": [], "warnings": []},
            "local_ubionai_get_course_assignments": error,
        },
        course_ids=[5],
    )
    assert result["fallback_errors"][0]["courseid"] == 5
    assert "accessexception" in result["fallback_errors"][0]["error"]
    assert result["hint"] == OPTIONAL_HINT.format(plugin="local_ubionai")


async def test_no_ids_and_empty_result_hints_pass_course_ids():
    result, calls = await call_list_assignments(
        {"mod_assign_get_assignments": {"courses": [], "warnings": []}}
    )
    assert [call["wsfunction"] for call in calls] == ["mod_assign_get_assignments"]
    assert result["hint"] == (
        "No courses returned; the service user is not enrolled in any course. "
        "Pass course_ids to list assignments for specific courses."
    )


def test_local_read_function_is_not_a_write():
    assert _is_write("local_ubionai_get_course_assignments") is False
    assert _is_write("local_ubionai_create_module") is True


async def test_fallback_output_is_pseudonymised():
    fallback = {
        "courses": [
            {
                "id": 5,
                "fullname": "Course",
                "assignments": [{"id": 9, "name": "김민수 essay"}],
            }
        ],
        "warnings": [],
    }
    token = _current_pseudonymizer.set(Pseudonymizer())
    try:
        result, _calls = await call_list_assignments(
            {
                "mod_assign_get_assignments": {"courses": [], "warnings": []},
                "local_ubionai_get_course_assignments": fallback,
            },
            course_ids=[5],
        )
    finally:
        _current_pseudonymizer.reset(token)
    rendered = json.dumps(result, ensure_ascii=False)
    assert "김민수" not in rendered
    assert PLACEHOLDER_RE.search(rendered)
    assert result["courses"][0]["source"] == "local_ubionai"
