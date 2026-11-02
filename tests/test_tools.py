import json

import pytest
import respx

from moodle_mcp.moodle import MoodleClient
from moodle_mcp.server import WRITE_NOTE, create_mcp

from .conftest import ENDPOINT, MOODLE_TOKEN
from .test_moodle import form

BASE = {"wstoken": MOODLE_TOKEN, "moodlewsrestformat": "json"}
WRITE_TOOLS = {
    "create_course", "create_assignment", "create_quiz", "create_forum", "create_page", "create_resource",
    "update_activity", "set_activity_visibility", "set_completion", "set_access_restriction",
    "add_quiz_questions", "add_sections", "update_section", "post_forum_discussion",
    "create_workshop", "create_wiki", "create_glossary", "create_feedback", "create_h5pactivity", "create_openmaic",
    "set_rubric", "set_grade_categories", "create_badge",
}  # fmt: skip


@pytest.fixture
def mcp():
    return create_mcp(MoodleClient(ENDPOINT, MOODLE_TOKEN))


async def run(mcp, name, args, response):
    with respx.mock:
        route = respx.post(ENDPOINT).respond(text=json.dumps(response))
        _content, structured = await mcp.call_tool(name, args)
        return structured, form(route.calls.last.request)


CASES = [
    ("site_info", {}, "core_webservice_get_site_info", {}),
    ("list_courses", {}, "core_course_get_courses", {}),
    ("list_courses", {"ids": [5, 6]}, "core_course_get_courses", {"options[ids][0]": "5", "options[ids][1]": "6"}),
    ("get_course_outline", {"course_id": 5}, "core_course_get_contents", {"courseid": "5"}),
    ("list_students", {"course_id": 5}, "core_enrol_get_enrolled_users", {"courseid": "5"}),
    ("list_assignments", {}, "local_ubionai_list_course_assignments", {"offset": "0", "limit": "25"}),
    (
        "list_assignments",
        {"course_ids": [5]},
        "local_ubionai_get_course_assignments",
        {"courseid": "5"},
    ),
    (
        "get_submissions",
        {"assignment_ids": [9, 10]},
        "mod_assign_get_submissions",
        {"assignmentids[0]": "9", "assignmentids[1]": "10", "status": ""},
    ),
    (
        "get_submissions",
        {"assignment_ids": [9], "status": "submitted"},
        "mod_assign_get_submissions",
        {"assignmentids[0]": "9", "status": "submitted"},
    ),
    ("list_categories", {}, "core_course_get_categories", {}),
    ("get_assignment_grades", {"assignment_ids": [9]}, "mod_assign_get_grades", {"assignmentids[0]": "9"}),
    ("gradebook_overview", {"course_id": 5}, "gradereport_user_get_grade_items", {"courseid": "5"}),
    (
        "gradebook_overview",
        {"course_id": 5, "user_id": 3},
        "gradereport_user_get_grade_items",
        {"courseid": "5", "userid": "3"},
    ),
    ("list_quizzes", {"course_ids": [5]}, "mod_quiz_get_quizzes_by_courses", {"courseids[0]": "5"}),
    (
        "list_quiz_attempts",
        {"quiz_id": 4, "user_id": 3},
        "mod_quiz_get_user_attempts",
        {"quizid": "4", "userid": "3", "status": "all", "includepreviews": "0"},
    ),
    ("review_attempt", {"attempt_id": 77}, "mod_quiz_get_attempt_review", {"attemptid": "77"}),
    ("attendance_sessions", {"attendance_id": 8}, "mod_attendance_get_sessions", {"attendanceid": "8"}),
    (
        "grade_submission",
        {"assignment_id": 9, "user_id": 3, "grade": 8.5, "feedback_text": "<p>Good</p>"},
        "mod_assign_save_grade",
        {
            "assignmentid": "9",
            "userid": "3",
            "grade": "8.5",
            "attemptnumber": "-1",
            "addattempt": "0",
            "workflowstate": "",
            "applytoall": "1",
            "plugindata[assignfeedbackcomments_editor][text]": "<p>Good</p>",
            "plugindata[assignfeedbackcomments_editor][format]": "1",
        },
    ),
    (
        "grade_submission",
        {"assignment_id": 9, "user_id": 3, "grade": 7, "attempt_number": 2, "workflow_state": "released"},
        "mod_assign_save_grade",
        {
            "assignmentid": "9",
            "userid": "3",
            "grade": "7.0",
            "attemptnumber": "2",
            "addattempt": "0",
            "workflowstate": "released",
            "applytoall": "1",
            "plugindata[assignfeedbackcomments_editor][text]": "",
            "plugindata[assignfeedbackcomments_editor][format]": "1",
        },
    ),
    (
        "bulk_grade",
        {
            "assignment_id": 9,
            "grades": [
                {"user_id": 3, "grade": 8, "feedback_text": "ok"},
                {"user_id": 4, "grade": 6.5},
            ],
        },
        "mod_assign_save_grades",
        {
            "assignmentid": "9",
            "applytoall": "1",
            **{
                f"grades[{i}][{k}]": v
                for i, (uid, g, fb) in enumerate([("3", "8.0", "ok"), ("4", "6.5", "")])
                for k, v in {
                    "userid": uid,
                    "grade": g,
                    "attemptnumber": "-1",
                    "addattempt": "0",
                    "workflowstate": "",
                    "plugindata][assignfeedbackcomments_editor][text": fb,
                    "plugindata][assignfeedbackcomments_editor][format": "1",
                }.items()
            },
        },
    ),
]


@pytest.mark.parametrize(("tool", "args", "wsfunction", "params"), CASES)
async def test_tool_calls_right_wsfunction(mcp, tool, args, wsfunction, params):
    _, sent = await run(mcp, tool, args, {"ok": 1})
    assert sent == {**BASE, "wsfunction": wsfunction, **params}


async def test_list_results_are_wrapped(mcp):
    result, _ = await run(mcp, "list_courses", {}, [{"id": 1}])
    assert result == {"courses": [{"id": 1}]}
    result, _ = await run(mcp, "list_students", {"course_id": 2}, [{"id": 3}])
    assert result == {"users": [{"id": 3}]}


async def test_dict_result_returned_as_is(mcp):
    payload = {"sitename": "Demo", "userid": 2}
    result, _ = await run(mcp, "site_info", {}, payload)
    assert result == payload


async def test_write_tools_report_ok(mcp):
    result, _ = await run(mcp, "grade_submission", {"assignment_id": 1, "user_id": 2, "grade": 3}, None)
    assert result == {"ok": True, "result": None}
    result, _ = await run(mcp, "bulk_grade", {"assignment_id": 1, "grades": [{"user_id": 2, "grade": 3}]}, [])
    assert result == {"ok": True, "graded": 1, "result": []}


async def test_moodle_error_returns_error_dict(mcp):
    err = {"exception": "moodle_exception", "errorcode": "invalidrecord", "message": "Can't find data record"}
    for tool, args in [("site_info", {}), ("grade_submission", {"assignment_id": 1, "user_id": 2, "grade": 3})]:
        result, _ = await run(mcp, tool, args, err)
        assert set(result) == {"error"}
        assert "invalidrecord" in result["error"]
        assert MOODLE_TOKEN not in json.dumps(result)


async def test_write_tools_are_marked(mcp):
    tools = {t.name: t for t in await mcp.list_tools()}
    assert set(tools) == {
        "site_info", "list_courses", "get_course_outline", "list_students", "list_assignments",
        "get_submissions", "get_assignment_grades", "gradebook_overview", "list_quizzes", "list_quiz_attempts", "review_attempt",
        "attendance_sessions", "grade_submission", "bulk_grade", "list_categories", "create_course",
        "list_forum_discussions", *WRITE_TOOLS,
    }  # fmt: skip
    writes = {"grade_submission", "bulk_grade", *WRITE_TOOLS}
    for name in writes:
        assert WRITE_NOTE in tools[name].description
    for name in set(tools) - writes:
        assert "WRITE" not in (tools[name].description or "")


async def test_create_course_preview_does_not_call_moodle(mcp):
    with respx.mock:
        route = respx.post(ENDPOINT).respond(text="{}")
        _c, out = await mcp.call_tool("create_course", {"fullname": "F", "shortname": "S", "numsections": 4})
        assert route.call_count == 0
    assert out["preview"] is True
    assert out["course"]["courseformatoptions"] == [{"name": "numsections", "value": "4"}]


async def create_course_confirmed(mcp, enrol_reply):
    replies = {
        "core_course_create_courses": [{"id": 42, "shortname": "S"}],
        "local_ubionai_enrol_course_creator": enrol_reply,
    }
    with respx.mock:
        route = respx.post(ENDPOINT).mock(
            side_effect=lambda req: respx.MockResponse(text=json.dumps(replies[form(req)["wsfunction"]]))
        )
        _c, out = await mcp.call_tool(
            "create_course", {"fullname": "F", "shortname": "S", "categoryid": 1, "confirm": True}
        )
        return out, [form(c.request) for c in route.calls]


async def test_create_course_confirm_creates_and_enrols(mcp):
    out, calls = await create_course_confirmed(mcp, {"courseid": 42, "roleid": 3, "enrolled": True})
    assert out == {"ok": True, "courseid": 42, "shortname": "S", "roleid": 3, "enrolled": True}
    assert [c["wsfunction"] for c in calls] == ["core_course_create_courses", "local_ubionai_enrol_course_creator"]
    assert calls[0]["courses[0][fullname]"] == "F" and calls[0]["courses[0][categoryid]"] == "1"
    assert calls[1] == {**BASE, "wsfunction": "local_ubionai_enrol_course_creator", "courseid": "42"}


async def test_create_course_already_enrolled_is_success(mcp):
    out, _ = await create_course_confirmed(mcp, {"courseid": 42, "roleid": 3, "enrolled": False})
    assert out == {"ok": True, "courseid": 42, "shortname": "S", "roleid": 3, "enrolled": False}


@pytest.mark.parametrize(
    "err",
    [
        {"exception": "dml_missing_record_exception", "errorcode": "invalidrecord",
         "message": "Can't find data record in database table external_functions."},
        {"exception": "webservice_access_exception", "errorcode": "accessexception",
         "message": "Access control exception"},
    ],
)  # fmt: skip
async def test_create_course_enrol_function_missing_falls_back(mcp, err):
    out, _ = await create_course_confirmed(mcp, err)
    assert out["ok"] is True and out["courseid"] == 42 and out["shortname"] == "S"
    assert err["errorcode"] in out["enrol_error"]
    assert "0.6.1-spike3" in out["note"] and "2026110202" in out["note"]
    assert "강좌는 생성되었지만" in out["note"]


async def test_create_course_enrol_other_error_keeps_course(mcp):
    err = {"exception": "moodle_exception", "errorcode": "nopermissions", "message": "Sorry, no permission"}
    out, _ = await create_course_confirmed(mcp, err)
    assert out["ok"] is True and out["courseid"] == 42
    assert "nopermissions" in out["enrol_error"]
    assert "note" not in out
