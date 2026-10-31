import base64
import json

import httpx
import pytest
import respx

from moodle_mcp.moodle import MoodleClient
from moodle_mcp.server import _download, _video_embed, create_mcp

from .conftest import ENDPOINT, MOODLE_TOKEN
from .test_moodle import form


@pytest.fixture
def mcp():
    return create_mcp(MoodleClient(ENDPOINT, MOODLE_TOKEN))


def routed(replies):
    """respx side effect answering each Moodle call by wsfunction."""
    return lambda req: httpx.Response(200, text=json.dumps(replies[form(req)["wsfunction"]]))


async def confirmed(mcp, tool, args, reply=None, confirm=True):
    with respx.mock:
        route = respx.post(ENDPOINT).respond(text=json.dumps(reply if reply is not None else {"ok": 1}))
        _c, out = await mcp.call_tool(tool, {**args, "confirm": confirm})
        return out, [form(c.request) for c in route.calls]


def without_auth(sent):
    return {k: v for k, v in sent.items() if k not in ("wstoken", "moodlewsrestformat")}


MODULE = {"course_id": 5, "section": 2, "name": "N"}
RUBRIC = [
    {"description": "Alignment", "levels": [{"definition": "weak", "score": 5.0}, {"definition": "strong", "score": 25.0}]},
    {"description": "Ethics", "levels": [{"definition": "none", "score": 0.0}, {"definition": "clear", "score": 25.0}]},
]
YT = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"

# (tool, args, wsfunction, expected params; "settings" / "questions" are compared as decoded JSON)
WRITES = [
    (
        "create_assignment",
        {**MODULE, "duedate": 100, "submission_types": ["onlinetext", "file"], "max_files": 3, "completion_submit": True},
        "local_grokbot_create_module",
        {
            "courseid": "5", "section": "2", "modname": "assign", "name": "N", "intro": "", "visible": "1",
            "settings": {
                "grade": 100, "assignsubmission_onlinetext_enabled": 1, "assignsubmission_file_enabled": 1,
                "assignsubmission_file_maxfiles": 3, "duedate": 100, "completion": 2, "completionsubmit": 1,
            },
        },
    ),
    (
        "create_assignment",
        {**MODULE, "intro": "<p>x</p>", "visible": 0, "grade": 20, "cutoffdate": 9, "allowsubmissionsfromdate": 1},
        "local_grokbot_create_module",
        {
            "courseid": "5", "section": "2", "modname": "assign", "name": "N", "intro": "<p>x</p>", "visible": "0",
            "settings": {
                "grade": 20, "assignsubmission_onlinetext_enabled": 1, "assignsubmission_file_enabled": 0,
                "assignsubmission_file_maxfiles": 1, "cutoffdate": 9, "allowsubmissionsfromdate": 1,
            },
        },
    ),
    (
        "create_quiz",
        {**MODULE, "timeopen": 10, "timelimit": 1800, "attempts": 2, "completion_pass_grade": 6},
        "local_grokbot_create_module",
        {
            "courseid": "5", "section": "2", "modname": "quiz", "name": "N", "intro": "", "visible": "1",
            "settings": {
                "attempts": 2, "grademethod": 1, "grade": 10, "timeopen": 10, "timelimit": 1800,
                "completion": 2, "completionusegrade": 1, "completionpassgrade": 1, "gradepass": 6,
            },
        },
    ),
    (
        "create_forum",
        {**MODULE, "type": "qanda", "max_grade": 10, "duedate": 7, "completion_posts": 2},
        "local_grokbot_create_module",
        {
            "courseid": "5", "section": "2", "modname": "forum", "name": "N", "intro": "", "visible": "1",
            "settings": {"type": "qanda", "grade_forum": 10, "duedate": 7, "completion": 2, "completionposts": 2},
        },
    ),
    (
        "create_page",
        {**MODULE, "content_html": "<p>Hi</p>", "completion_view": False},
        "local_grokbot_create_module",
        {
            "courseid": "5", "section": "2", "modname": "page", "name": "N", "intro": "", "visible": "1",
            "settings": {"content": "<p>Hi</p>"},
        },
    ),
    (
        "create_page",
        {**MODULE, "content_html": "<p>Hi</p>", "video_url": YT},
        "local_grokbot_create_module",
        {
            "courseid": "5", "section": "2", "modname": "page", "name": "N", "intro": "", "visible": "1",
            "settings": {"content": "<p>Hi</p>" + _video_embed(YT), "completion": 2, "completionview": 1},
        },
    ),
    (
        "update_activity",
        {"cmid": 12, "name": "New", "settings": {"duedate": 5}},
        "local_grokbot_update_module",
        {"cmid": "12", "name": "New", "intro": "", "visible": "-1", "settings": {"duedate": 5}},
    ),
    ("set_completion", {"cmid": 12, "mode": "none"}, "local_grokbot_update_module", {"cmid": "12", "settings": {"completion": 0}}),
    ("set_completion", {"cmid": 12, "mode": "manual"}, "local_grokbot_update_module", {"cmid": "12", "settings": {"completion": 1}}),
    (
        "set_completion",
        {"cmid": 12, "mode": "view"},
        "local_grokbot_update_module",
        {"cmid": "12", "settings": {"completion": 2, "completionview": 1}},
    ),
    (
        "set_completion",
        {"cmid": 12, "mode": "submit"},
        "local_grokbot_update_module",
        {"cmid": "12", "settings": {"completion": 2, "completionsubmit": 1}},
    ),
    (
        "set_completion",
        {"cmid": 12, "mode": "grade"},
        "local_grokbot_update_module",
        {"cmid": "12", "settings": {"completion": 2, "completionusegrade": 1}},
    ),
    (
        "set_completion",
        {"cmid": 12, "mode": "pass", "pass_grade": 5.5},
        "local_grokbot_update_module",
        {"cmid": "12", "settings": {"completion": 2, "completionusegrade": 1, "completionpassgrade": 1, "gradepass": 5.5}},
    ),
    (
        "set_completion",
        {"cmid": 12, "mode": "posts", "posts": 3},
        "local_grokbot_update_module",
        {"cmid": "12", "settings": {"completion": 2, "completionposts": 3}},
    ),
    (
        "set_access_restriction",
        {"target_type": "activity", "course_id": 5, "target": 12, "required_cmids": [3, 4], "open_from": 1000},
        "local_grokbot_update_module",
        {
            "cmid": "12",
            "settings": {
                "availability": json.dumps(
                    {
                        "op": "&",
                        "c": [
                            {"type": "completion", "cm": 3, "e": 1},
                            {"type": "completion", "cm": 4, "e": 1},
                            {"type": "date", "d": ">=", "t": 1000},
                        ],
                        "showc": [True, True, True],
                    }
                )
            },
        },
    ),
    (
        "set_access_restriction",
        {"target_type": "section", "course_id": 5, "target": 2, "required_cmids": [3]},
        "local_grokbot_set_section_availability",
        {
            "courseid": "5",
            "section": "2",
            "availability": json.dumps({"op": "&", "c": [{"type": "completion", "cm": 3, "e": 1}], "showc": [True]}),
        },
    ),
    (
        "set_access_restriction",
        {"target_type": "section", "course_id": 5, "target": 2},
        "local_grokbot_set_section_availability",
        {"courseid": "5", "section": "2", "availability": ""},
    ),
    (
        "add_quiz_questions",
        {
            "quiz_id": 4,
            "questions": [
                {"type": "truefalse", "text": "Sky is blue", "correct": True},
                {"type": "multichoice", "text": "2+2", "answers": [{"text": "4", "fraction": 1}, {"text": "5"}]},
            ],
        },
        "local_grokbot_add_quiz_questions",
        {
            "quizid": "4",
            "questions": [
                {"type": "truefalse", "text": "Sky is blue", "mark": 1.0, "generalfeedback": "", "correct": True},
                {
                    "type": "multichoice", "text": "2+2", "mark": 1.0, "generalfeedback": "",
                    "answers": [
                        {"text": "4", "fraction": 1.0, "feedback": ""},
                        {"text": "5", "fraction": 0.0, "feedback": ""},
                    ],
                },
            ],
        },
    ),
    (
        "add_sections",
        {"course_id": 5, "names": ["A", "B"], "summaries": ["<p>a</p>"]},
        "local_grokbot_add_sections",
        {"courseid": "5", "names[0]": "A", "names[1]": "B", "summaries[0]": "<p>a</p>"},
    ),
    ("add_sections", {"course_id": 5, "names": ["A"]}, "local_grokbot_add_sections", {"courseid": "5", "names[0]": "A"}),
    (
        "update_section",
        {"course_id": 5, "section": 1, "name": "Week 1"},
        "local_grokbot_update_section",
        {"courseid": "5", "section": "1", "name": "Week 1"},
    ),
    (
        "update_section",
        {"course_id": 5, "section": 1, "summary": "<p>s</p>"},
        "local_grokbot_update_section",
        {"courseid": "5", "section": "1", "summary": "<p>s</p>"},
    ),
    (
        "create_workshop",
        {**MODULE, "instructions_submission": "<p>s</p>", "submission_end": 50, "settings": {"nattachments": 3}},
        "local_grokbot_create_module",
        {
            "courseid": "5", "section": "2", "modname": "workshop", "name": "N", "intro": "", "visible": "1",
            "settings": {
                "strategy": "rubric", "grade": 80, "gradinggrade": 20, "submissiontypetext": 1, "submissiontypefile": 1,
                "useselfassessment": 0, "instructauthors": "<p>s</p>", "submissionend": 50, "nattachments": 3,
            },
        },
    ),
    (
        "create_workshop",
        {**MODULE, "strategy": "accumulative", "grade": 25, "gradinggrade": 10, "submission_types": ["file"],
         "self_assessment": True, "instructions_assessment": "<p>a</p>", "assessment_start": 7},
        "local_grokbot_create_module",
        {
            "courseid": "5", "section": "2", "modname": "workshop", "name": "N", "intro": "", "visible": "1",
            "settings": {
                "strategy": "accumulative", "grade": 25, "gradinggrade": 10, "submissiontypetext": 0,
                "submissiontypefile": 1, "useselfassessment": 1, "instructreviewers": "<p>a</p>", "assessmentstart": 7,
            },
        },
    ),
    (
        "create_wiki",
        {**MODULE, "mode": "individual", "first_page_title": "Start", "group_mode": 1},
        "local_grokbot_create_module",
        {
            "courseid": "5", "section": "2", "modname": "wiki", "name": "N", "intro": "", "visible": "1",
            "settings": {"wikimode": "individual", "groupmode": 1, "firstpagetitle": "Start"},
        },
    ),
    (
        "create_glossary",
        {**MODULE, "default_approval": False, "completion_entries": 2},
        "local_grokbot_create_module",
        {
            "courseid": "5", "section": "2", "modname": "glossary", "name": "N", "intro": "", "visible": "1",
            "settings": {
                "displayformat": "dictionary", "defaultapproval": 0, "allowcomments": 0, "completion": 2,
                "completionentries": 2,
            },
        },
    ),
    (
        "create_feedback",
        {**MODULE, "anonymous": False, "timeclose": 99, "page_after_submit": "<p>Thanks</p>", "completion_submit": True},
        "local_grokbot_create_module",
        {
            "courseid": "5", "section": "2", "modname": "feedback", "name": "N", "intro": "", "visible": "1",
            "settings": {
                "anonymous": 2, "multiple_submit": 0, "timeclose": 99, "page_after_submit": "<p>Thanks</p>",
                "completion": 2, "completionsubmit": 1,
            },
        },
    ),
    (
        "create_openmaic",
        {**MODULE, "prompt": "Teach agents", "settings": {"grade": 0}},
        "local_grokbot_create_module",
        {
            "courseid": "5", "section": "2", "modname": "openmaic", "name": "N", "intro": "", "visible": "1",
            "settings": {"grade": 0, "manuscript": "Teach agents", "completion": 2, "completionminprogress": 80},
        },
    ),
    (
        "create_openmaic",
        {**MODULE, "lecture_id": "abc-1", "completion_min_progress": 0},
        "local_grokbot_create_module",
        {
            "courseid": "5", "section": "2", "modname": "openmaic", "name": "N", "intro": "", "visible": "1",
            "settings": {"grade": 100, "lectureid": "abc-1"},
        },
    ),
    (
        "set_rubric",
        {"cmid": 12, "name": "R", "criteria": RUBRIC},
        "local_grokbot_set_rubric",
        {"cmid": "12", "name": "R", "criteria": RUBRIC, "description": "", "areaname": "submissions"},
    ),
    (
        "set_grade_categories",
        {"course_id": 5, "categories": [
            {"name": "Quizzes", "weight": 15, "cmids": [3, 4]},
            {"name": "Peer review", "weight": 10, "cmids": [{"cmid": 9, "itemnumber": 1}]},
        ]},
        "local_grokbot_set_grade_categories",
        {
            "courseid": "5", "aggregation": "weighted_mean",
            "categories": [
                {"name": "Quizzes", "weight": 15.0, "cmids": [3, 4]},
                {"name": "Peer review", "weight": 10.0, "cmids": [{"cmid": 9, "itemnumber": 1}]},
            ],
        },
    ),
    (
        "set_grade_categories",
        {"course_id": 5, "aggregation": "mean", "categories": [{"name": "All"}]},
        "local_grokbot_set_grade_categories",
        {"courseid": "5", "aggregation": "mean", "categories": [{"name": "All", "cmids": []}]},
    ),
    (
        "create_badge",
        {"course_id": 5, "name": "B", "description": "D", "activity_cmids": [3, 4], "min_course_grade": 70, "enable": True},
        "local_grokbot_create_badge",
        {
            "courseid": "5", "name": "B", "description": "D", "enable": "1",
            "criteria": {"activities": [3, 4], "min_course_grade": 70.0},
        },
    ),
    (
        "create_badge",
        {"course_id": 5, "name": "B", "description": "D", "activity_cmids": [3]},
        "local_grokbot_create_badge",
        {
            "courseid": "5", "name": "B", "description": "D", "enable": "0",
            "criteria": {"activities": [3], "min_course_grade": None},
        },
    ),
    (
        "post_forum_discussion",
        {"forum_id": 7, "subject": "Hello", "message": "<p>Welcome</p>"},
        "mod_forum_add_discussion",
        {"forumid": "7", "subject": "Hello", "message": "<p>Welcome</p>"},
    ),
]  # fmt: skip


@pytest.mark.parametrize(("tool", "args", "wsfunction", "params"), WRITES)
async def test_write_preview_does_not_call_moodle(mcp, tool, args, wsfunction, params):
    with respx.mock:
        route = respx.post(ENDPOINT).respond(text="{}")
        _c, out = await mcp.call_tool(tool, args)
        assert route.call_count == 0
    assert out["preview"] is True
    assert "confirm=true" in out["note"]


@pytest.mark.parametrize(("tool", "args", "wsfunction", "params"), WRITES)
async def test_write_confirm_calls_right_wsfunction(mcp, tool, args, wsfunction, params):
    out, calls = await confirmed(mcp, tool, args, {"cmid": 99})
    assert out == {"ok": True, "cmid": 99}
    assert len(calls) == 1
    sent = without_auth(calls[0])
    for key in ("settings", "questions", "criteria", "categories"):
        if key in sent:
            sent[key] = json.loads(sent[key])
    assert sent == {"wsfunction": wsfunction, **params}


@pytest.mark.parametrize(
    ("tool", "args", "message"),
    [
        ("create_assignment", {**MODULE, "submission_types": ["paper"]}, "submission_types"),
        ("create_forum", {**MODULE, "type": "wiki"}, "type must be"),
        ("set_completion", {"cmid": 1, "mode": "always"}, "mode must be"),
        ("set_completion", {"cmid": 1, "mode": "posts", "posts": 0}, "posts must be"),
        ("set_access_restriction", {"target_type": "course", "course_id": 5, "target": 1}, "target_type"),
        ("add_sections", {"course_id": 5, "names": ["A"], "summaries": ["a", "b"]}, "summaries"),
        ("update_section", {"course_id": 5, "section": 1}, "name and/or summary"),
        ("create_resource", {**MODULE, "filename": "a.pdf"}, "exactly one"),
        ("create_resource", {**MODULE, "filename": "a.pdf", "file_url": "https://x/a", "file_base64": "QQ=="}, "exactly one"),
        ("create_resource", {**MODULE, "filename": "a.pdf", "file_base64": "not base64!"}, "base64"),
        ("create_resource", {**MODULE, "filename": "../a.pdf", "file_base64": "QQ=="}, "plain file name"),
        ("create_workshop", {**MODULE, "strategy": "magic"}, "strategy must be"),
        ("create_workshop", {**MODULE, "submission_types": []}, "submission_types"),
        ("create_workshop", {**MODULE, "submission_types": ["paper"]}, "submission_types"),
        ("create_wiki", {**MODULE, "mode": "shared"}, "mode must be"),
        ("create_wiki", {**MODULE, "group_mode": 5}, "group_mode"),
        ("create_h5pactivity", {**MODULE, "filename": "a.zip", "file_base64": "QQ=="}, ".h5p"),
        ("create_h5pactivity", {**MODULE, "filename": "a.h5p"}, "exactly one"),
        ("create_openmaic", {**MODULE, "completion_min_progress": 101}, "between 0 and 100"),
        ("set_rubric", {"cmid": 1, "name": "R", "criteria": []}, "must not be empty"),
        ("set_rubric", {"cmid": 1, "name": "R", "criteria": [{"description": "x", "levels": [{"definition": "a", "score": 1}]}]},
         "at least 2 levels"),
        ("set_grade_categories", {"course_id": 5, "categories": []}, "must not be empty"),
        ("set_grade_categories", {"course_id": 5, "categories": [{"name": "Q", "cmids": [1]}]}, "needs a weight"),
        ("create_badge", {"course_id": 5, "name": "B", "description": "D"}, "activity_cmids and/or"),
        ("create_badge", {"course_id": 5, "name": "B", "description": " ", "activity_cmids": [1]}, "description"),
    ],
)  # fmt: skip
async def test_invalid_input_is_rejected_without_calls(mcp, tool, args, message):
    for confirm in (False, True):
        out, calls = await confirmed(mcp, tool, args, confirm=confirm)
        assert message in out["error"]
        assert calls == []


async def test_moodle_error_is_returned(mcp):
    err = {"exception": "invalid_parameter_exception", "errorcode": "invalidparameter", "message": "bad"}
    out, _ = await confirmed(mcp, "set_completion", {"cmid": 1, "mode": "view"}, err)
    assert set(out) == {"error"} and "invalidparameter" in out["error"]


@pytest.mark.parametrize("visible", [True, False])
async def test_set_activity_visibility_returns_plain_result(mcp, visible):
    _c, preview = await mcp.call_tool("set_activity_visibility", {"cmid": 12, "visible": visible})
    action = "show" if visible else "hide"
    assert preview["preview"] is True and preview["action"] == action
    out, calls = await confirmed(mcp, "set_activity_visibility", {"cmid": 12, "visible": visible}, "<li>html</li>")
    assert out == {"ok": True, "cmid": 12, "visible": visible}
    assert [without_auth(c) for c in calls] == [{"wsfunction": "core_course_edit_module", "action": action, "id": "12"}]


async def test_set_activity_visibility_error(mcp):
    err = {"exception": "x", "errorcode": "nopermissions", "message": "m"}
    out, _ = await confirmed(mcp, "set_activity_visibility", {"cmid": 12, "visible": True}, err)
    assert set(out) == {"error"}


async def test_set_rubric_preview_shows_max_score(mcp):
    _c, out = await mcp.call_tool("set_rubric", {"cmid": 12, "name": "R", "criteria": RUBRIC})
    assert out["preview"] is True and out["max_score"] == 50


async def test_set_grade_categories_preview_shows_total_weight(mcp):
    cats = [{"name": "A", "weight": 60, "cmids": [1]}, {"name": "B", "weight": 40}]
    _c, out = await mcp.call_tool("set_grade_categories", {"course_id": 5, "categories": cats})
    assert out["preview"] is True and out["total_weight"] == 100


PDF = b"%PDF-1.4 fake"
RESOURCE_REPLIES = {
    "core_webservice_get_site_info": {"userid": 10},
    "core_files_upload": {"itemid": 555, "filename": "notes.pdf", "contextid": 2},
    "local_grokbot_create_module": {"cmid": 77, "instance": 8, "modname": "resource"},
}


async def test_create_resource_preview_shows_size(mcp):
    args = {**MODULE, "filename": "notes.pdf", "file_base64": base64.b64encode(PDF).decode()}
    with respx.mock:
        route = respx.post(ENDPOINT).respond(text="{}")
        _c, out = await mcp.call_tool("create_resource", args)
        assert route.call_count == 0
    assert out["preview"] is True
    assert out["file"] == {"filename": "notes.pdf", "source": "base64", "size_bytes": len(PDF)}
    assert out["module"]["settings"] == {"completion": 2, "completionview": 1}


async def test_create_resource_base64_uploads_then_creates(mcp):
    args = {**MODULE, "filename": "notes.pdf", "file_base64": base64.b64encode(PDF).decode(), "confirm": True}
    with respx.mock:
        route = respx.post(ENDPOINT).mock(side_effect=routed(RESOURCE_REPLIES))
        _c, out = await mcp.call_tool("create_resource", args)
        calls = [form(c.request) for c in route.calls]
    assert out == {"ok": True, "cmid": 77, "instance": 8, "modname": "resource", "size_bytes": len(PDF)}
    assert [c["wsfunction"] for c in calls] == [
        "core_webservice_get_site_info",
        "core_files_upload",
        "local_grokbot_create_module",
    ]
    upload = calls[1]
    assert {k: upload[k] for k in ("contextlevel", "instanceid", "component", "filearea", "itemid", "filepath")} == {
        "contextlevel": "user",
        "instanceid": "10",
        "component": "user",
        "filearea": "draft",
        "itemid": "0",
        "filepath": "/",
    }
    assert upload["filename"] == "notes.pdf"
    assert base64.b64decode(upload["filecontent"]) == PDF
    create = calls[2]
    assert create["modname"] == "resource" and create["courseid"] == "5" and create["section"] == "2"
    assert json.loads(create["settings"]) == {"completion": 2, "completionview": 1, "files": 555}


async def test_create_resource_downloads_file_url(mcp):
    args = {**MODULE, "filename": "notes.pdf", "file_url": "https://files.test/notes.pdf", "completion_view": False}
    with respx.mock:
        download = respx.get("https://files.test/notes.pdf").respond(content=PDF)
        route = respx.post(ENDPOINT).mock(side_effect=routed(RESOURCE_REPLIES))
        _c, preview = await mcp.call_tool("create_resource", args)
        assert download.call_count == 0 and route.call_count == 0
        _c, out = await mcp.call_tool("create_resource", {**args, "confirm": True})
        calls = [form(c.request) for c in route.calls]
    assert preview["file"] == {"filename": "notes.pdf", "source": "https://files.test/notes.pdf"}
    assert out["ok"] is True and out["cmid"] == 77
    assert base64.b64decode(calls[1]["filecontent"]) == PDF
    assert json.loads(calls[2]["settings"]) == {"files": 555}


async def test_create_resource_download_error_stops(mcp):
    args = {**MODULE, "filename": "a.pdf", "file_url": "https://files.test/missing", "confirm": True}
    with respx.mock:
        respx.get("https://files.test/missing").respond(404)
        route = respx.post(ENDPOINT).respond(text="{}")
        _c, out = await mcp.call_tool("create_resource", args)
        assert route.call_count == 0
    assert out["error"].startswith("download failed")


async def test_create_resource_upload_error_stops(mcp):
    replies = {**RESOURCE_REPLIES, "core_files_upload": {"exception": "x", "errorcode": "fileexist", "message": "m"}}
    args = {**MODULE, "filename": "a.pdf", "file_base64": "QQ==", "confirm": True}
    with respx.mock:
        route = respx.post(ENDPOINT).mock(side_effect=routed(replies))
        _c, out = await mcp.call_tool("create_resource", args)
        assert route.call_count == 2
    assert "fileexist" in out["error"]


async def test_download_enforces_limit_and_scheme():
    with respx.mock:
        respx.get("https://files.test/big").respond(content=b"x" * 11)
        with pytest.raises(ValueError, match="larger"):
            await _download("https://files.test/big", limit=10)
        assert await _download("https://files.test/big", limit=11) == b"x" * 11
    with pytest.raises(ValueError, match="http"):
        await _download("file:///etc/passwd")


@pytest.mark.parametrize(
    ("url", "embed"),
    [
        ("https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=10", "https://www.youtube.com/embed/dQw4w9WgXcQ"),
        ("https://youtu.be/dQw4w9WgXcQ", "https://www.youtube.com/embed/dQw4w9WgXcQ"),
        ("https://www.youtube.com/shorts/dQw4w9WgXcQ", "https://www.youtube.com/embed/dQw4w9WgXcQ"),
        ("https://vimeo.com/123456", "https://player.vimeo.com/video/123456"),
    ],
)
def test_video_embed_iframe(url, embed):
    out = _video_embed(url)
    assert f'<iframe src="{embed}"' in out and "allowfullscreen" in out and "padding-bottom:56.25%" in out


def test_video_embed_falls_back_to_video_tag():
    out = _video_embed('https://cdn.test/clip.mp4?a=1&b="2"')
    assert out.startswith("<video controls") and "<iframe" not in out
    assert 'src="https://cdn.test/clip.mp4?a=1&amp;b=&quot;2&quot;"' in out


async def test_list_forum_discussions_combines_posts(mcp):
    replies = {
        "mod_forum_get_forum_discussions": {
            "discussions": [
                {"id": 100, "discussion": 1, "name": "Intro", "userfullname": "T", "created": 5, "numreplies": 1},
                {"id": 200, "discussion": 2, "name": "Q", "userfullname": "S", "created": 6, "numreplies": 0},
            ],
            "warnings": [],
        },
    }
    posts = {
        "1": {
            "posts": [
                {"id": 100, "parentid": None, "subject": "Intro", "message": "<p>Hi</p>",
                 "author": {"id": 3, "fullname": "T"}, "timecreated": 5, "html": {}},
                {"id": 101, "parentid": 100, "subject": "Re: Intro", "message": "<p>Yo</p>",
                 "author": {"id": 4, "fullname": "S"}, "timecreated": 7},
            ]
        },
        "2": {"exception": "x", "errorcode": "nopermission", "message": "no"},
    }  # fmt: skip

    def reply(req):
        sent = form(req)
        if sent["wsfunction"] == "mod_forum_get_discussion_posts":
            return httpx.Response(200, text=json.dumps(posts[sent["discussionid"]]))
        return httpx.Response(200, text=json.dumps(replies[sent["wsfunction"]]))

    with respx.mock:
        route = respx.post(ENDPOINT).mock(side_effect=reply)
        _c, out = await mcp.call_tool("list_forum_discussions", {"forum_id": 7})
        calls = [form(c.request) for c in route.calls]
    assert calls[0]["wsfunction"] == "mod_forum_get_forum_discussions" and calls[0]["forumid"] == "7"
    assert [c.get("discussionid") for c in calls[1:]] == ["1", "2"]
    first, second = out["discussions"]
    assert first["id"] == 1 and first["name"] == "Intro" and first["author"] == "T"
    assert first["posts"] == [
        {"id": 100, "parentid": None, "subject": "Intro", "message": "<p>Hi</p>", "author": "T", "timecreated": 5},
        {"id": 101, "parentid": 100, "subject": "Re: Intro", "message": "<p>Yo</p>", "author": "S", "timecreated": 7},
    ]
    assert "posts" not in second and "nopermission" in second["posts_error"]


async def test_list_forum_discussions_error(mcp):
    err = {"exception": "x", "errorcode": "invalidrecord", "message": "m"}
    with respx.mock:
        respx.post(ENDPOINT).respond(text=json.dumps(err))
        _c, out = await mcp.call_tool("list_forum_discussions", {"forum_id": 7})
    assert set(out) == {"error"}


H5P = b"PK\x03\x04 fake h5p"


async def test_create_h5pactivity_uploads_package(mcp):
    replies = {**RESOURCE_REPLIES, "local_grokbot_create_module": {"cmid": 78, "instance": 9, "modname": "h5pactivity"}}
    args = {**MODULE, "filename": "tutor.h5p", "file_base64": base64.b64encode(H5P).decode(), "completion_pass_grade": 60}
    with respx.mock:
        route = respx.post(ENDPOINT).mock(side_effect=routed(replies))
        _c, preview = await mcp.call_tool("create_h5pactivity", args)
        assert route.call_count == 0
        _c, out = await mcp.call_tool("create_h5pactivity", {**args, "confirm": True})
        calls = [form(c.request) for c in route.calls]
    assert preview["file"] == {"filename": "tutor.h5p", "source": "base64", "size_bytes": len(H5P)}
    assert preview["module"]["modname"] == "h5pactivity"
    assert out == {"ok": True, "cmid": 78, "instance": 9, "modname": "h5pactivity", "size_bytes": len(H5P)}
    assert [c["wsfunction"] for c in calls] == [
        "core_webservice_get_site_info",
        "core_files_upload",
        "local_grokbot_create_module",
    ]
    assert calls[1]["filename"] == "tutor.h5p" and base64.b64decode(calls[1]["filecontent"]) == H5P
    assert calls[2]["modname"] == "h5pactivity"
    assert json.loads(calls[2]["settings"]) == {
        "grade": 100, "completion": 2, "completionusegrade": 1, "completionpassgrade": 1, "gradepass": 60,
        "packagefile": 555,
    }  # fmt: skip
