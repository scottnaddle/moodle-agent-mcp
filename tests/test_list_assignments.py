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


async def call_list_assignments(replies, course_ids=None, offset=0, limit=25):
    handler, calls = make_handler(replies)
    with respx.mock as router:
        router.post(ENDPOINT).mock(side_effect=handler)
        args: dict = {"offset": offset, "limit": limit}
        if course_ids is not None:
            args["course_ids"] = course_ids
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


async def test_no_ids_uses_list_course_assignments_and_merges():
    page = {
        "courses": [
            {"id": 5, "fullname": "Five", "assignments": []},
            {"id": 6, "fullname": "Six", "assignments": [{"id": 9}]},
        ],
        "total": 3,
        "offset": 0,
        "limit": 2,
        "warnings": [],
    }
    result, calls = await call_list_assignments(
        {
            "mod_assign_get_assignments": {"courses": [], "warnings": []},
            "local_ubionai_list_course_assignments": page,
        },
        offset=0,
        limit=2,
    )
    assert [call["wsfunction"] for call in calls] == [
        "mod_assign_get_assignments",
        "local_ubionai_list_course_assignments",
    ]
    assert calls[1]["offset"] == "0"
    assert calls[1]["limit"] == "2"
    assert [course["id"] for course in result["courses"]] == [5, 6]
    assert all(course["source"] == "local_ubionai" for course in result["courses"])
    assert result["paging"] == {"offset": 0, "limit": 2, "total": 3, "next_offset": 2}


async def test_no_ids_skips_courses_already_enrolled():
    primary = {"courses": [{"id": 5, "fullname": "Five", "assignments": []}], "warnings": []}
    page = {
        "courses": [
            {"id": 5, "fullname": "Five", "assignments": []},
            {"id": 6, "fullname": "Six", "assignments": []},
        ],
        "total": 2,
        "offset": 0,
        "limit": 2,
        "warnings": [],
    }
    result, _calls = await call_list_assignments(
        {
            "mod_assign_get_assignments": primary,
            "local_ubionai_list_course_assignments": page,
        },
        offset=0,
        limit=2,
    )
    assert [course["id"] for course in result["courses"]] == [5, 6]
    assert "source" not in result["courses"][0]
    assert result["courses"][1]["source"] == "local_ubionai"


async def test_no_ids_last_page_next_offset_none():
    page = {
        "courses": [{"id": 7, "fullname": "Seven", "assignments": []}],
        "total": 3,
        "offset": 2,
        "limit": 2,
        "warnings": [],
    }
    result, _calls = await call_list_assignments(
        {
            "mod_assign_get_assignments": {"courses": [], "warnings": []},
            "local_ubionai_list_course_assignments": page,
        },
        offset=2,
        limit=2,
    )
    assert result["paging"]["next_offset"] is None
    assert result["paging"]["total"] == 3


async def test_no_ids_later_pages_do_not_resend_core_courses():
    primary = {"courses": [{"id": 9, "fullname": "Nine", "assignments": []}], "warnings": []}
    page = {
        "courses": [{"id": 10, "fullname": "Ten", "assignments": []}],
        "total": 4,
        "offset": 2,
        "limit": 2,
        "warnings": [],
    }
    result, _calls = await call_list_assignments(
        {
            "mod_assign_get_assignments": primary,
            "local_ubionai_list_course_assignments": page,
        },
        offset=2,
        limit=2,
    )
    assert [course["id"] for course in result["courses"]] == [10]
    assert result["courses"][0]["source"] == "local_ubionai"


async def test_limit_clamped():
    page = {
        "courses": [],
        "total": 0,
        "offset": 0,
        "limit": 100,
        "warnings": [],
    }
    _result, calls = await call_list_assignments(
        {
            "mod_assign_get_assignments": {"courses": [], "warnings": []},
            "local_ubionai_list_course_assignments": page,
        },
        offset=-3,
        limit=1000,
    )
    assert calls[1]["offset"] == "0"
    assert calls[1]["limit"] == "100"


async def test_no_ids_degraded_fallback_via_core_course_get_courses():
    error = {
        "exception": "webservice_access_exception",
        "errorcode": "invalidrecord",
        "message": "Function not available",
    }
    cc = {
        "courses": [
            {"id": 1, "format": "site"},
            {"id": 5, "format": "topics"},
            {"id": 6, "format": "topics"},
        ]
    }

    def assignments_for(data):
        if data["courseid"] == "6":
            return {"courses": [{"id": 6, "fullname": "Six", "assignments": [{"id": 9}]}], "warnings": []}
        return {"courses": [{"id": 5, "fullname": "Five", "assignments": []}], "warnings": []}

    result, calls = await call_list_assignments(
        {
            "mod_assign_get_assignments": {"courses": [], "warnings": []},
            "local_ubionai_list_course_assignments": error,
            "core_course_get_courses": cc,
            "local_ubionai_get_course_assignments": assignments_for,
        },
        offset=0,
        limit=25,
    )
    fallback_courses = [
        call["courseid"]
        for call in calls
        if call["wsfunction"] == "local_ubionai_get_course_assignments"
    ]
    assert fallback_courses == ["5", "6"]
    assert [course["id"] for course in result["courses"]] == [6]
    assert result["courses"][0]["source"] == "local_ubionai"
    assert "degraded" in result
    assert result["paging"]["total"] == 2


async def test_degraded_fallback_all_fail_sets_hint():
    error = {
        "exception": "webservice_access_exception",
        "errorcode": "invalidrecord",
        "message": "Function not available",
    }
    cc = {"courses": [{"id": 5, "format": "topics"}, {"id": 6, "format": "topics"}]}
    result, calls = await call_list_assignments(
        {
            "mod_assign_get_assignments": {"courses": [], "warnings": []},
            "local_ubionai_list_course_assignments": error,
            "core_course_get_courses": cc,
            "local_ubionai_get_course_assignments": error,
        },
        offset=0,
        limit=25,
    )
    assert result["hint"] == OPTIONAL_HINT.format(plugin="local_ubionai")
    assert len(result["fallback_errors"]) == 2
    assert "paging" in result
    assert [call["courseid"] for call in calls if call["wsfunction"] == "local_ubionai_get_course_assignments"] == [
        "5",
        "6",
    ]


async def test_degraded_surfaces_plugin_error_and_keeps_warnings():
    error = {
        "exception": "webservice_access_exception",
        "errorcode": "invalidrecord",
        "message": "Function not available",
    }
    cc = {"courses": [{"id": 5, "format": "topics"}]}
    fallback = {
        "courses": [{"id": 5, "fullname": "Five", "assignments": [{"id": 9}]}],
        "warnings": [{"item": "warning", "itemid": 5}],
    }
    result, _calls = await call_list_assignments(
        {
            "mod_assign_get_assignments": {"courses": [], "warnings": []},
            "local_ubionai_list_course_assignments": error,
            "core_course_get_courses": cc,
            "local_ubionai_get_course_assignments": fallback,
        },
        offset=0,
        limit=25,
    )
    assert "invalidrecord" in result["degraded"]
    assert "invalidrecord" in result["plugin_error"]
    assert result["warnings"] == fallback["warnings"]


async def test_degraded_offset_past_end_has_no_plugin_missing_hint():
    error = {
        "exception": "webservice_access_exception",
        "errorcode": "invalidrecord",
        "message": "Function not available",
    }
    cc = {"courses": [{"id": 5, "format": "topics"}]}
    result, _calls = await call_list_assignments(
        {
            "mod_assign_get_assignments": {"courses": [], "warnings": []},
            "local_ubionai_list_course_assignments": error,
            "core_course_get_courses": cc,
            "local_ubionai_get_course_assignments": error,
        },
        offset=5,
        limit=25,
    )
    assert result["courses"] == []
    assert "hint" not in result
    assert result["paging"]["next_offset"] is None


async def test_no_ids_output_pseudonymised():
    page = {
        "courses": [
            {
                "id": 5,
                "fullname": "데이터과학 입문",
                "assignments": [
                    {"id": 9, "name": "김민수 보충 과제"},
                    {"id": 10, "name": "조별 과제 발표"},
                ],
            }
        ],
        "users": [{"id": 7, "fullname": "김민수"}],
        "total": 1,
        "offset": 0,
        "limit": 25,
        "warnings": [],
    }
    token = _current_pseudonymizer.set(Pseudonymizer())
    try:
        result, _calls = await call_list_assignments(
            {
                "mod_assign_get_assignments": {"courses": [], "warnings": []},
                "local_ubionai_list_course_assignments": page,
                "core_enrol_get_enrolled_users": [{"id": 7, "fullname": "김민수"}],
            }
        )
    finally:
        _current_pseudonymizer.reset(token)
    rendered = json.dumps(result, ensure_ascii=False)
    assert result["courses"][0]["fullname"] == "데이터과학 입문"
    assert "김민수" not in rendered
    assert PLACEHOLDER_RE.search(rendered)
    assert result["courses"][0]["assignments"][1]["name"] == "조별 과제 발표"


async def test_enrolled_student_name_in_assignment_title_is_masked():
    page = {
        "courses": [
            {
                "id": 5,
                "fullname": "Course",
                "assignments": [{"id": 9, "name": "김민수 essay"}],
            }
        ],
        "total": 1,
        "offset": 0,
        "limit": 25,
        "warnings": [],
    }
    token = _current_pseudonymizer.set(Pseudonymizer())
    try:
        result, calls = await call_list_assignments(
            {
                "mod_assign_get_assignments": {"courses": [], "warnings": []},
                "local_ubionai_list_course_assignments": page,
                "core_enrol_get_enrolled_users": [
                    {"id": 7, "fullname": "김민수", "firstname": "민수", "lastname": "김"}
                ],
            }
        )
    finally:
        _current_pseudonymizer.reset(token)
    rendered = json.dumps(result, ensure_ascii=False)
    assert "김민수" not in rendered
    assert PLACEHOLDER_RE.search(result["courses"][0]["assignments"][0]["name"])
    assert [call["wsfunction"] for call in calls] == [
        "mod_assign_get_assignments",
        "local_ubionai_list_course_assignments",
        "core_enrol_get_enrolled_users",
    ]
    assert calls[2]["courseid"] == "5"


async def test_seeding_failure_masks_student_name_in_assignment_title():
    page = {
        "courses": [
            {
                "id": 5,
                "fullname": "Course",
                "assignments": [{"id": 9, "name": "김민수 보충 과제"}],
            }
        ],
        "total": 1,
        "offset": 0,
        "limit": 25,
        "warnings": [],
    }
    seed_error = {
        "exception": "moodle_exception",
        "errorcode": "nopermission",
        "message": "Sorry, but you do not currently have permissions to do that",
    }
    token = _current_pseudonymizer.set(Pseudonymizer())
    try:
        result, calls = await call_list_assignments(
            {
                "mod_assign_get_assignments": {"courses": [], "warnings": []},
                "local_ubionai_list_course_assignments": page,
                "core_enrol_get_enrolled_users": seed_error,
            }
        )
    finally:
        _current_pseudonymizer.reset(token)
    rendered = json.dumps(result, ensure_ascii=False)
    assert "김민수" not in rendered
    assert PLACEHOLDER_RE.search(result["courses"][0]["assignments"][0]["name"])
    assert calls[-1]["wsfunction"] == "core_enrol_get_enrolled_users"
    assert calls[-1]["courseid"] == "5"


ORDINARY_TITLES = ["조별 과제", "1주차 보고서", "중간고사 대비 정리", "강의 요약 과제"]


async def test_ordinary_assignment_title_stays_readable():
    page = {
        "courses": [
            {
                "id": 5,
                "fullname": "Course",
                "assignments": [
                    {"id": 9 + index, "name": title}
                    for index, title in enumerate(ORDINARY_TITLES)
                ],
            }
        ],
        "total": 1,
        "offset": 0,
        "limit": 25,
        "warnings": [],
    }
    token = _current_pseudonymizer.set(Pseudonymizer())
    try:
        result, _calls = await call_list_assignments(
            {
                "mod_assign_get_assignments": {"courses": [], "warnings": []},
                "local_ubionai_list_course_assignments": page,
                "core_enrol_get_enrolled_users": [{"id": 7, "fullname": "김민수"}],
            }
        )
    finally:
        _current_pseudonymizer.reset(token)
    rendered = json.dumps(result, ensure_ascii=False)
    assert [a["name"] for a in result["courses"][0]["assignments"]] == ORDINARY_TITLES
    assert PLACEHOLDER_RE.search(rendered) is None


# Names below are not enrolled anywhere, so only the title heuristic can mask them.
UNSEEDED_TITLES = {
    9: ("김철수 박사 특강 감상문", "김철수", " 박사 특강 감상문"),
    10: ("[이영희] 보충과제", "이영희", "] 보충과제"),
    11: ("박민수_기말보고서", "박민수", "_기말보고서"),
}
OTHER_STUDENT = [{"id": 7, "fullname": "최지우", "firstname": "지우", "lastname": "최"}]


def _unseeded_course(courseid=5):
    return {
        "id": courseid,
        "fullname": "Course",
        "assignments": [
            {"id": aid, "name": title} for aid, (title, _, _) in UNSEEDED_TITLES.items()
        ],
    }


def _assert_unseeded_names_masked(result):
    rendered = json.dumps(result, ensure_ascii=False)
    names = {a["id"]: a["name"] for c in result["courses"] for a in c["assignments"]}
    for aid, (_title, name, rest) in UNSEEDED_TITLES.items():
        assert name not in rendered
        assert PLACEHOLDER_RE.search(names[aid])
        assert names[aid].endswith(rest)


async def test_unseeded_names_in_titles_are_masked_without_course_ids():
    page = {"courses": [_unseeded_course()], "total": 1, "warnings": []}
    token = _current_pseudonymizer.set(Pseudonymizer())
    try:
        result, _calls = await call_list_assignments(
            {
                "mod_assign_get_assignments": {"courses": [], "warnings": []},
                "local_ubionai_list_course_assignments": page,
                "core_enrol_get_enrolled_users": OTHER_STUDENT,
            }
        )
    finally:
        _current_pseudonymizer.reset(token)
    _assert_unseeded_names_masked(result)


async def test_unseeded_names_in_titles_are_masked_with_course_ids():
    token = _current_pseudonymizer.set(Pseudonymizer())
    try:
        result, _calls = await call_list_assignments(
            {
                "mod_assign_get_assignments": {"courses": [], "warnings": []},
                "local_ubionai_get_course_assignments": {
                    "courses": [_unseeded_course()],
                    "warnings": [],
                },
                "core_enrol_get_enrolled_users": OTHER_STUDENT,
            },
            course_ids=[5],
        )
    finally:
        _current_pseudonymizer.reset(token)
    _assert_unseeded_names_masked(result)


async def test_title_masking_does_not_depend_on_cached_names():
    key = b"k" * 32
    title_page = {"courses": [_unseeded_course(5)], "total": 1, "warnings": []}
    other_page = {
        "courses": [{"id": 6, "fullname": "Six", "assignments": [{"id": 1, "name": "과제"}]}],
        "total": 1,
        "warnings": [],
    }

    def enrolled(data):
        if data["courseid"] == "6":
            # Course 6 enrols the people named in course 5's titles.
            return [
                {"id": 1, "fullname": "김철수", "firstname": "철수", "lastname": "김"},
                {"id": 2, "fullname": "이영희", "firstname": "영희", "lastname": "이"},
                {"id": 3, "fullname": "박민수", "firstname": "민수", "lastname": "박"},
            ]
        return OTHER_STUDENT

    async def run(pseudonymizer, page):
        token = _current_pseudonymizer.set(pseudonymizer)
        try:
            result, _calls = await call_list_assignments(
                {
                    "mod_assign_get_assignments": {"courses": [], "warnings": []},
                    "local_ubionai_list_course_assignments": page,
                    "core_enrol_get_enrolled_users": enrolled,
                }
            )
        finally:
            _current_pseudonymizer.reset(token)
        return result

    fresh = await run(Pseudonymizer(key), title_page)
    reused = Pseudonymizer(key)
    await run(reused, other_page)
    again = await run(reused, title_page)
    assert fresh == again
    _assert_unseeded_names_masked(fresh)


async def test_seed_calls_request_name_fields_only():
    page = {
        "courses": [
            {"id": 5, "fullname": "Five", "assignments": [{"id": 9, "name": "과제"}]},
            {"id": 6, "fullname": "Six", "assignments": [{"id": 10, "name": "과제"}]},
        ],
        "total": 2,
        "warnings": [],
    }
    token = _current_pseudonymizer.set(Pseudonymizer())
    try:
        _result, calls = await call_list_assignments(
            {
                "mod_assign_get_assignments": {"courses": [], "warnings": []},
                "local_ubionai_list_course_assignments": page,
                "core_enrol_get_enrolled_users": OTHER_STUDENT,
            }
        )
    finally:
        _current_pseudonymizer.reset(token)
    seeds = [call for call in calls if call["wsfunction"] == "core_enrol_get_enrolled_users"]
    assert sorted(call["courseid"] for call in seeds) == ["5", "6"]
    for call in seeds:
        assert call["options[0][name]"] == "userfields"
        assert call["options[0][value]"] == "id,firstname,lastname,fullname"
        assert "onlyactive" not in json.dumps(call)


async def test_one_failed_seed_among_many_keeps_full_heuristic():
    page = {
        "courses": [
            {"id": 5, "fullname": "Five", "assignments": [{"id": 9, "name": "김민수essay"}]},
            {"id": 6, "fullname": "Six", "assignments": [{"id": 10, "name": "과제"}]},
        ],
        "total": 2,
        "warnings": [],
    }
    seed_error = {
        "exception": "moodle_exception",
        "errorcode": "nopermission",
        "message": "no",
    }

    def enrolled(data):
        return seed_error if data["courseid"] == "6" else OTHER_STUDENT

    token = _current_pseudonymizer.set(Pseudonymizer())
    try:
        result, _calls = await call_list_assignments(
            {
                "mod_assign_get_assignments": {"courses": [], "warnings": []},
                "local_ubionai_list_course_assignments": page,
                "core_enrol_get_enrolled_users": enrolled,
            }
        )
    finally:
        _current_pseudonymizer.reset(token)
    # "김민수essay" is only caught by the full heuristic, which applies because
    # seeding course 6 failed.
    assert "김민수" not in json.dumps(result, ensure_ascii=False)


async def test_later_page_does_not_seed_core_courses():
    primary = {
        "courses": [{"id": 9, "fullname": "Nine", "assignments": [{"id": 1, "name": "과제"}]}],
        "warnings": [],
    }
    page = {
        "courses": [{"id": 10, "fullname": "Ten", "assignments": [{"id": 2, "name": "과제"}]}],
        "total": 40,
        "warnings": [],
    }
    token = _current_pseudonymizer.set(Pseudonymizer())
    try:
        result, calls = await call_list_assignments(
            {
                "mod_assign_get_assignments": primary,
                "local_ubionai_list_course_assignments": page,
                "core_enrol_get_enrolled_users": OTHER_STUDENT,
            },
            offset=25,
        )
    finally:
        _current_pseudonymizer.reset(token)
    seeds = [call["courseid"] for call in calls if call["wsfunction"] == "core_enrol_get_enrolled_users"]
    assert seeds == ["10"]
    assert [course["id"] for course in result["courses"]] == [10]


async def test_section_and_module_names_still_use_the_heuristic():
    sections = [
        {
            "id": 1,
            "name": "김민수 보충 수업",
            "modules": [{"id": 2, "name": "박지훈 개별 상담"}],
        }
    ]
    handler, _calls = make_handler({"core_course_get_contents": sections})
    token = _current_pseudonymizer.set(Pseudonymizer())
    try:
        with respx.mock as router:
            router.post(ENDPOINT).mock(side_effect=handler)
            _content, result = await mcp().call_tool(
                "get_course_outline", {"course_id": 5}
            )
    finally:
        _current_pseudonymizer.reset(token)
    rendered = json.dumps(result, ensure_ascii=False)
    assert "김민수" not in rendered
    assert "박지훈" not in rendered
    assert len(PLACEHOLDER_RE.findall(rendered)) == 2


def test_local_read_function_is_not_a_write():
    assert _is_write("local_ubionai_get_course_assignments") is False
    assert _is_write("local_ubionai_list_course_assignments") is False
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
        "users": [{"id": 7, "fullname": "김민수"}],
        "warnings": [],
    }
    token = _current_pseudonymizer.set(Pseudonymizer())
    try:
        result, _calls = await call_list_assignments(
            {
                "mod_assign_get_assignments": {"courses": [], "warnings": []},
                "local_ubionai_get_course_assignments": fallback,
                "core_enrol_get_enrolled_users": [{"id": 7, "fullname": "김민수"}],
            },
            course_ids=[5],
        )
    finally:
        _current_pseudonymizer.reset(token)
    rendered = json.dumps(result, ensure_ascii=False)
    assert "김민수" not in rendered
    assert PLACEHOLDER_RE.search(rendered)
    assert result["courses"][0]["source"] == "local_ubionai"
