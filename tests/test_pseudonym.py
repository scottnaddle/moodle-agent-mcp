import json
import logging
import re
import types

import pytest

from moodle_mcp import pseudonym as pseudonym_module
from moodle_mcp.pseudonym import PLACEHOLDER_RE, Pseudonymizer

NAME_RE = re.compile(r"\[이름_[0-9a-f]{8}\]")
STUDENT_ID_RE = re.compile(r"\[학번_[0-9a-f]{8}\]")
EMAIL_RE = re.compile(r"\[이메일_[0-9a-f]{8}\]")
PHONE_RE = re.compile(r"\[전화번호_[0-9a-f]{8}\]")


def one(pattern, text):
    match = pattern.search(text)
    assert match is not None, text
    return match.group(0)


def roundtrip(text):
    p = Pseudonymizer()
    masked = p.pseudonymize(text)
    assert p.restore(masked) == text
    return masked


def test_mixed_korean_roundtrip():
    text = (
        "안녕하세요. 홍길동님과 김철수 학생입니다. "
        "학번은 2023123456이고 이메일은 hong@example.com 입니다. "
        "Park Jisung (park@example.org) also joined."
    )
    masked = roundtrip(text)
    assert "홍길동" not in masked
    assert "김철수" not in masked
    assert "2023123456" not in masked
    assert "hong@example.com" not in masked
    assert NAME_RE.search(masked)
    assert STUDENT_ID_RE.search(masked)
    assert EMAIL_RE.search(masked)


def test_placeholders_are_stable_and_per_category():
    p = Pseudonymizer()
    first = p.pseudonymize("김철수")
    second = p.pseudonymize("김철수")
    assert first == second
    assert PLACEHOLDER_RE.fullmatch(first)

    both = p.pseudonymize("홍길동 김철수")
    names = NAME_RE.findall(both)
    assert len(names) == 2
    assert len(set(names)) == 2

    mixed = p.pseudonymize("박지성 2023123456")
    assert NAME_RE.search(mixed)
    assert STUDENT_ID_RE.search(mixed)

    spaced = p.pseudonymize("김 민수")
    assert spaced != p.pseudonymize("김민수")


def test_surrounding_hangul_and_particles_are_kept():
    p = Pseudonymizer()
    assert re.fullmatch(r"학생\[이름_[0-9a-f]{8}\]입니다", p.pseudonymize("학생김철수입니다"))
    p = Pseudonymizer()
    assert re.fullmatch(r"\[이름_[0-9a-f]{8}\]님", p.pseudonymize("홍길동님"))
    p = Pseudonymizer()
    assert re.fullmatch(r"\[이름_[0-9a-f]{8}\]의", p.pseudonymize("김철수의"))
    p = Pseudonymizer()
    assert re.fullmatch(r"학번 \[학번_[0-9a-f]{8}\]번", p.pseudonymize("학번 2023123456번"))
    p = Pseudonymizer()
    assert re.fullmatch(r"연락처는 \[이메일_[0-9a-f]{8}\]입니다\.", p.pseudonymize("연락처는 hong@example.com입니다."))
    p = Pseudonymizer()
    masked = p.pseudonymize("홍길동이랑 김철수가 왔습니다")
    assert re.fullmatch(
        r"\[이름_[0-9a-f]{8}\]이랑 \[이름_[0-9a-f]{8}\]가 왔습니다", masked
    )


def test_heuristic_boundaries():
    p = Pseudonymizer()
    assert p.pseudonymize("사과") == "사과"
    assert p.pseudonymize("학교") == "학교"
    assert p.pseudonymize("김철수영희박") == "김철수영희박"
    assert PLACEHOLDER_RE.fullmatch(p.pseudonymize("1234567"))
    assert p.pseudonymize("12345678901") == "12345678901"
    assert p.pseudonymize("A2023123456B") == "A2023123456B"
    assert p.pseudonymize("abc12345678xyz") == "abc12345678xyz"


def test_known_name_seeding_and_longest_first():
    p = Pseudonymizer(known_names=["김철수"])
    masked = p.pseudonymize("오늘 김철수 학생이 왔습니다")
    assert re.fullmatch(r"오늘 \[이름_[0-9a-f]{8}\] 학생이 왔습니다", masked)

    p = Pseudonymizer(known_names=["김철"])
    masked = p.pseudonymize("김철수")
    assert PLACEHOLDER_RE.fullmatch(masked)

    p = Pseudonymizer(known_names=["김철", "김철수"])
    assert PLACEHOLDER_RE.fullmatch(p.pseudonymize("김철수"))


def test_detected_names_are_reused_within_instance():
    p = Pseudonymizer()
    first = p.pseudonymize("김철수")
    assert p.pseudonymize("김철수님 안녕하세요") == first + "님 안녕하세요"


def test_same_key_is_stable_across_instances():
    key = b"k" * 32
    text = "김민수 학생의 학번은 20231234입니다"
    first = Pseudonymizer(key).pseudonymize(text)
    second = Pseudonymizer(key).pseudonymize(text)
    assert first == second
    assert "김민수" not in first and "20231234" not in first


def test_different_keys_change_placeholders():
    text = "김민수 학생"
    first = Pseudonymizer(b"a" * 32).pseudonymize(text)
    second = Pseudonymizer(b"b" * 32).pseudonymize(text)
    assert NAME_RE.search(first)
    assert NAME_RE.search(second)
    assert NAME_RE.search(first).group(0) != NAME_RE.search(second).group(0)


def test_idempotence():
    p = Pseudonymizer()
    masked = p.pseudonymize("김민수 학생의 학번은 20231234입니다")
    assert p.pseudonymize(masked) == masked
    assert len(PLACEHOLDER_RE.findall(p.pseudonymize(masked))) == 2


def test_email_and_phone_normalization():
    p = Pseudonymizer()
    assert p.pseudonymize("HONG@Example.com") == p.pseudonymize("hong@example.com")
    assert p.pseudonymize("010-1234-5678") == p.pseudonymize("010 1234 5678")
    assert PHONE_RE.fullmatch(p.pseudonymize("010-1234-5678"))


def test_forced_collision_is_ambiguous_and_unresolved(monkeypatch):
    fixed = types.SimpleNamespace(hexdigest=lambda: "deadbeef" * 8)
    monkeypatch.setattr(pseudonym_module.hmac, "new", lambda *args, **kwargs: fixed)
    p = Pseudonymizer(b"k" * 32)
    first = p.pseudonymize("김민수")
    second = p.pseudonymize("홍길동")
    assert first == second == "[이름_deadbeef]"
    assert first in p.unresolved(first)
    assert p.restore(first) == first


def test_course_fields_are_not_field_masked_but_users_are():
    p = Pseudonymizer()
    payload = {
        "courses": [
            {
                "id": 5,
                "fullname": "데이터과학 입문",
                "shortname": "DS101",
                "assignments": [{"id": 9, "name": "Week 1 essay"}],
            }
        ],
        "users": [
            {
                "id": 7,
                "fullname": "김민수",
                "email": "kim@example.com",
                "idnumber": "20231234",
            }
        ],
    }

    masked = p.pseudonymize_value(payload)

    assert masked["courses"][0]["fullname"] == "데이터과학 입문"
    assert masked["courses"][0]["shortname"] == "DS101"
    assert NAME_RE.fullmatch(masked["users"][0]["fullname"])
    assert EMAIL_RE.fullmatch(masked["users"][0]["email"])
    assert STUDENT_ID_RE.fullmatch(masked["users"][0]["idnumber"])


def test_user_like_objects_are_detected_by_marker_keys_and_containers():
    p = Pseudonymizer()
    payload = {
        "id": 1,
        "fullname": "데이터과학 입문",
        "shortname": "DS101",
        "category": {"id": 2, "fullname": "공학", "shortname": "ENG"},
        "author": {"id": 7, "fullname": "김민수"},
        "participants": [{"id": 8, "fullname": "홍길동"}],
    }

    masked = p.pseudonymize_value(payload)

    assert masked["fullname"] == "데이터과학 입문"
    assert masked["shortname"] == "DS101"
    assert masked["category"]["fullname"] == "공학"
    assert NAME_RE.fullmatch(masked["author"]["fullname"])
    assert NAME_RE.fullmatch(masked["participants"][0]["fullname"])


def test_top_level_user_markers_enable_field_masking():
    p = Pseudonymizer()
    masked = p.pseudonymize_value(
        {"fullname": "김민수", "email": "kim@example.com", "idnumber": "20231234"}
    )
    assert NAME_RE.fullmatch(masked["fullname"])
    assert EMAIL_RE.fullmatch(masked["email"])
    assert STUDENT_ID_RE.fullmatch(masked["idnumber"])


def test_assignment_titles_skip_heuristic_but_keep_known_names():
    p = Pseudonymizer()
    payload = {
        "assignments": [
            {"id": 9, "name": "조별 과제 발표"},
            {"id": 10, "name": "김민수 보충 과제"},
        ],
        "users": [{"id": 3, "fullname": "김민수"}],
    }
    masked = p.pseudonymize_value(payload, assignment_titles=True)
    assert masked["assignments"][0]["name"] == "조별 과제 발표"
    assert NAME_RE.fullmatch(masked["assignments"][1]["name"].split(" ")[0])
    assert "김민수" not in json.dumps(masked, ensure_ascii=False)


def test_non_assignment_names_keep_the_heuristic():
    p = Pseudonymizer()
    masked = p.pseudonymize_value(
        {"sections": [{"name": "김민수 보충 수업"}]}, assignment_titles=True
    )
    assert "김민수" not in masked["sections"][0]["name"]


def test_intro_free_text_still_heuristic():
    p = Pseudonymizer()
    masked = p.pseudonymize_value({"intro": "김민수 학생 제출"})
    assert "김민수" not in masked["intro"]


def test_pseudonymize_heuristic_flag_backward_compatible():
    p = Pseudonymizer()
    assert p.pseudonymize("홍길동", heuristic=True) == p.pseudonymize("홍길동")
    assert "홍길동" in p.pseudonymize("홍길동", heuristic=False)


def test_course_idnumber_does_not_trigger_user_masking():
    p = Pseudonymizer()
    payload = {
        "courses": [
            {
                "id": 5,
                "fullname": "데이터과학 입문",
                "shortname": "DS101",
                "idnumber": "DS-2026",
            }
        ]
    }
    masked = p.pseudonymize_value(payload)
    assert masked["courses"][0]["fullname"] == "데이터과학 입문"
    assert masked["courses"][0]["shortname"] == "DS101"
    assert masked["courses"][0]["idnumber"] == "DS-2026"


def test_user_with_only_id_and_fullname_under_users_still_masked():
    p = Pseudonymizer()
    masked = p.pseudonymize_value(
        {"users": [{"id": 7, "fullname": "김민수", "idnumber": "20231234"}]}
    )
    assert NAME_RE.fullmatch(masked["users"][0]["fullname"])
    assert STUDENT_ID_RE.fullmatch(masked["users"][0]["idnumber"])


def test_pseudonymize_restore_does_not_log_pii(caplog):
    caplog.set_level(logging.DEBUG)
    p = Pseudonymizer()
    masked = p.pseudonymize("홍길동 2023123456 hong@example.com")
    p.restore(masked)
    assert "홍길동" not in caplog.text
    assert "2023123456" not in caplog.text
    assert "hong@example.com" not in caplog.text
    assert "[이름_" not in caplog.text


def test_title_heuristic_masks_name_tokens_only():
    p = Pseudonymizer()
    for title in ("김철수 박사 특강 감상문", "[이영희] 보충과제", "박민수_기말보고서", "정민 학생 과제"):
        assert NAME_RE.search(p.pseudonymize(title, heuristic="title")), title
    for title in ("조별로 발표", "1주차 보고서", "2주차-발표자료", "우리의 이야기", "보고서의 구조"):
        assert p.pseudonymize(title, heuristic="title") == title


def test_assignment_title_heuristic_setting():
    payload = {"assignments": [{"id": 9, "name": "김철수 감상문"}]}
    masked = {
        mode: Pseudonymizer(assignment_title_heuristic=mode).pseudonymize_value(
            payload, assignment_titles=True
        )["assignments"][0]["name"]
        for mode in ("full", "title", "off")
    }
    assert NAME_RE.fullmatch(masked["full"].split(" ")[0])
    assert NAME_RE.fullmatch(masked["title"].split(" ")[0])
    assert masked["off"] == "김철수 감상문"
    assert Pseudonymizer().assignment_title_heuristic == "title"


def test_invalid_heuristic_mode_rejected():
    with pytest.raises(ValueError):
        Pseudonymizer(assignment_title_heuristic="loose")
    with pytest.raises(ValueError):
        Pseudonymizer().pseudonymize("김철수", heuristic="loose")


def test_known_names_longest_first_and_boundaries():
    p = Pseudonymizer(known_names=["김민", "김민수", "Kim"])
    masked = p.pseudonymize("김민수님, 김민과 Kim, Kimchi", heuristic="off")
    assert "김민" not in masked
    assert masked.count("[이름_") == 3
    assert "Kimchi" in masked
    assert p.pseudonymize("이김민수", heuristic="off") == "이김민수"


def test_known_names_are_capped_lru():
    p = Pseudonymizer(known_max=2)
    p.add_known("가나다")
    p.add_known("라마바")
    p.add_known("가나다")  # refresh: 라마바 is now the oldest
    p.add_known("사아자")
    assert "가나다" not in p.pseudonymize("가나다", heuristic="off")
    assert p.pseudonymize("라마바", heuristic="off") == "라마바"
    assert "사아자" not in p.pseudonymize("사아자", heuristic="off")


def _random_users(count):
    import random

    rnd = random.Random(20261101)
    syllables = [chr(code) for code in range(0xAC00, 0xD7A4)]
    users = []
    for index in range(count):
        first = "".join(rnd.choice(syllables) for _ in range(2))
        last = rnd.choice(pseudonym_module.SURNAMES)
        users.append(
            {"id": index, "firstname": first, "lastname": last, "fullname": last + first}
        )
    return users


@pytest.mark.slow
def test_known_name_matching_scales():
    import time

    p = Pseudonymizer()
    users = _random_users(5000)
    p.seed({"users": users})
    texts = [
        f"{users[index]['fullname']} 학생의 {index}주차 과제 제출" for index in range(1000)
    ]
    started = time.perf_counter()
    masked = [p.pseudonymize(text) for text in texts]
    assert time.perf_counter() - started < 2.0
    assert all(users[index]["fullname"] not in masked[index] for index in range(1000))


def test_useridnumber_in_grade_items_is_masked():
    p = Pseudonymizer()
    masked = p.pseudonymize_value(
        {
            "usergrades": [
                {"courseid": 3, "userid": 7, "userfullname": "홍길동", "useridnumber": "ST-001"}
            ]
        }
    )
    grade = masked["usergrades"][0]
    assert STUDENT_ID_RE.fullmatch(grade["useridnumber"])
    assert NAME_RE.fullmatch(grade["userfullname"])
    assert "ST-001" not in json.dumps(masked, ensure_ascii=False)


def test_idnumber_regressions():
    p = Pseudonymizer()
    course = p.pseudonymize_value({"id": 3, "fullname": "자료구조", "idnumber": "CS-2026"})
    assert course["fullname"] == "자료구조"
    users = p.pseudonymize_value(
        {"users": [{"id": 1, "idnumber": "ST-001", "fullname": "홍길동"}]}
    )
    assert STUDENT_ID_RE.fullmatch(users["users"][0]["idnumber"])
