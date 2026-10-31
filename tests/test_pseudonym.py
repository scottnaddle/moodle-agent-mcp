import logging
import re
import types

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


def test_pseudonymize_restore_does_not_log_pii(caplog):
    caplog.set_level(logging.DEBUG)
    p = Pseudonymizer()
    masked = p.pseudonymize("홍길동 2023123456 hong@example.com")
    p.restore(masked)
    assert "홍길동" not in caplog.text
    assert "2023123456" not in caplog.text
    assert "hong@example.com" not in caplog.text
    assert "[이름_" not in caplog.text
