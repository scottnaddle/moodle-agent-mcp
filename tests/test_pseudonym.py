import logging

from moodle_mcp.pseudonym import Pseudonymizer


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
    assert "[이름_1]" in masked
    assert "[학번_1]" in masked
    assert "[이메일_1]" in masked


def test_placeholders_are_stable_and_per_category():
    p = Pseudonymizer()
    first = p.pseudonymize("김철수")
    second = p.pseudonymize("김철수")
    assert first == second == "[이름_1]"

    both = p.pseudonymize("홍길동 김철수")
    assert "[이름_2]" in both
    assert "[이름_1]" in both

    mixed = p.pseudonymize("박지성 2023123456")
    assert "[이름_3]" in mixed
    assert "[학번_1]" in mixed


def test_surrounding_hangul_and_particles_are_kept():
    p = Pseudonymizer()
    assert p.pseudonymize("학생김철수입니다") == "학생[이름_1]입니다"
    p = Pseudonymizer()
    assert p.pseudonymize("홍길동님") == "[이름_1]님"
    p = Pseudonymizer()
    assert p.pseudonymize("김철수의") == "[이름_1]의"
    p = Pseudonymizer()
    assert p.pseudonymize("학번 2023123456번") == "학번 [학번_1]번"
    p = Pseudonymizer()
    assert p.pseudonymize("연락처는 hong@example.com입니다.") == "연락처는 [이메일_1]입니다."
    p = Pseudonymizer()
    assert p.pseudonymize("홍길동이랑 김철수가 왔습니다") == "[이름_1]이랑 [이름_2]가 왔습니다"


def test_heuristic_boundaries():
    p = Pseudonymizer()
    assert p.pseudonymize("사과") == "사과"
    assert p.pseudonymize("학교") == "학교"
    assert p.pseudonymize("김철수영희박") == "김철수영희박"
    assert p.pseudonymize("1234567") == "[학번_1]"
    assert p.pseudonymize("12345678901") == "12345678901"
    assert p.pseudonymize("A2023123456B") == "A2023123456B"
    assert p.pseudonymize("abc12345678xyz") == "abc12345678xyz"


def test_known_name_seeding_and_longest_first():
    p = Pseudonymizer(["김철수"])
    assert p.pseudonymize("오늘 김철수 학생이 왔습니다") == "오늘 [이름_1] 학생이 왔습니다"

    p = Pseudonymizer(["김철"])
    masked = p.pseudonymize("김철수")
    assert masked == "[이름_1]"
    assert "수" not in masked.replace("[이름_1]", "")

    p = Pseudonymizer(["김철", "김철수"])
    assert p.pseudonymize("김철수") == "[이름_1]"


def test_detected_names_are_reused_within_instance():
    p = Pseudonymizer()
    assert p.pseudonymize("김철수") == "[이름_1]"
    assert p.pseudonymize("김철수님 안녕하세요") == "[이름_1]님 안녕하세요"


def test_pseudonymize_restore_does_not_log_pii(caplog):
    caplog.set_level(logging.DEBUG)
    p = Pseudonymizer()
    masked = p.pseudonymize("홍길동 2023123456 hong@example.com")
    p.restore(masked)
    assert "홍길동" not in caplog.text
    assert "2023123456" not in caplog.text
    assert "hong@example.com" not in caplog.text
    assert "[이름_1]" not in caplog.text
