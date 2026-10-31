"""Reversible Korean PII pseudonymization for hub-mode requests.

A :class:`Pseudonymizer` keeps a bidirectional mapping between originals and
placeholders such as ``[이름_1]``, ``[학번_1]`` and ``[이메일_1]``. The mapping is
only kept in process memory; it is never logged or persisted.

Known tradeoff: if the original text already contains a literal string that
looks like an allocated placeholder (for example ``[이름_1]``), it collides with
the generated placeholder. It is not escaped.
"""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Iterable
from functools import lru_cache

_SINGLE_SURNAMES = (
    "김이박최정강조윤장임한오서신권황안송류유홍전고문양손배백허남심노하곽성차주우구"
    "민진나지엄채원천방공현함변염여추도소석선설마길연위표명기반라왕금옥육인맹제모탁"
    "국어은편용예경봉사부가복태목형피두감음계"
)
SURNAMES = _SINGLE_SURNAMES
_TWO_SYLLABLE_SURNAMES = ("남궁", "황보", "제갈", "선우", "독고", "동방", "서문", "사공")
_NAME_LABELS = {
    "name": "이름",
    "student_id": "학번",
    "email": "이메일",
    "phone": "전화번호",
    "resident_id": "주민번호",
}
_NAME_FIELDS = {"firstname", "lastname", "fullname", "userfullname", "username"}
_EMAIL_FIELDS = {"email", "emailaddress"}

# Particles/endings and titles that may directly follow a Korean name. They are
# kept in the text while the name itself is replaced. Longest first so "입니다"
# wins over "이".
_PARTICLES = (
    "입니다",
    "입니까",
    "이에요",
    "예요",
    "이다",
    "이고",
    "이며",
    "이라",
    "이란",
    "이랑",
    "은요",
    "는요",
    "이요",
    "에게",
    "한테",
    "께서",
    "에서",
    "부터",
    "까지",
    "으로",
    "보다",
    "처럼",
    "만큼",
    "밖에",
    "하고",
    "님",
    "씨",
    "의",
    "이",
    "가",
    "은",
    "는",
    "을",
    "를",
    "도",
    "만",
    "께",
    "로",
    "와",
    "과",
    "랑",
)
_TITLES = ("학생", "교수", "선생", "조교", "군", "양", "외", "님")
_SUFFIXES = tuple(
    sorted(set(_PARTICLES) | set(_TITLES), key=len, reverse=True)
)

# Used only for heuristic (unseeded) matching. These are ordinary words that
# happen to start with a surname syllable, not people. Ambiguous two-syllable
# words that are also common given names (정원, 이민, 이용, 정의, 송이, 장기,
# 이은) are deliberately not listed.
_STOPWORDS = frozenset(
    {
        "이것", "이거", "이제", "이번", "이날", "이때", "이를", "이와", "이후", "이전",
        "이상", "이하", "이외", "이내", "이어", "이고", "이며", "이나", "이란", "이라",
        "이든", "이런", "이렇", "이쪽", "이곳", "이분", "이들", "이중", "이만", "이밖",
        "이른", "이야기", "이렇게", "이러한", "이래", "이로", "이에", "이조", "이불",
        "이사", "이혼", "이해", "이론", "이익", "이슈", "이력", "이름",
        "이메일", "메일", "이모", "이벤트", "이력서", "이용자", "이용료", "이웃",
        "안녕", "안녕하세요", "안녕하십니까", "안녕히", "하세요",
        "연락처", "사과",
        "한국", "한글", "한번", "하나", "하루", "한쪽", "한편", "한때", "한층", "한마디",
        "한가지", "한국어", "한국인", "한눈", "한데", "한잔", "한강",
        "강의", "강좌", "강사", "강조", "강력", "강변", "강물", "강아지", "강하다",
        "강의실", "강당", "강점", "강제", "강화",
        "조금", "조사", "조회", "조치", "조정", "조심", "조용", "조용히", "조합",
        "조절", "조건", "조기", "조명", "조언", "조각",
        "정말", "정도", "정리", "정보", "정확", "정책", "정부", "정상", "정지", "제공",
        "정면", "정말로", "정성", "정오", "정형",
        "최근", "최대", "최소", "최선", "최고", "최초", "최종", "최신", "최우선",
        "박수", "박사", "박물관", "박스", "박자", "박수갈채",
        "윤리", "윤곽",
        "장소", "장점", "장학", "장비", "장면", "장애", "장관", "장난", "장르",
        "임시", "임의", "임금", "임대", "임차", "임신",
        "오늘", "오후", "오전", "오래", "오류", "오직", "오히려", "오랜", "오늘날", "오해",
        "서로", "서버", "서비스", "서류", "서두", "서부", "서울", "서쪽", "서울시",
        "신청", "신규", "신속", "신고", "신뢰", "신제품", "신입", "신체", "신분", "신호",
        "권한", "권리", "권고", "권유",
        "황당", "황금", "황색",
        "안전", "안내", "안경", "안과", "안쪽", "안되", "안된다",
        "송부", "송금", "송년",
        "김치", "김밥", "김장", "김포", "김해",
        "최악", "최적",
        "선생", "학생", "교수", "조교",
        "류현", "류머티즘",
    }
)


@lru_cache(maxsize=None)
def _is_particle_word(word: str) -> bool:
    """True when the whole word can be segmented into particles (e.g. 이가)."""
    if not word:
        return True
    return any(
        word.startswith(particle) and _is_particle_word(word[len(particle) :])
        for particle in _PARTICLES
    )


def _is_stopword(word: str) -> bool:
    if word in _STOPWORDS:
        return True
    for suffix in _SUFFIXES:
        if word.endswith(suffix):
            base = word[: -len(suffix)]
            if len(base) >= 3 and base in _STOPWORDS:
                return True
    return False


def _hangul_only(text: str) -> bool:
    return bool(text) and all("\uac00" <= char <= "\ud7a3" for char in text)


def _starts_with_suffix(text: str) -> bool:
    return bool(text) and any(text.startswith(suffix) for suffix in _SUFFIXES)


def _ends_with_suffix(text: str) -> bool:
    return any(text.endswith(suffix) for suffix in _SUFFIXES)


def _boundary_ok(after: str) -> bool:
    if not after:
        return True
    if not _hangul_only(after[0]):
        return True
    return _starts_with_suffix(after)


def _heuristic_match_at(text: str, start: int) -> tuple[int, str, str] | None:
    if start + 2 <= len(text) and text[start : start + 2] in _TWO_SYLLABLE_SURNAMES:
        surname_len = 2
    elif text[start] in _SINGLE_SURNAMES:
        surname_len = 1
    else:
        return None

    options: list[tuple[int, str, str]] = []
    for given_len in (1, 2, 3):
        end = start + surname_len + given_len
        if end > len(text):
            continue
        candidate = text[start:end]
        if not _hangul_only(candidate):
            continue
        after = text[end:]
        if not _boundary_ok(after):
            continue
        if _is_stopword(candidate):
            continue
        if any(candidate.startswith(title) for title in _TITLES if len(title) >= 2):
            continue
        if given_len == 1 and _is_particle_word(candidate):
            continue
        options.append((given_len, candidate, after))
    if not options:
        return None

    longest = max(options, key=lambda option: option[0])
    if _ends_with_suffix(longest[1]):
        alternatives = [
            option
            for option in options
            if 2 <= option[0] < longest[0] and _starts_with_suffix(option[2])
        ]
        if alternatives:
            longest = max(alternatives, key=lambda option: option[0])
    return longest


# Student ids: 7-10 bare digits, hyphenated ids such as 2023-12345, and
# letter-prefixed ids such as S20231234 / ID20231234. Arbitrary longer runs and
# ids embedded in larger alphanumeric tokens are left alone.
_STUDENT_ID_RE = re.compile(
    r"(?<![0-9A-Za-z])(?:[A-Za-z]{1,3})?(?:\d{4}-\d{4,6}|\d{7,10})(?![0-9A-Za-z])"
)
_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._+-])[A-Za-z0-9._+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?![A-Za-z0-9-])"
)
_RESIDENT_ID_RE = re.compile(r"(?<!\d)\d{6}[- ]?\d{7}(?!\d)")
_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+82[- ]?0?|0)(?:1[016789]|[2-6]\d?)[- ]?\d{3,4}[- ]?\d{4}(?!\d)"
)


def _known_pattern(name: str) -> re.Pattern[str]:
    escaped = re.escape(name)
    before = r"(?<![가-힣])" if _hangul_only(name[:1]) else r"(?<!\w)"
    after = (
        rf"(?=(?:{'|'.join(re.escape(suffix) for suffix in _SUFFIXES)}|[^가-힣]|$))"
        if _hangul_only(name[-1:])
        else r"(?!\w)"
    )
    return re.compile(before + escaped + after)


def _field_category(key: str | None, name_keys: frozenset[str] = frozenset()) -> str | None:
    if not isinstance(key, str):
        return None
    lowered = key.lower()
    if lowered in _NAME_FIELDS or lowered in name_keys:
        return "name"
    if lowered == "idnumber":
        return "student_id"
    if lowered in _EMAIL_FIELDS:
        return "email"
    return None


class Pseudonymizer:
    """Reversible pseudonymizer for Korean names, ids, emails and phone numbers."""

    def __init__(self, known_names: Iterable[str] = ()) -> None:
        self._known: set[str] = set()
        self._forward: dict[str, dict[str, str]] = {
            category: {} for category in _NAME_LABELS
        }
        self._reverse: dict[str, str] = {}
        self._counters: dict[str, int] = {category: 0 for category in _NAME_LABELS}
        self._lock = threading.RLock()
        for name in known_names:
            self.add_known(name)

    def add_known(self, name: str) -> None:
        name = name.strip()
        if name:
            with self._lock:
                self._known.add(name)

    def _allocate(self, category: str, original: str) -> str:
        with self._lock:
            mapping = self._forward[category]
            placeholder = mapping.get(original)
            if placeholder is not None:
                return placeholder
            self._counters[category] += 1
            placeholder = f"[{_NAME_LABELS[category]}_{self._counters[category]}]"
            mapping[original] = placeholder
            self._reverse[placeholder] = original
            return placeholder

    def _seed_name(self, value: str) -> None:
        value = value.strip()
        if len(value) < 2:
            return
        self.add_known(value)
        for part in re.split(r"\s+", value):
            if len(part) >= 2:
                self.add_known(part)

    def _seed_from(self, value: object, name_keys: frozenset[str] = frozenset()) -> None:
        if isinstance(value, dict):
            lowered: dict[str, object] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    continue
                lowered[key.lower()] = item
                if isinstance(item, str) and _field_category(key, name_keys) == "name":
                    self._seed_name(item)
                self._seed_from(item, name_keys)
            last = lowered.get("lastname")
            first = lowered.get("firstname")
            if isinstance(last, str) and isinstance(first, str):
                self._seed_name(last + first)
                self._seed_name(last + " " + first)
                self._seed_name(first + last)
                self._seed_name(first + " " + last)
            for key in ("fullname", "userfullname"):
                full = lowered.get(key)
                if isinstance(full, str):
                    self._seed_name(full)
        elif isinstance(value, (list, tuple)):
            for item in value:
                self._seed_from(item, name_keys)

    def _transform(self, value: object, key: str | None = None, name_keys: frozenset[str] = frozenset()) -> object:
        if isinstance(value, dict):
            out: dict[object, object] = {}
            for item_key, item in value.items():
                new_key = self.pseudonymize(item_key) if isinstance(item_key, str) else item_key
                out[new_key] = self._transform(item, item_key, name_keys)
            return out
        if isinstance(value, (list, tuple)):
            return [self._transform(item, key=None, name_keys=name_keys) for item in value]
        if isinstance(value, str):
            category = _field_category(key, name_keys)
            if category is not None:
                return self._allocate(category, value)
            return self.pseudonymize(value)
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            category = _field_category(key, name_keys)
            if category is not None:
                return self._allocate(category, str(value))
        return value

    def pseudonymize_value(self, value: object, *, name_keys: frozenset[str] = frozenset()) -> object:
        self._seed_from(value, name_keys)
        return self._transform(value, name_keys=name_keys)

    def pseudonymize_chat_payload(self, payload: object) -> object:
        self._seed_from(payload)
        if isinstance(payload, dict):
            messages = payload.get("messages")
            if isinstance(messages, list):
                for message in messages:
                    if not isinstance(message, dict):
                        continue
                    if isinstance(message.get("name"), str):
                        self._seed_name(message["name"])
                        message["name"] = self._allocate("name", message["name"])
                    tool_calls = message.get("tool_calls")
                    if not isinstance(tool_calls, list):
                        continue
                    for call in tool_calls:
                        function = call.get("function") if isinstance(call, dict) else None
                        arguments = function.get("arguments") if isinstance(function, dict) else None
                        if not isinstance(arguments, str):
                            continue
                        try:
                            parsed = json.loads(arguments)
                        except (ValueError, TypeError):
                            continue
                        if isinstance(parsed, (dict, list)):
                            function["arguments"] = json.dumps(
                                self.pseudonymize_value(parsed), ensure_ascii=False
                            )
            if isinstance(payload.get("user"), str):
                self._seed_name(payload["user"])
                payload["user"] = self._allocate("name", payload["user"])
        return self._transform(payload)

    def _replace(self, sentinels: dict[str, str], category: str, original: str) -> str:
        placeholder = self._allocate(category, original)
        sentinel = f"\x00{len(sentinels)}\x00"
        sentinels[sentinel] = placeholder
        return sentinel

    def pseudonymize(self, text: str) -> str:
        if not text:
            return text

        sentinels: dict[str, str] = {}

        def replace(original: str, category: str) -> str:
            return self._replace(sentinels, category, original)

        result = text
        for name in sorted(self._known, key=len, reverse=True):
            result = _known_pattern(name).sub(
                lambda match: replace(match.group(0), "name"), result
            )

        pieces: list[str] = []
        index = 0
        while index < len(result):
            match = _heuristic_match_at(result, index)
            if match is None:
                pieces.append(result[index])
                index += 1
                continue
            _, candidate, _ = match
            pieces.append(replace(candidate, "name"))
            index += len(candidate)
        result = "".join(pieces)

        result = _EMAIL_RE.sub(lambda match: replace(match.group(0), "email"), result)
        result = _RESIDENT_ID_RE.sub(
            lambda match: replace(match.group(0), "resident_id"), result
        )
        result = _PHONE_RE.sub(lambda match: replace(match.group(0), "phone"), result)
        result = _STUDENT_ID_RE.sub(
            lambda match: replace(match.group(0), "student_id"), result
        )
        for sentinel, placeholder in sentinels.items():
            result = result.replace(sentinel, placeholder)
        return result

    def restore(self, text: str) -> str:
        if not text:
            return text
        with self._lock:
            items = list(self._reverse.items())
        for placeholder, original in items:
            text = text.replace(placeholder, original)
        return text

    def restore_value(self, value: object) -> object:
        if isinstance(value, str):
            return self.restore(value)
        if isinstance(value, (list, tuple)):
            return [self.restore_value(item) for item in value]
        if isinstance(value, dict):
            return {
                self.restore(key) if isinstance(key, str) else key: self.restore_value(item)
                for key, item in value.items()
            }
        return value
