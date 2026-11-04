"""Reversible Korean PII pseudonymization for hub-mode requests.

A :class:`Pseudonymizer` maps originals to deterministic placeholders such as
``[이름_3fa9c1d2]``. In hub mode the mapping is stored encrypted in the tenant
registry; single-tenant and unit-test use falls back to an in-process store.
Mappings and key material are never logged.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import threading
import time
import unicodedata
from collections import OrderedDict
from collections.abc import Iterable
from functools import lru_cache
from typing import TYPE_CHECKING, Literal, Protocol

from .crypto import (
    PURPOSE_PSEUDONYM_HMAC,
    PURPOSE_PSEUDONYM_MAP,
    Kek,
    derive_key,
)
from .registry import PSEUDONYM_TTL

if TYPE_CHECKING:
    from .registry import Registry

logger = logging.getLogger(__name__)

_COLLISION_COUNT = 0
_CACHE_MAX = 4096

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
# Field-key masking only applies inside user-like objects. Courses, categories
# and activities also have fullname/shortname fields that must stay readable.
_USER_CONTAINER_KEYS = frozenset(
    {"users", "participants", "members", "students", "author", "user"}
)
_USER_MARKER_KEYS = frozenset(
    {"firstname", "lastname", "email", "emailaddress", "username", "userid"}
)
# Names of non-user objects (courses, categories, activities) are kept as-is,
# including from heuristic name detection, unless the object is user-like.
_PLAIN_OBJECT_FIELDS = frozenset(
    {"fullname", "shortname", "displayname", "categoryname", "coursename"}
)
# Structural label fields of non-user objects (activities, grade items,
# sections). Free-text fields (intro/summary/message/text) keep the full
# heuristic since student names may appear inside them.
_LABEL_FIELDS = frozenset({"name", "itemname", "sectionname"})
# Assignment titles (only inside "assignments" lists of list_assignments
# results): full heuristic Korean-name detection causes false positives on
# activity titles, so the assignment "name" uses the tenant's
# assignment_title_heuristic mode (default "title", a weaker heuristic).
# Known names seeded from the courses' enrolled users are always masked there.
# _LABEL_FIELDS (name/itemname/sectionname) use the same mode, but only when
# the call is seeded (assignment_titles=True); unseeded calls keep the full
# heuristic on every field so a failed seed fails closed. Free-text fields
# (intro/summary/message/text) always keep the full heuristic.
_ASSIGNMENT_LIST_KEY = "assignments"
_ASSIGNMENT_TITLE_KEY = "name"

HeuristicMode = Literal["full", "title", "off"]
HEURISTIC_MODES: tuple[str, ...] = ("full", "title", "off")
DEFAULT_ASSIGNMENT_TITLE_HEURISTIC: HeuristicMode = "title"
# Upper bound on seeded known names per pseudonymizer (least recently seeded
# names are evicted first).
KNOWN_NAMES_MAX = 50_000


def _looks_like_user(value: object) -> bool:
    return isinstance(value, dict) and any(
        isinstance(key, str) and key.lower() in _USER_MARKER_KEYS for key in value
    )


def _is_user_container_key(key: object) -> bool:
    return isinstance(key, str) and key.lower() in _USER_CONTAINER_KEYS

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


# Title mode only: activity vocabulary that starts with a surname syllable and
# commonly stands alone in assignment titles ("조별 과제", "기말 보고서").
_ACTIVITY_STOPWORDS = frozenset(
    {
        "주차", "주차별", "보고서", "과제", "발표", "실습", "기말", "중간", "정리", "제출",
        "조별", "모둠", "모둠별", "감상", "감상문", "소감", "소감문", "소개", "요약", "문제",
        "문제풀이", "연습", "연구", "설계", "사례", "계획", "계획서", "기획", "기획서", "성찰",
        "마감", "복습", "예습", "진도", "피드백", "구현", "구상", "주제", "제안", "제안서",
        "제목", "제작", "기초", "기본", "심화", "성적", "점수", "최종", "원고", "모의",
        "공지", "공동", "공학", "기술", "기사", "도서", "문학", "문헌", "문법", "국어",
        "사회", "경제", "경영", "정치", "지리", "음악", "가정", "기하", "함수", "방정식",
        "계산", "인터뷰", "유튜브", "영상", "우리", "주간", "평가", "시험", "특강", "토론",
        "실험", "탐구", "자료", "학습", "활동", "개인", "팀별", "수업", "강의", "강독",
        "기타", "공통", "선택", "필수", "추가", "보충", "재제출", "연장", "진행", "준비",
        "결과", "결과물", "분석", "정답", "해설", "구조", "방법", "변경", "선행", "전체",
        "전공", "교양", "포트폴리오", "초안", "수정", "보완",
    }
)
# Title mode: a candidate standing between these (or whitespace / string
# boundaries) is treated as a name token.
_TITLE_DELIMITERS = frozenset("_[]()-/")


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


def _is_activity_word(word: str) -> bool:
    """Activity vocabulary, optionally followed by particles (e.g. 조별로)."""
    return any(
        word[:end] in _ACTIVITY_STOPWORDS and _is_particle_word(word[end:])
        for end in range(2, len(word) + 1)
    )


def _is_title_delimiter(char: str) -> bool:
    return char in _TITLE_DELIMITERS or char.isspace()


def _title_candidate(text: str, start: int, match: tuple[int, str, str]) -> bool:
    """Weaker heuristic for activity titles.

    A 2-3 syllable candidate (3-4 with a two-syllable surname) at the start of
    a word is a name only if a title/particle follows it directly, or it stands
    between delimiters (``_ [ ] ( ) - /``, whitespace or string boundaries).
    Activity vocabulary is never a name.
    """
    given_len, candidate, after = match
    if given_len > 2 or _is_activity_word(candidate):
        return False
    before = text[start - 1] if start > 0 else ""
    if before and _hangul_only(before):
        return False
    if after and _starts_with_suffix(after):
        return True
    return (not before or _is_title_delimiter(before)) and (
        not after or _is_title_delimiter(after[0])
    )


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


def _is_word_char(char: str) -> bool:
    return char.isalnum() or char == "_"


def _known_before_ok(text: str, start: int) -> bool:
    """A known name must not continue a preceding word (Hangul for Hangul names)."""
    if start == 0:
        return True
    previous = text[start - 1]
    if _hangul_only(text[start]):
        return not _hangul_only(previous)
    return not _is_word_char(previous)


def _known_after_ok(text: str, end: int) -> bool:
    """A Hangul-final name may only be followed by a particle/title or a
    non-Hangul character; other names end at a word boundary."""
    if end >= len(text):
        return True
    if _hangul_only(text[end - 1]):
        return not _hangul_only(text[end]) or _starts_with_suffix(text[end:])
    return not _is_word_char(text[end])


def _field_category(key: str | None, name_keys: frozenset[str] = frozenset()) -> str | None:
    if not isinstance(key, str):
        return None
    lowered = key.lower()
    if lowered in _NAME_FIELDS or lowered in name_keys:
        return "name"
    if lowered in ("idnumber", "useridnumber"):
        return "student_id"
    if lowered in _EMAIL_FIELDS:
        return "email"
    return None


PLACEHOLDER_RE = re.compile(r"\[(이름|학번|이메일|전화번호|주민번호)_[0-9a-f]{8}\]")
LOOKALIKE_RE = re.compile(
    r"\[(이름|학번|이메일|전화번호|주민번호)_[^\]\s]{1,64}\]"
)


def norm(category: str, original: str) -> str:
    """Normalize an original for HMAC input and collision comparison."""
    text = unicodedata.normalize("NFC", original).strip()
    if category == "email":
        return text.lower()
    if category in ("phone", "resident_id"):
        return re.sub(r"[- ]", "", text)
    return text


class PseudonymMap(Protocol):
    def allocate(
        self, category: str, original: str, placeholder: str | None = None
    ) -> str | None: ...

    def lookup(self, placeholder: str) -> str | None: ...


class _MemoryPseudonymMap:
    """In-process map used in single-tenant mode and by unit tests."""

    def __init__(self) -> None:
        self._items: dict[str, tuple[str, str]] = {}
        self._ambiguous: set[str] = set()
        self._lock = threading.RLock()

    def allocate(
        self, category: str, original: str, placeholder: str | None = None
    ) -> str | None:
        if placeholder is None:
            raise TypeError("placeholder is required")
        with self._lock:
            if placeholder in self._ambiguous:
                return None
            item = self._items.get(placeholder)
            if item is not None and norm(item[0], item[1]) != norm(category, original):
                self._ambiguous.add(placeholder)
                return None
            if item is None:
                self._items[placeholder] = (category, original)
            return placeholder

    def lookup(self, placeholder: str) -> str | None:
        with self._lock:
            if placeholder in self._ambiguous:
                return None
            item = self._items.get(placeholder)
            return item[1] if item is not None else None


class RegistryPseudonymMap:
    """Encrypted, shared reverse map backed by a :class:`Registry`."""

    def __init__(
        self,
        registry: "Registry",
        site_id: str,
        kek: Kek,
        ttl: int = PSEUDONYM_TTL,
    ) -> None:
        self._registry = registry
        self._site_id = site_id
        self._ttl = int(ttl)
        self._key = derive_key(kek, PURPOSE_PSEUDONYM_MAP, site_id)
        self._hmac_key = derive_key(kek, PURPOSE_PSEUDONYM_HMAC, site_id)
        self._ambiguous: set[str] = set()
        self._cache: OrderedDict[str, tuple[str, float]] = OrderedDict()
        self._lock = threading.RLock()

    def _cache_get(self, placeholder: str) -> str | None:
        with self._lock:
            item = self._cache.get(placeholder)
            if item is None:
                return None
            original, expires_at = item
            if expires_at <= time.time():
                del self._cache[placeholder]
                return None
            self._cache.move_to_end(placeholder)
            return original

    def _cache_put(self, placeholder: str, original: str) -> None:
        with self._lock:
            self._cache[placeholder] = (original, time.time() + self._ttl)
            self._cache.move_to_end(placeholder)
            while len(self._cache) > _CACHE_MAX:
                self._cache.popitem(last=False)

    def _cache_drop(self, placeholder: str) -> None:
        with self._lock:
            self._cache.pop(placeholder, None)

    def allocate(
        self, category: str, original: str, placeholder: str | None = None
    ) -> str | None:
        global _COLLISION_COUNT
        if placeholder is None:
            message = category.encode("utf-8") + b"\x00" + norm(
                category, original
            ).encode("utf-8")
            digest = hmac.new(self._hmac_key, message, hashlib.sha256).hexdigest()[:8]
            placeholder = f"[{_NAME_LABELS[category]}_{digest}]"
        with self._lock:
            if placeholder in self._ambiguous:
                return None
            now = int(time.time())
            existing = self._registry.pmap_norm(self._site_id, placeholder, now)
            if existing is not None and existing != norm(category, original):
                self._ambiguous.add(placeholder)
                self._cache_drop(placeholder)
                _COLLISION_COUNT += 1
                logger.warning("pseudonym collision site=%s", self._site_id)
                return None
            self._registry.pmap_put(
                self._site_id, placeholder, category, original, self._ttl, now
            )
            row = self._registry.pmap_get(
                self._site_id, placeholder, now, ttl=self._ttl
            )
            self._cache_put(placeholder, row[1] if row is not None else original)
            return placeholder

    def lookup(self, placeholder: str) -> str | None:
        with self._lock:
            if placeholder in self._ambiguous:
                return None
            cached = self._cache_get(placeholder)
            if cached is not None:
                return cached
            row = self._registry.pmap_get(
                self._site_id, placeholder, int(time.time()), ttl=self._ttl
            )
            if row is None:
                return None
            original = row[1]
            self._cache_put(placeholder, original)
            return original


class Pseudonymizer:
    """Reversible pseudonymizer for Korean names, ids, emails and phone numbers."""

    def __init__(
        self,
        hmac_key: bytes | None = None,
        store: PseudonymMap | None = None,
        known_names: Iterable[str] = (),
        *,
        assignment_title_heuristic: HeuristicMode = DEFAULT_ASSIGNMENT_TITLE_HEURISTIC,
        known_max: int = KNOWN_NAMES_MAX,
    ) -> None:
        self._key = bytes(hmac_key) if hmac_key is not None else os.urandom(32)
        self._store: PseudonymMap = store if store is not None else _MemoryPseudonymMap()
        self._known: OrderedDict[str, None] = OrderedDict()
        self._known_max = max(1, int(known_max))
        # First character -> candidate name lengths, longest first. Lengths of
        # evicted names may linger; they only cost a failed set lookup.
        self._known_lengths: dict[str, tuple[int, ...]] = {}
        self._lock = threading.RLock()
        self.assignment_title_heuristic = assignment_title_heuristic
        for name in known_names:
            self.add_known(name)

    @property
    def assignment_title_heuristic(self) -> HeuristicMode:
        return self._assignment_title_heuristic

    @assignment_title_heuristic.setter
    def assignment_title_heuristic(self, mode: str) -> None:
        if mode not in HEURISTIC_MODES:
            raise ValueError("invalid assignment_title_heuristic")
        self._assignment_title_heuristic = mode  # type: ignore[assignment]

    def add_known(self, name: str) -> None:
        name = name.strip()
        if not name:
            return
        with self._lock:
            if name in self._known:
                self._known.move_to_end(name)
                return
            self._known[name] = None
            while len(self._known) > self._known_max:
                self._known.popitem(last=False)
            lengths = self._known_lengths.get(name[0], ())
            if len(name) not in lengths:
                self._known_lengths[name[0]] = tuple(
                    sorted((*lengths, len(name)), reverse=True)
                )

    def _known_spans(self, text: str) -> list[tuple[int, int]]:
        """Spans of seeded names, found in one left-to-right pass with the
        longest name first at each position (cost does not grow with the
        number of known names)."""
        spans: list[tuple[int, int]] = []
        with self._lock:
            known = self._known
            lengths_by_char = self._known_lengths
            index = 0
            size = len(text)
            while index < size:
                lengths = lengths_by_char.get(text[index])
                if lengths and _known_before_ok(text, index):
                    for length in lengths:
                        end = index + length
                        if (
                            end <= size
                            and text[index:end] in known
                            and _known_after_ok(text, end)
                        ):
                            spans.append((index, end))
                            index = end
                            break
                    else:
                        index += 1
                    continue
                index += 1
        return spans

    def _allocate(self, category: str, original: str) -> str:
        message = category.encode("utf-8") + b"\x00" + norm(category, original).encode(
            "utf-8"
        )
        digest = hmac.new(self._key, message, hashlib.sha256).hexdigest()[:8]
        placeholder = f"[{_NAME_LABELS[category]}_{digest}]"
        self._store.allocate(category, original, placeholder)
        return placeholder

    def _seed_name(self, value: str) -> None:
        value = value.strip()
        if len(value) < 2:
            return
        self.add_known(value)
        for part in re.split(r"\s+", value):
            if len(part) >= 2:
                self.add_known(part)

    def _seed_from(
        self,
        value: object,
        name_keys: frozenset[str] = frozenset(),
        user_like: bool = False,
    ) -> None:
        if isinstance(value, dict):
            is_user = user_like or _looks_like_user(value)
            lowered: dict[str, object] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    continue
                lowered[key.lower()] = item
                if (
                    is_user
                    and isinstance(item, str)
                    and _field_category(key, name_keys) == "name"
                ):
                    self._seed_name(item)
                child_user = _is_user_container_key(key) or (
                    is_user and not isinstance(item, (dict, list, tuple))
                )
                self._seed_from(item, name_keys, child_user)
            if is_user:
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
                self._seed_from(item, name_keys, user_like)

    def _transform(
        self,
        value: object,
        key: str | None = None,
        name_keys: frozenset[str] = frozenset(),
        user_like: bool = False,
        assignment_titles: bool = False,
        assignment_title_item: bool = False,
    ) -> object:
        if isinstance(value, dict):
            is_user = user_like or _looks_like_user(value)
            out: dict[object, object] = {}
            for item_key, item in value.items():
                new_key = self.pseudonymize(item_key) if isinstance(item_key, str) else item_key
                child_user = _is_user_container_key(item_key) or (
                    is_user and not isinstance(item, (dict, list, tuple))
                )
                out[new_key] = self._transform(
                    item,
                    item_key,
                    name_keys,
                    child_user,
                    assignment_titles,
                    assignment_title_item,
                )
            return out
        if isinstance(value, (list, tuple)):
            in_assignments = (
                assignment_titles
                and isinstance(key, str)
                and key.lower() == _ASSIGNMENT_LIST_KEY
            )
            return [
                self._transform(
                    item,
                    key=None,
                    name_keys=name_keys,
                    user_like=user_like,
                    assignment_titles=assignment_titles,
                    assignment_title_item=in_assignments,
                )
                for item in value
            ]
        if isinstance(value, str):
            if user_like:
                category = _field_category(key, name_keys)
                if category is not None:
                    return self._allocate(category, value)
            elif isinstance(key, str) and key.lower() in _PLAIN_OBJECT_FIELDS:
                return value
            elif (
                assignment_titles
                and isinstance(key, str)
                and key.lower() in _LABEL_FIELDS
            ):
                return self.pseudonymize(
                    value, heuristic=self.assignment_title_heuristic
                )
            elif (
                assignment_title_item
                and isinstance(key, str)
                and key.lower() == _ASSIGNMENT_TITLE_KEY
            ):
                return self.pseudonymize(
                    value, heuristic=self.assignment_title_heuristic
                )
            return self.pseudonymize(value)
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            category = _field_category(key, name_keys) if user_like else None
            if category is not None:
                return self._allocate(category, str(value))
        return value

    def pseudonymize_value(
        self,
        value: object,
        *,
        name_keys: frozenset[str] = frozenset(),
        assignment_titles: bool = False,
    ) -> object:
        self._seed_from(value, name_keys)
        return self._transform(
            value, name_keys=name_keys, assignment_titles=assignment_titles
        )

    def seed(self, value: object) -> None:
        self._seed_from(value)

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

    def pseudonymize(
        self, text: str, *, heuristic: HeuristicMode | bool = "full"
    ) -> str:
        """Mask PII in text.

        heuristic: "full" masks every unseeded Korean-name candidate, "title"
        only candidates that look like a name token in an activity title (see
        :func:`_title_candidate`), "off" only seeded known names. True/False
        are accepted as "full"/"off".
        """
        if not text:
            return text
        if heuristic is True:
            heuristic = "full"
        elif heuristic is False:
            heuristic = "off"
        elif heuristic not in HEURISTIC_MODES:
            raise ValueError("invalid heuristic mode")

        sentinels: dict[str, str] = {}
        protected: dict[str, str] = {}

        def protect(match: re.Match[str]) -> str:
            sentinel = f"\x00P{len(protected)}\x00"
            protected[sentinel] = match.group(0)
            return sentinel

        def replace(original: str, category: str) -> str:
            return self._replace(sentinels, category, original)

        result = PLACEHOLDER_RE.sub(protect, text)
        parts: list[str] = []
        index = 0
        for start, end in self._known_spans(result):
            parts.append(result[index:start])
            parts.append(replace(result[start:end], "name"))
            index = end
        parts.append(result[index:])
        result = "".join(parts)

        if heuristic != "off":
            pieces: list[str] = []
            index = 0
            while index < len(result):
                match = _heuristic_match_at(result, index)
                if match is None or (
                    heuristic == "title" and not _title_candidate(result, index, match)
                ):
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
        for sentinel, placeholder in protected.items():
            result = result.replace(sentinel, placeholder)
        return result

    def restore(self, text: str) -> str:
        if not text:
            return text

        def replace(match: re.Match[str]) -> str:
            placeholder = match.group(0)
            original = self._store.lookup(placeholder)
            return original if original is not None else placeholder

        return PLACEHOLDER_RE.sub(replace, text)

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

    def unresolved(self, value: object) -> set[str]:
        found: set[str] = set()

        def walk(item: object) -> None:
            if isinstance(item, str):
                stripped = item.strip()
                if stripped.startswith(("{", "[")):
                    try:
                        decoded = json.loads(stripped)
                    except (ValueError, TypeError):
                        decoded = None
                    if isinstance(decoded, (dict, list)):
                        walk(decoded)
                        return
                for match in LOOKALIKE_RE.finditer(item):
                    placeholder = match.group(0)
                    resolvable = (
                        PLACEHOLDER_RE.fullmatch(placeholder) is not None
                        and self._store.lookup(placeholder) is not None
                    )
                    if not resolvable:
                        found.add(placeholder)
                return
            if isinstance(item, dict):
                for key, nested in item.items():
                    if isinstance(key, str):
                        walk(key)
                    walk(nested)
                return
            if isinstance(item, (list, tuple)):
                for nested in item:
                    walk(nested)

        walk(value)
        return found
