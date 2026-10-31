import base64
import os

import pytest

from moodle_mcp.crypto import (
    FIELD_LITELLM_KEY,
    FIELD_MOODLE_TOKEN,
    DecryptError,
    Kek,
    KekError,
    load_kek,
    open_,
    seal,
)


def make_kek(tmp_path, raw=None, mode=0o600, name="kek"):
    raw = raw if raw is not None else os.urandom(32)
    path = tmp_path / name
    path.write_bytes(base64.b64encode(raw) + b"\n")
    os.chmod(path, mode)
    return path, raw


def test_roundtrip_and_nondeterministic(tmp_path):
    path, raw = make_kek(tmp_path)
    kek = load_kek(path)
    assert kek.kek_id == __import__("hashlib").sha256(raw).hexdigest()[:8]
    first = seal(kek, b"secret-token", "site-a", FIELD_MOODLE_TOKEN)
    second = seal(kek, b"secret-token", "site-a", FIELD_MOODLE_TOKEN)
    assert first != second
    assert bytes(open_(kek, first, "site-a", FIELD_MOODLE_TOKEN)) == b"secret-token"
    assert isinstance(open_(kek, first, "site-a", FIELD_MOODLE_TOKEN), bytearray)


def test_tamper_every_region_and_truncate(tmp_path):
    path, _ = make_kek(tmp_path)
    kek = load_kek(path)
    blob = seal(kek, b"hello world", "site-a", FIELD_MOODLE_TOKEN)
    regions = [(0, 1), (1, 13), (13, 61), (61, 73), (73, len(blob))]
    for start, end in regions:
        for index in {start, min(end - 1, start + 3)}:
            tampered = bytearray(blob)
            tampered[index] ^= 0x01
            with pytest.raises(DecryptError):
                open_(kek, bytes(tampered), "site-a", FIELD_MOODLE_TOKEN)
    for length in (0, 1, 88, len(blob) - 1):
        with pytest.raises(DecryptError):
            open_(kek, blob[:length], "site-a", FIELD_MOODLE_TOKEN)


def test_wrong_kek_and_wrong_aad(tmp_path):
    path_a, _ = make_kek(tmp_path, name="a")
    path_b, _ = make_kek(tmp_path, name="b")
    kek_a = load_kek(path_a)
    kek_b = load_kek(path_b)
    blob = seal(kek_a, b"hello", "site-a", FIELD_MOODLE_TOKEN)
    with pytest.raises(DecryptError):
        open_(kek_b, blob, "site-a", FIELD_MOODLE_TOKEN)
    with pytest.raises(DecryptError):
        open_(kek_a, blob, "site-b", FIELD_MOODLE_TOKEN)
    with pytest.raises(DecryptError):
        open_(kek_a, blob, "site-a", FIELD_LITELLM_KEY)


def test_load_kek_rejects_bad_files(tmp_path):
    cases = {
        "missing": None,
        "empty": b"",
        "non-base64": b"SECRETCONTENT!",
        "31": base64.b64encode(os.urandom(31)),
        "33": base64.b64encode(os.urandom(33)),
    }
    for name, content in cases.items():
        path = tmp_path / name
        if content is not None:
            path.write_bytes(content)
            os.chmod(path, 0o600)
        with pytest.raises(KekError) as exc:
            load_kek(path)
        assert str(exc.value) == "KEK file invalid"
        assert "SECRETCONTENT" not in str(exc.value)
    path, _ = make_kek(tmp_path, mode=0o644, name="world-readable")
    with pytest.raises(KekError):
        load_kek(path)
    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(KekError):
        load_kek(directory)


def test_kek_repr_hides_material(tmp_path):
    path, raw = make_kek(tmp_path)
    kek = load_kek(path)
    text = repr(kek)
    assert text == f"Kek(kek_id={kek.kek_id!r})"
    assert base64.b64encode(raw).decode() not in text
    assert raw.hex() not in text
    with pytest.raises(KekError):
        Kek(os.urandom(31))
