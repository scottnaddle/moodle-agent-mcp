import base64
import json
import logging
import os
import re
from urllib.parse import parse_qs

import pytest
import respx
from starlette.testclient import TestClient

from moodle_mcp.crypto import load_kek
from moodle_mcp.registry import Registry
from moodle_mcp.server import create_app

MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}
ENDPOINT = "https://moodle.test/webservice/rest/server.php"
PLACEHOLDER_RE = re.compile(r"\[(?:이름|학번|이메일|전화번호|주민번호)_[0-9a-f]{8}\]")


def write_kek(path):
    path.write_bytes(base64.b64encode(os.urandom(32)) + b"\n")
    os.chmod(path, 0o600)


@pytest.fixture
def hub(tmp_path, monkeypatch):
    monkeypatch.delenv("MOODLE_TOKEN", raising=False)
    monkeypatch.delenv("MCP_BEARER_TOKEN", raising=False)
    monkeypatch.setenv("UBIONAI_HUB_PUBLIC_URL", "https://hub.test")
    kek_file = tmp_path / "kek"
    write_kek(kek_file)
    db = tmp_path / "hub.sqlite3"
    registry = Registry.open(str(db), load_kek(kek_file))
    registry.add("test1", "https://moodle.test", b"wstoken-1", None, "bearer-1")
    app = create_app(hub_db=str(db), kek_file=str(kek_file))
    with TestClient(app, base_url="http://hub.test") as client:
        yield client, registry


def headers():
    return {**MCP_HEADERS, "Authorization": "Bearer bearer-1"}


def tool_call(client, name, arguments, request_id=2):
    return client.post(
        "/t/test1/mcp",
        json={
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
        headers=headers(),
    )


def form(request):
    return {
        key: value[0]
        for key, value in parse_qs(
            request.content.decode(), keep_blank_values=True
        ).items()
    }


def first_placeholder(text):
    match = PLACEHOLDER_RE.search(text)
    assert match is not None, text
    return match.group(0)


def test_read_placeholder_restored_in_separate_write(hub):
    client, _ = hub
    with respx.mock as router:
        router.post(ENDPOINT).respond(
            json=[
                {
                    "id": 7,
                    "fullname": "김민수",
                    "idnumber": "20231234",
                    "email": "kim@example.com",
                }
            ]
        )
        listing = tool_call(client, "list_students", {"course_id": 5})
        assert listing.status_code == 200, listing.text
        assert "김민수" not in listing.text
        name_placeholder = first_placeholder(listing.text)
        assert "[학번_" in listing.text
        assert "[이메일_" in listing.text

    with respx.mock as router:
        route = router.post(ENDPOINT).respond(json={"ok": 1})
        result = tool_call(
            client,
            "grade_submission",
            {
                "assignment_id": 9,
                "user_id": 7,
                "grade": 90,
                "feedback_text": f"{name_placeholder} 학생 잘했어요",
            },
        )
        assert result.status_code == 200, result.text
        sent = form(route.calls.last.request)
    assert sent["plugindata[assignfeedbackcomments_editor][text]"] == "김민수 학생 잘했어요"
    assert name_placeholder not in json.dumps(sent, ensure_ascii=False)


def test_update_activity_restores_inside_settings_json(hub):
    client, _ = hub
    name = '김"민수'
    with respx.mock as router:
        router.post(ENDPOINT).respond(json=[{"id": 7, "fullname": name}])
        listing = tool_call(client, "list_students", {"course_id": 5})
        placeholder = first_placeholder(listing.text)

    with respx.mock as router:
        route = router.post(ENDPOINT).respond(json={"ok": 1})
        result = tool_call(
            client,
            "update_activity",
            {
                "cmid": 12,
                "settings": {"intro": placeholder},
                "confirm": True,
            },
        )
        assert result.status_code == 200, result.text
        sent = form(route.calls.last.request)
    assert json.loads(sent["settings"]) == {"intro": name}
    assert placeholder not in sent["settings"]


def test_unknown_placeholder_in_write_is_rejected_without_moodle_call(hub):
    client, _ = hub
    unknown = "[이름_deadbeef]"
    with respx.mock as router:
        route = router.post(ENDPOINT).respond(json={"ok": 1})
        result = tool_call(
            client,
            "grade_submission",
            {
                "assignment_id": 9,
                "user_id": 7,
                "grade": 90,
                "feedback_text": f"{unknown} 학생",
            },
        )
        assert route.call_count == 0
    assert result.status_code == 200, result.text
    assert "unresolved placeholders" in result.text
    assert unknown in result.text


def test_preview_lists_unresolved_placeholders(hub):
    client, _ = hub
    unknown = "[이름_deadbeef]"
    with respx.mock as router:
        route = router.post(ENDPOINT).respond(json={"ok": 1})
        result = tool_call(
            client,
            "update_activity",
            {"cmid": 12, "settings": {"intro": unknown}},
        )
        assert route.call_count == 0
    assert result.status_code == 200, result.text
    assert "unresolved_placeholders" in result.text
    assert unknown in result.text


@pytest.mark.parametrize(
    "lookalike",
    ["[이름_deadbeefcafe]", "[학번_12]", "[이름_1]", "[이메일_hong@example.com]"],
)
def test_malformed_lookalike_in_write_is_rejected_without_moodle_call(hub, lookalike):
    client, _ = hub
    with respx.mock as router:
        route = router.post(ENDPOINT).respond(json={"ok": 1})
        result = tool_call(
            client,
            "grade_submission",
            {
                "assignment_id": 9,
                "user_id": 7,
                "grade": 90,
                "feedback_text": f"{lookalike} 학생",
            },
        )
        assert route.call_count == 0
    assert result.status_code == 200, result.text
    assert "unresolved placeholders" in result.text
    assert lookalike in result.text


@pytest.mark.parametrize(
    "lookalike",
    ["[이름_deadbeefcafe]", "[학번_12]", "[이름_1]"],
)
def test_malformed_lookalike_in_preview_is_reported(hub, lookalike):
    client, _ = hub
    with respx.mock as router:
        route = router.post(ENDPOINT).respond(json={"ok": 1})
        result = tool_call(
            client,
            "update_activity",
            {"cmid": 12, "settings": {"intro": lookalike}},
        )
        assert route.call_count == 0
    assert result.status_code == 200, result.text
    assert "unresolved_placeholders" in result.text
    assert lookalike in result.text


def test_malformed_lookalike_rejected_even_with_resolvable_placeholder(hub):
    client, _ = hub
    with respx.mock as router:
        router.post(ENDPOINT).respond(json=[{"id": 7, "fullname": "김민수"}])
        listing = tool_call(client, "list_students", {"course_id": 5})
        known = first_placeholder(listing.text)

    malformed = "[이름_deadbeefcafe]"
    with respx.mock as router:
        route = router.post(ENDPOINT).respond(json={"ok": 1})
        result = tool_call(
            client,
            "grade_submission",
            {
                "assignment_id": 9,
                "user_id": 7,
                "grade": 90,
                "feedback_text": f"{known} {malformed}",
            },
        )
        assert route.call_count == 0
    assert result.status_code == 200, result.text
    assert "unresolved placeholders" in result.text
    assert malformed in result.text


def test_no_originals_in_logs(hub, caplog):
    client, _ = hub
    caplog.set_level(logging.DEBUG)
    with respx.mock as router:
        router.post(ENDPOINT).respond(
            json=[{"id": 7, "fullname": "김민수", "idnumber": "20231234"}]
        )
        listing = tool_call(client, "list_students", {"course_id": 5})
        placeholder = first_placeholder(listing.text)
    with respx.mock as router:
        router.post(ENDPOINT).respond(json={"ok": 1})
        tool_call(
            client,
            "grade_submission",
            {
                "assignment_id": 9,
                "user_id": 7,
                "grade": 90,
                "feedback_text": f"{placeholder} 학생",
            },
        )
    assert "김민수" not in caplog.text
    assert "20231234" not in caplog.text
    assert "[이름_" not in caplog.text
