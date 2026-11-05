import base64
import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
import respx
from starlette.testclient import TestClient

from moodle_mcp.crypto import load_kek
from moodle_mcp.registry import Registry
from moodle_mcp.server import create_app

LITELLM_URL = "https://litellm.test"
CHAT = "/t/{site}/v1/chat/completions"
PLACEHOLDER_RE = re.compile(r"\[(?:이름|학번|이메일|전화번호|주민번호)_[0-9a-f]{8}\]")
MCP_ENDPOINT = "https://moodle2.test/webservice/rest/server.php"


def write_kek(path):
    path.write_bytes(base64.b64encode(os.urandom(32)) + b"\n")
    os.chmod(path, 0o600)


@pytest.fixture
def proxy(tmp_path, monkeypatch):
    monkeypatch.delenv("MOODLE_TOKEN", raising=False)
    monkeypatch.delenv("MCP_BEARER_TOKEN", raising=False)
    monkeypatch.setenv("UBIONAI_HUB_PUBLIC_URL", "https://hub.test")
    monkeypatch.setenv("UBIONAI_HUB_LITELLM_URL", LITELLM_URL)
    kek_file = tmp_path / "kek"
    write_kek(kek_file)
    db = tmp_path / "hub.sqlite3"
    registry = Registry.open(str(db), load_kek(kek_file))
    registry.add("test2", "https://moodle2.test", b"wstoken-2", b"site-test2", "bearer-2")
    registry.add("test3", "https://moodle3.test", b"wstoken-3", b"site-test3", "bearer-3")
    registry.add("nokey", "https://moodle4.test", b"wstoken-4", None, "bearer-4")
    registry.add(
        "plain", "https://moodle5.test", b"wstoken-5", b"site-plain", "bearer-5", pseudonymize=False
    )
    app = create_app(hub_db=str(db), kek_file=str(kek_file))
    with TestClient(app, base_url="http://hub.test") as client:
        yield client, registry


def headers(bearer, extra=None):
    out = dict(extra or {})
    if bearer is not None:
        out["Authorization"] = f"Bearer {bearer}"
    return out


def chat_payload(text="학생 김철수 학번 2023123456", **extra):
    return {"model": "gpt-test", "messages": [{"role": "user", "content": text}], **extra}


def test_happy_path_pseudonymizes_forward_and_restores_response(proxy):
    client, _ = proxy

    def upstream(request):
        forwarded = json.loads(request.content)
        text = forwarded["messages"][0]["content"]
        placeholders = PLACEHOLDER_RE.findall(text)
        assert len(placeholders) == 2
        return httpx.Response(
            200,
            json={
                "id": "x",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": f"{placeholders[0]} 학생의 학번은 {placeholders[1]}입니다.",
                        },
                    }
                ],
            },
        )

    with respx.mock as router:
        route = router.post(f"{LITELLM_URL}/v1/chat/completions").mock(side_effect=upstream)
        response = client.post(
            CHAT.format(site="test2"), json=chat_payload(), headers=headers("bearer-2")
        )
        assert response.status_code == 200, response.text
        forwarded = json.loads(route.calls.last.request.content)
        forwarded_text = forwarded["messages"][0]["content"]
        assert forwarded["model"] == "gpt-test"
        assert "김철수" not in forwarded_text
        assert "2023123456" not in forwarded_text
        assert len(PLACEHOLDER_RE.findall(forwarded_text)) == 2
        assert route.calls.last.request.headers["authorization"] == "Bearer site-test2"
        assert "김철수" in response.json()["choices"][0]["message"]["content"]
        assert "2023123456" in response.json()["choices"][0]["message"]["content"]


def test_content_parts_are_pseudonymized(proxy):
    client, _ = proxy
    body = {
        "model": "gpt-test",
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "홍길동님 학번 2023123456"},
                    {"type": "text", "text": "김철수 학생"},
                ],
            }
        ],
    }
    with respx.mock as router:
        route = router.post(f"{LITELLM_URL}/v1/chat/completions").respond(
            json={"choices": [{"message": {"content": "ok"}}]}
        )
        response = client.post(
            CHAT.format(site="test2"), json=body, headers=headers("bearer-2")
        )
        assert response.status_code == 200, response.text
        forwarded = json.loads(route.calls.last.request.content)
        parts = forwarded["messages"][0]["content"]
        assert PLACEHOLDER_RE.match(parts[0]["text"])
        assert PLACEHOLDER_RE.match(parts[1]["text"])
        assert "2023123456" not in json.dumps(forwarded, ensure_ascii=False)


def test_auth_and_missing_feature(proxy):
    client, registry = proxy
    unknown = client.post(
        CHAT.format(site="unknown"), json=chat_payload(), headers=headers("bearer-2")
    )
    no_key = client.post(
        CHAT.format(site="nokey"), json=chat_payload(), headers=headers("bearer-4")
    )
    assert unknown.status_code == no_key.status_code == 403
    assert unknown.json() == no_key.json() == {"error": "forbidden"}

    for auth in (None, "Basic x", "Bearer ", "Bearer  spaced"):
        response = client.post(
            CHAT.format(site="test2"), json=chat_payload(), headers=headers(auth)
        )
        assert response.status_code == 403
        assert response.json() == {"error": "forbidden"}

    wrong = client.post(
        CHAT.format(site="test2"), json=chat_payload(), headers=headers("bearer-3")
    )
    assert wrong.status_code == 403
    assert wrong.json() == {"error": "forbidden"}

    registry.set_status("test3", "disabled")
    disabled = client.post(
        CHAT.format(site="test3"), json=chat_payload(), headers=headers("bearer-3")
    )
    assert disabled.status_code == 403
    assert disabled.content == wrong.content


def test_stream_is_forced_off(proxy):
    client, _ = proxy
    with respx.mock as router:
        route = router.post(f"{LITELLM_URL}/v1/chat/completions").respond(
            json={"choices": [{"message": {"content": "ok"}}]}
        )
        response = client.post(
            CHAT.format(site="test2"),
            json=chat_payload(stream=True),
            headers=headers("bearer-2"),
        )
        assert response.status_code == 200
        forwarded = json.loads(route.calls.last.request.content)
        assert forwarded["stream"] is False
        assert response.headers["content-type"].startswith("application/json")


def test_upstream_error_body_is_passed_through(proxy):
    client, _ = proxy
    with respx.mock as router:
        router.post(f"{LITELLM_URL}/v1/chat/completions").respond(
            status_code=429,
            json={"error": {"message": "rate limited [이름_deadbeef] / [학번_deadbeef]"}},
        )
        response = client.post(
            CHAT.format(site="test2"), json=chat_payload(), headers=headers("bearer-2")
        )
        assert response.status_code == 429
        text = response.json()["error"]["message"]
        assert text == "rate limited [이름_deadbeef] / [학번_deadbeef]"


def test_bad_body_and_oversize(proxy):
    client, _ = proxy
    assert client.post(
        CHAT.format(site="test2"),
        content=b"not json",
        headers=headers("bearer-2", {"Content-Type": "application/json"}),
    ).status_code == 400
    assert client.post(
        CHAT.format(site="test2"),
        json={"messages": [{"role": "user", "content": 3}]},
        headers=headers("bearer-2"),
    ).status_code == 400
    oversized = b"x" * (1024 * 1024 + 1)
    assert client.post(
        CHAT.format(site="test2"), content=oversized, headers=headers("bearer-2")
    ).status_code == 413


def test_interleaved_tenants_keep_independent_maps(proxy):
    client, _ = proxy

    def upstream(request):
        key = request.headers["authorization"].split()[-1]
        name = "김철수" if key == "site-test2" else "홍길동"
        request_body = json.loads(request.content)
        assert name not in json.dumps(request_body, ensure_ascii=False)
        match = PLACEHOLDER_RE.search(json.dumps(request_body, ensure_ascii=False))
        assert match is not None
        return httpx.Response(
            200, json={"choices": [{"message": {"content": match.group(0)}}]}
        )

    with respx.mock as router:
        router.post(f"{LITELLM_URL}/v1/chat/completions").mock(side_effect=upstream)

        def invoke(index):
            site, bearer, name = (
                ("test2", "bearer-2", "김철수")
                if index % 2 == 0
                else ("test3", "bearer-3", "홍길동")
            )
            response = client.post(
                CHAT.format(site=site),
                json=chat_payload(text=f"{name} 학생"),
                headers=headers(bearer),
            )
            return name, response.status_code, response.json()["choices"][0]["message"]["content"]

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(invoke, range(20)))
        for name, status, content in results:
            assert status == 200
            assert content == name


def test_no_secrets_or_pii_in_logs(proxy, caplog, capsys):
    client, _ = proxy
    caplog.set_level(logging.DEBUG)
    with respx.mock as router:
        router.post(f"{LITELLM_URL}/v1/chat/completions").respond(
            json={"choices": [{"message": {"content": "[이름_1]"}}]}
        )
        response = client.post(
            CHAT.format(site="test2"), json=chat_payload(), headers=headers("bearer-2")
        )
        assert response.status_code == 200
    captured = capsys.readouterr()
    combined = caplog.text + captured.out + captured.err
    for secret in ("site-test2", "bearer-2", "김철수", "2023123456"):
        assert secret not in combined


MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def mcp_call(client, site, bearer, name, arguments, request_id=2):
    return client.post(
        f"/t/{site}/mcp",
        json={
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
        headers={**MCP_HEADERS, "Authorization": f"Bearer {bearer}"},
    )


def test_chat_requests_reuse_stable_placeholder(proxy):
    client, _ = proxy
    seen = []

    def upstream(request):
        forwarded = json.loads(request.content)
        text = forwarded["messages"][0]["content"]
        seen.append(text)
        assert "김민수" not in text
        return httpx.Response(200, json={"choices": [{"message": {"content": text}}]})

    with respx.mock as router:
        router.post(f"{LITELLM_URL}/v1/chat/completions").mock(side_effect=upstream)
        for _ in range(2):
            response = client.post(
                CHAT.format(site="test2"),
                json=chat_payload(text="김민수 학생"),
                headers=headers("bearer-2"),
            )
            assert response.status_code == 200, response.text
            assert "김민수" in response.json()["choices"][0]["message"]["content"]
    assert seen[0] == seen[1]
    assert PLACEHOLDER_RE.search(seen[0])


def test_tool_call_arguments_are_restored_as_json(proxy):
    client, _ = proxy
    captured = {}

    def first_upstream(request):
        forwarded = json.loads(request.content)
        captured["placeholder"] = PLACEHOLDER_RE.search(
            forwarded["messages"][0]["content"]
        ).group(0)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    with respx.mock as router:
        router.post(f"{LITELLM_URL}/v1/chat/completions").mock(side_effect=first_upstream)
        assert client.post(
            CHAT.format(site="test2"),
            json=chat_payload(text="김민수 학생"),
            headers=headers("bearer-2"),
        ).status_code == 200

    placeholder = captured["placeholder"]
    arguments = json.dumps(
        {"feedback_text": f"{placeholder} 학생 수고했어요"}, ensure_ascii=False
    )
    broken = f"not-json {placeholder}"
    with respx.mock as router:
        router.post(f"{LITELLM_URL}/v1/chat/completions").respond(
            json={
                "choices": [
                    {
                        "message": {
                            "content": "",
                            "tool_calls": [
                                {
                                    "type": "function",
                                    "function": {"name": "f", "arguments": arguments},
                                },
                                {
                                    "type": "function",
                                    "function": {"name": "g", "arguments": broken},
                                },
                            ],
                        }
                    }
                ]
            }
        )
        response = client.post(
            CHAT.format(site="test2"), json=chat_payload(), headers=headers("bearer-2")
        )
    calls = response.json()["choices"][0]["message"]["tool_calls"]
    restored = json.loads(calls[0]["function"]["arguments"])
    assert restored == {"feedback_text": "김민수 학생 수고했어요"}
    assert calls[1]["function"]["arguments"] == broken


def test_mcp_and_chat_share_the_same_map(proxy):
    client, _ = proxy
    with respx.mock as router:
        router.post(MCP_ENDPOINT).respond(json=[{"id": 7, "fullname": "김민수"}])
        listing = mcp_call(client, "test2", "bearer-2", "list_students", {"course_id": 5})
        assert listing.status_code == 200, listing.text
        placeholder = PLACEHOLDER_RE.search(listing.text).group(0)

    with respx.mock as router:
        router.post(f"{LITELLM_URL}/v1/chat/completions").respond(
            json={"choices": [{"message": {"content": placeholder}}]}
        )
        response = client.post(
            CHAT.format(site="test2"), json=chat_payload(text="안녕"), headers=headers("bearer-2")
        )
    assert response.json()["choices"][0]["message"]["content"] == "김민수"

    captured = {}

    def chat_upstream(request):
        forwarded = json.loads(request.content)
        captured["placeholder"] = PLACEHOLDER_RE.search(
            forwarded["messages"][0]["content"]
        ).group(0)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    with respx.mock as router:
        router.post(f"{LITELLM_URL}/v1/chat/completions").mock(side_effect=chat_upstream)
        assert client.post(
            CHAT.format(site="test2"),
            json=chat_payload(text="박지성 학생"),
            headers=headers("bearer-2"),
        ).status_code == 200
    chat_placeholder = captured["placeholder"]

    with respx.mock as router:
        router.post(MCP_ENDPOINT).respond(json=[{"id": 8, "fullname": "박지성"}])
        listing = mcp_call(
            client, "test2", "bearer-2", "list_students", {"course_id": 5}, request_id=3
        )
    assert chat_placeholder in listing.text
    assert "박지성" not in listing.text


def test_pseudonymize_off_passes_through(proxy):
    client, _ = proxy
    text = "김민수 학번 20231234"

    def upstream(request):
        forwarded = json.loads(request.content)
        assert forwarded["messages"][0]["content"] == text
        return httpx.Response(200, json={"choices": [{"message": {"content": text}}]})

    with respx.mock as router:
        router.post(f"{LITELLM_URL}/v1/chat/completions").mock(side_effect=upstream)
        response = client.post(
            CHAT.format(site="plain"),
            json=chat_payload(text=text),
            headers=headers("bearer-5"),
        )
    assert response.status_code == 200, response.text
    assert response.json()["choices"][0]["message"]["content"] == text


PLAN_PLACES = [
    {"action": "create_page", "name": "서울 지역 문화 탐방"},
    {"action": "create_quiz", "name": "Jeju Island field trip"},
]


def test_json_plan_place_names_survive_and_student_name_restored(proxy):
    client, _ = proxy
    plan_text = json.dumps({"plan": PLAN_PLACES}, ensure_ascii=False)
    user_text = f"{plan_text}\n위 계획을 김철수 학생에게 별도 안내로 복사해 줘."
    seen = {}

    def upstream(request):
        forwarded = json.loads(request.content)
        seen["text"] = forwarded["messages"][0]["content"]
        return httpx.Response(
            200, json={"choices": [{"message": {"content": seen["text"]}}]}
        )

    with respx.mock as router:
        router.post(f"{LITELLM_URL}/v1/chat/completions").mock(side_effect=upstream)
        response = client.post(
            CHAT.format(site="test2"),
            json=chat_payload(text=user_text),
            headers=headers("bearer-2"),
        )
    assert response.status_code == 200, response.text
    upstream_text = seen["text"]
    assert "김철수" not in upstream_text
    assert not re.search(r"<[A-Z_]+>", upstream_text)
    json.loads(upstream_text.splitlines()[0])
    content = response.json()["choices"][0]["message"]["content"]
    assert json.loads(content.splitlines()[0])["plan"] == PLAN_PLACES
    assert content == user_text


def test_course_fullname_in_tool_json_passes_through(proxy):
    client, _ = proxy
    tool_json = json.dumps(
        {
            "name": "create_course",
            "arguments": {
                "fullname": "서울 지역 문화 탐방",
                "summary": "Jeju Island field trip 보충 자료",
            },
        },
        ensure_ascii=False,
    )
    seen = {}

    def upstream(request):
        forwarded = json.loads(request.content)
        seen["text"] = forwarded["messages"][0]["content"]
        return httpx.Response(
            200, json={"choices": [{"message": {"content": seen["text"]}}]}
        )

    with respx.mock as router:
        router.post(f"{LITELLM_URL}/v1/chat/completions").mock(side_effect=upstream)
        response = client.post(
            CHAT.format(site="test2"),
            json=chat_payload(text=tool_json),
            headers=headers("bearer-2"),
        )
    assert response.status_code == 200, response.text
    assert seen["text"] != tool_json
    json.loads(seen["text"])
    assert response.json()["choices"][0]["message"]["content"] == tool_json
