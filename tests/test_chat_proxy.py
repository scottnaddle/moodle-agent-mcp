import base64
import json
import logging
import os
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
    with respx.mock as router:
        route = router.post(f"{LITELLM_URL}/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": "x",
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": "[이름_1] 학생의 학번은 [학번_1]입니다.",
                            },
                        }
                    ],
                },
            )
        )
        response = client.post(
            CHAT.format(site="test2"), json=chat_payload(), headers=headers("bearer-2")
        )
        assert response.status_code == 200, response.text
        forwarded = json.loads(route.calls.last.request.content)
        forwarded_text = forwarded["messages"][0]["content"]
        assert forwarded["model"] == "gpt-test"
        assert "김철수" not in forwarded_text
        assert "2023123456" not in forwarded_text
        assert "[이름_1]" in forwarded_text
        assert "[학번_1]" in forwarded_text
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
        assert parts[0]["text"].startswith("[이름_1]")
        assert parts[1]["text"].startswith("[이름_2]")
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


def test_upstream_error_status_and_restore(proxy):
    client, _ = proxy
    with respx.mock as router:
        router.post(f"{LITELLM_URL}/v1/chat/completions").respond(
            status_code=429,
            json={"error": {"message": "rate limited [이름_1] / [학번_1]"}},
        )
        response = client.post(
            CHAT.format(site="test2"), json=chat_payload(), headers=headers("bearer-2")
        )
        assert response.status_code == 429
        text = response.json()["error"]["message"]
        assert "김철수" in text
        assert "2023123456" in text


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
        assert "[이름_1]" in json.dumps(request_body, ensure_ascii=False)
        return httpx.Response(200, json={"choices": [{"message": {"content": "[이름_1]"}}]})

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
