from urllib.parse import parse_qs

import httpx
import pytest
import respx

from moodle_mcp.moodle import MoodleClient, MoodleError, flatten_params

from .conftest import ENDPOINT, MOODLE_TOKEN


def form(request: httpx.Request) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(request.content.decode(), keep_blank_values=True).items()}


def test_flatten_simple_list():
    assert flatten_params({"courseids": [5, 7]}) == {"courseids[0]": "5", "courseids[1]": "7"}


def test_flatten_nested_list_of_dicts():
    out = flatten_params(
        {"grades": [{"userid": 3, "grade": 7.5, "plugindata": {"ed": {"text": "hi", "format": 1}}}]}
    )
    assert out == {
        "grades[0][userid]": "3",
        "grades[0][grade]": "7.5",
        "grades[0][plugindata][ed][text]": "hi",
        "grades[0][plugindata][ed][format]": "1",
    }


def test_flatten_dict_bool_none_and_scalars():
    out = flatten_params({"options": {"ids": [1]}, "flag": True, "off": False, "skip": None, "s": ""})
    assert out == {"options[ids][0]": "1", "flag": "1", "off": "0", "s": ""}


def test_flatten_empty_list_omitted():
    assert flatten_params({"courseids": []}) == {}


@respx.mock
async def test_call_posts_form_with_token_and_function():
    route = respx.post(ENDPOINT).respond(json={"sitename": "X"})
    client = MoodleClient(ENDPOINT, MOODLE_TOKEN)
    assert await client.call("core_webservice_get_site_info", courseids=[2]) == {"sitename": "X"}
    data = form(route.calls.last.request)
    assert data == {
        "wstoken": MOODLE_TOKEN,
        "wsfunction": "core_webservice_get_site_info",
        "moodlewsrestformat": "json",
        "courseids[0]": "2",
    }
    # token is never in the URL
    assert MOODLE_TOKEN not in str(route.calls.last.request.url)


@respx.mock
async def test_moodle_exception_raises_without_token():
    respx.post(ENDPOINT).respond(
        json={
            "exception": "webservice_access_exception",
            "errorcode": "accessexception",
            "message": f"Access control exception (token {MOODLE_TOKEN})",
        }
    )
    client = MoodleClient(ENDPOINT, MOODLE_TOKEN)
    with pytest.raises(MoodleError) as ei:
        await client.call("core_course_get_courses")
    msg = str(ei.value)
    assert "accessexception" in msg and "Access control exception" in msg
    assert MOODLE_TOKEN not in msg
    assert ei.value.errorcode == "accessexception"
    assert MOODLE_TOKEN not in repr(client)


@respx.mock
async def test_http_error_and_non_json():
    route = respx.post(ENDPOINT)
    client = MoodleClient(ENDPOINT, MOODLE_TOKEN)
    route.respond(status_code=500)
    with pytest.raises(MoodleError, match="HTTP 500"):
        await client.call("x")
    route.respond(text="<html>")
    with pytest.raises(MoodleError, match="non-JSON"):
        await client.call("x")
    route.side_effect = httpx.ConnectError("boom")
    with pytest.raises(MoodleError, match="ConnectError"):
        await client.call("x")


@respx.mock
async def test_list_result_is_not_error():
    respx.post(ENDPOINT).respond(json=[{"exception": "not-a-dict-level-error"}])
    assert await MoodleClient(ENDPOINT, MOODLE_TOKEN).call("x") == [{"exception": "not-a-dict-level-error"}]


async def test_unconfigured_client():
    with pytest.raises(MoodleError, match="not configured"):
        await MoodleClient("", "").call("x")


@respx.mock
async def test_empty_and_null_body_return_none():
    route = respx.post(ENDPOINT)
    client = MoodleClient(ENDPOINT, MOODLE_TOKEN)
    route.respond(text="null")
    assert await client.call("mod_assign_save_grade") is None
    route.respond(text="")
    assert await client.call("mod_assign_save_grade") is None
