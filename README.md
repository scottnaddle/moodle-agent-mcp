# moodle-mcp

A small [MCP](https://modelcontextprotocol.io) server that exposes Moodle REST web services as tools.
It only reads from and writes to Moodle — content generation happens in the calling bot (Grok Bot).

- Python 3.12, official `mcp` SDK (`FastMCP`, pinned `<2`), Streamable HTTP (`stateless_http=True`, `json_response=True`)
- Served by uvicorn at `http://0.0.0.0:$MCP_PORT/mcp` (default port `8791`)
- Bearer-token auth on every request except `GET /health`

## Configuration

| Variable             | Description                                                          |
|----------------------|----------------------------------------------------------------------|
| `MOODLE_WS_ENDPOINT` | REST endpoint, e.g. `https://moodle.example.com/webservice/rest/server.php` |
| `MOODLE_TOKEN`       | Moodle web service token                                             |
| `MCP_BEARER_TOKEN`   | Token clients must send as `Authorization: Bearer …` (**required**; server refuses to start if empty) |
| `MCP_PORT`           | Listen port (default `8791`)                                         |
| `LOG_LEVEL`          | Optional, default `INFO`                                             |

Token values are never logged or included in error messages. See `.env.example`; never commit a real `.env`.

## Tools

| Tool | Moodle function |
|------|-----------------|
| `site_info()` | `core_webservice_get_site_info` |
| `list_courses(ids=None)` | `core_course_get_courses` (`options[ids]`) |
| `get_course_outline(course_id)` | `core_course_get_contents` |
| `list_students(course_id)` | `core_enrol_get_enrolled_users` |
| `list_assignments(course_ids=None)` | `mod_assign_get_assignments` |
| `get_submissions(assignment_ids, status="")` | `mod_assign_get_submissions` |
| `gradebook_overview(course_id, user_id=None)` | `gradereport_user_get_grade_items` |
| `list_quizzes(course_ids=None)` | `mod_quiz_get_quizzes_by_courses` |
| `list_quiz_attempts(quiz_id, user_id, status="all")` | `mod_quiz_get_user_attempts` (no previews) |
| `review_attempt(attempt_id)` | `mod_quiz_get_attempt_review` |
| `attendance_sessions(attendance_id)` | `mod_attendance_get_sessions` |
| `grade_submission(...)` **WRITE** | `mod_assign_save_grade` |
| `bulk_grade(assignment_id, grades)` **WRITE** | `mod_assign_save_grades` |

Every tool returns a JSON object. Moodle responses are returned unchanged when they are objects. Lists and nulls are wrapped (for example `{"courses": [...]}`, `{"users": [...]}`, `{"result": null}`), and the write tools add `"ok": true`.
Moodle errors come back as `{"error": "<wsfunction>: [errorcode] message"}`.
WRITE tools are described as "only call after the teacher confirmed".

Your Moodle web service must include all of these functions, and the token's user needs the matching capabilities.
`mod_attendance_get_sessions` requires the Attendance plugin.

## Run locally

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e ".[test]"
export MOODLE_WS_ENDPOINT=... MOODLE_TOKEN=... MCP_BEARER_TOKEN=...
.venv/bin/python -m moodle_mcp
curl localhost:8791/health
```

## Docker

```bash
docker build -t moodle-mcp .
docker run --rm -p 8791:8791 --memory 256m \
  -e MOODLE_WS_ENDPOINT -e MOODLE_TOKEN -e MCP_BEARER_TOKEN moodle-mcp
```

The image is `python:3.12-slim` (multi-stage build) and runs as a non-root user. Idle RSS is about 60 MB.

## Example request

```bash
curl -s localhost:8791/mcp \
  -H "Authorization: Bearer $MCP_BEARER_TOKEN" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"site_info","arguments":{}}}'
```

## Tests

```bash
.venv/bin/pytest
```

The tests use fake env values and mock Moodle with `respx`, so they don't need a network connection.
