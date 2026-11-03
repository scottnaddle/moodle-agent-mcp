"""Static "ask your Moodle administrator" pages for /m/<host>/oauth/authorize (contract §5).

Only the canonical host_key (HTML-escaped) and hub-generated links are rendered; query
parameters of the request are never reflected as text. No scripts; CSP pins the one style block.
"""

from __future__ import annotations

import base64
import hashlib
import html

from starlette.responses import HTMLResponse

_STYLE = (
    "body{font-family:system-ui,-apple-system,'Apple SD Gothic Neo','Malgun Gothic',sans-serif;"
    "max-width:40rem;margin:3rem auto;padding:0 1rem;color:#1f2328;line-height:1.6}"
    "h1{font-size:1.4rem}.host{font-size:1.25rem;font-weight:600;word-break:break-all;"
    "background:#f6f8fa;padding:.5rem .75rem;border-radius:6px}"
    "textarea{width:100%;min-height:7rem;font:inherit;padding:.5rem;box-sizing:border-box}"
    ".note{color:#57606a;font-size:.9rem}a.button{display:inline-block;margin-top:1rem;"
    "padding:.5rem 1rem;border-radius:6px;background:#0969da;color:#fff;text-decoration:none}"
)
_STYLE_HASH = base64.b64encode(hashlib.sha256(_STYLE.encode()).digest()).decode()

CSP = (
    f"default-src 'none'; style-src 'sha256-{_STYLE_HASH}'; form-action 'none'; "
    "frame-ancestors 'none'; base-uri 'none'"
)
PAGE_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": CSP,
    "X-Robots-Tag": "noindex",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}

_TEXT = {
    "ko": {
        "unregistered": (
            "이 Moodle 사이트는 아직 UBION AI에 연결되지 않았습니다",
            "학교 Moodle 관리자에게 아래 요청을 전달하세요.",
        ),
        "pending": (
            "연결 검토 중입니다",
            "관리자가 연결을 요청했고 UBION에서 확인 중입니다. 보통 1영업일이 걸립니다.",
        ),
        "disabled": ("현재 이 사이트에서는 사용할 수 없습니다", "학교 관리자에게 문의하세요."),
        "non_canonical": (
            "주소 형식이 올바르지 않습니다",
            "Claude에 아래 주소를 그대로 입력하세요.",
        ),
        "request": (
            "Moodle 사이트 관리 > 플러그인 설치에서 UBION AI(local_ubionai) 플러그인을 설치하고, "
            "설치 후 나타나는 'UBION AI 연결' 설정 화면에서 [동의하고 연결]을 저장해 주세요. "
            "사이트 주소: {url}"
        ),
        "request_label": "관리자에게 보낼 요청 (복사해서 전달하세요)",
        "private": "학교 내부망에서만 접속되는 Moodle은 현재 지원하지 않습니다.",
        "back": "Claude로 돌아가기",
        "lang": "ko",
    },
    "en": {
        "unregistered": (
            "This Moodle site is not connected to UBION AI yet",
            "Please forward the request below to your Moodle administrator.",
        ),
        "pending": (
            "The connection is under review",
            "Your administrator requested the connection and UBION is reviewing it. This usually takes one business day.",
        ),
        "disabled": ("This site is currently unavailable", "Please contact your school administrator."),
        "non_canonical": ("This address is not in canonical form", "Enter the address below in Claude exactly."),
        "request": (
            "In Moodle Site administration > Install plugins, install the UBION AI (local_ubionai) plugin, "
            "then save [Agree and connect] on the 'UBION AI connection' settings page. Site address: {url}"
        ),
        "request_label": "Request for your administrator (copy and send it)",
        "private": "Moodle sites reachable only from a school's internal network are not supported yet.",
        "back": "Back to Claude",
        "lang": "en",
    },
}

STATUS_CODES = {"unregistered": 404, "pending": 403, "disabled": 403, "non_canonical": 400}


def page_language(accept_language: str | None) -> str:
    """Korean by default; English when the first preference is English."""
    first = (accept_language or "").split(",", 1)[0].split(";", 1)[0].strip().lower()
    return "en" if first == "en" or first.startswith("en-") else "ko"


def render_site_page(
    kind: str,
    host_key: str,
    lang: str = "ko",
    back_href: str | None = None,
    canonical_url: str | None = None,
) -> HTMLResponse:
    """``kind``: unregistered, pending, disabled or non_canonical."""
    t = _TEXT.get(lang, _TEXT["ko"])
    title, lead = t[kind]
    esc = html.escape
    parts = [
        f'<!doctype html><html lang="{t["lang"]}"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<meta name="robots" content="noindex">',
        f"<title>UBION AI — {esc(title)}</title><style>{_STYLE}</style></head><body>",
        f"<h1>{esc(title)}</h1>",
    ]
    if kind == "non_canonical":
        parts.append(f"<p>{esc(lead)}</p>")
        if canonical_url:
            parts.append(f'<p class="host">{esc(canonical_url)}</p>')
    else:
        parts.append(f'<p class="host">{esc(host_key)}</p><p>{esc(lead)}</p>')
        if kind == "unregistered":
            request_text = t["request"].format(url="https://" + host_key)
            parts.append(
                f'<label for="req">{esc(t["request_label"])}</label>'
                f'<textarea id="req" readonly>{esc(request_text)}</textarea>'
                f'<p class="note">{esc(t["private"])}</p>'
            )
    if back_href:
        parts.append(f'<p><a class="button" href="{esc(back_href, quote=True)}">{esc(t["back"])}</a></p>')
    parts.append("</body></html>")
    return HTMLResponse("".join(parts), status_code=STATUS_CODES[kind], headers=PAGE_HEADERS)
