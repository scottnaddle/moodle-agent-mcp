# 허브 OAuth 2.1 (Easy Connect Phase 1)

허브(`moodle-agent-mcp`)가 테넌트별 **인가 서버(AS)** 와 **리소스 서버(RS)** 를 겸해
교사(=사용자) 본인 권한으로 Moodle을 호출하게 하는 기능입니다. 로그인은 Moodle
플러그인 `local_ubionai` (>= 0.6.0, `oauth/authorize.php` · `oauth/exchange.php` ·
`oauth/revoke.php` 제공)에게 위임하고, 허브는 그 교사의 web service 토큰만 KEK로 봉인해
보관합니다.

- 정적(테넌트) Bearer 토큰은 그대로 동작합니다. OAuth는 **테넌트별**로 붙습니다.
- `UBIONAI_HUB_TENANT_SECRETS_DIR`가 비어 있으면 OAuth는 완전히 꺼져 있고, 이전과
  똑같이 정적 Bearer만 동작합니다.
- 교사 토큰의 `list_courses`는 그 교사가 수강 중인 강좌만 보입니다
  (`core_enrol_get_users_courses`). 과제 목록은 등록 여부와 무관하게 보이는 경로가
  별도로 있습니다(`local_ubionai_get_course_assignments`).

## 1. 엔드포인트

`<public>` = `UBIONAI_HUB_PUBLIC_URL`, `<site>` = 테넌트 site_id.

| 메서드 | 경로 | 설명 |
|---|---|---|
| GET | `/.well-known/oauth-protected-resource/t/<site>/mcp` | PRM. `resource`, `authorization_servers`, `scopes_supported`, `bearer_methods_supported` |
| GET | `/.well-known/oauth-authorization-server/t/<site>` | AS 메타데이터. `code_challenge_methods_supported`는 `["S256"]` 하나뿐 |
| GET | `/.well-known/openid-configuration/t/<site>` | OIDC discovery. AS 메타데이터와 동일 내용 |
| GET | `/t/<site>/.well-known/openid-configuration` | OIDC discovery (테넌트 경로 형태) |
| POST | `/t/<site>/oauth/register` | DCR(동적 클라이언트 등록). 공개 클라이언트만(`token_endpoint_auth_method=none`) |
| GET | `/t/<site>/oauth/authorize` | 인가 요청. PKCE S256 필수, `resource` 정확 일치 필수 |
| GET | `/t/<site>/oauth/callback` | Moodle가 브라우저로 되돌려 보내는 콜백 |
| POST | `/t/<site>/oauth/token` | `authorization_code` / `refresh_token` 교환 |
| POST | `/t/<site>/oauth/revoke` | RFC 7009 토큰 폐기. 항상 200 |

`issuer` = `<public>/t/<site>`, `resource` = `<public>/t/<site>/mcp`.
접근 토큰의 대상은 **자기 테넌트의 MCP URL 한 곳**뿐이라, 토큰을 다른 테넌트로 넘겨
사용할 수 없습니다.

허브가 지원하는 scope는 `moodle:read`, `moodle:write` 두 개입니다(AS 메타데이터는
`offline_access`도 함께 광고합니다). `resource`는 scope와 별개로 항상
`<public>/t/<site>/mcp` 하나만 유효합니다.

## 2. 흐름

```
클라이언트                허브(AS/RS)                 Moodle 플러그인          Moodle
    |                        |                             |                  |
    |-- PRM 조회 ----------->|                             |                  |
    |-- authorize ---------->|  (PKCE S256, resource 확인) |                  |
    |                        |--- 302 req=<signed> ------->| 로그인·동의     |
    |                        |                             |-- wstoken 발급->|
    |<-- 302 callback?code&state (브라우저 바인딩 쿠키 확인)                  |
    |-- token(code, verifier)->|--- exchange.php ---------->|                 |
    |                        |<-- {userid,tokenid,wstoken,validuntil} ---------|
    |                        |  site_info로 교사·서비스 검증 → KEK 봉인 저장   |
    |<-- access/refresh 토큰 |                             |                  |
    |-- MCP 호출(Bearer) ---->|  교사 토큰으로 Moodle API 호출 ---------------->|
```

1. 클라이언트는 PRM을 읽고 `authorize`를 호출합니다. `code_challenge_method=S256`,
   `code_challenge`는 정확히 43자(`[A-Za-z0-9_-]`), `resource`는 위 값과 정확히 같아야
   합니다. `redirect_uri`는 허용목록(§4)에 있고 등록된 값과 일치해야 합니다.
2. 허브는 `req=<서명>`을 붙여 `<moodle_url>/local/ubionai/oauth/authorize.php` 로 302 합니다.
3. 플러그인이 로그인·동의를 마치고 `code`와 `state`를 콜백으로 돌려줍니다. 플러그인은
   사이트 관리자와 `local/ubionai:connect` 권한이 강좌 하나도 없는 사용자를 거부합니다.
   허브는 authorize 단계에서 내려준 **브라우저 바인딩 쿠키**(`ubionai_oauth`,
   httponly·samesite=lax·공개 URL이 https면 secure)가 같은 브라우저인지 확인합니다.
   다르면 400으로 거부합니다.
4. 허브는 `exchange.php`로 코드를 교환해 교사 wstoken을 받습니다. 그 토큰으로
   `core_webservice_get_site_info`를 호출해 (a) 교사本人인지, (b) 사이트 관리자가
   아닌지, (c) 토큰의 함수 목록이 `ubionai_user` 화이트리스트(§9) 안에만 있는지를
   확인합니다. 하나라도 어기면 토큰을 즉시 폐기하고 `access_denied`을 반환합니다.
5. 통과한 wstoken은 KEK로 봉인해 `oauth_grants`에 저장하고, 액세스/리프레시 토큰을 발급합니다.
   액세스 토큰 TTL 1시간, 리프레시 토큰 TTL 30일, 코드 TTL 60초, 인가 요청 TTL 10분.
6. 리프레시 토큰은 **회전**합니다. 이미 사용한 리프레시 토큰을 다시 쓰면(재사용)
   해당 grant와 Moodle 토큰을 즉시 폐기합니다.
7. `revoke`는 RFC 7009대로 항상 200을 반환합니다. 리프레시 토큰을 폐기하면 grant 전체가
   폐기됩니다.

### 클라이언트 등록 방식 두 가지

| 방식 | client_id | 등록 |
|---|---|---|
| DCR | `dcr_...` (허브가 발급) | `POST /oauth/register` (redirect_uris 필수, `none` 인증) |
| CIMD | `https://...` 문서 URL | 클라이언트가 제공하는 Client ID Metadata Document |

CIMD는 `https`만 허용하고, 문서를 읽을 때 호스트를 해석해 **공인 IP만** 접속하며
(SSRF·DNS 리바인딩 방지), 64KB·5초 제한과 TTL 캐시가 있습니다. 리다이렉트는 https
만 따라갑니다. 문서에는 클라이언트 시크릿이 있으면 거부합니다.

## 3. 환경변수

| 변수 | 설명 | 기본 |
|---|---|---|
| `UBIONAI_HUB_PUBLIC_URL` | 허브의 외부 URL. OAuth 사용 시 **필수**, `https`만 허용(로컬 테스트의 loopback `http` 예외) | 없음 |
| `UBIONAI_HUB_TENANT_SECRETS_DIR` | 테넌트 비밀 디렉터리. 비어 있으면 OAuth 전체 off | 빈 값 |
| `UBIONAI_HUB_OAUTH_STRICT_RESOURCE` | `1`이면 token 요청에 `resource`가 **필수**. 누락 시 `invalid_target` | 허용(현행) |
| `UBIONAI_HUB_DB` | 레지스트리 SQLite 경로 | 없음 |
| `UBIONAI_HUB_KEK_FILE` | KEK 파일 경로 | 없음 |

`resource` 정책은 두 단계입니다.

- **불일치**(보낸 값이 `<public>/t/<site>/mcp`가 아님): 항상 `invalid_target`으로 거부.
- **누락**: 기본은 허용(지금까지의 동작). `UBIONAI_HUB_OAUTH_STRICT_RESOURCE=1`이면
  `authorization_code`·`refresh_token` 요청 모두 `invalid_target`으로 거부.

## 4. redirect_uri 허용목록

허브 공통 허용목록(`redirect_allowed`)은 다음뿐입니다.

- `https://claude.ai/api/mcp/auth_callback`
- `https://claude.com/api/mcp/auth_callback`
- loopback `http` (Claude Code 등, 포트 무관)

등록된 `redirect_uri`와의 비교는 정확히 일치해야 하고, loopback끼리는 **포트만** 달라도
됩니다(RFC 8252 §7.3). 이 정책은 `OAuthServer.redirect_policy` 훅으로 교체 가능하며,
기본값은 위 목록과 동일합니다.

## 5. 비밀 파일

| 항목 | 값 |
|---|---|
| 경로 | `<UBIONAI_HUB_TENANT_SECRETS_DIR>/<site>/oauth.secret` |
| 권한 | `0400`, 소유자 `10001:10001` (컨테이너 `app` 사용자) |
| 내용 | 32바이트 이상 랜덤 바이트 |
| 예외 | 정규 파일이 아니거나, 그룹·기타 권한(비어 있지 않은 `0o077` 비트)이 붙어 있거나, 길이가 32바이트 미만이면 그 사이트 OAuth는 **off**(에러 로그만 남고 진행) |

- 파일이 없으면 그 사이트만 OAuth off, 나머지 사이트와 정적 Bearer는 영향 없습니다.
- 생성 예(값을 화면에 찍지 않는 형태). `<secrets_dir>` = `UBIONAI_HUB_TENANT_SECRETS_DIR`:
  ```sh
  install -d -m 0700 -o 10001 -g 10001 <secrets_dir>/<site>
  umask 077 && head -c 48 /dev/urandom | base64 > <secrets_dir>/<site>/oauth.secret
  chown 10001:10001 <secrets_dir>/<site>/oauth.secret
  chmod 0400 <secrets_dir>/<site>/oauth.secret
  ```
- **커밋 금지.** 저장소에는 절대 넣지 말고, 배포 PR에서 마운트만 정의합니다.
  (`deploy/hub/docker-compose.yml` 변경은 배포 PR에서 별도로 진행)

### Moodle 쪽에도 같은 값이 필요합니다

플러그인은 테넌트별로 세 가지 설정을 요구합니다. 하나라도 없으면 OAuth가 동작하지
않습니다(back-channel 서명 검증 실패 → 로그인 진행 안 함).

| Moodle 설정 | 값 |
|---|---|
| `local_ubionai/oauth_secret` | 위 파일의 내용과 **같은 값**(최소 32자) |
| `local_ubionai/hub_url` | 허브 공개 URL (예: `https://hub.example`) |
| `local_ubionai/hub_site_id` | 이 사이트의 site_id (`<public>/t/<site>/mcp`의 `<site>`) |

## 6. 스키마 v5

레지스트리 DB(`UBIONAI_HUB_DB`) 스키마 버전은 5이고, OAuth 테이블은 `Registry`가 소유합니다
(허브·관리자 CLI가 같은 DB를 쓰므로 OAuth를 꺼도 테이블은 존재합니다).

| 테이블 | 컬럼(요지) |
|---|---|
| `oauth_clients` | `site_id`, `client_id`, `redirect_uris`, `client_name`, `source`(`dcr`/`cimd`), `created_at` |
| `oauth_grants` | `grant_id`, `site_id`, `moodle_userid`, `client_id`, `scope`, `resource`, `wstoken_ct`(봉인값), `moodle_tokenid`, `valid_until`, `kek_id`, `created_at`, `revoked_at` |
| `oauth_tokens` | `token_hash`, `kind`(`access`/`refresh`), `grant_id`, `expires_at`, `used_at` |

- `oauth_tokens_grant`, `oauth_grants_site_user` 인덱스 2개가 붙습니다.
- grant 단위 = `(site, moodle_userid, client_id)`. 그래서 클라이언트 하나만 골라 해지할 수 있습니다.
- 테넌트를 삭제하면 해당 사이트의 `oauth_tokens` → `oauth_grants` → `oauth_clients` →
  `pseudonym_map` → `tenants` 순으로 같은 트랜잭션에서 지워집니다.
- 기존 v4 DB는 `CREATE TABLE IF NOT EXISTS`로 5로 업그레이드되고 기존 데이터는 그대로입니다.

## 7. 교사 자격증명 인터페이스 (향후 AI 블록 재사용 대비)

허브는 앞으로 chat·블록 경로가 MCP 경로와 **같은** 교사 토큰을 쓰게 할 인터페이스를
이미 갖고 있습니다. 이번 PR에서 바뀐 동작은 없고(인터페이스만 추가) 테스트로 고정되어
있습니다.

| 이름 | 정의 | 역할 |
|---|---|---|
| `OAuthPrincipal` | `oauth.py`의 frozen dataclass: `site_id`, `moodle_userid`, `client_id`, `scope`, `grant_id` | "이 요청은 어느 사이트의 어느 교사가 어느 클라이언트를 통해 왔나"를 나타내는 주체 표현 |
| `TeacherCredentialSource` | `Protocol`: `principal(site_id, access_token) -> OAuthPrincipal \| None`, `moodle_token(tenant, principal) -> bytearray` | 경로(MCP/chat/블록)와 무관하게 "액세스 토큰 → 주체 → 교사 wstoken"을 얻는 방법 |
| `RedirectPolicy` | `Callable[[str, Tenant], bool]` | `redirect_uri` 허용 판단. 기본값은 §4의 공통 허용목록 |

- `OAuthServer`는 `TeacherCredentialSource`를 만족합니다. `principal()`·`moodle_token()`은
  `authenticate()`·`user_token()` 위에 얇게 얹은 래퍼일 뿐입니다.
- `TenantRouterMiddleware`는 요청마다 `scope["state"]["oauth_principal"]`에
  `OAuthPrincipal`을 넣습니다. 정적(테넌트) Bearer면 `None`입니다. 호환용으로
  `scope["state"]["moodle_userid"]`도 그대로 둡니다.
- `grant` 단위가 `(site, moodle_userid, client_id)`이므로 **클라이언트 단위로 독립
  해지**할 수 있습니다. Claude 연결을 해지해도 블록 연결은 남고 그 반대도 같습니다
  (`moodle-hub-admin oauth-revoke --client-id <client> --yes`).

### 향후 AI 블록에서 지켜야 할 규칙 (구현은 나중)

- 블록은 같은 AS의 **1st-party 클라이언트**로 붙습니다. 콜백은
  `<tenant.moodle_url>/blocks/<name>/…` 형태가 필요한데 지금은 허용목록에 없습니다.
  테넌트별로 허용하려면 `redirect_policy` 훅에 정책만 추가하면 됩니다
  (`OAuthServer(redirect_policy=...)`).
- **교사 wstoken을 Moodle 쪽으로 되돌려 주는 API는 만들지 않습니다.** 블록도 허브
  토큰만 들고, Moodle 호출은 항상 허브가 교사 토큰으로 합니다(토큰 패스스루 금지).
- 블록 클라이언트 등록 방식(사전 등록 vs CIMD), chat 경로의 OAuth 인증, 새 scope
  (`ai:chat` 등), 블록 UI는 Phase 1 범위 밖입니다.

## 8. 단일 워커 제약

인가 요청(`state`)과 인가 코드(code)는 **프로세스 메모리**에 있습니다(`oauth.py`의
`requests`/`codes`). 따라서 허브는 **uvicorn 워커 1개**로 돌려야 합니다. 워커를 여러 개
쓰면 authorize와 callback이 서로 다른 프로세스에 있어 로그인이 실패합니다. 인가 요청을
DB로 옮기는 작업은 Phase 1b입니다.

## 9. back-channel 계약 (플러그인 Phase 2 구현 기준)

허브와 Moodle 플러그인은 테넌트별 공유 비밀(`oauth.secret`)로 HMAC 서명 메시지를 주고받습니다.

### 메시지 형식

```
<message> = b64url(json) "." b64url(HMAC-SHA256(secret, "ubionai-oauth-v1." + b64url(json)))
```

- `json`은 `separators=(",",":")`, `sort_keys=True`로 직렬화한 객체입니다(허브의 서명
  규칙). 플러그인은 서명된 문자열을 그대로 검증하므로 직렬화 방식을 다시 맞출 필요가
  없습니다.
- base64url은 패딩(`=`)을 붙이지 않습니다.
- HMAC 키는 테넌트 공유 비밀 바이트입니다.

### 메시지 종류별 클레임

| typ | 방향·전송 위치 | 클레임 |
|---|---|---|
| `authz_req` | 허브 → `GET <moodle_url>/local/ubionai/oauth/authorize.php?req=<message>` | `typ`, `iss`(=허브 issuer), `aud`(=`moodle_url`), `site`, `state`, `client_name`, `client_host`(CIMD 호스트, 없으면 null), `redirect_host`, `scope`, `callback`(=`<issuer>/oauth/callback`), `exp` |
| `exchange` | 허브 → `POST <moodle_url>/local/ubionai/oauth/exchange.php` (폼 `assertion`) | `typ`, `iss`, `aud`, `site`, `code`, `state`, `jti`, `exp` |
| `revoke` | 허브 → `POST <moodle_url>/local/ubionai/oauth/revoke.php` (폼 `assertion`) | `typ`, `iss`, `aud`, `site`, `userid`, `tokenid`, `jti`, `exp` |

- `exp`는 Unix 시각입니다. 백채널 메시지 TTL은 60초(`authz_req`만 10분).
- `jti`는 메시지 고유값입니다. `exchange`·`revoke`만 `jti`를 보냅니다.
- `exchange` 응답: `{"userid": int, "tokenid": int, "wstoken": str, "validuntil": int}`.
  하나라도 없거나 타입이 다르면 허브는 `access_denied`으로 처리하고 토큰을 폐기합니다.
- `revoke` 응답: HTTP 200이면 성공.

### 검증 상태 (Phase 1 스파이크 → Phase 2)

플러그인 0.6.0 스파이크가 실제로 검증하는 것과 Phase 2에서 채워야 할 것을 구분합니다.
허브는 아래 "Phase 2" 항목을 아직 신뢰하지 않습니다.

| 항목 | 0.6.0 스파이크 | Phase 2에서 할 일 |
|---|---|---|
| MAC(`ubionai-oauth-v1.` 접두) | 검증 | 유지 |
| `typ` | 검증 | 유지 |
| `aud`(= Moodle `wwwroot`) · `site` · `exp` | 검증 | 유지 |
| `callback`(= 허브 콜백 URL) | 검증 | 유지 |
| `iss`(= 허브 issuer) | **미검증** | 허브 issuer와 일치하는지 확인 |
| `jti` 재전송 방지 | **미구현** | `jti`를 기억해 같은 메시지의 재전송을 거부 |

### 플러그인 경로 3개

```
/local/ubionai/oauth/authorize.php   (GET,  req=<message>)
/local/ubionai/oauth/exchange.php    (POST, assertion=<message>)
/local/ubionai/oauth/revoke.php      (POST, assertion=<message>)
```

### 서비스 함수 화이트리스트

허브는 `site_info`의 함수 목록이 아래 13개의 **부분집합일 때만** 교사 토큰을 받아들입니다
(목록에 없는 함수—`moodle_mobile_app`, 수동 서비스, 주입된 함수—가 하나라도 있으면
거부합니다). 플러그인 `db/services.php`의 `ubionai_user` 목록은 아래와 반드시 같아야
합니다(바뀌면 양쪽을 같이 고치세요).

```
core_webservice_get_site_info
core_enrol_get_users_courses
core_course_get_courses_by_field
core_course_get_contents
core_enrol_get_enrolled_users
mod_assign_get_assignments
mod_assign_get_submissions
mod_assign_get_grades
mod_assign_save_grade
local_ubionai_create_module
local_ubionai_update_module
local_ubionai_get_course_assignments
local_ubionai_list_course_assignments
```

## 10. 운영 런북

CLI는 `moodle-hub-admin`이며 `UBIONAI_HUB_DB`, `UBIONAI_HUB_KEK_FILE`이 필요합니다.

### 조회

```sh
moodle-hub-admin oauth-list --site-id <site>
moodle-hub-admin oauth-list --site-id <site> --json --include-revoked
```

- `clients` 블록: `client_id`, `source`(`dcr`/`cimd`), `client_name`, `created_at`, `active_grants`
- `grants` 블록: `grant_id`, `moodle_userid`, `client_id`, `scope`, `created_at`,
  `valid_until`, `revoked_at`, `live_tokens`
- 토큰·봉인값·해시·공유 비밀은 **어떤 경우에도 출력되지 않습니다**.
- 없는 site → `error: site not found`, 종료코드 1.

### 해지/삭제 (기본은 dry-run)

```sh
moodle-hub-admin oauth-revoke --site-id <site> --all                      # dry-run (기본)
moodle-hub-admin oauth-revoke --site-id <site> --all --yes                # 실제 실행
moodle-hub-admin oauth-revoke --site-id <site> --client-id <client> --delete-client --yes
moodle-hub-admin oauth-revoke --site-id <site> --grant-id <grant> --yes
moodle-hub-admin oauth-revoke --site-id <site> --user-id <n> --yes
moodle-hub-admin oauth-revoke --site-id <site> --all --yes --skip-moodle  # Moodle 폐기 생략
```

- 대상 선택(`--client-id` / `--grant-id` / `--user-id` / `--all`)은 **정확히 하나**만
  지정해야 합니다(그대로 두면 argparse 오류, 종료코드 2).
- `--yes`가 없으면 dry-run입니다. DB는 그대로이고 대상만 출력합니다:
  `DRY-RUN would revoke grant=<id> userid=<n> client=<c>`,
  `DRY-RUN would delete client=<c>`, 요약 `grants=<k> clients=<m>`.
- `--yes` 실행 순서: ① 허브 grant 해지(즉시 차단) → ② 각 grant의 Moodle 토큰 back-channel
  폐기 → ③ `--delete-client`/`--all`이면 client 삭제.
- Moodle 폐기를 하려면 CLI 실행 환경에 `UBIONAI_HUB_PUBLIC_URL`과
  `UBIONAI_HUB_TENANT_SECRETS_DIR`이 있어야 하고, `<dir>/<site>/oauth.secret`이 유효해야
  합니다. 없으면 Moodle 폐기만 건너뛰고
  `warning: moodle token not revoked grant=<id> (expires <valid_until>)`를 출력합니다.
- 결과 줄: `revoked grant=<id> moodle=ok|failed|skipped`, `deleted client=<c>`
- 종료코드: `0` 전부 성공 또는 dry-run · `1` 입력·DB 오류 · `3` 허브 해지는 됐지만
  Moodle 폐기가 일부 실패/건너뜀.

### 시험 클라이언트 정리 절차

시험 환경에 남은 클라이언트를 지우는 순서입니다. **실제 id·값은 문서에 쓰지 마세요.**

1. `moodle-hub-admin oauth-list --site-id <site>` → 남은 client와 grant를 확인합니다.
2. `moodle-hub-admin oauth-revoke --site-id <site> --all` (dry-run) → 대상 목록을 확인합니다.
3. 대상이 맞으면 `moodle-hub-admin oauth-revoke --site-id <site> --all --yes` → 실행합니다.
4. `moodle-hub-admin oauth-list --site-id <site> --include-revoked` → grant가 모두 폐기됐는지
   확인합니다.
5. Moodle 쪽 폐기가 `moodle=skipped`/`failed`로 남으면(플러그인에 `revoke.php`가 없거나
   비밀 파일이 없는 경우) 해당 토큰은 Moodle에서 **자연 만료**까지 살아 있습니다
   (교사 wstoken TTL이 끝날 때까지). 만료 시각은 `valid_until`에 있습니다.
6. 클라이언트 행까지 지우려면 `--all --yes`가 client 삭제까지 포함합니다
   (`--delete-client`는 대상 클라이언트를 함께 지웁니다).

## 11. 롤백

| 단계 | 방법 | 효과 |
|---|---|---|
| 한 사이트만 OAuth 끄기 | `<secrets_dir>/<site>/oauth.secret` 삭제(또는 이름 변경) | 그 사이트만 OAuth off, 정적 Bearer는 그대로 동작 |
| 전부 OAuth 끄기 | `UBIONAI_HUB_TENANT_SECRETS_DIR`을 비우고 재시작 | 정적 Bearer만 동작(배포 전과 동일) |
| 토큰만 회수 | `moodle-hub-admin oauth-revoke --site-id <site> --all --yes` | 허브 grant와 Moodle 토큰 폐기 |

`oauth.secret`을 지우면 그 사이트의 OAuth가 꺼지면서 **이미 발급된 액세스·리프레시 토큰도
즉시 쓸 수 없게 됩니다**(허브가 OAuth 인증을 시도하지 않고, token 엔드포인트도 404가
됩니다). 다만 **Moodle에 발급된 교사 wstoken은 Moodle 쪽에 그대로 남아** 그 토큰의 만료
시각까지 유효합니다. Moodle 쪽까지 회수하려면 `oauth-revoke --yes`를 먼저 실행한 뒤
비밀 파일을 지우세요.
