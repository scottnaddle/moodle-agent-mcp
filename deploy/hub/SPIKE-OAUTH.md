# hub-staging 시험: 교사별 OAuth (Easy Connect 스파이크 2)

- 브랜치: 허브 `spike/phase0-oauth`(PR #9), 플러그인 `spike/phase0-oauth`(PR #9, `local_ubionai` 0.6.0-spike2 / `2026110200`)
- 목적: claude.ai 커넥터에 `https://hub-staging.ubion.global/t/<site>/mcp` URL 하나만 넣고, 교사가 **자기 Moodle 계정**으로 로그인·동의하면 그 교사 권한으로 도구가 실행되는지 실측
- 운영(lms) 배포 금지. 스테이징 Moodle + 가짜 교사·강좌로만

## 1. 무엇이 바뀌나

| 구분 | 내용 |
|---|---|
| 새 경로 (허브) | `/.well-known/oauth-protected-resource/t/<site>/mcp`, `/.well-known/oauth-authorization-server/t/<site>`, `/.well-known/openid-configuration/t/<site>`, `/t/<site>/.well-known/openid-configuration`, `/t/<site>/oauth/{register,authorize,callback,token,revoke}` |
| `/t/<site>/mcp` | 테넌트 정적 Bearer는 **그대로** 동작. OAuth가 켜진 사이트는 토큰이 없으면 `401 WWW-Authenticate: Bearer resource_metadata="…", scope="…"`, 틀린 토큰은 `401 error="invalid_token"`(이전 403). OAuth가 꺼진 사이트는 이전과 같음(401 `Bearer` / 403) |
| 교사 토큰 | 플러그인이 발급한 교사 본인 WS 토큰(서비스 `ubionai_user`만, 30일)을 KEK로 봉인해 저장. AAD = site + `user_wstoken:<grant>:<userid>` + moodle_url |
| 거부 | 사이트 관리자: 플러그인 동의 단계에서 거부 + 허브가 `site_info.userissiteadmin`으로 재확인. `moodle_mobile_app` 등 다른 서비스 토큰: 플러그인은 `ubionai_user`만 발급·폐기, 허브는 `site_info.functions ⊆ ubionai_user 화이트리스트`가 아니면 거부하고 그 토큰을 폐기 |
| `list_courses` | OAuth(교사) 요청이면 `core_enrol_get_users_courses(userid=본인)`. 정적 Bearer면 이전처럼 `core_course_get_courses`. `list_assignments` 대체 경로도 같음 |
| 공개 URL | issuer·메타데이터·`resource`는 모두 `UBIONAI_HUB_PUBLIC_URL` 기준(요청 Host/스킴을 쓰지 않음) → nginx/Cloudflare 뒤 http로 들어와도 `https://…`로 나감. OAuth를 켜면 https가 아니면 기동 거부(loopback http만 예외) |
| 허용 redirect_uri | `https://claude.ai/api/mcp/auth_callback`, `https://claude.com/api/mcp/auth_callback`, loopback(`http://127.0.0.1|localhost|[::1]:<포트>/…`, 포트만 달라도 됨). CIMD(MCP 2025-11-25): `client_id`가 https URL(경로 필수, userinfo·fragment 금지)이면 문서를 가져와 검증 — 5초 타임아웃, 64KB 상한, https 리다이렉트만(재검증), DNS 해석 후 사설/루프백/링크로컬/예약/멀티캐스트(IPv6·IPv4-mapped 포함) 차단하고 검증된 IP로 접속, 캐시(Cache-Control max-age 60s–1h, 기본 10분, 실패 30초). 문서의 `client_id`가 URL과 정확히 일치, `redirect_uri`가 `redirect_uris`에 정확히 포함(위 허용목록도 적용), `token_endpoint_auth_method`는 `none`(없으면 none)만. 동의 화면 이름은 `<client_name> — <client_id 호스트>` |

흐름: Claude → `401` → PRM → AS 메타데이터 → DCR(또는 CIMD) → `/t/<site>/oauth/authorize`(PKCE S256, `resource` 정확 일치) → 302 `<moodle>/local/ubionai/oauth/authorize.php?req=<서명>` → Moodle 로그인·동의 → 302 `/t/<site>/oauth/callback?code&state` (브라우저 바인딩 쿠키 확인) → 허브가 `<moodle>/local/ubionai/oauth/exchange.php`로 back-channel 교환 → `site_info` 검증 → Claude 콜백에 `code`+`iss` → `/oauth/token` → access 1시간 / refresh 30일(회전, 재사용 감지 시 grant와 Moodle 토큰 폐기).

## 2. 새 환경변수

| 변수 | 값 (hub-staging) | 설명 |
|---|---|---|
| `UBIONAI_HUB_TENANT_SECRETS_DIR` | `/run/secrets/tenants` (compose에 추가됨) | 비우면 OAuth 전체 off(이전과 동일). 설정하면 `<dir>/<site>/oauth.secret`이 있는 사이트만 OAuth on |
| `UBIONAI_HUB_PUBLIC_URL` | `https://hub-staging.ubion.global` (기존) | OAuth on이면 **필수**, https여야 함 |
| `UBIONAI_HUB_ALLOW_HTTP` | 설정하지 않음 | (기존) 로컬 시험에서만 `1` |

## 3. 비밀 파일 (값은 서버에서 직접 생성 — 리포·채팅·PR에 넣지 말 것)

| 호스트 경로 | 컨테이너 경로 | 소유자·권한 | 내용 |
|---|---|---|---|
| `/opt/ubionai-hub/secrets/tenants/` | `/run/secrets/tenants/` (ro) | `root:10001` `0750` | 디렉터리 |
| `/opt/ubionai-hub/secrets/tenants/<site>/` | `…/<site>/` | `root:10001` `0750` | 디렉터리 (기존 `bearer.token`이 있어도 됨 — 허브는 읽지 않음, root 0600이면 컨테이너에서 못 읽음) |
| `/opt/ubionai-hub/secrets/tenants/<site>/oauth.secret` | `…/<site>/oauth.secret` | **`10001:10001` `0400`** | 허브↔플러그인 공유 비밀 (32바이트 이상, 한 줄) |

- 10001 = 이미지의 `app` 사용자(`Dockerfile`). 그룹·기타 권한 비트가 있거나 심볼릭 링크·32자 미만이면 허브가 **그 사이트만 OAuth off**로 두고 로그에 `oauth secret …`을 남김(기동은 계속)
- 생성 명령 (값을 화면에 출력하지 않음):

```sh
SITE=<site_id>   # 허브 레지스트리의 site_id (admin.py list)
sudo install -d -o root -g 10001 -m 0750 /opt/ubionai-hub/secrets/tenants /opt/ubionai-hub/secrets/tenants/$SITE
sudo sh -c "umask 077; openssl rand -base64 48 | tr -d '\n' > /opt/ubionai-hub/secrets/tenants/$SITE/oauth.secret"
sudo chown 10001:10001 /opt/ubionai-hub/secrets/tenants/$SITE/oauth.secret
sudo chmod 0400 /opt/ubionai-hub/secrets/tenants/$SITE/oauth.secret
```

- 같은 값을 그 사이트 Moodle 플러그인 설정 `local_ubionai/oauth_secret`에 넣음 (아래 4). 회전 = 파일 교체 + 플러그인 설정 교체 (허브는 요청마다 파일을 읽으므로 재시작 불필요. 교체 사이의 진행 중 로그인만 실패)

## 4. Moodle(스테이징) 플러그인 설정

플러그인 0.6.0-spike2 설치/업그레이드 후 (`admin/cli/upgrade.php --non-interactive`, 테이블 `local_ubionai_codes` 생성, capability `local/ubionai:connect` 추가 — editingteacher·teacher 기본 허용):

| 설정 이름 | 값 |
|---|---|
| `local_ubionai/hub_url` | `https://hub-staging.ubion.global` |
| `local_ubionai/hub_site_id` | 허브 레지스트리의 `<site>` |
| `local_ubionai/oauth_secret` | 3의 `oauth.secret`과 같은 값 |

- 관리 화면: 사이트 관리 > 플러그인 > 로컬 플러그인 > UBION AI connection. CLI: `php admin/cli/cfg.php --component=local_ubionai --name=hub_site_id --set=<site>` (비밀은 화면 입력 권장 — CLI 인자는 프로세스 목록에 보임)
- 전제: 웹 서비스·REST 프로토콜 활성(`enablewebservices=1`, `webserviceprotocols`에 `rest`), 서비스 `UBION AI (per-user)`(`ubionai_user`) 활성 — 플러그인 설치 시 생성됨
- Moodle 주소는 허브 테넌트 `moodle_url`과 **정확히** 같아야 함(`$CFG->wwwroot`, 끝 `/` 없음). 서명 요청의 `aud`로 검사함
- 교사에게 시스템 역할 `ubionai_wsuser`(`webservice/rest:use`만)가 첫 연결 때 자동 배정되고, 마지막 연결을 해지하면 해제됨
- 교사 프로필 > "Claude connections"(`/local/ubionai/connections.php`)에서 연결 목록·해지

## 5. 마이그레이션

- 허브 레지스트리 스키마 4 → **5**: 테이블 `oauth_clients`, `oauth_grants`, `oauth_tokens` 추가(`CREATE TABLE IF NOT EXISTS`), 기존 테이블·데이터 변경 없음. OAuth가 켜진 상태로 허브가 처음 뜰 때 자동 적용
- 인가 요청(10분)과 code(60초)는 프로세스 메모리에만 있음 → 재시작하면 진행 중 로그인만 다시 하면 됨. grant·토큰은 DB에 있으므로 재시작 후에도 유지
- 플러그인: `2026110200` 업그레이드 단계가 `local_ubionai_codes` 생성

## 6. 배포 절차 (hub-staging)

1. 백업: `docker compose -f deploy/hub/docker-compose.yml stop hub` 후 볼륨의 `hub.sqlite3`(+`-wal`/`-shm`) 복사, 현재 `IMAGE_TAG` 기록
2. 이미지 빌드: 브랜치 `spike/phase0-oauth`에서 `docker build -t moodle-mcp:spike-oauth .`
3. 3의 비밀 파일 생성 (시험할 `<site>` 하나만)
4. compose: 이 브랜치의 `deploy/hub/docker-compose.yml`(환경변수 + `/opt/ubionai-hub/secrets/tenants` ro 마운트 추가) 사용, `IMAGE_TAG=spike-oauth docker compose -f deploy/hub/docker-compose.yml up -d hub`
5. 스테이징 Moodle에 플러그인 0.6.0-spike2 설치·업그레이드, 4의 설정 3개 입력
6. 확인
   - `curl -s https://hub-staging.ubion.global/.well-known/oauth-protected-resource/t/<site>/mcp` → `resource`·`authorization_servers`가 `https://hub-staging…`
   - `curl -s https://hub-staging.ubion.global/.well-known/oauth-authorization-server/t/<site>` → `issuer=https://hub-staging.ubion.global/t/<site>`
   - `curl -si -X POST https://hub-staging.ubion.global/t/<site>/mcp` → 401 + `resource_metadata=`
   - 기존 정적 Bearer 클라이언트(`client/moodle-mcp-remote.sh` 등)로 `tools/list` → 200 (회귀 확인)
   - claude.ai > 설정 > 커넥터 > 사용자 지정 커넥터 추가: `https://hub-staging.ubion.global/t/<site>/mcp` → Moodle 로그인(가짜 교사) → 동의 → `list_courses`, `create_assignment`(confirm=false 미리보기)
   - 관리자 계정으로 같은 흐름 → Moodle에서 "Site administrators cannot connect" 거부
   - 허브 로그: `oauth grant created site=<site> userid=<n>`; 실패 시 `exchange failed … reason=…` / `user token refused …`
7. 프록시: nginx 템플릿은 `location /` 전체를 넘기므로 변경 불필요. Cloudflare를 쓰면 `/.well-known/*`, `/t/*/oauth/*`도 `/t/*/mcp`처럼 캐시 Bypass, WAF/봇 차단에서 제외 (Claude 서버가 `/oauth/register`·`/oauth/token`·`/t/*/mcp`를 직접 호출, egress `160.79.104.0/21`)

## 7. 롤백

- 빠른 off (재배포 없이): `/opt/ubionai-hub/secrets/tenants/<site>/oauth.secret` 삭제(또는 이름 변경) → 그 사이트는 즉시 OAuth off(401 `Bearer`/403, 이전과 동일). 정적 Bearer는 계속 동작
- 전체 롤백: 기록해 둔 이전 `IMAGE_TAG`로 `up -d hub`(compose의 새 env·마운트는 이전 이미지가 무시함). 이전 코드는 스키마 5 DB를 그대로 열 수 있음(확인함: 추가 테이블은 무시, 기존 tenants·bearer 정상). 깨끗이 하려면 백업한 `hub.sqlite3`로 복원
- 교사 토큰 정리: 허브를 되돌려도 Moodle에 발급된 `ubionai-user` 토큰은 남음(최대 30일 후 만료). 즉시 지우려면 Moodle 사이트 관리 > 서버 > 웹 서비스 > 토큰 관리에서 서비스 `UBION AI (per-user)` 토큰 삭제, 또는 `local_ubionai/oauth_secret`을 비워 새 로그인 차단
- 플러그인 롤백: 스테이징 Moodle에서 0.6.0-spike(이전)로 코드만 되돌리면 Moodle이 버전 다운그레이드를 거부하므로, 시험 후에는 그대로 두거나 플러그인 제거(`uninstall_plugins.php --plugins=local_ubionai --run` — 서비스·토큰·역할·`local_ubionai_codes` 삭제)

## 8. 알려진 한계 (스파이크)

- 가명화 키·placeholder 맵은 아직 테넌트 단위(설계 §5.6의 사용자 단위 분리는 미적용)
- 쓰기 confirm은 기존 `confirm` 인자 방식 그대로(설계 §5.4 서버 강제 confirm_token 미적용)
- scope(`moodle:read`/`moodle:write`)는 기록만 하고 도구별 강제는 안 함
- Moodle 토큰 만료·삭제(`invalidtoken`)는 도구 결과 오류로만 보임 → refresh 시 grant의 `valid_until`로만 만료 처리
- 인가 요청·code가 메모리에 있으므로 허브 프로세스는 1개(현재 uvicorn 단일 워커)여야 함
- 감사 로그·레이트 리밋·사이트 자동 등록(§5.8)은 범위 밖
