# 설치 가이드 (end-to-end)

순서: **0 요구사항 → 1 플러그인 → 2 Moodle 설정 스크립트 → 3 MCP 서버 → 4 nginx/TLS → 5 클라이언트 연결 → 6 스모크 테스트 → 7 보안 점검**

## 0. 요구사항
| 항목 | 내용 |
|---|---|
| Moodle | **5.1 이상** (`local_grokbot` requires 2025100600). 검증: 5.3 (Build 20261005, 운영) · 5.3+ (Build 20261030, 깨끗한 Docker 테스트 사이트, PHP 8.3, PostgreSQL 17) |
| 필수 플러그인 | `local_grokbot` (이 리포 `plugins/local_grokbot`) |
| 선택 플러그인 | `mod_attendance` (→ `attendance_sessions`), `mod_openmaic` (→ `create_openmaic`, 별도 배포·이 리포 미포함). 없어도 설치/동작에 문제 없음 |
| 코어 모듈 | assign, quiz, forum, page, resource, workshop, wiki, glossary, feedback, h5pactivity (기본 활성) |
| MCP 서버 호스트 | Docker 24+ & compose v2, 아웃바운드로 Moodle URL 접근 가능 |
| 외부 공개 | 도메인 1개 (예: `mcp.example.com`) + nginx(또는 다른 리버스 프록시) + TLS |
| 클라이언트 | Node 18+ (`npx mcp-remote`) |

아래 예시에서 Moodle dirroot는 `/var/www/moodle`, 웹루트는 5.1+ 구조라 `/var/www/moodle/public` 입니다.

## 1. local_grokbot 설치
```bash
sudo cp -a plugins/local_grokbot /var/www/moodle/public/local/grokbot   # 5.0 이하라면 /var/www/moodle/local/grokbot
sudo chown -R www-data:www-data /var/www/moodle/public/local/grokbot
sudo -u www-data php /var/www/moodle/admin/cli/upgrade.php --non-interactive
```
확인: 사이트 관리 → 플러그인 → 플러그인 개요에 `local_grokbot 0.3.0`.

## 2. Moodle 웹서비스 자동 설정 (재실행 가능)
```bash
sudo install -m 600 -o root /dev/null /root/grokbot.token
sudo -u www-data php moodle-setup/setup_grokbot_ws.php --moodle=/var/www/moodle --token-file=/tmp/grokbot.token \
     [--iprestriction=<MCP 서버 egress IP>] && sudo mv /tmp/grokbot.token /root/grokbot.token
```
스크립트가 하는 일(수작업으로 해도 동일):
1. **웹 서비스 활성화** + **REST 프로토콜 활성화** (`enablewebservices=1`, `webserviceprotocols`에 `rest`).
2. **전용 사용자** `svc_grokbot` (manual 인증, 랜덤 비밀번호 — 로그인용 아님, 토큰 전용).
3. **역할** `grokbot_service`: manager 아키타입 권한 + `webservice/rest:use` 등, **시스템 컨텍스트에 부여**. editingteacher/teacher/student 배정 허용(강좌 생성 시 봇을 editingteacher로 등록하기 위해).
4. **외부 서비스** `grokbot` (`restrictedusers=1`, 파일 업/다운로드 허용) + 함수 44개(코어/모듈 30 · mod_attendance 5(선택) · local_grokbot 9). 사이트에 없는 함수는 `[skip]`으로 건너뜁니다.
5. 서비스에 `svc_grokbot` **허가된 사용자** 등록 (선택: IP 제한).
6. **영구 토큰 발급** → `--token-file` (mode 600). 화면에 출력하지 않습니다. `--no-token`이면 발급 생략(재실행 시 토큰이 계속 늘지 않게).

> 최소 권한을 더 원하면 `grokbot_service` 역할에서 안 쓰는 권한을 빼면 됩니다. 시스템 manager 수준이 필요한 건 주로 `create_course`(강좌 생성·카테고리 조회)와 배지/성적 카테고리입니다. 쓰기 도구를 아예 안 쓸 거면 서비스 함수에서 쓰기 함수를 빼고 역할도 읽기 권한만 남기세요.

## 3. MCP 서버 (Docker)
```bash
cp .env.example deploy/.env && chmod 600 deploy/.env
# deploy/.env 채우기:
#   MOODLE_WS_ENDPOINT=https://moodle.example.com/webservice/rest/server.php   ← 반드시 Moodle $CFG->wwwroot와 같은 호스트 (다르면 HTTP 303)
#   MOODLE_TOKEN=<2단계 토큰 파일 내용>
#   MCP_BEARER_TOKEN=<openssl rand -hex 32>
#   MCP_PORT=8791
TAG=$(date +%Y%m%d-%H%M); docker build -t moodle-mcp:$TAG -t moodle-mcp:latest .
cd deploy && IMAGE_TAG=$TAG docker compose up -d
curl -fsS http://127.0.0.1:8791/health      # {"status": "ok"}
```
- compose는 `127.0.0.1`에만 바인딩합니다. 외부 공개는 4단계 리버스 프록시로만.
- MCP 서버와 Moodle이 같은 호스트면 `MOODLE_WS_ENDPOINT`를 공개 URL로 두면 됩니다(컨테이너 → 공개 URL).
- 업그레이드/롤백: [ROLLBACK.md](ROLLBACK.md).

## 4. nginx + TLS
```bash
export MCP_DOMAIN=mcp.example.com MCP_PORT=8791
envsubst '${MCP_DOMAIN} ${MCP_PORT}' < deploy/nginx/mcp.conf.template | sudo tee /etc/nginx/sites-available/mcp.conf >/dev/null
sudo ln -s ../sites-available/mcp.conf /etc/nginx/sites-enabled/mcp.conf
sudo certbot --nginx -d $MCP_DOMAIN && sudo nginx -t && sudo systemctl reload nginx
curl -fsS https://$MCP_DOMAIN/health
```
Cloudflare를 쓰면 [deploy/TLS_CLOUDFLARE.md](deploy/TLS_CLOUDFLARE.md) 참고(Full strict, `/mcp` 캐시 Bypass).

## 5. 클라이언트 연결 (Grok Bot / 아무 MCP 클라이언트)
```bash
mkdir -p ~/.config/moodle-mcp && (umask 077; printf '%s' '<MCP_BEARER_TOKEN>' > ~/.config/moodle-mcp/token)
MCP_URL=https://mcp.example.com/mcp MCP_TOKEN_FILE=~/.config/moodle-mcp/token client/moodle-mcp-remote.sh
```
- 래퍼는 토큰을 **600 파일에서 읽어 환경변수로** mcp-remote 헤더에 넘깁니다(argv/`ps`에 노출 안 됨). 권한이 600/400이 아니면 실행을 거부합니다.
- MCP 클라이언트 설정 예 (stdio):
  ```json
  { "mcpServers": { "moodle": { "command": "/path/to/client/moodle-mcp-remote.sh",
      "env": { "MCP_URL": "https://mcp.example.com/mcp", "MCP_TOKEN_FILE": "/home/me/.config/moodle-mcp/token" } } } }
  ```
- ⚠️ **도구 목록 캐시**: Grok Bot 앱은 커넥터의 도구 목록을 **커넥터 이름 기준으로 캐시**합니다. 서버에 도구를 추가/변경한 뒤 재시작만으로는 반영되지 않으니 **커넥터를 삭제 후 다시 추가**하세요. 그래도 옛 목록이 보이면 **새 이름**(예: `moodle2`)으로 추가하세요.

## 6. 스모크 테스트
```bash
python3 -m venv .venv && .venv/bin/pip install "mcp>=1.26,<2"
MCP_URL=https://mcp.example.com/mcp MCP_BEARER_TOKEN_FILE=~/.config/moodle-mcp/token .venv/bin/python scripts/smoke_test.py          # 읽기만
MCP_URL=https://mcp.example.com/mcp MCP_BEARER_TOKEN_FILE=~/.config/moodle-mcp/token .venv/bin/python scripts/smoke_test.py --write  # 테스트 강좌 생성
```
기대 결과: `list_tools: 39 tools`, site_info/list_categories/list_courses PASS, `--write` 시 `MCP-SMOKE-<ts>` 강좌 + 섹션·페이지·과제 생성 PASS. 끝나면 테스트 강좌는 Moodle에서 삭제하세요.
에이전트에게는 "site_info 보여줘", "강좌 목록 보여줘", "테스트 강좌 하나 만들어 줘(미리보기 먼저)" 정도로 확인하면 됩니다.

## 7. 보안 체크리스트
- [ ] **최소 권한**: 전용 사용자·전용 역할·`restrictedusers=1` 서비스. admin 토큰, `moodle_mobile_app` 서비스 토큰 사용 금지. 쓰기 도구가 필요 없으면 쓰기 함수 제거.
- [ ] **IP 제한**: 토큰/서비스 사용자에 `--iprestriction`(MCP 서버 egress IP), nginx에 `allow/deny`(클라이언트·Cloudflare 대역).
- [ ] **비밀값**: `deploy/.env`, 토큰 파일은 600, 커밋 금지. `MCP_BEARER_TOKEN`은 32바이트 이상 랜덤. 유출 의심 시 Moodle 토큰 삭제 후 스크립트 재실행, Bearer 교체 후 `docker compose up -d`.
- [ ] **실데이터 전 검증**: 테스트 강좌/스테이징에서 먼저 돌려 보고, 쓰기는 항상 미리보기 → 사람 승인 → 실행.
- [ ] **로그**: nginx access log와 Moodle 로그(사이트 관리 → 보고서 → 로그, 사용자 `svc_grokbot`)로 호출 확인.
- [ ] 리포에 포함된 문서의 호스트명은 모두 예시(`example.com`)입니다.
