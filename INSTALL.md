# 설치 가이드 (end-to-end)

순서: **0 요구사항 → 1 플러그인 → 2 Moodle 설정 스크립트 → 3 MCP 서버 → 4 nginx/TLS → 5 클라이언트 연결 → 6 스모크 테스트 → 7 보안 점검**

## 0. 요구사항
| 항목 | 내용 |
|---|---|
| Moodle | **5.3 LTS 이상** (5.1·5.2·4.5 미지원), 이미 설치되어 동작 중이어야 함 (`local_ubionai` requires 2026100500). 검증: 5.3 (Build 20261005, 운영) · 5.3+ (Build 20261030, 새 Ubuntu 24.04 서버에 nginx + PHP 8.3-FPM + PostgreSQL 17로 처음부터 설치) |
| 필수 플러그인 | `local_ubionai` — 별도 리포 [scottnaddle/moodle-local_ubionai](https://github.com/scottnaddle/moodle-local_ubionai) (비공개), `local/ubionai`에 설치 |
| 선택 플러그인 | `mod_attendance` (→ `attendance_sessions`), `mod_openmaic` (→ `create_openmaic`, 별도 배포·이 리포 미포함). 없어도 설치/동작에 문제 없음 |
| 코어 모듈 | assign, quiz, forum, page, resource, workshop, wiki, glossary, feedback, h5pactivity (기본 활성) |
| MCP 서버 호스트 | Docker 24+ & compose v2 ([Docker 공식 apt 저장소](https://docs.docker.com/engine/install/ubuntu/) 권장), 컨테이너 안에서 Moodle 호스트명이 해석되고 접속 가능해야 함(3단계 참고) |
| 외부 공개 | 도메인 1개 (예: `mcp.example.com`) + nginx(또는 다른 리버스 프록시) + TLS |
| 클라이언트 | **Node 20.18+** (`npx mcp-remote`; 최신 mcp-remote는 Node 18에서 `File is not defined`로 죽음. Ubuntu 24.04 apt의 nodejs는 18이라 nodejs.org/NodeSource 배포본 사용) |
| 도구 | `git`, `envsubst`(`gettext-base` 패키지), `python3-venv`(스모크 테스트), `openssl` |

> **Moodle 자체 설치는 이 가이드 범위 밖**입니다([Moodle 설치 문서](https://docs.moodle.org/en/Installing_Moodle)). 새 서버에서 해 보며 걸렸던 점:
> - Moodle **5.3은 PostgreSQL 17 이상**을 요구합니다. Ubuntu 24.04 기본 패키지는 16이므로 [PGDG 저장소](https://www.postgresql.org/download/linux/ubuntu/)(`postgresql-common`의 `apt.postgresql.org.sh`)로 17을 설치하세요. (5.1/5.2는 PostgreSQL 15+ / 16 가능)
> - 5.1+는 nginx `root`를 `/var/www/moodle/public`으로 두고, CLI(`admin/cli/*.php`)는 `/var/www/moodle/admin/cli`에 있습니다.
> - `php.ini`의 `max_input_vars = 5000`(fpm·cli 둘 다), 크론(`* * * * * www-data php /var/www/moodle/admin/cli/cron.php`).
> - CLI 설치(`admin/cli/install.php`)는 `config.php`를 쓰므로 그동안만 dirroot를 www-data가 쓸 수 있게 하고, 끝나면 되돌리세요.

아래 예시에서 Moodle dirroot는 `/var/www/moodle`, 웹루트는 5.1+ 구조라 `/var/www/moodle/public` 입니다.

## 1. local_ubionai 설치
```bash
sudo git clone https://github.com/scottnaddle/moodle-local_ubionai.git /var/www/moodle/public/local/ubionai   # 5.0 이하라면 /var/www/moodle/local/ubionai (비공개 리포: 접근 권한 필요, 또는 릴리스 zip 복사)
sudo chown -R www-data:www-data /var/www/moodle/public/local/ubionai
sudo -u www-data php /var/www/moodle/admin/cli/upgrade.php --non-interactive
```
확인: 사이트 관리 → 플러그인 → 플러그인 개요에 `local_ubionai 0.1.0 (2026103100)`.

## 2. Moodle 웹서비스 자동 설정 (재실행 가능)
리포 체크아웃(예: `/opt/moodle-mcp`)에서 실행합니다. 스크립트는 www-data로 돌기 때문에 리포 경로를 www-data가 읽을 수 있어야 합니다(`/root`나 `chmod 700` 홈 아래면 실패).
```bash
cd /opt/moodle-mcp
sudo -u www-data php moodle-setup/setup_ubionai_ws.php --moodle=/var/www/moodle --token-file=/tmp/ubionai.token \
     [--iprestriction=<MCP 서버 egress IP>] \
  && sudo install -m 600 -o root -g root /tmp/ubionai.token /root/ubionai.token && sudo rm -f /tmp/ubionai.token
```
- 마지막 줄은 www-data 소유로 만들어진 토큰 파일을 root 600으로 옮깁니다(`mv`는 소유자를 www-data로 남깁니다).
- 다시 실행할 때는 `--no-token`을 붙이세요(토큰이 계속 늘지 않음). `--iprestriction=`을 바꿔서 다시 실행하면 허가된 사용자와 **기존 토큰**의 IP 제한도 같이 갱신됩니다.
- `--iprestriction`에는 **Moodle이 보는** 접속 IP를 넣습니다. MCP 서버가 같은 호스트의 Docker에서 돌면 컨테이너 대역(예: `172.16.0.0/12`)이고, 다른 호스트면 그 호스트의 공인 egress IP입니다.
스크립트가 하는 일(수작업으로 해도 동일):
1. **웹 서비스 활성화** + **REST 프로토콜 활성화** (`enablewebservices=1`, `webserviceprotocols`에 `rest`).
2. **전용 사용자** `svc_ubionai` (manual 인증, 랜덤 비밀번호 — 로그인용 아님, 토큰 전용).
3. **역할** `ubionai_service`: manager 아키타입 권한 + `webservice/rest:use` 등, **시스템 컨텍스트에 부여**. editingteacher/teacher/student 배정 허용(강좌 생성 시 봇을 editingteacher로 등록하기 위해).
4. **외부 서비스** `ubionai` (`restrictedusers=1`, 파일 업/다운로드 허용) + 함수 44개(코어/모듈 30 · mod_attendance 5(선택) · local_ubionai 9). 사이트에 없는 함수는 `[skip]`으로 건너뜁니다.
5. 서비스에 `svc_ubionai` **허가된 사용자** 등록 (선택: IP 제한).
6. **영구 토큰 발급** → `--token-file` (mode 600). 화면에 출력하지 않습니다. `--no-token`이면 발급 생략(재실행 시 토큰이 계속 늘지 않게).

> 최소 권한을 더 원하면 `ubionai_service` 역할에서 안 쓰는 권한을 빼면 됩니다. 시스템 manager 수준이 필요한 건 주로 `create_course`(강좌 생성·카테고리 조회)와 배지/성적 카테고리입니다. 쓰기 도구를 아예 안 쓸 거면 서비스 함수에서 쓰기 함수를 빼고 역할도 읽기 권한만 남기세요.

## 3. MCP 서버 (Docker)
아래 `docker` 명령은 root 또는 `docker` 그룹 사용자로 실행합니다(`sudo usermod -aG docker $USER` 후 재로그인).
```bash
cd /opt/moodle-mcp
cp .env.example deploy/.env && chmod 600 deploy/.env
# deploy/.env 채우기:
#   MOODLE_WS_ENDPOINT=https://moodle.example.com/webservice/rest/server.php   ← 반드시 Moodle $CFG->wwwroot와 같은 호스트 (다르면 HTTP 303)
#   MOODLE_TOKEN=<2단계 토큰 파일 내용>
#   MCP_BEARER_TOKEN=<openssl rand -hex 32>
#   MCP_PORT=8791            (나머지 선택 값은 예시 기본값 그대로 두면 됨)
TAG=$(date +%Y%m%d-%H%M); docker build -t moodle-mcp:$TAG -t moodle-mcp:latest .
cd deploy && IMAGE_TAG=$TAG docker compose up -d
curl -fsS http://127.0.0.1:8791/health      # {"status": "ok"}
```
- compose는 `127.0.0.1`에만 바인딩합니다. 외부 공개는 4단계 리버스 프록시로만.
- MCP 서버와 Moodle이 같은 호스트면 `MOODLE_WS_ENDPOINT`를 공개 URL로 두면 됩니다(컨테이너 → 공개 URL). 단 컨테이너는 호스트의 `/etc/hosts`를 보지 않고, NAT 환경에선 자기 공인 IP로 되돌아오는 접속(hairpin)이 막히기도 합니다. 그럴 땐 `deploy/docker-compose.override.yml.example`을 `docker-compose.override.yml`로 복사해 `extra_hosts: ["<moodle 호스트>:host-gateway"]`를 쓰세요(Moodle nginx가 `0.0.0.0:443`에서 듣고 있어야 함).
- Moodle 인증서가 사설 CA라면 같은 override 파일로 CA를 마운트하고 `SSL_CERT_FILE`을 지정합니다. 공인 인증서(Let's Encrypt 등)면 필요 없습니다.
- 확인: 아래 6단계 스모크 테스트의 `site_info`가 PASS여야 Moodle 연결까지 된 것입니다(`/health`는 Moodle에 접속하지 않습니다). `request failed (ConnectError)`면 이름 해석/접속, `CERTIFICATE_VERIFY_FAILED`면 CA 문제입니다.
- 업그레이드/롤백: [ROLLBACK.md](ROLLBACK.md).

## 4. nginx + TLS
도메인의 DNS A 레코드가 이 서버를 가리켜야 합니다. **인증서를 먼저** 받고 vhost를 켭니다(`listen 443 ssl` 블록은 인증서 없이는 `nginx -t`를 통과하지 못하므로 `certbot --nginx`를 vhost 활성화 뒤에 돌리면 실패합니다).
```bash
export MCP_DOMAIN=mcp.example.com MCP_PORT=8791
# 1) 인증서 (기존 nginx의 80번 포트로 HTTP-01 인증; apt install certbot python3-certbot-nginx)
sudo certbot certonly --nginx -d $MCP_DOMAIN
export MCP_TLS_CERT=/etc/letsencrypt/live/$MCP_DOMAIN/fullchain.pem MCP_TLS_KEY=/etc/letsencrypt/live/$MCP_DOMAIN/privkey.pem
# 2) vhost
envsubst '${MCP_DOMAIN} ${MCP_PORT} ${MCP_TLS_CERT} ${MCP_TLS_KEY}' < deploy/nginx/mcp.conf.template | sudo tee /etc/nginx/sites-available/mcp.conf >/dev/null
sudo ln -sf ../sites-available/mcp.conf /etc/nginx/sites-enabled/mcp.conf
sudo nginx -t && sudo systemctl reload nginx
curl -fsS https://$MCP_DOMAIN/health
```
- 템플릿은 nginx 1.18+에서 동작합니다(`http2 on;`은 1.25.1+ 전용이라 Ubuntu 24.04의 1.24에서 `unknown directive "http2"`가 나므로 `listen 443 ssl http2`를 씁니다).
- 내부망/테스트처럼 공인 DNS가 없으면 certbot 대신 사내 CA나 자체 서명 인증서 경로를 `MCP_TLS_CERT`/`MCP_TLS_KEY`에 넣으면 됩니다. 이때 클라이언트가 그 CA를 믿게 해야 합니다(5·6단계 참고).
- IP 허용 목록: vhost의 `allow`/`deny` 주석을 풀면 나머지는 403입니다(`/health`도 포함).
Cloudflare를 쓰면 [deploy/TLS_CLOUDFLARE.md](deploy/TLS_CLOUDFLARE.md) 참고(Full strict, `/mcp` 캐시 Bypass).

## 5. 클라이언트 연결 (Grok Bot / 아무 MCP 클라이언트)
```bash
mkdir -p ~/.config/moodle-mcp && (umask 077; printf '%s' '<MCP_BEARER_TOKEN>' > ~/.config/moodle-mcp/token)
MCP_URL=https://mcp.example.com/mcp MCP_TOKEN_FILE=~/.config/moodle-mcp/token client/moodle-mcp-remote.sh
```
- 서버 인증서가 사설 CA라면 `NODE_EXTRA_CA_CERTS=/path/to/ca.crt`도 넘기세요(Node는 OS 신뢰 저장소를 쓰지 않음). `MCP_REMOTE_VERSION=x.y.z`로 mcp-remote 버전을 고정할 수 있습니다.
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
- `MCP_URL`을 빼면 `http://127.0.0.1:8791/mcp`(서버 로컬)로 붙습니다. 사설 CA 인증서면 `SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt`(CA를 OS 저장소에 넣은 뒤)처럼 지정하세요.

기대 결과: `list_tools: 40 tools`, site_info/list_categories/list_courses PASS, `--write` 시 `MCP-SMOKE-<ts>` 강좌 + 섹션·페이지·과제 생성 PASS. 끝나면 테스트 강좌는 Moodle에서 삭제하세요.
에이전트에게는 "site_info 보여줘", "강좌 목록 보여줘", "테스트 강좌 하나 만들어 줘(미리보기 먼저)" 정도로 확인하면 됩니다.

## 7. 보안 체크리스트
- [ ] **최소 권한**: 전용 사용자·전용 역할·`restrictedusers=1` 서비스. admin 토큰, `moodle_mobile_app` 서비스 토큰 사용 금지. 쓰기 도구가 필요 없으면 쓰기 함수 제거.
- [ ] **IP 제한**: 토큰/서비스 사용자에 `--iprestriction`(MCP 서버 egress IP), nginx에 `allow/deny`(클라이언트·Cloudflare 대역).
- [ ] **비밀값**: `deploy/.env`, 토큰 파일은 600, 커밋 금지. `MCP_BEARER_TOKEN`은 32바이트 이상 랜덤. 유출 의심 시 Moodle 토큰 삭제 후 스크립트 재실행, Bearer 교체 후 `docker compose up -d`.
- [ ] **실데이터 전 검증**: 테스트 강좌/스테이징에서 먼저 돌려 보고, 쓰기는 항상 미리보기 → 사람 승인 → 실행.
- [ ] **로그**: nginx access log와 Moodle 로그(사이트 관리 → 보고서 → 로그, 사용자 `svc_ubionai`)로 호출 확인.
- [ ] 리포에 포함된 문서의 호스트명은 모두 예시(`example.com`)입니다.

## 부록: local_grokbot → local_ubionai 전환

기존에 `local_grokbot`을 설치했다면: (1) `local_ubionai`를 `local/ubionai`에 설치하고 `admin/cli/upgrade.php` 실행, (2) `admin/cli/uninstall_plugins.php --plugins=local_grokbot --run` 으로 제거하고 `local/grokbot` 디렉터리 삭제, (3) `moodle-setup/setup_ubionai_ws.php` 재실행. 새 기본값은 서비스 `ubionai`, 사용자 `svc_ubionai`, 역할 `ubionai_service` 이며 새 토큰이 발급됩니다(MCP 서버 토큰 교체 필요). 이전 `grokbot` 서비스/`svc_grokbot` 사용자/역할은 자동 삭제되지 않으니 필요 시 수동 정리하세요. DB 테이블이 없어 데이터 이전은 없습니다.
