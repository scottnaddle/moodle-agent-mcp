# INSTALL.md 검증 기록 (2026-10-31)

깨끗한 Ubuntu 24.04 서버(systemd 부팅, 사전 설치 없음)에서 리포만 가지고 INSTALL.md를 그대로 따라 한 결과.
테스트 도메인은 `/etc/hosts`의 `moodle.test.local` / `mcp.test.local`, TLS는 로컬 CA.

| 단계 | 결과 | 비고 |
|---|---|---|
| 사전: Moodle 5.3+ (Build 20261030) nginx + PHP 8.3-FPM + PostgreSQL | PASS (수정 후) | 5.3은 PostgreSQL 17 필요, Ubuntu 기본은 16 → PGDG |
| 1 local_grokbot 설치 | PASS | 0.3.0 (2026103104) |
| 2 setup_grokbot_ws.php | PASS (문서 수정) | 39개 함수, mod_attendance 5개 skip. 토큰 파일 소유자가 www-data로 남던 문제 수정 |
| 2 재실행 `--no-token --iprestriction` | PASS (스크립트 수정) | 이전엔 재실행 시 IP 제한이 반영되지 않았음 |
| 3 docker build / compose up | PASS (코드 수정) | `.env.example`의 빈 값 그대로면 `ValueError`로 재시작 반복 → 기본값 처리 |
| 3 컨테이너 → Moodle | PASS (override) | `/etc/hosts` 이름은 컨테이너에서 안 보임 → `extra_hosts`, 사설 CA → `SSL_CERT_FILE` |
| 4 nginx 템플릿 | PASS (템플릿 수정) | `http2 on;`은 nginx 1.24에서 오류, 인증서 없는 `listen ssl`은 `nginx -t` 실패 |
| 4 certbot | 미검증 | 공인 DNS 필요 (설계상). 로컬 CA 인증서로 대체 |
| 4 IP allowlist (nginx) | PASS | 허용 외 403 |
| 5 client/moodle-mcp-remote.sh | PASS (문서 수정) | Node 18에선 mcp-remote 실패 → Node 20.18+. 600 아닌 토큰 파일 거부 확인, `ps`에 토큰 없음 |
| 6 smoke_test.py / --write | PASS | 4/4, 12/12 |
| 선택 플러그인 없음 | PASS | attendance_sessions / create_openmaic는 오류+설치 안내 hint 반환, 나머지 정상 |
| ROLLBACK (태그→업그레이드→롤백→재업그레이드) | PASS (문서 수정) | 스모크 테스트 명령에 venv/env 누락, 플러그인 경로(5.1+ public/) 수정, `.env` 백업 추가 |
