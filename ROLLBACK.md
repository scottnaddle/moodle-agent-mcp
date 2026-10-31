# 업그레이드 / 롤백 절차

이미지는 항상 **날짜 태그**로 빌드하고, `latest`는 그중 하나를 가리키게 둡니다. 롤백 = 이전 태그로 compose up.

```bash
cd /opt/moodle-mcp            # 리포 체크아웃 위치
# 0) 현재 돌고 있는 이미지 기록 (롤백 대상)
docker inspect -f '{{.Config.Image}} {{.Image}}' moodle-mcp | tee -a deploy/IMAGE_HISTORY.txt
docker tag moodle-mcp:latest moodle-mcp:prev-$(date +%Y%m%d-%H%M)   # 현재 latest 보존 (Config.Image가 :latest라 위 기록만으론 롤백 대상이 안 남음)
cp -p deploy/.env deploy/.env.bak-$(date +%Y%m%d-%H%M)                # 옛 이미지가 새 .env 형식을 못 읽을 수 있음

# 1) 업그레이드
git pull
NEW=$(date +%Y%m%d-%H%M); docker build -t moodle-mcp:$NEW -t moodle-mcp:latest .
cd deploy && IMAGE_TAG=$NEW docker compose up -d && cd ..
curl -fsS http://127.0.0.1:8791/health \
  && MCP_URL=https://mcp.example.com/mcp MCP_BEARER_TOKEN_FILE=~/.config/moodle-mcp/token .venv/bin/python scripts/smoke_test.py   # 확인 (venv: INSTALL.md 6단계)

# 2) 문제 시 롤백
docker images moodle-mcp                    # prev-* 태그 확인
cp -p deploy/.env.bak-YYYYMMDD-HHMM deploy/.env   # 업그레이드 때 .env를 바꿨다면 같이 되돌림
cd deploy && IMAGE_TAG=prev-YYYYMMDD-HHMM docker compose up -d
docker ps --format '{{.Image}} {{.Status}}'    # 'Restarting'이면 docker logs moodle-mcp (대개 .env 값 문제)
curl -fsS http://127.0.0.1:8791/health
# 다시 최신으로: cd deploy && docker compose up -d   (IMAGE_TAG 없으면 latest)
```
- INSTALL.md 3단계에서 만든 날짜 태그(`moodle-mcp:YYYYMMDD-HHMM`)도 남아 있으므로 `docker images moodle-mcp`에서 골라 롤백해도 됩니다.
- 참고: 2026-10-31 이전 이미지는 `.env`의 **빈 값**(`MOODLE_EDITINGTEACHER_ROLE_ID=`, `LOG_LEVEL=`, `MCP_PORT=`)에서 `ValueError`로 죽습니다. 그 이미지로 롤백할 땐 값을 채우거나 줄을 지우세요.

- Moodle 쪽(`local_grokbot`)을 올렸다면 플러그인 디렉터리 백업(`sudo cp -a /var/www/moodle/public/local/grokbot /root/grokbot.bak-$(date +%F)`, 5.0 이하는 `/var/www/moodle/local/grokbot`)을 먼저 두세요. Moodle은 플러그인 **버전 다운그레이드를 허용하지 않으므로**, 롤백은 DB 백업 복원이 원칙입니다. 서버(MCP)만 롤백하는 건 언제든 안전합니다.
- **도구를 추가/이름 변경한 뒤**에는 클라이언트에서 커넥터를 다시 추가해야 새 도구 목록이 보입니다(INSTALL.md 5단계 참고).
