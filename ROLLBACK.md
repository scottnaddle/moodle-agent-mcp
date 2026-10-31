# 업그레이드 / 롤백 절차

이미지는 항상 **날짜 태그**로 빌드하고, `latest`는 그중 하나를 가리키게 둡니다. 롤백 = 이전 태그로 compose up.

```bash
cd /opt/moodle-mcp            # 리포 체크아웃 위치
# 0) 현재 돌고 있는 이미지 기록 (롤백 대상)
docker inspect -f '{{.Config.Image}} {{.Image}}' moodle-mcp | tee -a deploy/IMAGE_HISTORY.txt
docker tag moodle-mcp:latest moodle-mcp:prev-$(date +%Y%m%d-%H%M)   # 현재 latest 보존

# 1) 업그레이드
git pull
NEW=$(date +%Y%m%d-%H%M); docker build -t moodle-mcp:$NEW -t moodle-mcp:latest .
cd deploy && IMAGE_TAG=$NEW docker compose up -d && cd ..
curl -fsS http://127.0.0.1:8791/health && python3 scripts/smoke_test.py   # 확인

# 2) 문제 시 롤백
docker images moodle-mcp                    # prev-* 태그 확인
cd deploy && IMAGE_TAG=prev-YYYYMMDD-HHMM docker compose up -d
curl -fsS http://127.0.0.1:8791/health
```

- Moodle 쪽(`local_grokbot`)을 올렸다면 플러그인 디렉터리 백업(`cp -a local/grokbot /root/grokbot.bak-$(date +%F)`)을 먼저 두세요. Moodle은 플러그인 **버전 다운그레이드를 허용하지 않으므로**, 롤백은 DB 백업 복원이 원칙입니다. 서버(MCP)만 롤백하는 건 언제든 안전합니다.
- **도구를 추가/이름 변경한 뒤**에는 클라이언트에서 커넥터를 다시 추가해야 새 도구 목록이 보입니다(INSTALL.md 5단계 참고).
