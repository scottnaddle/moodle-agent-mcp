# 무들(Moodle) AI 에이전트 개발 현황 — 코스모스팀 공유용 브리프 (2026-10-31 기준)
출처: 각 담당 봇의 보고(무들봇, 개발자, 엔지니어, 연구팀, AI교수법 강의 조교, OpenMAIC Moodle 개발). 비밀번호·토큰 값은 절대 넣지 말 것.

## 한 줄 요약
Grok Bot 같은 AI 에이전트가 교수자 권한으로 Moodle(moodle.example.com, Moodle 5.3)을 조회·채점·강좌 생성까지 할 수 있도록, Moodle REST 웹서비스를 감싼 MCP 서버(툴 16개)를 하루 만에 설계→인프라→구현→라이브 테스트까지 완료.

## 무엇을 만들었나 (MCP 툴 16개)
- 조회 13: site_info, list_courses, list_categories, get_course_outline, list_students, list_assignments, get_submissions, get_assignment_grades, gradebook_overview, list_quizzes, list_quiz_attempts, review_attempt, attendance_sessions
- 쓰기 3: grade_submission, bulk_grade, create_course
- 안전장치: create_course는 confirm=false 미리보기 → confirm=true 실행. 쓰기는 교수자(Scott)에게 대상·점수·피드백을 보여주고 확인받은 뒤에만 실행(채점 툴은 현재 설명 문구로 규정, confirm 플래그 추가는 결정 대기).

## 구조
Grok Bot(무들봇) → moodle-lms 커넥터(박스 stdio 래퍼, mcp-remote) → https://mcp.example.com/mcp (Cloudflare 프록시, Let's Encrypt TLS) → lms 서버 nginx vhost → 127.0.0.1:8791 Docker `moodle-mcp` → Moodle REST 웹서비스(전용 계정 grokbot, 외부 서비스 grokbot, 함수 30여 개)
- 스택: Python 3.12, MCP SDK FastMCP(Streamable HTTP), uvicorn, httpx
- 인증: Bearer 토큰(토큰 없으면 401). 비밀값은 서버 .env(root 600)에만.
- 설계 원칙(연구팀): "Grok Bot이 생성하고, MCP는 읽고 쓰기만". 우선순위 P0 조회 → P1 알림·다이제스트 → P2 쓰기.
- 공개 Moodle MCP 서버 5개(loyaniu, peancor, 1alexandrer, Snaw80, tcpassos) 비교 → 대부분 학생용/로컬 실행이라 교수자용은 새로 구현.

## 역할 분담 (멀티 에이전트 협업)
- 연구팀: 연동 방식 조사, 설계 문서(/workspace/moodle-grokbot-integration-2026-10-31.md), 배치·시나리오·툴 매핑
- 엔지니어: Moodle grokbot 계정·웹서비스·토큰, Docker 슬롯, nginx, TLS, DNS(mcp.example.com)
- 개발자: MCP 서버 구현, 단위 테스트 44개 통과, 라이브 배포, create_course·list_categories 추가, 커넥터 연결
- 무들봇: 교수자 도우미로 실사용 테스트, 기능 요청(create_course), 강좌 생성 검증(id 8)
- Scott 결정: 08:03 MCP 서버는 lms 서버에 / 연구용이라 보안 가볍게, 08:06 인프라 승인

## 데모 시나리오 (무들봇 채팅)
1. "내 강좌 목록 보여줘" → list_courses
2. "강좌 3 과제 제출 현황" → get_submissions (test01 채점됨, test02 미채점)
3. "test02 90점, 피드백 '좋아요'" → 미리보기 → 확인 → grade_submission → gradebook_overview로 반영 확인
4. "퀴즈 2 응시 리뷰" → list_quiz_attempts / review_attempt (문항별 응답·점수)
5. "테스트 강좌 하나 만들어줘" → create_course 미리보기 → 확인 → 생성 (실제로 id 7, id 8 생성 성공)

## 남은 이슈 / 다음 단계
- 활동·콘텐츠 생성 툴 없음 → local_grokbot Moodle 플러그인(섹션 수정, 활동 생성, 문항 import, 이벤트 웹훅→Grok Bot 루틴 알림, 리포트)
- 앱 커넥터 툴 목록 캐시: 툴 추가 시 커넥터 재등록 필요
- 실학생 데이터 전 보안 재검토(토큰 1개=교수자/Manager 권한, IP 제한 없음, 최소 권한화, 개인정보·가명처리)
- moodle-mcp 리포 GitHub push는 Scott 승인 대기(현재 로컬 커밋)
- 진행 중: 'AI 에이전트 시대의 교육' 강좌 — AI교수법 강의 조교가 설계(v0.1 작성 중), Scott 승인 후 무들봇이 강좌 8에 구성
- 확장 가능성: 같은 구조로 Canvas(대구교대) 등 다른 LMS, 코스모스 LMS에도 적용 검토 가능 [제안]

## 관련 작업(별도): mod_openmaic
OpenMAIC 기반 Moodle 활동 플러그인. 교수자 프롬프트 → 멀티에이전트 인터랙티브 강의(슬라이드·퀴즈) 생성 → 검토 후 공개, 학생 진도·퀴즈 점수가 성적부·이수·출석에 반영. https://moodle.example.com/openmaic . 남은 일: 아웃라인 검토 단계, Privacy API, 자동 테스트. 향후 MCP에 강의 생성 웹서비스로 연결 검토.
