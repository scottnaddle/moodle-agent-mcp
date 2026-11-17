# LiteLLM Presidio guardrail 참조 설정

## 원인
LiteLLM guardrail(`presidio`, `mode: pre_call`, `default_on: true`)에 `pii_entities_config`가 없으면
Presidio의 전체 엔티티(LOCATION, PERSON, DATE_TIME, NRP, URL …)가 마스킹된다.
장소명이 `<LOCATION>` 토큰으로 깨지면 LLM이 JSON 계획 문자열 안에 `<LOCATION>`을 그대로 넣어 계획이 깨진다
(`output_parse_pii`는 되돌리기 기능일 뿐, LLM 출력 자체를 고치지 못한다).
사람 이름은 hub 의 가명화기(pseudonymizer)가 가역적으로 처리하므로 Presidio 쪽에서 다시 마스킹하면 안 된다.

## 변경
- `pii_entities_config` allowlist: `EMAIL_ADDRESS`, `PHONE_NUMBER`, `CREDIT_CARD`, `KR_RRN`, `KR_STUDENT_ID`만 MASK.
- `LOCATION`, `PERSON`, `DATE_TIME`, `NRP`, `URL` 등 NER 엔티티는 제외.
- 한국어 PII 인식기(`ko_recognizers.json`): 주민등록번호, 휴대폰, 학번.

## 적용 (staging / prod 공통)
1. 기존 설정 백업: `cp /opt/litellm-<env>/config.yaml /opt/litellm-<env>/config.yaml.bak-<date>`
2. `deploy/litellm/config.yaml`와 `ko_recognizers.json`을 서버의 `/opt/litellm-<env>/`(및 컨테이너 `/app/`)로 복사.
3. **⚠️ `docker compose restart litellm`는 Scott 승인 후에만 실행.**
4. 배포 후 합성 데이터로 확인: 장소명이 포함된 JSON 계획이 `<LOCATION>` 없이 통과하는지, 학번/주민등록번호는 MASK되는지.

## 롤백
백업해 둔 `config.yaml.bak-<date>`를 원래 위치로 되돌린 뒤 `docker compose restart litellm`(동일하게 Scott 승인 필요)만 하면 된다.
