<img width="816" height="600" alt="화면 캡처 2026-03-30 215335" src="https://github.com/user-attachments/assets/eee2b8bc-15a9-4045-91a1-9866f1c77309" />


요청하신 대로 강조용 별표(**)를 모두 제거한 깔끔한 버전입니다. 바로 복사해서 사용하시면 됩니다!

🚀 eBPF 기반 EDR Agent (Policy + Risk Engine) 프로토타입
1. 개요 (Overview)
본 프로젝트는 eBPF 기반 EDR(Endpoint Detection and Response) Agent의 정책 기반 탐지 및 위험도 분석 로직을 구현한 프로토타입입니다.
현재 단계의 구현은 실제 운영(Production) 수준이 아니며, 정책 수신 ➡️ 탐지 ➡️ 위험도 계산 ➡️ 대응으로 이어지는 전체 파이프라인의 아키텍처 흐름을 검증하기 위한 테스트 목적으로 구성되어 있습니다.

2. 전체 동작 구조 (Architecture Flow)
Plaintext
Collector ➡️ normalized.jsonl (Replay) ➡️ Runtime Agent
          ➡️ Policy 판단 (Deny/Focus) 
          ➡️ Risk 계산 (Base Score + 가중치) 
          ➡️ Scenario 분석 (복합 공격 탐지) 
          ➡️ 로그 출력 (+ 임시 차단)
3. 코드 구조 및 역할 (Directory Structure)
🛡️ 3.1 정책 파싱 및 적용 (internal/policy)
parser.go: 서버로부터 받은 YAML 형식의 정책 데이터를 Go 구조체로 변환합니다.

list.go: 파싱된 deny / focus 정책을 Rule 리스트로 변환하여 메모리에 적재합니다. 인입된 이벤트(프로세스명, 파일 경로 등)와 비교하여 차단 및 집중 모니터링 여부를 판단합니다.

🔄 3.2 정책 동기화 (internal/policy/checker.go)
서버의 정책 해시값과 로컬 정책 파일의 해시값을 비교합니다.

변경이 감지되면 새로운 정책 파일을 로컬에 저장하고 즉시 파싱하여 런타임 메모리에 반영(Update)합니다.

🧮 3.3 위험도 및 시나리오 분석 (internal/policy)
engine.go: 단일 이벤트에 대한 기본 위험도(Base Score)를 산출합니다.

risk.go: 산출된 Base Score를 바탕으로 파일/네트워크 민감도(target)와 Root 실행 여부(env) 등의 가중치를 곱하여 최종 위험도를 계산합니다.

scenario.go: 이벤트 흐름(버퍼)을 기억하여 복합적인 공격 흐름에 대한 보너스 점수를 부여합니다. (예: 민감 파일 접근 + 네트워크 통신 = 데이터 유출)

⚙️ 3.4 런타임 및 설정 (internal/app & config)
runtime_app.go: 핵심 메인 루프. 이벤트 수신(JSONL Replay) ➡️ 정책 평가 ➡️ 차단 판단 ➡️ 위험도/시나리오 분석 ➡️ 최종 로그 출력 및 전송을 담당합니다.

bootstrap_app.go: Agent 최초 실행 시 서버 등록 및 초기 설정(Enrollment)을 담당합니다.

4. 로그 출력 예시
에이전트 단에서 위험도를 산출하고 차단을 수행한 최종 결과 로그입니다.

Plaintext
PROCESS: bash
RESULT: DENIED= true FOCUSED= false
BLOCK: bash
🚨 FINAL SCORE: 33.00 | MEDIUM | patterns=[]
RISK DETAIL: base=30 rule=shell_execution risk=33 final=33 severity=MEDIUM
5. 현재 구현 상태 (팩트 체크)
🟢 정책 동기화: 서버-에이전트 간 정책 해시 비교 및 런타임 메모 실시간 반영 정상 동작

🟢 정책 평가: deny / focus 리스트 기반의 단일 이벤트 탐지 및 필터링 정상 동작

🟢 분석 엔진: 단일 이벤트 위험도 산출 및 버퍼 기반 시나리오 로직 정상 동작

🟢 파이프라인: 이벤트 수집부터 분석, 최종 JSON 데이터 병합 및 전송까지의 전체 흐름 연결 완료

6. 핵심 한계점 (Known Issues) ⚠️ 중요
본 프로토타입은 구조 검증용이므로 다음과 같은 뚜렷한 한계점들을 가지고 있습니다.

🔴 6.1 점수 로직 하드코딩
현황: Base Score 산출(engine.go)이 외부 동적 정책 기반이 아닌, 코드 내 정적 조건(예: /etc/shadow 접근 시 90점, bash 실행 시 30점 등)으로 하드코딩되어 있습니다.

문제: 환경별 유연한 대응이 불가능하며 룰셋 업데이트 시 코드 수정이 불가피합니다.

🚫 6.2 차단 로직의 근본적 한계 (pkill 사후 차단)
현황: 위협 탐지 시 pkill -f <process> 시스템 명령어를 통해 차단을 시도합니다.

문제: eBPF Hook 기반의 원천 차단이 아니기 때문에 프로세스 실행 이후에만 개입하는 사후 대응입니다. Race Condition이 발생할 수 있으며 우회가 가능해 실제 운영 수준의 보안 기능으로 보기 어렵습니다.

📥 6.3 eBPF 이벤트 미연동 (JSONL Replay)
현황: 실제 커널에서 실시간으로 발생하는 eBPF 이벤트 스트림을 사용하지 않고, 수집된 파일(testdata/normalized.jsonl)을 읽어들이는 Replay 환경에서 동작합니다.

🧩 6.4 미활용 로직 (MITRE & Focus)
현황: risk.go 내에 MITRE ATT&CK 기반 보너스 점수 구조가 있으나 실제 파이프라인에는 연결되지 않았습니다. 또한 focus 정책은 현재 로그 마킹만 수행할 뿐 2차 대응(심층 로깅 등) 로직이 부재합니다.

현황: scenario.go의 복합 탐지 로직이 일부 조건에만 반응하도록 매우 제한적으로 구현되어 있습니다.

7. 자체 평가 및 향후 보완 방향 (To-Do)
📊 자체 평가
현재 상태: "동작하는 구조 검증 단계"의 기능 검증용 프로토타입

객관적 평가: 정책 수신부터 분석까지의 아키텍처(뼈대)는 성공적으로 분리 및 구현되었으나, 실질적인 보안 통제(차단) 및 유연한 탐지 로직 측면에서는 상용 EDR 수준에 미치지 못함.

🚀 향후 보완 방향
[ ] 하드코딩된 위험도 점수 체계를 서버 정책 기반의 동적 시스템으로 전환

[ ] pkill 사후 차단을 eBPF 커널 레벨의 사전 차단(Deny) 로직으로 교체 연동

[ ] 파일 기반 Replay 입력을 실시간 eBPF 이벤트 스트림 채널로 교체

[ ] MITRE Tactic/Technique 매핑 적용 및 탐지 시나리오 다양화

[ ] Focus 자산에 대한 상세 모니터링(심층 로깅) 액션 추가
