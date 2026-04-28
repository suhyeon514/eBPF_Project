### K9 EDR Agent (agent-server)
Linux eBPF 기반 엔드포인트 탐지·대응(EDR) 에이전트
커널 수준의 eBPF 이벤트부터 네트워크 흐름, 시스템 자원까지 통합 수집·정규화하며, 중앙 분석 서버와 연동하여 실시간 정책 관리 및 메모리 덤프(IR) 대응을 수행하는 Go 기반 에이전트입니다.

---

### ✨ 핵심 기능 (Key Features)
1. 하이브리드 멀티 컬렉터: eBPF(Tetragon) 커널 이벤트를 중심으로 Auditd, Journald, Conntrack(네트워크 추적), Nginx 등 다양한 시스템 지표를 병렬 수집합니다.

2. 표준 이벤트 정규화 파이프라인: 이기종의 원시 로그(Raw Logs)를 통일된 model.Event 스키마(JSONL)로 정규화하여 분석 서버가 이해하기 쉬운 형태로 가공합니다.

3. 제로 트러스트 기반 에이전트 등록: 최초 실행 시 CSR(인증서 서명 요청)을 생성하고 중앙 서버의 승인을 거쳐 mTLS 인증서를 발급받는 안전한 등록(Enrollment) 프로세스를 제공합니다.

4. 실시간 침해사고 대응 (IR): WebSocket을 통해 중앙 서버와 상시 연결되며, 위협 탐지 시 관리자 명령에 따라 즉각적으로 AVML 기반 시스템 메모리 덤프를 수행하고 AWS S3로 안전하게 전송합니다.

---

### 🔄 에이전트 라이프사이클 (Lifecycle)
에이전트는 철저하게 2단계 프로세스로 동작하도록 설계되었습니다.

**1. Bootstrap 단계 (agent bootstrap)**
중앙 서버에 에이전트를 등록하고 승인을 대기합니다.
승인 완료 시 mTLS 인증서와 초기 런타임 정책(Runtime Policy)을 수령하여 로컬에 저장합니다.

**2. Runtime 단계 (agent runtime)**
승인된 정책을 바탕으로 다중 이벤트 컬렉터를 가동합니다.
30초 주기로 중앙 서버와 통신하여 정책 해시(SHA-256)를 비교하고, 변경 시 최신 탐지 정책으로 핫스왑(동기화)합니다.
WebSocket을 열어 포렌식(메모리 덤프) 명령을 대기합니다.

---

### 📂 핵심 디렉터리 구조
모든 개별 .go 파일 대신, 에이전트의 데이터 흐름을 이해할 수 있는 도메인별 핵심 모듈 위주로 정리했습니다.
```
cmd/agent/                 # 에이전트 CLI 엔트리포인트 (main.go)
internal/
 ├── app/                  # Agent 통합/부트스트랩/런타임 생명주기 제어 루틴
 ├── bootstrap/            # mTLS 인증서 발급 및 서버 등록(Enrollment) 클라이언트
 │
 ├── collector/            # [Input] 소스별 원시 데이터 수집기 (tetragon, auditd, conntrack 등)
 ├── normalize/            # [Process] 이기종 원시 로그를 EDR 표준 Event 모델로 파싱 및 정규화
 ├── output/               # [Output] 정규화된 이벤트를 로컬 JSONL 파일로 기록
 │
 ├── action/               # 침해사고 대응 로직 (AVML 실행 및 AWS S3 멀티파트 업로드)
 ├── service/policy/       # 30초 주기 중앙 서버 탐지 정책(Rule) 해시 비교 및 동기화
 ├── transport/            # 외부 통신 레이어 (REST API 클라이언트 및 WebSocket 리스너)
 └── model/                # 전체 시스템에서 공유하는 공통 도메인 Event 스키마
```

---

### 🚀 실행 방법 (Getting Started)
1. 요구 사항 (Prerequisites)
OS / Kernel: Linux Ubuntu 20.04+ (Kernel 5.10 이상 권장, eBPF 지원 필수)

Language: Go 1.21+

권한: eBPF 제어 및 메모리 덤프를 위해 root 권한 필수

의존성 도구: Tetragon (커널 이벤트 수집), AVML (메모리 덤프), Fluent Bit (로그 전송)


```
# 1. 저장소 클론 및 패키지 초기화
git clone -b agent-server https://github.com/suhyeon514/eBPF_Project.git
cd eBPF_Project
go mod init github.com/suhyeon514/eBPF_Project && go mod tidy

# 2. 에이전트 빌드
go build -o agent ./cmd/agent/...

# 3. 에이전트 실행 (통합 모드: Bootstrap 후 자동으로 Runtime 전환)
sudo ./agent run -bootstrap-config configs/bootstrap.lab.yaml
```
* 개발 목적의 단일 단계 실행이 필요한 경우 sudo ./agent bootstrap ... 또는 sudo ./agent runtime ... 명령어를 개별적으로 사용할 수 있습니다.

---

### ⚙️ 주요 설정 (Configuration)
에이전트는 두 가지 설정 파일을 기반으로 동작합니다.

* **bootstrap.yaml (초기 인프라 설정)**
에이전트가 중앙 서버와 연결하기 위한 필수 정보가 담겨 있습니다.

```
server.base_url: 중앙 분석 서버 주소
identity: 자산 식별자(host-001) 및 역할(web, db 등)
s3dumpinfo: 메모리 덤프 업로드를 위한 S3 버킷 정보 및 자격 증명 (※ 프로덕션 환경에서는 IAM Role 사용 권장)
```

* **runtime.yaml (동적 탐지 정책)**
중앙 서버로부터 수신받아 동적으로 갱신되는 런타임 설정입니다.

```
collectors: 각 수집기(Tetragon, Auditd, Nginx 등)의 활성화 여부(enabled: true/false) 및 로그 경로 지정
rules: 탐지 제외(Allowlist) 및 집중 모니터링(Focus_list) 규칙
```


---

### 🛠 확인 사항 (트러블슈팅)

1. enrollment_status: pending 상태에서 멈출 경우
  * 원인: 중앙 관리자가 아직 에이전트의 CSR 등록 요청을 승인하지 않았습니다.
  * 해결: 분석 서버 웹 대시보드에서 해당 에이전트의 가입 요청을 승인해야 합니다.

2. runtime cannot start: enrollment has not completed
  * 해결: Runtime 진입 전 mTLS 인증서가 필요합니다. agent bootstrap 서브커맨드를 먼저 실행하여 서버 등록을 완료하세요.

3. 메모리 덤프(AVML) 실패 오류 발생
  * 원인: avml 바이너리가 시스템 PATH에 없거나, 권한이 부족합니다.
  * 해결: 호스트에 Microsoft AVML을 설치하고, 에이전트가 root 권한으로 실행 중인지 확인하세요. RAM 용량만큼의 디스크 여유 공간도 필요합니다.

