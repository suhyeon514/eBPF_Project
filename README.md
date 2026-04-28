### K9 EDR Agent (agent-server)
Linux eBPF 기반 엔드포인트 탐지·대응(EDR) 에이전트
* 커널 수준의 eBPF 이벤트부터 네트워크 흐름, 시스템 자원까지 통합 수집·정규화하며, 중앙 분석 서버와 연동하여 실시간 정책 관리 및 메모리 덤프(IR) 대응을 수행하는 Go 기반 에이전트입니다.

---

### ✨ 핵심 기능 (Key Features)
1. 하이브리드 멀티 컬렉터: eBPF(Tetragon) 커널 이벤트를 중심으로 Auditd, Journald, Conntrack(네트워크 추적), Nginx 등 다양한 시스템 지표를 병렬 수집합니다.

2. 표준 이벤트 정규화 파이프라인: 이기종의 원시 로그(Raw Logs)를 통일된 model.Event 스키마(JSONL)로 정규화하여 분석 서버가 이해하기 쉬운 형태로 가공합니다.

3. 제로 트러스트 기반 에이전트 등록: 최초 실행 시 CSR(인증서 서명 요청)을 생성하고 중앙 서버의 승인을 거쳐 mTLS 인증서를 발급받는 안전한 등록(Enrollment) 프로세스를 제공합니다.

4. 실시간 침해사고 대응 (IR): WebSocket을 통해 중앙 서버와 상시 연결되며, 위협 탐지 시 관리자 명령에 따라 즉각적으로 AVML 기반 시스템 메모리 덤프를 수행하고 AWS S3로 안전하게 전송합니다.

| 기능 | 내용 |
| :--- | :--- |
| **다중 소스 이벤트 수집** | Tetragon(eBPF), Journald, Auditd, Conntrack, NFTables, Nginx, Resource 수집 |
| **표준 이벤트 정규화** | `model.Event` 스키마로 변환 후 JSONL 파일로 기록 |
| **에이전트 등록 (Enrollment)** | mTLS 기반 CSR 발급/서명 ➔ 서버 승인 대기 ➔ 인증서 수령 |
| **런타임 정책 동기화** | 30초 주기 SHA-256 해시 비교, 서버에서 신규 정책 수령 시 파일 교체 |
| **포렌식 AVML 메모리 덤프** | WebSocket을 통해 서버 명령 수신 ➔ `avml` 실행 ➔ S3 멀티파트 업로드 |
| **헬스 모니터링** | 내부 Registry를 통해 collector별 마지막 수신 시각, 이벤트/드롭 카운트 추적 |

---

### 🔄 에이전트 라이프사이클 (Lifecycle)
에이전트는 철저하게 2단계 프로세스로 동작하도록 설계되었습니다.

**1. Bootstrap 단계 (agent bootstrap)**
* 중앙 서버에 에이전트를 등록하고 승인을 대기합니다.
* 승인 완료 시 mTLS 인증서와 초기 런타임 정책(Runtime Policy)을 수령하여 로컬에 저장합니다.

**2. Runtime 단계 (agent runtime)**
* 승인된 정책을 바탕으로 다중 이벤트 컬렉터를 가동합니다.
* 30초 주기로 중앙 서버와 통신하여 정책 해시(SHA-256)를 비교하고, 변경 시 최신 탐지 정책으로 핫스왑(동기화)합니다.
* WebSocket을 열어 포렌식(메모리 덤프) 명령을 대기합니다.

---

### 📂 핵심 디렉터리 구조
모든 개별 .go 파일 대신, 에이전트의 데이터 흐름을 이해할 수 있는 도메인별 핵심 모듈 위주로 정리했습니다.
```
.
├── cmd/agent/main.go          # 엔트리포인트 (run/bootstrap/runtime 서브커맨드)
└── internal/
    ├── app/                   # 애플리케이션 레이어
    │   ├── agent_app.go       # 통합 실행 (bootstrap → runtime)
    │   ├── bootstrap_app.go   # 등록·의존성·초기 정책 수신
    │   ├── runtime_app.go     # 이벤트 수집·처리 메인 루프
    │   ├── runtime_deps.go    # 런타임 의존성 묶음
    │   └── topic_route.go     # 이벤트 → 라우팅 토픽
    ├── collector/             # 이벤트 수집기
    │   ├── collector.go       # Collector 인터페이스
    │   ├── tetragon/          # eBPF(Tetragon) JSONL 수집
    │   ├── auditd/            # Linux audit 로그
    │   ├── journald/          # systemd journal
    │   ├── conntrack/         # 네트워크 연결 추적
    │   ├── nftables/          # 방화벽 로그
    │   ├── nginx/             # Nginx 접근 로그
    │   ├── resource/          # 시스템 자원(gopsutil)
    │   └── health/            # 에이전트 헬스 상태
    ├── normalize/             # 원시 이벤트 → 표준 이벤트 변환
    │   ├── normalizer.go      # Normalizer 인터페이스 + Router
    │   ├── tetragon/          # process_exec/exit/kprobe 변환
    │   └── ...                # 기타 소스별 normalizer
    ├── model/                 # 공통 데이터 모델
    │   ├── event.go           # Event, EventType, HostMeta 등
    │   └── raw.go             # RawEnvelope, RawSource
    ├── config/                # 설정 로드/검증
    ├── service/policy/        # 정책 동기화 비즈니스 로직
    ├── transport/             # 서버 통신
    │   ├── api/               # REST API 클라이언트
    │   ├── websocket/         # WebSocket 포렌식 리스너
    │   └── dto/               # 요청/응답 데이터 구조체
    ├── bootstrap/             # 등록 HTTP 클라이언트 + TLS 팩토리
    ├── action/                # AVML 덤프 + S3 업로드
    ├── crypto/                # SHA-256 파일 해시
    ├── health/                # 헬스 Registry
    └── output/jsonl/          # JSONL 파일 쓰기
```

---

### 🚀 실행 방법 (Getting Started)

* 요구 사항 (Prerequisites)
    * OS / Kernel: Linux Ubuntu 20.04+ (Kernel 5.10 이상 권장, eBPF 지원 필수)

    * Language: Go 1.21+

    * 권한: eBPF 제어 및 메모리 덤프를 위해 root 권한 필수

    * 의존성 도구: Tetragon (커널 이벤트 수집), AVML (메모리 덤프), Fluent Bit (로그 전송)

### 📦 주요 패키지 및 의존성

| 패키지 | 용도 |
| :--- | :--- |
| `github.com/gorilla/websocket` | 포렌식 WebSocket 연결 |
| `github.com/shirou/gopsutil/v3` | CPU/메모리/디스크/네트워크/로드 수집 |
| `github.com/aws/aws-sdk-go-v2` | S3 멀티파트 업로드 |
| `gopkg.in/yaml.v3` | YAML 설정 파일 파싱 |
| **표준 라이브러리** | TLS, crypto/x509, crypto/ecdsa 등 |


### 🛠 빌드 (Build)

```bash
# 1. Go 모듈 초기화 및 의존성 다운로드
go mod init github.com/suhyeon514/eBPF_Project
go mod tidy

# 2. 기본 빌드
go build -o agent ./cmd/agent/...

# 3. 정적 빌드 (선택 사항, 타겟 서버 배포용)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o agent ./cmd/agent/...
```

### 실행 (Usage)
* 실행 목적에 따라 제공되는 서브커맨드(run, bootstrap, runtime)를 활용할 수 있습니다. (eBPF 제어를 위해 root 권한이 필요합니다.)

```
# 1) 전체 통합 실행 (Bootstrap 완료 후 자동으로 Runtime 전환)
sudo ./agent run -bootstrap-config configs/bootstrap.lab.yaml

# 2) Bootstrap만 실행 (중앙 서버 최초 등록 및 설치 시)
sudo ./agent bootstrap -bootstrap-config configs/bootstrap.lab.yaml

# 3) Runtime만 실행 (이미 Bootstrap이 완료되어 인증서가 있는 경우)
sudo ./agent runtime -bootstrap-config configs/bootstrap.lab.yaml

# 4) Runtime 실행 (별도의 런타임 정책 파일을 수동으로 지정할 때)
sudo ./agent runtime \
  -bootstrap-config configs/bootstrap.lab.yaml \
  -runtime-config /var/lib/ebpf-edr/policies/runtime.yaml
```

---

### ⚙️ 주요 설정 (Configuration)
에이전트는 두 가지 설정 파일을 기반으로 동작합니다. 각 파일의 상세 역할과 설정 값은 아래 화살표를 클릭하여 펼쳐볼 수 있습니다.

<details>
<summary><b>1. Bootstrap 설정 (configs/bootstrap.lab.yaml) 펼쳐보기</b></summary>

에이전트가 중앙 서버와 연결하기 위한 필수 정보(초기 인프라 및 인증 설정)가 담겨 있습니다.

* **`server.base_url`**: 중앙 분석 서버 주소
* **`identity`**: 자산 식별자(`host-001`) 및 역할(`web`, `db` 등)
* **`s3dumpinfo`**: 메모리 덤프 업로드를 위한 S3 버킷 정보 및 자격 증명 (※ 프로덕션 환경에서는 IAM Role 사용 권장)

```yaml
server:
  base_url: "http://your-server:8000"        # 분석 서버 URL (HTTPS 권장)
  ca_cert_path: "/etc/ebpf-edr/certs/ca.crt" # HTTPS 시 필수
  enroll_request_path: "/api/v1/enroll/request"
  enroll_status_path: "/api/v1/enroll/requests"
  heartbeat_path: "/api/v1/heartbeat"
  initial_runtime_policy_path: "/api/v1/runtime/policy/current"
  policy_check_update_path: "/api/v1/policy/check-update"
  artifact_manifest_path: "/api/v1/artifacts/manifest"
  artifact_download_path: "/api/v1/artifacts/download"

identity:
  host_id: "your-host"          # 운영자 자산 식별자
  hostname: "your-linux-host"
  requested_env: "production"
  requested_role: "web"

paths:
  state_path: "/var/lib/ebpf-edr/state.json"
  install_state_path: "/var/lib/ebpf-edr/install-state.json"
  private_key_path: "/etc/ebpf-edr/certs/client.key"
  csr_path: "/var/lib/ebpf-edr/client.csr"
  certificate_path: "/etc/ebpf-edr/certs/client.crt"
  runtime_policy_path: "/var/lib/ebpf-edr/policies/runtime.yaml"
  artifact_cache_dir: "/var/lib/ebpf-edr/artifacts"
  work_dir: "/var/lib/ebpf-edr/work"

enrollment:
  request_timeout: "10s"
  poll_interval: "10s"
  pending_retry_interval: "15s"
  max_pending_duration: "30m"

artifact:
  download_timeout: "2m"
  retry_interval: "15s"
  require_sha256: true

s3dumpinfo:
  s3_bucket_name: "your-forensic-bucket"
  s3_region: "....."
  s3_access_key_id: "dummy-key..."       # ⚠️ 프로덕션에서는 IAM Role 사용 권장
  s3_secret_access_key: "..."
```
</details>

* **보안 참고 (Security Notice)**
    * client.key (개인키) 및 state.json (상태 정보)과 같은 민감한 파일들은 에이전트 구동 시 자동으로 0600 권한으로 생성 및 관리되며, root 사용자 외의 접근을 원천 차단하여 탈취 위험을 방지합니다.


<br>

<details>
<summary><b>2. Runtime 정책 (/var/lib/ebpf-edr/policies/runtime.yaml) 펼쳐보기</b></summary>

중앙 서버로부터 수신받아 동적으로 갱신되는 런타임 설정입니다. 

* **`collectors`**: 각 수집기(Tetragon, Auditd, Nginx 등)의 활성화 여부(`enabled: true/false`) 및 로그 경로 지정
* **`rules`**: 탐지 제외(Allowlist) 및 집중 모니터링(Focus_list) 규칙

```yaml
policy:
  version: "1.0.0"
  hash: ""
  issued_at: ""

host:
  hostname: "your-linux-host"
  env: "production"
  role: "web"

collectors:
  tetragon:
    enabled: true
    log_path: "/var/log/tetragon/tetragon.log"
    poll_interval: "1s"
    read_from_head: false

  journald:
    enabled: true
    profiles: ["sshd", "sudo", "su", "systemd"]
    tail_lines: 100

  auditd:
    enabled: true
    log_path: "/var/log/audit/audit.log"
    poll_interval: "1s"

  conntrack:
    enabled: true
    args: ["-E", "-o", "timestamp,extended"]
    restart_on_exit: true
    restart_delay: "2s"

  nftables:
    enabled: false
    log_path: "/var/log/syslog"
    poll_interval: "1s"
    prefixes: ["NFT_DROP", "NFT_ACCEPT"]

  nginx:
    enabled: false
    log_path: "/var/log/nginx/access.log"

  resource:
    poll_interval: "10s"

rules:
  allowlist: []   # 억제할 이벤트 규칙
  focus_list: []  # 중점 모니터링 규칙

output:
  normalized_path: "/var/lib/ebpf-edr/events/normalized.jsonl"

forensic:
  dump_path: "/your/forensic/dumps/path"
```
</details>



---

### 🛠 확인 사항 (트러블슈팅)

1. **`enrollment_status: pending` 상태에서 멈출 경우**
  * **원인:** 중앙 관리자가 아직 에이전트의 CSR 등록 요청을 승인하지 않았습니다.
  * **해결:** 분석 서버 웹 대시보드에서 해당 에이전트의 가입 요청을 승인해야 합니다.

2. **`runtime cannot start: enrollment has not completed` 오류**
  * **해결:** Runtime 진입 전 mTLS 인증서가 필요합니다. `agent bootstrap` 서브커맨드를 먼저 실행하여 서버 등록을 완료하세요.

3. **메모리 덤프(AVML) 실패 오류 발생**
  * **원인:** `avml` 바이너리가 시스템 PATH에 없거나, 권한이 부족합니다.
  * **해결:** 호스트에 Microsoft AVML을 설치하고, 에이전트가 `root` 권한으로 실행 중인지 확인하세요. (※ RAM 용량만큼의 디스크 여유 공간 필요)


---



