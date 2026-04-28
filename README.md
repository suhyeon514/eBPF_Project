# eBPF_Project
eBPF 기반 실시간 탐지 및 대응 솔루션
## 🛡️ K9 - eBPF 기반 실시간 탐지 및 침해사고 대응(IR) 자동화 EDR 솔루션


**K9(Kernel 9)**은 커널 제어 기술인 eBPF를 활용하여 호스트 시스템을 안전하게 모니터링하고, 탐지부터 메모리 덤프, LLM 기반 법정 규격 보고서 자동 생성까지 **침해사고 대응(IR)의 End-to-End 과정을 자동화**한 사용자 친화적 지능형 엔드포인트 보안 플랫폼입니다.

---

## 🎯 Project Overview

**기획 배경:** 대형 통신사를 타겟으로 한 은닉형 악성코드 사태 등 고도화된 보안 위협이 증가함에 따라, 시스템 수정 없이 커널 샌드박스에서 안전하게 길목을 제어할 수 있는 `eBPF` 기술의 필요성 대두
**기대 효과:** 
  1. 위협 발생 시 커널 레벨에서 즉각 탐지하여 Slack으로 실시간 알림 전송
  2. 사용자 요청 시 침해 시스템의 메모리 덤프(AVML)를 즉각 수행해 원본 증거 데이터 확보
  3. 정보통신망법 형식에 맞춘 보고서 초안을 자동으로 생성하여 초기 대응 인력 보강

---

## 📂 저장소 구조 및 컴포넌트 안내
본 레포지토리는 목적에 따라 브랜치를 분리하여 각 서버 컴포넌트를 독립적으로 관리하고 있습니다. 코드를 확인하시려면 아래의 각 브랜치 링크를 클릭해 주세요.
| Component | Branch | Description |
| :--- | :--- | :--- |
| **Agent Server** | [`agent-server` 바로가기](https://github.com/suhyeon514/eBPF_Project/tree/agent-server) | eBPF 기반 이벤트 수집, 정규화 및 엔드포인트 제어 |
| **Analysis Server** | [`analysis-server` 바로가기](https://github.com/suhyeon514/eBPF_Project/tree/analysis-server) | 데이터 파이프라인, 위협 분석 및 LLM 워커 연동 |

### 🏗 System Architecture
K9의 아키텍처는 크게 에이전트(Agent)와 분석 중앙 서버(Analysis Server)로 구성됩니다.

* **Agent Layer:** `eBPF(Tetragon)` 엔진을 통해 커널 레벨의 이벤트(프로세스, 파일, 네트워크, 권한)를 감시하며, 동시에 L7 계층 분석을 위한 전용 컬렉터(Nginx, Auditd 등)를 병행 운용합니다.
* **Data Pipeline:** 수집된 이기종 로그는 `Fluent-bit`를 거쳐 중앙 서버의 `Kafka` 메시지 큐로 스트리밍되며, Python Worker가 데이터를 추출해 정규화 및 위험도를 산출합니다.
* **Analysis & DB Layer:** 정제된 데이터는 빠른 검색을 위해 `OpenSearch`에, 프로세스 상관관계 분석을 위해 `Neo4j` 그래프 DB에 적재되며 `PostgreSQL`로 자산을 관리합니다.
* **Web UI & IR:** 시각화는 `Grafana`, `FastAPI`, `React`를 통해 제공되며, 메모리 덤프(AVML) 파일은 S3 버킷으로 다이렉트 전송됩니다.

---

## ✨ Key Features

### 1. eBPF 기반 하이브리드 멀티 컬렉터 (Multi-Collector)
* 시스템 콜(예: `_x64_sys_openat`)을 직접 후킹하여 악성 행위를 실시간으로 캡처합니다
* 방대한 웹 페이로드 등 L7 계층 데이터를 커널에서 조립할 때 발생하는 시스템 오버헤드를 방지하기 위해, Nginx 및 Auditd 등 8개 영역의 전용 컬렉터(Dedicated Collectors)를 분산 운용하여 가시성을 확보합니다.
  
### 2. 다차원 위험도 스코어링 (Risk Scoring System)
* 단일 룰 매칭이 아닌 **최종 점수 = `(Base * Target * Env) + Mitre`** 공식을 적용합니다.
* `Target`(민감 파일 접근 시 20% 가중), `Env`(Root 권한 실행 시 10% 가중), `Mitre`(전술 중요도에 따른 보너스 점수)를 합산하여 공격의 맥락과 우선순위를 정교하게 분류합니다.

### 3. Neo4j 기반 프로세스 계층 시각화 대시보드
* 단일 로그 텍스트를 넘어, 특정 위협 프로세스(예: `sh`, `nc`)를 중심으로 부모-자식 관계를 노드(Node) 형태로 시각화합니다
* 심각도(CRITICAL 등)에 따른 시각적 분류와 `MITRE ATT&CK` ID(T1090 등) 매핑 정보를 함께 표출하여 분석 효율을 높입니다

### 4. 침해사고 대응(IR) 자동화 및 Slack 연동
* 위험 이벤트 발생 시 관리자의 Slack으로 상세 내역을 즉시 알림 전송합니다.
* 대시보드 내 클릭 한 번으로 해당 호스트의 메모리 덤프(AVML) 명령을 하달하고 결과물을 S3에 안전하게 보관합니다.
* AI를 활용하여 '정보통신망법 형식' 스크립트를 기반으로 한 시나리오 초안 보고서를 자동 생성합니다.

---

## 🛠 Tech Stack

<img width="676" height="274" alt="Image" src="https://github.com/user-attachments/assets/5bdd2664-3dcf-4301-af77-d5f2e2f00fa7" />


### Environment & Versions

**Agent (에이전트 및 테스트 베드)**
* **OS:** Ubuntu 22.04 (Kernel 3.18+)
* **Web/DB:** Nginx 1.18.x, PHP-FPM 8.1.x, MariaDB 10.6.x
* **Target App:** WordPress 6.9.x
* **Language:** Go (Golang)
* **eBPF Engine:** Tetragon
* **OS/Net/Sys:** Auditd, Journald, Conntrack, Nftables, gopsutil

**Analysis Server (중앙 분석 서버)**
* **Data Pipeline & MQ:** Kafka 3.8.0, Python (Worker)
* **Database & Search Engine:** * OpenSearch 2.12.0
  * Neo4j 5.15.0
  * PostgreSQL 15.6
* **Web & Visualization:** Grafana 10.4.0, FastAPI, React

---


