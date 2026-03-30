# 🛡️ eBPF Security Analysis Server

이 저장소는 eBPF 에이전트로부터 수집된 실시간 보안 로그를 **수집(Ingest), 탐지(Detect), 저장(Store), 및 그래프 시각화(Graph Visualize)**하기 위한 통합 보안 분석 인프라 설정을 포함하고 있습니다.

---

## 🏗️ 시스템 아키텍처
본 서버는 단순한 로그 저장을 넘어, 실시간 위협 탐지와 프로세스 간의 상관관계 분석을 위해 다음과 같은 파이프라인 흐름을 가집니다.

1.  **Kafka (Ingestion):** 에이전트로부터 전송된 대량의 Raw 로그를 유실 없이 수신하는 버퍼 역할
2.  **Python Log-Processor (Detection Engine):** Kafka 로그를 구독하여 PostgreSQL의 탐지 룰과 매칭, 데이터 정규화 및 위협 탐지 수행
3.  **OpenSearch (Log Storage):** 정규화된 로그 및 탐지된 알람(Alert) 데이터를 인덱싱하여 고속 검색 지원
4.  **PostgreSQL (Metadata & Rules):** 탐지 정책(Detection Rules), 사용자 권한 및 시스템 메타데이터 관리
5.  **Neo4j (Graph Analysis):** 프로세스 간의 부모-자식 관계 및 네트워크 연결을 그래프 데이터로 구조화하여 시각화
6.  **Grafana (Dashboard):** OpenSearch와 연동하여 전체 보안 위협 현황을 실시간 대시보드로 시각화

---

## 🛠️ 기술 스택 및 컴포넌트

| 컴포넌트 | 기술 (버전) | 역할 |
| :--- | :--- | :--- |
| **Message Queue** | **Apache Kafka** (3.8.0) | 실시간 로그 버퍼링 및 분산 큐잉 |
| **Detection Worker** | **Python** (3.11-slim) | 룰 기반 위협 탐지, 데이터 정규화 및 ETL |
| **Search Engine** | **OpenSearch** (2.12.0) | 분산 로그 검색 및 보안 이벤트 저장 |
| **Graph DB** | **Neo4j** (5.15.0) | 프로세스 실행 계층 및 행위 상관관계 분석 |
| **Management DB** | **PostgreSQL** (15.6) | 탐지 룰(Detection Rules) 및 메타데이터 관리 |
| **Visualization** | **Grafana** (10.4.0) | 실시간 보안 관제 및 위협 통계 대시보드 |

---

## 📋 사전 요구 사항
* **OS:** Ubuntu 22.04 LTS (권장)
* **Runtime:** Docker 20.10+ & Docker Compose v2.0+
* **Hardware:** 최소 **8GB RAM** 이상 (OpenSearch, Kafka, Neo4j 구동을 위한 권장 사양)