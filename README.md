# 🛡️ eBPF Security Analysis Server

이 저장소는 eBPF 에이전트로부터 수집된 실시간 보안 로그를 **수집(Ingest), 가공(Process), 저장(Store), 및 시각화(Visualize)**하기 위한 분석 서버 인프라 설정을 포함하고 있습니다.

## 🏗️ 시스템 아키텍처
본 서버는 효율적인 보안 데이터 처리를 위해 다음과 같은 파이프라인 흐름을 가집니다.

1. **Kafka (Ingestion):** 에이전트로부터 전송된 대량의 Raw 로그를 유실 없이 수신
2. **Data Prepper (Pipeline):** 로그 형식 통일, 처리 시간 기록 및 분석 태그 추가
3. **OpenSearch (Storage):** 가공된 로그 인덱싱 및 빠른 보안 데이터 검색 지원
4. **PostgreSQL (Metadata):** 탐지 정책 및 시스템 메타데이터 관리
5. **Grafana (Dashboard):** 수집된 위협 데이터를 실시간 차트로 시각화

---

## 🛠️ 기술 스택 및 컴포넌트

| 컴포넌트 | 기술 (버전) | 역할 |
| :--- | :--- | :--- |
| **Message Queue** | Apache Kafka (3.8.0) | 실시간 로그 버퍼링 및 큐잉 |
| **Pipeline** | Data Prepper (2.7.0) | 데이터 ETL 및 OpenSearch 전송 |
| **Search Engine** | OpenSearch (2.12.0) | 분산 로그 검색 및 보안 데이터 저장 |
| **Management DB** | PostgreSQL (15.6) | 시스템 메타데이터 관리 |
| **Visualization** | Grafana (10.4.0) | 보안 관제 대시보드 시각화 |

---

## 📋 사전 요구 사항
- **OS:** Ubuntu 22.04 LTS (권장)
- **Runtime:** Docker 20.10+ & Docker Compose v2.0+
- **Hardware:** 최소 **8GB RAM** (OpenSearch 및 Kafka 구동 필수)