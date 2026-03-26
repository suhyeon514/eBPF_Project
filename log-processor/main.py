import json
import os
import time
from datetime import datetime, timezone
from kafka import KafkaConsumer
from opensearchpy import OpenSearch
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from name_map import FIELD_MAPPING, transform_logic

# --- [1. 설정 및 환경변수] ---
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:29092")
OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "opensearch")
DATABASE_URL = os.getenv("DATABASE_URL")

# --- [2. OpenSearch 연결] ---
os_client = OpenSearch(
    hosts=[{"host": OPENSEARCH_HOST, "port": 9200}],
    use_ssl=False, 
    verify_certs=False
)

# --- [3. 유틸리티 함수] ---

def flatten_log(d, parent_key='', sep='.'):
    """중첩된 JSON 구조를 1차원 평면 구조로 변환"""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_log(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)

def normalize_log(f_log):
    """평면화된 로그에 name_map 기반 표준 필드명 매핑 및 변환 로직 적용"""
    # 특수 변환 로직 (예: IP/MAC 처리)
    f_log = transform_logic(f_log)
    
    # 표준 필드명 매핑
    new_fields = {}
    for key, value in f_log.items():
        if key in FIELD_MAPPING:
            std_key = FIELD_MAPPING[key]
            new_fields[std_key] = value
            
    # 원본에 표준 필드 통합 (원본 데이터 보존)
    f_log.update(new_fields)
    return f_log

# --- [4. 탐지 엔진 클래스] ---

class DetectionEngine:
    def __init__(self, db_url):
        self.engine = create_engine(db_url)
        self.Session = sessionmaker(bind=self.engine)
        self.rules = []
        self.last_update = 0

    def refresh_rules(self):
        """DB에서 탐지 규칙 메모리 캐싱 (1분 주기)"""
        now = time.time()
        if now - self.last_update < 60:
            return
        
        session = self.Session()
        try:
            query = text("""
                SELECT rule_name, conditions, base_score, severity, mitre_tactic, mitre_technique_id 
                FROM detection_rules 
                WHERE is_active = True
            """)
            result = session.execute(query)
            self.rules = [dict(row._mapping) for row in result]
            self.last_update = now
            print(f"🔄 {len(self.rules)}개의 최신 탐지 규칙 로드 완료")
        finally:
            session.close()

    def match(self, n_log):
        """정규화된 로그와 규칙 매칭"""
        matched_results = []
        for rule in self.rules:
            conditions = rule['conditions']
            if not conditions: continue
            
            match_count = 0
            for cond in conditions:
                field = cond.get('field')
                op = cond.get('op')
                expected = cond.get('value')
                actual = n_log.get(field)

                if actual is None: continue

                # 연산자 처리 로직
                if op == "equal" and str(actual) == str(expected): match_count += 1
                elif op == "contains" and str(expected) in str(actual): match_count += 1
                elif op == "in" and str(actual) in expected: match_count += 1
                elif op == "startswith" and str(actual).startswith(str(expected)): match_count += 1
                elif op == "startswith_list":
                    if any(str(actual).startswith(prefix) for prefix in expected): match_count += 1

            if match_count == len(conditions):
                matched_results.append(rule)
        
        return matched_results

# --- [5. 메인 워커 루프] ---

def main():
    engine = DetectionEngine(DATABASE_URL)
    
    topics = [
        'tetragon.process', 'tetragon.auth', 'tetragon.network', 'tetragon.file',
        'network', 'auditd', 'journald', 'sensor'
    ]

    consumer = KafkaConsumer(
        *topics,
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        group_id='k9-detection-group',
        auto_offset_reset='earliest',
        value_deserializer=lambda m: json.loads(m.decode('utf-8'))
    )

    print(f"🚀 워커 시작: {len(topics)}개 토픽 모니터링 중...")

    for message in consumer:
        raw_log = message.value
        topic = message.topic
        
        # [A] 에이전트 수집 시간 추출 및 인덱스 날짜 결정
        agent_ts = raw_log.get("@timestamp")
        try:
            # Unix Timestamp(float/int)를 datetime 객체로 변환
            if isinstance(agent_ts, (int, float)):
                dt_object = datetime.fromtimestamp(agent_ts, tz=timezone.utc)
            else:
                # ISO 포맷 문자열일 경우 처리
                dt_object = datetime.fromisoformat(str(agent_ts).replace('Z', '+00:00'))
            log_date = dt_object.strftime("%Y.%m.%d")
        except Exception:
            # 타임스탬프 오류 시 현재 시스템 시간 사용
            log_date = datetime.now(timezone.utc).strftime("%Y.%m.%d")

        # [B] 메타데이터 필드 추가 (원본 @timestamp는 유지)
        raw_log["processed_at"] = datetime.now(timezone.utc).isoformat()
        raw_log["kafka_topic"] = topic

        # [C] 데이터 분석 파이프라인
        engine.refresh_rules()
        f_log = flatten_log(raw_log)
        n_log = normalize_log(f_log)
        matches = engine.match(n_log)

        # [D] 위험도 인리치먼트 및 인덱스 결정
        target_index = f"security-{topic}-{log_date}"
        alert_index = f"security-alerts-{log_date}"
        
        if matches:
            top_rule = max(matches, key=lambda x: x['base_score'])
            print(f"⚠️  [ALERT] {top_rule['severity']} - {top_rule['rule_name']} (Score: {top_rule['base_score']})")
            
            raw_log['risk_info'] = {
                "detected": True,
                "rule_name": top_rule['rule_name'],
                "severity": top_rule['severity'],
                "score": top_rule['base_score'],
                "tactic": top_rule['mitre_tactic'],
                "technique_id": top_rule['mitre_technique_id']
            }
            # 탐지된 로그는 알람 전용 인덱스에 별도로 추가 저장
            os_client.index(index=alert_index, body=raw_log)
        else:
            print(".", end="", flush=True)
            raw_log['risk_info'] = {
                "detected": False, 
                "score": 0, 
                "severity": "None"
            }

        # [E] 최종 OpenSearch 저장 (원본 인덱스)
        os_client.index(index=target_index, body=raw_log)

if __name__ == "__main__":
    # 인프라(Kafka, DB) 안정화를 위한 대기
    time.sleep(15)
    main()