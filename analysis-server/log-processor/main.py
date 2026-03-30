import json
import os
import time
from datetime import datetime, timezone
from kafka import KafkaConsumer
from opensearchpy import OpenSearch
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from name_map import FIELD_MAPPING, transform_logic
import ipaddress

# --- [1. 설정 및 환경변수] ---
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:29092")
OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "opensearch")
DATABASE_URL = os.getenv("DATABASE_URL")

os_client = OpenSearch(
    hosts=[{"host": OPENSEARCH_HOST, "port": 9200}],
    use_ssl=False, 
    verify_certs=False
)

# --- [2. 유틸리티 함수] ---

def flatten_log(d, parent_key='', sep='.'):
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_log(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)

def normalize_log(f_log):
    f_log = transform_logic(f_log)
    new_fields = {}
    for key, value in f_log.items():
        if key in FIELD_MAPPING:
            std_key = FIELD_MAPPING[key]
            new_fields[std_key] = value
    f_log.update(new_fields)
    return f_log

# --- [3. 최적화된 위험도 연산 로직] ---

def calculate_dynamic_risk(n_log, rule):
    """
    슬림화된 가중치 로직 적용 (1~100 범위 최적화)
    """
    # [A] Action: 기본 점수 (DB 설정값)
    base_score = rule.get('base_score', 1) # 기본 1점 보장
    
    # [T] Target: 민감 객체 가중치 (기존 1.4 -> 1.2로 하향)
    target_mult = 1.0
    sensitive_paths = ["/etc/shadow", "/etc/sudoers", "/etc/passwd", "/root/", "wp-config.php"]
    sensitive_ports = [22, 4444, 3389, 8888]
    
    proc_path = str(n_log.get("target.process_path", ""))
    proc_args = str(n_log.get("target.process_args", ""))
    dest_port = n_log.get("target.dest_port")

    if any(p in proc_path or p in proc_args for p in sensitive_paths):
        target_mult = 1.2  # 20% 가중
    elif dest_port in sensitive_ports:
        target_mult = 1.1  # 10% 가중

    # [E] Env: 실행 환경 가중치 (기존 1.2 -> 1.1로 하향)
    env_mult = 1.0
    # Root 권한 행위 가중
    if n_log.get("target.uid") == 0 or n_log.get("target.uid") == "0":
        env_mult = 1.1
    
    # [M] Mitre: 전술별 보너스 (최대 40 -> 15로 하향)
    mitre_bonus = 0
    tactic_weights = {
        "Initial Access": 2,
        "Execution": 5,
        "Persistence": 8,
        "Privilege Escalation": 10,
        "Defense Evasion": 12,
        "Credential Access": 12,
        "Exfiltration": 15,
        "Impact": 15
    }
    mitre_bonus = tactic_weights.get(rule.get('mitre_tactic'), 0)

    # 최종 계산: (Base * T * E) + M
    calculated = (base_score * target_mult * env_mult) + mitre_bonus
    
    # 1~100 범위 강제 (Capping)
    final_score = max(1, min(int(calculated), 100))

    # 등급 매핑
    severity = "Low"
    if final_score >= 75: severity = "Critical"
    elif final_score >= 50: severity = "High"
    elif final_score >= 25: severity = "Medium"
    
    return final_score, severity

# --- [4. 탐지 엔진 클래스] ---

class DetectionEngine:
    def __init__(self, db_url):
        self.engine = create_engine(db_url)
        self.Session = sessionmaker(bind=self.engine)
        self.rules = []
        self.last_update = 0
        # 현재는 테스트용으로 하드코딩
        self.ip_blocklist = ["1.2.3.4", "8.8.4.4"]

    def refresh_rules(self):
        now = time.time()
        if now - self.last_update < 60: return
        
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
            print(f"🔄 {len(self.rules)}개의 탐지 규칙 로드 완료")
        finally:
            session.close()

    def match(self, n_log):
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

                # [기본 연산자]
                if op == "equal" and str(actual) == str(expected): match_count += 1
                elif op == "contains" and str(expected) in str(actual): match_count += 1
                elif op == "in" and str(actual) in expected: match_count += 1
                elif op == "startswith" and str(actual).startswith(str(expected)): match_count += 1
                
                # [팀원 룰 대응 - 고도화 연산자 추가]
                elif op == "not_in" and str(actual) not in expected: match_count += 1
                elif op == "contains_any": # 리스트 중 하나라도 포함되어 있는지
                    if any(str(item) in str(actual) for item in expected): match_count += 1
                elif op == "startswith_list":
                    if any(str(actual).startswith(prefix) for prefix in expected): match_count += 1
                elif op == "endswith_list":
                    if any(str(actual).endswith(suffix) for suffix in expected): match_count += 1
                elif op == "ioc_match": # IP 블랙리스트 대조
                    if str(actual) in self.ip_blocklist: match_count += 1
                elif op == "in_cidr": # 네트워크 대역 체크
                    try:
                        if ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(expected)):
                            match_count += 1
                    except: pass

            if match_count == len(conditions):
                matched_results.append(rule)
        return matched_results

# --- [5. 메인 워커 루프] ---

def main():
    engine = DetectionEngine(DATABASE_URL)
    topics = ['tetragon.process', 'tetragon.auth', 'tetragon.network', 'tetragon.file', 'network', 'auditd', 'journald', 'sensor']

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
        
        agent_ts = raw_log.get("@timestamp")
        try:
            dt_object = datetime.fromtimestamp(agent_ts, tz=timezone.utc) if isinstance(agent_ts, (int, float)) else datetime.fromisoformat(str(agent_ts).replace('Z', '+00:00'))
            log_date = dt_object.strftime("%Y.%m.%d")
        except:
            log_date = datetime.now(timezone.utc).strftime("%Y.%m.%d")

        raw_log["processed_at"] = datetime.now(timezone.utc).isoformat()
        raw_log["kafka_topic"] = topic

        engine.refresh_rules()
        f_log = flatten_log(raw_log)
        n_log = normalize_log(f_log)
        matches = engine.match(n_log)

        target_index = f"security-{topic}-{log_date}"
        alert_index = f"security-alerts-{log_date}"
        
        if matches:
            best_match = None
            max_calculated_score = -1
            final_severity = "None"

            for rule in matches:
                calc_score, calc_sev = calculate_dynamic_risk(n_log, rule)
                if calc_score > max_calculated_score:
                    max_calculated_score = calc_score
                    final_severity = calc_sev
                    best_match = rule
            
            print(f"⚠️  [ALERT] {final_severity} - {best_match['rule_name']} (Final Score: {max_calculated_score})")
            
            raw_log['risk_info'] = {
                "detected": True,
                "rule_name": best_match['rule_name'],
                "severity": final_severity,
                "score": max_calculated_score,
                "base_score": best_match['base_score'],
                "tactic": best_match['mitre_tactic'],
                "technique_id": best_match['mitre_technique_id']
            }
            os_client.index(index=alert_index, body=raw_log)
        else:
            # 탐지되지 않은 일반 로그도 실무 관례에 따라 최소 점수 1점(Low) 부여
            print(".", end="", flush=True)
            raw_log['risk_info'] = {
                "detected": False, 
                "score": 1, 
                "severity": "Low"
            }

        os_client.index(index=target_index, body=raw_log)

if __name__ == "__main__":
    time.sleep(15)
    main()