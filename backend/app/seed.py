import os
import uuid
import random
import bcrypt
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from opensearchpy import OpenSearch
from .models import DetectionRule, User, Role, Assets
from .database import SessionLocal, engine, Base

# 1. OpenSearch 연결 설정 (로컬 도커 환경)
os_client = OpenSearch(
    hosts=[{"host": "localhost", "port": 9200}],
    use_ssl=False,
    verify_certs=False,
    sniff_on_start=False
)

# 2. 비밀번호 암호화 함수
def get_password_hash(password: str) -> str:
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode('utf-8')

# --- [추가] 자산 샘플 데이터 생성 함수 ---
def seed_assets(db: Session):
    print("🖥️ 자산(Assets) 샘플 데이터 생성 중...")
    
    # 이미 데이터가 있으면 건너뜀
    if db.query(Assets).count() > 0:
        print("⏭️ 자산 데이터가 이미 존재하여 건너뜁니다.")
        return

    asset_samples = [
        # 웹 서버군
        {"hostname": "web-prod-01", "ip": "192.168.10.11", "os": "Ubuntu 22.04 LTS", "status": "정상", "risk": 5},
        {"hostname": "web-prod-02", "ip": "192.168.10.12", "os": "Ubuntu 22.04 LTS", "status": "정상", "risk": 12},
        {"hostname": "web-dev-test", "ip": "192.168.10.50", "os": "Ubuntu 20.04 LTS", "status": "주의", "risk": 45},
        
        # DB 서버군
        {"hostname": "db-master-01", "ip": "10.0.1.10", "os": "Debian 11", "status": "정상", "risk": 0},
        {"hostname": "db-slave-01", "ip": "10.0.1.11", "os": "Debian 11", "status": "오프라인", "risk": 0},
        
        # 관리 및 보안 서버
        {"hostname": "k9-mgmt-srv", "ip": "10.0.0.5", "os": "Ubuntu 22.04 LTS", "status": "정상", "risk": 2},
        {"hostname": "auth-radius", "ip": "10.0.0.20", "os": "CentOS 7", "status": "위험", "risk": 88},
        
        # 연구실/테스트 기기 (사용자님 환경 반영)
        {"hostname": "lab-mini-pc", "ip": "192.168.50.100", "os": "Kali Linux 2024.1", "status": "정상", "risk": 15},
        {"hostname": "honey-pot-01", "ip": "192.168.50.200", "os": "Ubuntu 18.04 LTS", "status": "위험", "risk": 95},
        {"hostname": "gitlab-local", "ip": "192.168.50.10", "os": "Ubuntu 22.04 LTS", "status": "주의", "risk": 30},
    ]

    # 부족한 개수는 랜덤으로 채움 (총 15개)
    for i in range(len(asset_samples), 15):
        asset_samples.append({
            "hostname": f"workstation-{i:02d}",
            "ip": f"172.16.0.{100+i}",
            "os": random.choice(["Ubuntu 22.04 LTS", "Debian 12", "Fedora 39"]),
            "status": random.choice(["정상", "정상", "주의", "오프라인"]), # 정상이 많이 나오도록
            "risk": random.randint(0, 40)
        })

    for item in asset_samples:
        asset = Assets(
            hostname=item["hostname"],
            ip_address=item["ip"],
            os_info=item["os"],
            status=item["status"],
            cpu_usage=round(random.uniform(1.5, 65.0), 1),
            memory_usage=round(random.uniform(10.0, 85.0), 1),
            risk_score=item["risk"],
            unassigned_alerts_count=random.randint(0, 5) if item["risk"] < 50 else random.randint(5, 20),
            last_heartbeat=datetime.now(timezone.utc) - timedelta(minutes=random.randint(0, 120))
        )
        db.add(asset)
    
    db.commit()
    print(f"✅ 자산 샘플 데이터 {db.query(Assets).count()}건 삽입 완료")

# 3. 30개의 샘플 로그 생성 함수 (프로세스 10, 네트워크 10, 인증 10)
def generate_mock_logs():
    logs = []
    hosts = [
        {"host_id": "host-web-01", "hostname": "web-srv", "env": "prod", "role": "web-server"},
        {"host_id": "host-db-01", "hostname": "db-srv", "env": "prod", "role": "database"},
        {"host_id": "host-lab-01", "hostname": "mini-pc", "env": "lab", "role": "test"}
    ]

    # --- (1) 프로세스 로그 10건 ---
    for _ in range(10):
        logs.append({
            "schema_version": "v1",
            "event_id": str(uuid.uuid4()),
            "event_type": random.choice(["edr.process.exec", "edr.process.exit"]),
            "@timestamp": datetime.now(timezone.utc).isoformat(), 
            "host": random.choice(hosts),
            "collector": {"name": "tetragon", "source_type": "ebpf"},
            "process": {
                "pid": random.randint(1000, 9999),
                "comm": "bash",
                "exe": "/bin/bash",
                "uid": 1000,
                "gid": 1000
            },
            "raw_ref": {"source": "tetragon", "raw_type": "process_event"}
        })

    # --- (2) 네트워크 로그 10건 ---
    for _ in range(10):
        logs.append({
            "schema_version": "v1",
            "event_id": str(uuid.uuid4()),
            "event_type": "edr.network.flow",
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "host": random.choice(hosts),
            "collector": {"name": "conntrack", "source_type": "flow"},
            "network": {
                "protocol": "tcp",
                "src_ip": "192.168.1.50",
                "src_port": random.randint(10000, 60000),
                "dst_ip": "8.8.8.8",
                "dst_port": 443,
                "action": "NEW"
            },
            "raw_ref": {"source": "conntrack", "raw_type": "flow_event"}
        })

    # --- (3) 인증 로그 10건 ---
    for _ in range(10):
        logs.append({
            "schema_version": "v1",
            "event_id": str(uuid.uuid4()),
            "event_type": "edr.auth.sudo",
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "host": random.choice(hosts),
            "auth": {"method": "sudo", "result": "success"},
            "raw_ref": {"source": "journald", "raw_type": "auth_event"}
        })

    return logs

def seed_db():
    print("⏳ 도커 컨테이너 DB(PostgreSQL) 및 OpenSearch 초기화 중...")
    # 테이블 생성 (Assets 모델이 models.py에 있다면 여기서 함께 생성됩니다)
    Base.metadata.create_all(bind=engine) 
    db: Session = SessionLocal()
    
    try:
        # [1] PostgreSQL 초기화 (계정 및 권한)
        print("👤 관리자 계정 생성 중...")
        admin_role = db.query(Role).filter(Role.role_name == "admin").first()
        if not admin_role:
            admin_role = Role(role_name="admin", description="전체 관리자")
            db.add(admin_role)
            db.commit()
            db.refresh(admin_role)

        if not db.query(User).filter(User.username == "admin").first():
            admin_user = User(
                username="admin",
                password_hash=get_password_hash("admin123!"),
                full_name="관리자",
                role_id=admin_role.id,
                email="admin@example.com"
            )
            db.add(admin_user)
            db.commit()
        
        print("✅ PostgreSQL 설정 완료")

        seed_assets(db)           # 👈 자산 데이터 생성 함수 호출
        seed_detection_rules(db)  # 👈 탐지 룰 생성 함수 호출

        # [2] OpenSearch 초기화 (로그 데이터)
        print("🔍 OpenSearch 샘플 로그 생성 중...")
        index_name = f"ebpf-logs-{datetime.now().strftime('%Y.%m.%d')}"
        
        if not os_client.indices.exists(index=index_name):
            os_client.indices.create(index=index_name)

        mock_logs = generate_mock_logs()
        for log in mock_logs:
            os_client.index(index=index_name, body=log)
        
        print(f"✅ OpenSearch 샘플 데이터 {len(mock_logs)}건 삽입 완료")
        print("\n✨ 모든 데이터 초기 설정이 완료되었습니다!")

    except Exception as e:
        print(f"❌ 오류 발생: {e}")
        db.rollback()
    finally:
        db.close()


def seed_detection_rules(db: Session):
    """
    K9 플랫폼 초기 탐지 룰 데이터 삽입 (슬림한 위험도 연산 로직에 최적화된 점수 반영)
    """
    print("🛡️ 탐지 룰 통합 시딩 시작...")
    
    # 1. 초기 침투 및 실행 (Initial Access & Execution)
    initial_access_rules = [
        DetectionRule(target_topic="tetragon.process", category="Initial Access & Execution", rule_name="Web Server Spawning Shell", conditions=[{"field": "process.parent_comm", "op": "contains", "value": "nginx"}, {"field": "process.comm", "op": "in", "value": ["sh", "bash", "dash", "zsh"]}], detection_method="advanced_json", base_score=45, severity="High", mitre_technique_id="T1190", mitre_tactic="Initial Access", description="Nginx 하위 셸 실행 탐지."),
        DetectionRule(target_topic="tetragon.process", category="Execution", rule_name="Base64 Encoded Command Execution", conditions=[{"field": "process.args", "op": "contains", "value": "base64"}, {"field": "process.args", "op": "contains", "value": "-d"}], detection_method="advanced_json", base_score=65, severity="Critical", mitre_technique_id="T1059.004", mitre_tactic="Execution", description="인코딩된 명령어 실행 탐지."),
        DetectionRule(target_topic="tetragon.process", category="Execution", rule_name="Execution from Suspicious Directory", conditions=[{"field": "process.exe", "op": "startswith_list", "value": ["/tmp/", "/dev/shm/", "/var/tmp/"]}], detection_method="advanced_json", base_score=50, severity="High", mitre_technique_id="T1059", mitre_tactic="Execution", description="임시 디렉토리 내 바이너리 실행 탐지."),
        DetectionRule(target_topic="tetragon.process", category="Initial Access & Discovery", rule_name="Web Server System Discovery", conditions=[{"field": "process.parent_comm", "op": "contains", "value": "nginx"}, {"field": "process.comm", "op": "in", "value": ["id", "whoami", "hostname", "uname"]}], detection_method="advanced_json", base_score=40, severity="High", mitre_technique_id="T1087", mitre_tactic="Discovery", description="웹 서버 권한 시스템 정찰 탐지."),
        DetectionRule(target_topic="tetragon.process", category="Execution", rule_name="Hidden File Execution", conditions=[{"field": "process.comm", "op": "startswith", "value": "."}], detection_method="advanced_json", base_score=25, severity="Medium", mitre_technique_id="T1564.001", mitre_tactic="Defense Evasion", description="숨김 파일 실행 탐지.")
    ]

    # 2. 내부 탐색 및 자격 증명 탈취 (Discovery & Credential Access)
    discovery_credential_rules = [
        DetectionRule(target_topic="tetragon.process", category="Discovery & Credential Access", rule_name="WordPress Config Access", conditions=[{"field": "process.args", "op": "contains", "value": "wp-config.php"}, {"field": "process.comm", "op": "in", "value": ["cat", "grep", "vi", "nano"]}], detection_method="advanced_json", base_score=55, severity="High", mitre_technique_id="T1552.001", mitre_tactic="Credential Access", description="WP 설정 파일 접근 탐지."),
        DetectionRule(target_topic="tetragon.process", category="Discovery", rule_name="System User Discovery", conditions=[{"field": "process.comm", "op": "in", "value": ["whoami", "id", "groups", "last"]}], detection_method="advanced_json", base_score=15, severity="Medium", mitre_technique_id="T1087.001", mitre_tactic="Discovery", description="사용자 정보 정찰 탐지."),
        DetectionRule(target_topic="tetragon.process", category="Discovery", rule_name="Network Configuration Discovery", conditions=[{"field": "process.comm", "op": "in", "value": ["ifconfig", "ip", "netstat", "ss", "route"]}], detection_method="advanced_json", base_score=15, severity="Medium", mitre_technique_id="T1016", mitre_tactic="Discovery", description="네트워크 설정 정찰 탐지."),
        DetectionRule(target_topic="tetragon.process", category="Credential Access", rule_name="Shadow File Read Attempt", conditions=[{"field": "process.args", "op": "contains", "value": "/etc/shadow"}], detection_method="advanced_json", base_score=70, severity="Critical", mitre_technique_id="T1003.008", mitre_tactic="Credential Access", description="/etc/shadow 접근 탐지."),
        DetectionRule(target_topic="tetragon.process", category="Discovery", rule_name="Process Listing Discovery", conditions=[{"field": "process.comm", "op": "in", "value": ["ps", "top", "htop"]}], detection_method="advanced_json", base_score=15, severity="Medium", mitre_technique_id="T1057", mitre_tactic="Discovery", description="프로세스 목록 조회 탐지.")
    ]

    # 3. 권한 상승 및 지속성 유지
    persistence_escalation_rules = [
        DetectionRule(target_topic="tetragon.process", category="Persistence & Privilege Escalation", rule_name="Sudoers Modification via Command Line", conditions=[{"field": "process.args", "op": "contains", "value": "/etc/sudoers"}, {"field": "process.comm", "op": "in", "value": ["echo", "sed", "tee", "visudo"]}], detection_method="advanced_json", base_score=70, severity="Critical", mitre_technique_id="T1548.003", mitre_tactic="Persistence", description="sudoers 파일 무단 수정 탐지."),
        DetectionRule(target_topic="tetragon.process", category="Persistence", rule_name="Scheduled Task Creation via Crontab", conditions=[{"field": "process.comm", "op": "equal", "value": "crontab"}, {"field": "process.args", "op": "contains", "value": "-e"}], detection_method="advanced_json", base_score=45, severity="High", mitre_technique_id="T1053.003", mitre_tactic="Persistence", description="crontab 예약 작업 등록 탐지."),
        DetectionRule(target_topic="tetragon.process", category="Persistence", rule_name="Suspicious Service Unit Creation", conditions=[{"field": "process.comm", "op": "equal", "value": "systemctl"}, {"field": "process.args", "op": "contains", "value": "enable"}], detection_method="advanced_json", base_score=50, severity="High", mitre_technique_id="T1543.002", mitre_tactic="Persistence", description="systemd 서비스 유닛 등록 탐지."),
        DetectionRule(target_topic="tetragon.process", category="Privilege Escalation", rule_name="Abuse of Setuid Binaries", conditions=[{"field": "process.comm", "op": "in", "value": ["find", "python", "perl", "lua"]}, {"field": "process.args", "op": "contains", "value": "exec"}], detection_method="advanced_json", base_score=65, severity="Critical", mitre_technique_id="T1548.001", mitre_tactic="Privilege Escalation", description="SUID 바이너리 악용 실행 탐지."),
        DetectionRule(target_topic="tetragon.process", category="Privilege Escalation", rule_name="Capabilities Discovery", conditions=[{"field": "process.comm", "op": "equal", "value": "getcap"}, {"field": "process.args", "op": "contains", "value": "-r"}], detection_method="advanced_json", base_score=40, severity="High", mitre_technique_id="T1611", mitre_tactic="Privilege Escalation", description="시스템 특수 권한 정찰 탐지.")
    ]

    # 4. 방어 회피 (Defense Evasion)
    defense_evasion_rules = [
        DetectionRule(target_topic="tetragon.process", category="Defense Evasion", rule_name="Bash History Indicator Removal", conditions=[{"field": "process.comm", "op": "in", "value": ["rm", "truncate"]}, {"field": "process.args", "op": "contains", "value": ".bash_history"}], detection_method="advanced_json", base_score=55, severity="High", mitre_technique_id="T1070.003", mitre_tactic="Defense Evasion", description="명령 기록(.bash_history) 변조 탐지."),
        DetectionRule(target_topic="tetragon.process", category="Defense Evasion", rule_name="File Timestomping via Touch", conditions=[{"field": "process.comm", "op": "equal", "value": "touch"}, {"field": "process.args", "op": "in", "value": ["-r", "-t", "--timestamp"]}], detection_method="advanced_json", base_score=35, severity="Medium", mitre_technique_id="T1070.006", mitre_tactic="Defense Evasion", description="파일 타임스탬프 조작 탐지."),
        DetectionRule(target_topic="tetragon.process", category="Defense Evasion", rule_name="Immutable Attribute Removal", conditions=[{"field": "process.comm", "op": "equal", "value": "chattr"}, {"field": "process.args", "op": "contains", "value": "-i"}], detection_method="advanced_json", base_score=50, severity="High", mitre_technique_id="T1222.002", mitre_tactic="Defense Evasion", description="파일 불변(Immutable) 속성 제거 탐지."),
        DetectionRule(target_topic="tetragon.process", category="Defense Evasion", rule_name="Audit Service Tampering", conditions=[{"field": "process.comm", "op": "in", "value": ["systemctl", "service"]}, {"field": "process.args", "op": "contains", "value": "stop"}, {"field": "process.args", "op": "contains", "value": "auditd"}], detection_method="advanced_json", base_score=70, severity="Critical", mitre_technique_id="T1562.001", mitre_tactic="Defense Evasion", description="감사 서비스(auditd) 중단 시도 탐지."),
        DetectionRule(target_topic="tetragon.process", category="Defense Evasion", rule_name="Hidden Files and Directories Creation", conditions=[{"field": "process.args", "op": "contains", "value": "/. "}, {"field": "process.comm", "op": "in", "value": ["mkdir", "touch"]}], detection_method="advanced_json", base_score=25, severity="Medium", mitre_technique_id="T1564.001", mitre_tactic="Defense Evasion", description="숨김 파일/디렉토리 생성 탐지.")
    ]

    # 5. 유출 및 영향 (Exfiltration & Impact)
    exfiltration_impact_rules = [
        DetectionRule(target_topic="tetragon.process", category="Exfiltration", rule_name="Data Compressed for Exfiltration", conditions=[{"field": "process.comm", "op": "in", "value": ["tar", "zip", "gzip", "7z"]}, {"field": "process.args", "op": "contains", "value": "/var/www/html"}], detection_method="advanced_json", base_score=30, severity="Medium", mitre_technique_id="T1560.001", mitre_tactic="Exfiltration", description="웹 루트 디렉토리 압축 탐지."),
        DetectionRule(target_topic="tetragon.process", category="Exfiltration", rule_name="Data Exfiltration via Wget/Curl", conditions=[{"field": "process.comm", "op": "in", "value": ["curl", "wget"]}, {"field": "process.args", "op": "contains_any", "value": ["--post-data", "--post-file", "--upload-file"]}], detection_method="advanced_json", base_score=55, severity="High", mitre_technique_id="T1048.003", mitre_tactic="Exfiltration", description="외부 데이터 전송 시도 탐지."),
        DetectionRule(target_topic="tetragon.process", category="Exfiltration", rule_name="Sensitive Database Dump Access", conditions=[{"field": "process.args", "op": "contains", "value": ".sql"}, {"field": "process.comm", "op": "in", "value": ["cat", "grep", "tar"]}], detection_method="advanced_json", base_score=65, severity="Critical", mitre_technique_id="T1530", mitre_tactic="Exfiltration", description="DB 덤프 파일 비정상 접근 탐지."),
        DetectionRule(target_topic="tetragon.process", category="Impact", rule_name="Service Disruption (Stop/Disable)", conditions=[{"field": "process.comm", "op": "equal", "value": "systemctl"}, {"field": "process.args", "op": "contains", "value": "stop"}, {"field": "process.args", "op": "contains_any", "value": ["nginx", "mysql", "mariadb", "php-fpm"]}], detection_method="advanced_json", base_score=50, severity="High", mitre_technique_id="T1489", mitre_tactic="Impact", description="핵심 웹 서비스 중단 시도 탐지."),
        DetectionRule(target_topic="tetragon.process", category="Impact", rule_name="Unauthorized System Shutdown/Reboot", conditions=[{"field": "process.comm", "op": "in", "value": ["reboot", "shutdown", "halt", "poweroff"]}], detection_method="advanced_json", base_score=70, severity="Critical", mitre_technique_id="T1529", mitre_tactic="Impact", description="비인가 시스템 종료/재부팅 명령 탐지.")
    ]

    # 1. 프로세스 실행 (Execution)
    process_rules = [
        DetectionRule(target_topic="tetragon.process", category="Execution", rule_name="Fileless Execution via memfd_create", conditions=[{"field": "process.syscall", "op": "in", "value": ["memfd_create"]}, {"field": "process.exe", "op": "startswith", "value": "/proc/self/fd"}], detection_method="advanced_json", base_score=70, severity="Critical", mitre_technique_id="T1620", mitre_tactic="Execution", description="메모리 기반(Fileless) 실행 탐지."),
        DetectionRule(target_topic="tetragon.process", category="Privilege Escalation", rule_name="SUID/SGID Binary Execution", conditions=[{"field": "process.file_mode", "op": "contains", "value": "suid"}], detection_method="advanced_json", base_score=45, severity="High", mitre_technique_id="T1548.001", mitre_tactic="Privilege Escalation", description="SUID 비트 설정 파일 실행 탐지."),
        DetectionRule(target_topic="tetragon.process", category="Discovery", rule_name="Short-Lived Process Burst", conditions=[{"field": "process.duration_ms", "op": "lt", "value": 1000}, {"field": "process.burst_count", "op": "gte", "value": 10}], detection_method="advanced_json", base_score=30, severity="Medium", mitre_technique_id="T1059", mitre_tactic="Execution", description="단명 프로세스 대량 생성 탐지.")
    ]

    # 2. 권한 / 자격증명 (Privilege & Credentials)
    privilege_rules = [
        DetectionRule(target_topic="tetragon.process", category="Credential Access", rule_name="Passwd/Shadow File Write", conditions=[{"field": "process.args", "op": "contains_any", "value": ["/etc/passwd", "/etc/shadow"]}, {"field": "event.type", "op": "equal", "value": "file_write"}], detection_method="advanced_json", base_score=70, severity="Critical", mitre_technique_id="T1098", mitre_tactic="Credential Access", description="계정 정보 파일 수정 탐지."),
        DetectionRule(target_topic="tetragon.process", category="Privilege Escalation", rule_name="Setuid Zero Call", conditions=[{"field": "process.syscall", "op": "in", "value": ["setuid", "setgid"]}, {"field": "process.syscall_arg0", "op": "equal", "value": 0}], detection_method="advanced_json", base_score=65, severity="Critical", mitre_technique_id="T1068", mitre_tactic="Privilege Escalation", description="루트 권한 획득 시스템 콜 탐지."),
        DetectionRule(target_topic="tetragon.process", category="Privilege Escalation", rule_name="Dangerous Capability Addition", conditions=[{"field": "process.comm", "op": "equal", "value": "setcap"}, {"field": "process.args", "op": "contains_any", "value": ["cap_sys_admin", "cap_net_admin", "cap_sys_ptrace"]}], detection_method="advanced_json", base_score=55, severity="High", mitre_technique_id="T1611", mitre_tactic="Privilege Escalation", description="위험 권한(Capability) 추가 탐지.")
    ]

    # 3. 네트워크 (Network)
    network_rules = [
        DetectionRule(target_topic="tetragon.network", category="Command and Control", rule_name="Known C2 IP/Domain Connection", conditions=[{"field": "network.dst_ip", "op": "ioc_match", "value": "ip_blocklist"}], detection_method="advanced_json", base_score=70, severity="Critical", mitre_technique_id="T1090", mitre_tactic="Command and Control", description="알려진 C2 IP 연결 탐지."),
        DetectionRule(target_topic="tetragon.network", category="Command and Control", rule_name="Reverse Shell Pattern Detected", conditions=[{"field": "process.comm", "op": "in", "value": ["bash", "sh", "nc", "socat"]}, {"field": "network.direction", "op": "equal", "value": "outbound"}], detection_method="advanced_json", base_score=65, severity="Critical", mitre_technique_id="T1021", mitre_tactic="Command and Control", description="리버스 셸 패턴 탐지."),
        DetectionRule(target_topic="tetragon.network", category="Exfiltration", rule_name="Large Outbound Data Transfer", conditions=[{"field": "network.bytes_sent", "op": "gte", "value": 10485760}], detection_method="advanced_json", base_score=50, severity="High", mitre_technique_id="T1041", mitre_tactic="Exfiltration", description="대용량 외부 데이터 전송 탐지.")
    ]

        # 4. 파일 시스템 (File)
    file_rules = [
        DetectionRule(target_topic="tetragon.file", category="Impact", rule_name="Ransomware Pattern File Creation", conditions=[{"field": "file.name", "op": "endswith_list", "value": [".locked", ".enc", ".crypt"]}], detection_method="advanced_json", base_score=70, severity="Critical", mitre_technique_id="T1486", mitre_tactic="Impact", description="랜섬웨어 의심 파일 생성 탐지."),
        DetectionRule(target_topic="tetragon.file", category="Defense Evasion", rule_name="LD_PRELOAD Library Hijacking", conditions=[{"field": "file.path", "op": "equal", "value": "/etc/ld.so.preload"}], detection_method="advanced_json", base_score=65, severity="Critical", mitre_technique_id="T1574.006", mitre_tactic="Defense Evasion", description="라이브러리 하이재킹 시도 탐지.")
    ]

    # 5. 클라우드 VM 특화 (Cloud)
    cloud_rules = [
        DetectionRule(target_topic="tetragon.network", category="Credential Access", rule_name="IMDSv1 Endpoint Direct Access", conditions=[{"field": "network.dst_ip", "op": "equal", "value": "169.254.169.254"}], detection_method="advanced_json", base_score=70, severity="Critical", mitre_technique_id="T1552.005", mitre_tactic="Credential Access", description="클라우드 자격증명 탈취 시도 탐지.")
    ]

    # 6. 커널 / 시스템 콜 (Kernel)
    kernel_rules = [
        DetectionRule(target_topic="tetragon.process", category="Persistence", rule_name="Kernel Module Load", conditions=[{"field": "process.syscall", "op": "in", "value": ["init_module", "finit_module"]}], detection_method="advanced_json", base_score=70, severity="Critical", mitre_technique_id="T1547.006", mitre_tactic="Persistence", description="비인가 커널 모듈 삽입 탐지.")
    ]

    # 7. WordPress 특화 (WP)
    wordpress_rules = [
        DetectionRule(target_topic="tetragon.network", category="Credential Access", rule_name="WordPress Login Brute Force", conditions=[{"field": "network.http_uri", "op": "contains", "value": "/wp-login.php"}], detection_method="advanced_json", base_score=25, severity="Medium", mitre_technique_id="T1110.001", mitre_tactic="Credential Access", description="WP 로그인 무차별 대입 탐지."),
        DetectionRule(target_topic="tetragon.process", category="Initial Access", rule_name="WordPress Plugin RCE via Child Process", conditions=[{"field": "process.parent_args", "op": "contains", "value": "/wp-content/plugins/"}], detection_method="advanced_json", base_score=45, severity="High", mitre_technique_id="T1190", mitre_tactic="Initial Access", description="WP 플러그인 RCE 의심 행위 탐지.")
    ]

    # 합산 및 중복 방지 삽입
    all_new_rules = process_rules + privilege_rules + network_rules + file_rules + cloud_rules + kernel_rules + wordpress_rules
    inserted = 0
    for rule in all_new_rules:
        if not db.query(DetectionRule).filter(DetectionRule.rule_name == rule.rule_name).first():
            db.add(rule)
            inserted += 1

    all_rules = initial_access_rules + discovery_credential_rules + persistence_escalation_rules + defense_evasion_rules + exfiltration_impact_rules+process_rules+privilege_rules+network_rules+file_rules+cloud_rules+kernel_rules+wordpress_rules

    try:
        db.add_all(all_rules)
        db.commit()
        print(f"✅ {len(all_rules)}개의 탐지 룰 최적화 점수 반영 완료")
    except Exception as e:
        db.rollback()
        print(f"❌ Error during seeding: {e}")

if __name__ == "__main__":
    seed_db()