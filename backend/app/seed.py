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
                password_hash=get_password_hash("ADMIN"),
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
    K9 플랫폼 초기 탐지 룰 데이터 삽입 (Seed Data)
    """
    
    # 1. 초기 침투 및 실행 (Initial Access & Execution) 그룹 룰 정의
    initial_access_rules = [
        DetectionRule(
            target_topic="tetragon.process",
            category="Initial Access & Execution",
            rule_name="Web Server Spawning Shell",
            conditions=[
                {"field": "process.parent_comm", "op": "contains", "value": "nginx"},
                {"field": "process.comm", "op": "in", "value": ["sh", "bash", "dash", "zsh"]}
            ],
            detection_method="advanced_json",
            base_score=60,
            severity="High",
            mitre_technique_id="T1190",
            mitre_tactic="Initial Access",
            reference_url="https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_web_server_shell.yml",
            description="Nginx 웹 서버 프로세스 하위에서 쉘이 실행되었습니다. 웹 취약점(RCE)을 통한 침투가 강력히 의심됩니다."
        ),
        DetectionRule(
            target_topic="tetragon.process",
            category="Execution",
            rule_name="Base64 Encoded Command Execution",
            conditions=[
                {"field": "process.args", "op": "contains", "value": "base64"},
                {"field": "process.args", "op": "contains", "value": "-d"}
            ],
            detection_method="advanced_json",
            base_score=75,
            severity="Critical",
            mitre_technique_id="T1059.004",
            mitre_tactic="Execution",
            description="인코딩된 명령어가 실행되었습니다. 탐지 우회를 시도하는 악성 스크립트일 가능성이 높습니다."
        ),
        DetectionRule(
            target_topic="tetragon.process",
            category="Execution",
            rule_name="Execution from Suspicious Directory",
            conditions=[
                {"field": "process.exe", "op": "startswith_list", "value": ["/tmp/", "/dev/shm/", "/var/tmp/"]}
            ],
            detection_method="advanced_json",
            base_score=70,
            severity="High",
            mitre_technique_id="T1059",
            mitre_tactic="Execution",
            description="임시 디렉토리(/tmp 등)에서 실행 파일이 포착되었습니다. 악성코드 드롭 후 실행되는 전형적인 패턴입니다."
        ),
        DetectionRule(
            target_topic="tetragon.process",
            category="Initial Access & Discovery",
            rule_name="Web Server System Discovery",
            conditions=[
                {"field": "process.parent_comm", "op": "contains", "value": "nginx"},
                {"field": "process.comm", "op": "in", "value": ["id", "whoami", "hostname", "uname"]}
            ],
            detection_method="advanced_json",
            base_score=60,
            severity="High",
            mitre_technique_id="T1087",
            mitre_tactic="Discovery",
            description="웹 서버 권한으로 시스템 정찰 명령이 수행되었습니다. 침투 성공 후 초기 정보 수집 단계로 판단됩니다."
        ),
        DetectionRule(
            target_topic="tetragon.process",
            category="Execution",
            rule_name="Hidden File Execution",
            conditions=[
                {"field": "process.comm", "op": "startswith", "value": "."}
            ],
            detection_method="advanced_json",
            base_score=50,
            severity="Medium",
            mitre_technique_id="T1564.001",
            mitre_tactic="Defense Evasion",
            description="숨김 파일(.) 형태의 바이너리가 실행되었습니다. 시스템 내 은폐를 시도하는 악성 프로세스일 수 있습니다."
        )
    ]

    # 2. 내부 탐색 및 자격 증명 탈취 (Discovery & Credential Access)
    discovery_credential_rules = [
        DetectionRule(
            target_topic="tetragon.process",
            category="Discovery & Credential Access",
            rule_name="WordPress Config Access",
            conditions=[
                {"field": "process.args", "op": "contains", "value": "wp-config.php"},
                {"field": "process.comm", "op": "in", "value": ["cat", "grep", "vi", "nano"]}
            ],
            detection_method="advanced_json",
            base_score=75,
            severity="High",
            mitre_technique_id="T1552.001",
            mitre_tactic="Credential Access",
            description="WordPress 설정 파일(wp-config.php)에 접근 시도가 탐지되었습니다. DB 자격 증명 유출 위험이 있습니다."
        ),
        DetectionRule(
            target_topic="tetragon.process",
            category="Discovery",
            rule_name="System User Discovery",
            conditions=[
                {"field": "process.comm", "op": "in", "value": ["whoami", "id", "groups", "last"]}
            ],
            detection_method="advanced_json",
            base_score=40,
            severity="Medium",
            mitre_technique_id="T1087.001",
            mitre_tactic="Discovery",
            reference_url="https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_user_discovery.yml",
            description="사용자 계정 및 권한 정보를 확인하는 명령이 실행되었습니다. 시스템 정찰 행위로 판단됩니다."
        ),
        DetectionRule(
            target_topic="tetragon.process",
            category="Discovery",
            rule_name="Network Configuration Discovery",
            conditions=[
                {"field": "process.comm", "op": "in", "value": ["ifconfig", "ip", "netstat", "ss", "route"]}
            ],
            detection_method="advanced_json",
            base_score=40,
            severity="Medium",
            mitre_technique_id="T1016",
            mitre_tactic="Discovery",
            description="네트워크 설정 및 연결 상태를 확인하는 명령이 실행되었습니다. 내부 이동을 위한 정찰 활동일 수 있습니다."
        ),
        DetectionRule(
            target_topic="tetragon.process",
            category="Credential Access",
            rule_name="Shadow File Read Attempt",
            conditions=[
                {"field": "process.args", "op": "contains", "value": "/etc/shadow"}
            ],
            detection_method="advanced_json",
            base_score=90,
            severity="Critical",
            mitre_technique_id="T1003.008",
            mitre_tactic="Credential Access",
            description="민감한 계정 정보 파일(/etc/shadow)에 대한 접근 시도가 탐지되었습니다. 비밀번호 크래킹 시도로 보입니다."
        ),
        DetectionRule(
            target_topic="tetragon.process",
            category="Discovery",
            rule_name="Process Listing Discovery",
            conditions=[
                {"field": "process.comm", "op": "in", "value": ["ps", "top", "htop"]}
            ],
            detection_method="advanced_json",
            base_score=40,
            severity="Medium",
            mitre_technique_id="T1057",
            mitre_tactic="Discovery",
            description="실행 중인 프로세스 목록을 조회했습니다. 시스템 환경 및 보안 솔루션 탐색 행위입니다."
        )
    ]

    # 3. 권한 상승 및 지속성 유지
    persistence_escalation_rules = [
        # 1. Sudoers 파일 변조 (Persistence / Priv Esc)
        DetectionRule(
            target_topic="tetragon.process",
            category="Persistence & Privilege Escalation",
            rule_name="Sudoers Modification via Command Line",
            conditions=[
                {"field": "process.args", "op": "contains", "value": "/etc/sudoers"},
                {"field": "process.comm", "op": "in", "value": ["echo", "sed", "tee", "visudo"]}
            ],
            detection_method="advanced_json",
            base_score=90,
            severity="Critical",
            mitre_technique_id="T1548.003",
            mitre_tactic="Persistence",
            reference_url="https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_sudoers_modification.yml",
            description="권한 상승을 위해 sudoers 설정 파일을 직접 수정하려는 시도가 탐지되었습니다."
        ),
        
        # 2. 크론탭을 이용한 지속성 확보 (Persistence)
        DetectionRule(
            target_topic="tetragon.process",
            category="Persistence",
            rule_name="Scheduled Task Creation via Crontab",
            conditions=[
                {"field": "process.comm", "op": "equal", "value": "crontab"},
                {"field": "process.args", "op": "contains", "value": "-e"}
            ],
            detection_method="advanced_json",
            base_score=70,
            severity="High",
            mitre_technique_id="T1053.003",
            mitre_tactic="Persistence",
            description="crontab을 이용한 예약 작업 등록이 포착되었습니다. 악성 코드의 자동 재실행을 위한 설정일 수 있습니다."
        ),

        # 3. 비정상 서비스 등록 (Persistence)
        DetectionRule(
            target_topic="tetragon.process",
            category="Persistence",
            rule_name="Suspicious Service Unit Creation",
            conditions=[
                {"field": "process.comm", "op": "equal", "value": "systemctl"},
                {"field": "process.args", "op": "contains", "value": "enable"}
            ],
            detection_method="advanced_json",
            base_score=75,
            severity="High",
            mitre_technique_id="T1543.002",
            mitre_tactic="Persistence",
            description="systemd 유닛 등록을 통해 시스템 서비스로 백도어를 유지하려는 행위가 의심됩니다."
        ),

        # 4. SUID 바이너리 악용 (Privilege Escalation)
        DetectionRule(
            target_topic="tetragon.process",
            category="Privilege Escalation",
            rule_name="Abuse of Setuid Binaries",
            conditions=[
                {"field": "process.comm", "op": "in", "value": ["find", "python", "perl", "lua"]},
                {"field": "process.args", "op": "contains", "value": "exec"}
            ],
            detection_method="advanced_json",
            base_score=85,
            severity="Critical",
            mitre_technique_id="T1548.001",
            mitre_tactic="Privilege Escalation",
            description="SUID 권한이 설정된 정상 도구(find 등)를 이용해 루트 권한으로 명령을 실행하려는 시도입니다."
        ),

        # 5. 권한 조사 행위 (Discovery / Priv Esc)
        DetectionRule(
            target_topic="tetragon.process",
            category="Privilege Escalation",
            rule_name="Capabilities Discovery",
            conditions=[
                {"field": "process.comm", "op": "equal", "value": "getcap"},
                {"field": "process.args", "op": "contains", "value": "-r"}
            ],
            detection_method="advanced_json",
            base_score=65,
            severity="High",
            mitre_technique_id="T1611",
            mitre_tactic="Privilege Escalation",
            reference_url="https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_capabilities_discovery.yml",
            description="권한 상승이나 컨테이너 탈출을 위해 시스템의 특수 권한(Capabilities)을 정찰 중입니다."
        )
    ]

    # 4. 방어 회피 (Defense Evasion) - Sigma HQ Rules 기반 설계
    defense_evasion_rules = [
        DetectionRule(
            target_topic="tetragon.process",
            category="Defense Evasion",
            rule_name="Bash History Indicator Removal",
            conditions=[
                {"field": "process.comm", "op": "in", "value": ["rm", "truncate"]},
                {"field": "process.args", "op": "contains", "value": ".bash_history"}
            ],
            detection_method="advanced_json",
            base_score=80,
            severity="High",
            mitre_technique_id="T1070.003",
            mitre_tactic="Defense Evasion",
            reference_url="https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_susp_histfile_operations.yml",
            description="쉘 명령 기록 파일(.bash_history)에 대한 삭제 또는 변조 시도가 탐지되었습니다. 침투 흔적 인멸 행위로 의심됩니다."
        ),
        DetectionRule(
            target_topic="tetragon.process",
            category="Defense Evasion",
            rule_name="File Timestomping via Touch",
            conditions=[
                {"field": "process.comm", "op": "equal", "value": "touch"},
                {"field": "process.args", "op": "in", "value": ["-r", "-t", "--timestamp"]}
            ],
            detection_method="advanced_json",
            base_score=60,
            severity="Medium",
            mitre_technique_id="T1070.006",
            mitre_tactic="Defense Evasion",
            reference_url="https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_change_file_time_attr.yml",
            description="touch 명령어를 이용한 파일 타임스탬프 조작이 탐지되었습니다. 포렌식 분석을 방해하려는 시도일 수 있습니다."
        ),
        DetectionRule(
            target_topic="tetragon.process",
            category="Defense Evasion",
            rule_name="Immutable Attribute Removal",
            conditions=[
                {"field": "process.comm", "op": "equal", "value": "chattr"},
                {"field": "process.args", "op": "contains", "value": "-i"}
            ],
            detection_method="advanced_json",
            base_score=75,
            severity="High",
            mitre_technique_id="T1222.002",
            mitre_tactic="Defense Evasion",
            reference_url="https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_chattr_immutable_removal.yml",
            description="파일의 불변(Immutable) 속성 강제 제거가 탐지되었습니다. 시스템 보호 설정 무력화 시도가 의심됩니다."
        ),
        DetectionRule(
            target_topic="tetragon.process",
            category="Defense Evasion",
            rule_name="Audit Service Tampering",
            conditions=[
                {"field": "process.comm", "op": "in", "value": ["systemctl", "service"]},
                {"field": "process.args", "op": "contains", "value": "stop"},
                {"field": "process.args", "op": "contains", "value": "auditd"}
            ],
            detection_method="advanced_json",
            base_score=90,
            severity="Critical",
            mitre_technique_id="T1562.001",
            mitre_tactic="Defense Evasion",
            description="보안 감사 서비스(auditd) 중단 시도가 탐지되었습니다. 시스템 감시 체계를 무력화하려는 고위험 공격 행위입니다."
        ),
        DetectionRule(
            target_topic="tetragon.process",
            category="Defense Evasion",
            rule_name="Hidden Files and Directories Creation",
            conditions=[
                {"field": "process.args", "op": "contains", "value": "/. "},  # 숨김 폴더 생성 패턴
                {"field": "process.comm", "op": "in", "value": ["mkdir", "touch"]}
            ],
            detection_method="advanced_json",
            base_score=50,
            severity="Medium",
            mitre_technique_id="T1564.001",
            mitre_tactic="Defense Evasion",
            reference_url="https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_hidden_files_directories.yml",
            description="시스템 내 숨김 디렉토리 또는 파일 생성이 탐지되었습니다. 악성 코드나 유출 데이터를 은닉하기 위한 시도일 수 있습니다."
        )
    ]

    exfiltration_impact_rules = [
        # 1. 유출용 데이터 압축 (Exfiltration)
        DetectionRule(
            target_topic="tetragon.process",
            category="Exfiltration",
            rule_name="Data Compressed for Exfiltration",
            conditions=[
                {"field": "process.comm", "op": "in", "value": ["tar", "zip", "gzip", "7z"]},
                {"field": "process.args", "op": "contains", "value": "/var/www/html"} # 웹 루트 압축 감시
            ],
            detection_method="advanced_json",
            base_score=55,
            severity="Medium",
            mitre_technique_id="T1560.001",
            mitre_tactic="Exfiltration",
            reference_url="https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_data_compressed.yml",
            description="웹 루트 디렉토리를 압축하려는 시도가 탐지되었습니다. 데이터 유출을 위한 사전 준비일 수 있습니다."
        ),
        
        # 2. 웹 도구를 이용한 데이터 유출 (Exfiltration)
        DetectionRule(
            target_topic="tetragon.process",
            category="Exfiltration",
            rule_name="Data Exfiltration via Wget/Curl",
            conditions=[
                {"field": "process.comm", "op": "in", "value": ["curl", "wget"]},
                {"field": "process.args", "op": "contains_any", "value": ["--post-data", "--post-file", "--upload-file"]}
            ],
            detection_method="advanced_json",
            base_score=80,
            severity="High",
            mitre_technique_id="T1048.003",
            mitre_tactic="Exfiltration",
            reference_url="https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_data_exfil_wget.yml",
            description="curl 또는 wget을 이용해 데이터를 외부 서버로 전송하려는 시도가 탐지되었습니다."
        ),

        # 3. 데이터베이스 덤프 접근 (Collection / Exfiltration)
        DetectionRule(
            target_topic="tetragon.process",
            category="Exfiltration",
            rule_name="Sensitive Database Dump Access",
            conditions=[
                {"field": "process.args", "op": "contains", "value": ".sql"},
                {"field": "process.comm", "op": "in", "value": ["cat", "grep", "tar"]}
            ],
            detection_method="advanced_json",
            base_score=85,
            severity="Critical",
            mitre_technique_id="T1530",
            mitre_tactic="Exfiltration",
            description="데이터베이스 덤프 파일(.sql)에 대한 비정상적인 접근이 탐지되었습니다. 기밀 데이터 유출 위험이 매우 높습니다."
        ),

        # 4. 핵심 서비스 중단 (Impact)
        DetectionRule(
            target_topic="tetragon.process",
            category="Impact",
            rule_name="Service Disruption (Stop/Disable)",
            conditions=[
                {"field": "process.comm", "op": "equal", "value": "systemctl"},
                {"field": "process.args", "op": "contains", "value": "stop"},
                {"field": "process.args", "op": "contains_any", "value": ["nginx", "mysql", "mariadb", "php-fpm"]}
            ],
            detection_method="advanced_json",
            base_score=75,
            severity="High",
            mitre_technique_id="T1489",
            mitre_tactic="Impact",
            description="Nginx 또는 DB와 같은 핵심 웹 서비스의 중단 시도가 탐지되었습니다. 가용성 침해 공격(DoS)일 수 있습니다."
        ),

        # 5. 시스템 강제 종료/재부팅 (Impact)
        DetectionRule(
            target_topic="tetragon.process",
            category="Impact",
            rule_name="Unauthorized System Shutdown/Reboot",
            conditions=[
                {"field": "process.comm", "op": "in", "value": ["reboot", "shutdown", "halt", "poweroff"]}
            ],
            detection_method="advanced_json",
            base_score=90,
            severity="Critical",
            mitre_technique_id="T1529",
            mitre_tactic="Impact",
            reference_url="https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_system_shutdown_reboot.yml",
            description="인가되지 않은 시스템 종료 또는 재부팅 명령이 실행되었습니다. 서비스 전체 마비 및 데이터 파괴 위험이 있습니다."
        )
    ]
    # --- 기존에 정의된 다른 그룹의 룰이 있다면 여기에 추가 가능 ---
    all_rules = initial_access_rules + discovery_credential_rules + persistence_escalation_rules + defense_evasion_rules + exfiltration_impact_rules
    # -----------------------------------------------------

    try:
        # 중복 방지를 위해 기존 룰을 모두 삭제하거나, rule_name 기준으로 존재 여부 확인 후 삽입 권장
        # 여기서는 단순 add_all을 사용합니다.
        db.add_all(all_rules)
        db.commit()
        print(f"Successfully seeded {len(all_rules)} detection rules.")
    except Exception as e:
        db.rollback()
        print(f"Error during seeding: {e}")

if __name__ == "__main__":
    seed_db()