import os
import uuid
import random
import bcrypt
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from opensearchpy import OpenSearch

# 프로젝트 내부 모듈 임포트
from .database import SessionLocal, engine, Base
from .models import User, Role
# 주의: Assets는 이 시점의 모델에 없었으므로 임포트하지 않거나, 
# 만약 이미 models.py에 추가했다면 아래 코드를 실행할 때 테이블만 생성됩니다.

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
                password_hash=get_password_hash("[관리자 비밀번호]"),
                full_name="관리자",
                role_id=admin_role.id,
                email="admin@example.com"
            )
            db.add(admin_user)
            db.commit()
        
        print("✅ PostgreSQL 설정 완료")

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

if __name__ == "__main__":
    seed_db()