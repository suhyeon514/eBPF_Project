import os
from pathlib import Path
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# .env 로드
env_path = Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

POSTGRES_USER = os.getenv("POSTGRES_USER", "admin")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD")
POSTGRES_DB = os.getenv("POSTGRES_DB", "ebpf_db")

# DB URL 구성
SQLALCHEMY_DATABASE_URL = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@localhost:5432/{POSTGRES_DB}"

# 🔥 핵심: DB 연결 실패해도 서버 안 죽게 처리
engine = None
SessionLocal = None

try:
    engine = create_engine(SQLALCHEMY_DATABASE_URL)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    print("✅ PostgreSQL 연결 성공")
except Exception as e:
    print("⚠️ DB 연결 실패 - DB 없이 실행:", e)

Base = declarative_base()

# DB 세션 의존성 함수
def get_db():
    if SessionLocal is None:
        # DB 없을 때는 None 반환
        yield None
        return

    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
