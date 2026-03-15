from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine
from opensearchpy import OpenSearch
import logging

app = FastAPI()

# CORS 설정 (React 연동용)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# 1. PostgreSQL 연결 설정 (6432 포트 사용)
PG_URL = "postgresql://admin:goo42_3jo_Ming!@localhost:6432/ebpf_db"
engine = create_engine(PG_URL)

# 2. OpenSearch 연결 설정 (보안 비활성화 모드)
os_client = OpenSearch(hosts=[{"host": "localhost", "port": 9200}], use_ssl=False)

@app.get("/health")
def health_check():
    status = {"postgresql": "🔴 연결 실패", "opensearch": "🔴 연결 실패"}
    
    # PostgreSQL 체크
    try:
        with engine.connect() as connection:
            status["postgresql"] = "🟢 연결 성공!"
    except Exception as e:
        print(f"❌ PostgreSQL 연결 에러 발생: {e}") 

    # OpenSearch 체크
    try:
        if os_client.ping():
            status["opensearch"] = "🟢 연결 성공!"
    except Exception: pass

    return status