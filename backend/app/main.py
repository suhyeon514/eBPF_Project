import os
from pathlib import Path
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from neo4j import GraphDatabase
from sqlalchemy import text
from .core.config import os_client
from .database import engine, get_db
from . import models
# 분리한 라우터 임포트
from .api.auth.router import router as auth_router
from .api.dashboard.router import router as dashboard_router
from .api.assets.router import router as assets_router
from .api.policy.router import router as policy_router  # 정책 라우터 임포트

env_path = Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

app = FastAPI(title="K9")

# 테스트용 ip 
ALLOWED_IPS = os.getenv("ALLOWED_IPS", "0.0.0.0").split(",")

@app.middleware("http")
async def ip_filter_middleware(request: Request, call_next):
    client_ip = request.client.host
    if client_ip not in ALLOWED_IPS:
        return JSONResponse(status_code=403, content={"detail": "접근이 거부되었습니다."})
    response = await call_next(request)
    return response

# DB 테이블 생성
# models.Base.metadata.create_all(bind=engine)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# [라우터 등록] 분리한 인증 기능을 앱에 포함시킵니다.
app.include_router(auth_router)
app.include_router(dashboard_router)
app.include_router(assets_router)

# 정책 확인 라우터 추가
app.include_router(policy_router)

# --- 인프라 설정 및 Health Check (기존 코드 유지) ---

NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"

@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    status = {"postgresql": "🔴 실패", "opensearch": "🔴 실패", "neo4j": "🔴 실패"}
    try:
        db.execute(text("SELECT 1"))
        status["postgresql"] = "🟢 성공"
    except: pass
    try:
        if os_client.ping(): status["opensearch"] = "🟢 성공"
    except: pass
    try:
        with GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD)) as driver:
            driver.verify_connectivity()
            status["neo4j"] = "🟢 성공"
    except: pass
    return status