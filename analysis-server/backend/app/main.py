import os
from pathlib import Path
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text
from neo4j import GraphDatabase
from apscheduler.schedulers.background import BackgroundScheduler

from .core.config import os_client
from .database import engine, get_db, SessionLocal
from . import models

# ✅ 존재하는 라우터만 import
from .api.auth.router import router as auth_router
from .api.dashboard.router import router as dashboard_router
from .api.assets.router import router as assets_router
from .api.policy.router import router as policy_router
from .api.forensic.router import router as forensic_router

from .api.dashboard.service import DashboardService
from .core.ca import init_ca

from .api.analysis.router import router as analysis_router

env_path = Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

app = FastAPI(title="K9")

ALLOWED_IPS = os.getenv("ALLOWED_IPS", "0.0.0.0,127.0.0.1,::1").split(",")

@app.middleware("http")
async def ip_filter_middleware(request: Request, call_next):
    if request.method == "OPTIONS":
        return await call_next(request)

    client_ip = request.client.host

    if "0.0.0.0" in ALLOWED_IPS:
        return await call_next(request)

    if client_ip not in ALLOWED_IPS:
        return JSONResponse(status_code=403, content={"detail": "접근이 거부되었습니다."})

    return await call_next(request)

# ✅ DB 초기화 (안전 처리)
if engine:
    try:
        models.Base.metadata.create_all(bind=engine)
        print("✅ DB 테이블 생성 완료")
    except Exception as e:
        print("⚠️ DB 초기화 실패:", e)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5174"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ 존재하는 라우터만 등록
app.include_router(auth_router)
app.include_router(dashboard_router)
app.include_router(assets_router)
app.include_router(policy_router)
app.include_router(forensic_router)

NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"

# ✅ DB 없으면 스킵
def update_dashboard_task():
    if not SessionLocal:
        return
    db = SessionLocal()
    try:
        DashboardService.sync_alerts_from_os(db)
    finally:
        db.close()

def mark_offline_agents_task():
    if not SessionLocal:
        return
    db = SessionLocal()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
        stale = db.query(models.Assets).filter(
            models.Assets.status != "오프라인",
            models.Assets.last_heartbeat < cutoff,
        ).all()
        for agent in stale:
            agent.status = "오프라인"
        if stale:
            db.commit()
    finally:
        db.close()

scheduler = BackgroundScheduler()
scheduler.add_job(update_dashboard_task, 'interval', minutes=1)
scheduler.add_job(mark_offline_agents_task, 'interval', minutes=1)
scheduler.start()

@app.on_event("startup")
def startup_event():
    init_ca()

@app.on_event("shutdown")
def shutdown_event():
    scheduler.shutdown()

@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    status = {"postgresql": "🔴 실패", "opensearch": "🔴 실패", "neo4j": "🔴 실패"}

    try:
        if db:
            db.execute(text("SELECT 1"))
            status["postgresql"] = "🟢 성공"
    except:
        pass

    try:
        if os_client.ping():
            status["opensearch"] = "🟢 성공"
    except:
        pass

    try:
        with GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD)) as driver:
            driver.verify_connectivity()
            status["neo4j"] = "🟢 성공"
    except:
        pass

    return status

app.include_router(analysis_router)
