import os
from pathlib import Path
from datetime import datetime, timezone
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text
from neo4j import GraphDatabase
from datetime import timedelta
from .core.config import os_client
from .database import engine, get_db, SessionLocal
from . import models
# 분리한 라우터 임포트
from .api.auth.router import router as auth_router
from .api.dashboard.router import router as dashboard_router
from .api.assets.router import router as assets_router
from .api.dashboard.service import DashboardService
from apscheduler.schedulers.background import BackgroundScheduler
from .api.policy.router import router as policy_router  # 정책 라우터 임포트
from .api.forensic.router import router as forensic_router  # 포렌식 라우터 임포트
from .api.enroll.router import router as enroll_router      # 등록 라우터 임포트
from .api.runtime.router import router as runtime_router    # 런타임 정책 라우터 임포트
from .api.agent.router import router as agent_router        # 에이전트 heartbeat 라우터
from .api.artifacts.router import router as artifacts_router  # 아티팩트 배포 라우터
from .core.ca import init_ca

env_path = Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

app = FastAPI(title="K9")

# 테스트용 ip 
ALLOWED_IPS = os.getenv("ALLOWED_IPS", "0.0.0.0,127.0.0.1,::1").split(",")

@app.middleware("http")
async def ip_filter_middleware(request: Request, call_next):
    # 프론트엔드(5173, 5174 등)에서 POST 전송 전, 서버가 허용하는지 찌르는 'OPTIONS' 요청 처리
    # 브라우저의 사전 요청(Preflight) 프리패스를 허용하여 CORS 정책을 우회할 수 있도록 처리 
    if request.method == "OPTIONS":
        return await call_next(request)

    # 토큰 기반 승인/거부, 에이전트 heartbeat, 아티팩트 다운로드는 IP 제한 없이 허용
    if request.url.path in ("/api/v1/enroll/approve", "/api/v1/enroll/reject", "/api/v1/agent/heartbeat") \
            or request.url.path.startswith("/api/v1/artifacts/"):
        return await call_next(request)

    client_ip = request.client.host

    # 0.0.0.0 이 포함되어 있다면 모든 IP 허용이므로 검사 패스
    if "0.0.0.0" in ALLOWED_IPS:
        return await call_next(request)

    if client_ip not in ALLOWED_IPS:
        print(f"[IP Filter] 차단된 IP 접근 시도: {client_ip}")
        return JSONResponse(status_code=403, content={"detail": "접근이 거부되었습니다."})
    
    response = await call_next(request)
    return response

# DB 테이블 생성
models.Base.metadata.create_all(bind=engine)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5174"],
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
# 포렌식 명령 라우터 추가
app.include_router(forensic_router)
# 에이전트 등록 라우터 추가
app.include_router(enroll_router)
# 런타임 정책 라우터 추가
app.include_router(runtime_router)
# 에이전트 heartbeat 라우터 추가
app.include_router(agent_router)
# 아티팩트 배포 라우터 추가
app.include_router(artifacts_router)

# --- 인프라 설정 및 Health Check (기존 코드 유지) ---

NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"

# --- [스케줄러 설정] ---
def update_dashboard_task():
    db = SessionLocal()
    try:
        print(f"🔄 [Sync] 대시보드 데이터 동기화 시작 ({datetime.now()})")
        DashboardService.sync_alerts_from_os(db)
    finally:
        db.close()


def mark_offline_agents_task():
    """마지막 heartbeat로부터 5분 이상 지난 에이전트를 오프라인으로 표시."""
    db = SessionLocal()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
        stale = db.query(models.Assets).filter(
            models.Assets.status != "오프라인",
            models.Assets.last_heartbeat < cutoff,
        ).all()
        for agent in stale:
            agent.status = "오프라인"
            print(f"📴 [Offline] {agent.hostname} → 오프라인 처리")
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