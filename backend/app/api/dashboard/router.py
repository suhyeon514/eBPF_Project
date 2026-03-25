# app/dashboard/router.py
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List
from .service import DashboardService
from ...database import get_db
from ...schemas import TopAlertResponse
from ..auth.service import get_current_user

router = APIRouter(prefix="/api/v1/dashboard", tags=["대시보드"])

@router.get("/top-alerts", response_model=List[TopAlertResponse])
def read_top_alerts(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    # 1. 먼저 최신 데이터를 동기화 (실무에선 스케줄러가 따로 돌지만, 일단 여기 포함)
    DashboardService.sync_alerts_from_os(db)
    
    # 2. DB에서 상위 5개 반환
    return DashboardService.get_top_5_alerts(db)

@router.get("/stats")
def read_dashboard_stats(current_user=Depends(get_current_user)):
    # 목업용 임시 데이터 (나중에 DB 쿼리로 대체 가능)
    return {
        "critical_alerts": 12,
        "unassigned_alerts": 48,
        "active_agents": 1240,
        "status_score": 92
    }