# app/dashboard/router.py
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, or_
from typing import List, Optional
from .service import DashboardService
from ...database import get_db
from ...schemas import TopAlertResponse
from ...models import TopAlert, Assets
from ..auth.service import get_current_user

router = APIRouter(prefix="/api/v1/dashboard", tags=["대시보드"])

@router.get("/top-alerts", response_model=List[TopAlertResponse])
def read_top_alerts(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    return DashboardService.get_top_5_alerts(db)

@router.get("/stats")
def read_dashboard_stats(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    # 심각 알람 (CRITICAL + pending)
    critical_count = db.query(func.count(TopAlert.id)).filter(
        TopAlert.severity == "CRITICAL",
        TopAlert.status == "pending"
    ).scalar() or 0

    # 미배정 알람 (전체 pending)
    unassigned_count = db.query(func.count(TopAlert.id)).filter(
        TopAlert.status == "pending"
    ).scalar() or 0

    # 활성 에이전트 (오프라인 제외)
    active_agents = db.query(func.count(Assets.id)).filter(
        Assets.status != "오프라인"
    ).scalar() or 0

    total_agents = db.query(func.count(Assets.id)).scalar() or 0
    total_alerts = db.query(func.count(TopAlert.id)).scalar() or 0

    # 에이전트 가동률 (0.0 ~ 1.0)
    online_ratio = active_agents / total_agents if total_agents > 0 else 1.0

    # 알람 해결률 (pending이 없을수록 높음)
    resolved_ratio = (total_alerts - unassigned_count) / total_alerts if total_alerts > 0 else 1.0

    # 상태 점수 계산 (0 ~ 100)
    # 에이전트 건강도 40% + 알람 해결률 60% - 크리티컬 페널티 (최대 30점)
    raw_score = online_ratio * 40 + resolved_ratio * 60 - min(critical_count * 5, 30)
    status_score = max(0, min(100, round(raw_score)))

    return {
        "critical_alerts": critical_count,
        "unassigned_alerts": unassigned_count,
        "active_agents": active_agents,
        "total_agents": total_agents,
        "online_ratio": round(online_ratio * 100, 1),
        "status_score": status_score,
    }


@router.get("/alerts", response_model=dict)
def read_alerts(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=100),
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    q = db.query(TopAlert)
    if severity:
        q = q.filter(TopAlert.severity == severity)
    if status:
        q = q.filter(TopAlert.status == status)
    if search:
        q = q.filter(
            or_(
                TopAlert.alert_name.ilike(f"%{search}%"),
                TopAlert.host_info.ilike(f"%{search}%"),
            )
        )
    total = q.count()
    items = q.order_by(TopAlert.event_time.desc()).offset((page - 1) * size).limit(size).all()
    return {
        "total": total,
        "page": page,
        "size": size,
        "items": [TopAlertResponse.from_orm(item) for item in items],
    }