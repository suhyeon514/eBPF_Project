from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from ...database import get_db
from ...models import Assets
from ...schemas import AgentHeartbeatRequest

router = APIRouter(prefix="/api/v1/agent", tags=["에이전트 상태"])


def _determine_status(cpu: float, memory: float) -> str:
    if cpu > 90 or memory > 90:
        return "위험"
    if cpu > 70 or memory > 70:
        return "주의"
    return "정상"


@router.post("/heartbeat")
def agent_heartbeat(payload: AgentHeartbeatRequest, db: Session = Depends(get_db)):
    """
    에이전트가 주기적으로 자신의 상태를 보고합니다.
    hostname 기준으로 Assets 테이블을 upsert 합니다.
    """
    status = _determine_status(payload.cpu_usage, payload.memory_usage)

    asset = db.query(Assets).filter(Assets.hostname == payload.hostname).first()

    if asset:
        asset.ip_address = payload.ip_address
        asset.cpu_usage = payload.cpu_usage
        asset.memory_usage = payload.memory_usage
        asset.status = status
        asset.last_heartbeat = datetime.now(timezone.utc)
        if payload.os_info:
            asset.os_info = payload.os_info
    else:
        asset = Assets(
            hostname=payload.hostname,
            ip_address=payload.ip_address,
            os_info=payload.os_info or "",
            cpu_usage=payload.cpu_usage,
            memory_usage=payload.memory_usage,
            status=status,
            risk_score=0,
            unassigned_alerts_count=0,
        )
        db.add(asset)

    db.commit()
    return {"status": "ok", "agent_status": status}
