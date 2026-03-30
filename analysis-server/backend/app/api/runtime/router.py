from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import Optional

from ...database import get_db
from ...schemas import RuntimePolicyResponse
from .service import RuntimeService

router = APIRouter(prefix="/api/v1/runtime", tags=["런타임 정책(RuntimePolicy)"])


@router.get("/policy/current", response_model=RuntimePolicyResponse)
def get_current_runtime_policy(
    agent_id: Optional[str] = None,
    install_uuid: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """승인된 에이전트의 초기 런타임 정책 반환."""
    return RuntimeService.get_policy_for_agent(db, agent_id, install_uuid)
