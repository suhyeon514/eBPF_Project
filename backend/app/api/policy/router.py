from fastapi import APIRouter, Depends, Query
from typing import Optional
from sqlalchemy.orm import Session
from ... import schemas
from . import service
from ..auth.service import get_current_user
from ...database import get_db
from ...models import EnrollmentRequest

router = APIRouter(
    prefix="/api/v1/policy",
    tags=["정책 확인(Policy Check)"]
)

@router.post("/check-update")
def check_policy_update(payload: schemas.PolicyCheckUpdateRequest):
    """
    에이전트의 정책 해시값을 서버의 최신 해시값과 비교하여 업데이트 여부를 알려줍니다.
    """
    server_hash = service.get_current_policy_hash()
    
    # 해시값이 같다면 업데이트 불필요
    if payload.agent_hash == server_hash:
        # return {"update_required": False, "message": "가장 최신 정책을 유지 중. 업데이트 필요 없음."}
        return {"update_required": False, "message": f"가장 최신 정책을 유지 중. 업데이트 필요 없음. (해시: {server_hash})"}
    # 해시값이 다르다면 새로운 정책 데이터 반환
    new_policy = service.get_policy_data()
    return {
        "update_required": True,
        "new_hash": server_hash,
        "new_policy": new_policy,
        "message": f"새로운 정책이 업데이트 되었습니다. 에이전트의 정책을 업데이트했습니다. (해시: {server_hash})"
}


@router.get("/check-update")
def check_policy_update_get(
    agent_id: str = Query(..., description="에이전트 ID"),
    current_version: Optional[str] = Query(default=None, description="에이전트가 현재 가진 정책 해시"),
    db: Session = Depends(get_db),
):
    """
    스펙 준수 GET 버전: agent_id + current_version(해시) 기반 정책 업데이트 확인.
    업데이트 없으면 {"updated": false}, 있으면 {"updated": true, "policy_yaml": ..., ...}
    """
    server_hash = service.get_current_policy_hash()

    # agent_id로 assigned_env / assigned_role 조회
    record = db.query(EnrollmentRequest).filter(EnrollmentRequest.agent_id == agent_id).first()
    assigned_env = record.assigned_env if record else None
    assigned_role = record.assigned_role if record else None

    if current_version and current_version == server_hash:
        return {"updated": False, "version": server_hash, "assigned_env": assigned_env, "assigned_role": assigned_role}

    return {
        "updated": True,
        "version": server_hash,
        "policy_yaml": service.get_policy_data(),
        "assigned_env": assigned_env,
        "assigned_role": assigned_role,
    }


@router.get("/content")
def get_policy_content(current_user=Depends(get_current_user)):
    """관리자용: 현재 정책 YAML 내용 및 해시값 반환."""
    return {
        "content": service.get_policy_data(),
        "hash": service.get_current_policy_hash(),
    }