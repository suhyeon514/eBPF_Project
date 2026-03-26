from fastapi import APIRouter
from ... import schemas
from . import service

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
        return {"update_required": False, "message": "가장 최신 정책을 유지 중. 업데이트 필요 없음."}
    
    # 해시값이 다르다면 새로운 정책 데이터 반환
    new_policy = service.get_policy_data()
    return {
        "update_required": True,
        "new_hash": server_hash,
        "new_policy": new_policy,
        "message": "새로운 정책이 업데이트 되었습니다. 에이전트의 정책을 업데이트했습니다."
}