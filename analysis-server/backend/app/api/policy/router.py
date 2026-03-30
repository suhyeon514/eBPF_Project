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

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ... import schemas
from . import service
from app.database import get_db
from app import models

router = APIRouter(
    prefix="/api/v1/policy",
    tags=["정책"]
)

# 🔥 정책 체크 (항상 내려줌)
@router.post("/check-update")
def check_policy_update(payload: schemas.PolicyCheckUpdateRequest):

    server_hash = service.get_current_policy_hash()
    new_policy = service.get_policy_data()

    return {
        "update_required": True,
        "new_hash": server_hash,
        "new_policy": new_policy,
        "message": f"강제 정책 동기화 (hash: {server_hash})"
    }


# =========================
# 정책 조회
# =========================
@router.get("/rules")
def get_rules(db: Session = Depends(get_db)):
    return db.query(models.DetectionRule).all()


# =========================
# 정책 추가
# =========================
@router.post("/rules")
def create_rule(rule: dict, db: Session = Depends(get_db)):

    new_rule = models.DetectionRule(
        target_topic=rule["target_topic"],
        rule_name=rule["rule_name"],
        conditions=rule["conditions"],
        base_score=rule["base_score"],
        severity=rule["severity"],
        mitre_tactic=rule.get("mitre_tactic"),
        is_active=True
    )

    db.add(new_rule)
    db.commit()
    db.refresh(new_rule)

    return new_rule


# =========================
# 정책 삭제
# =========================
@router.delete("/rules/{rule_id}")
def delete_rule(rule_id: int, db: Session = Depends(get_db)):

    rule = db.query(models.DetectionRule).filter(
        models.DetectionRule.rule_id == rule_id
    ).first()

    if not rule:
        return {"error": "not found"}

    db.delete(rule)
    db.commit()

    return {"message": "deleted"}
