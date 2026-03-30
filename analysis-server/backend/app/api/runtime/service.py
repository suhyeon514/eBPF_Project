from fastapi import HTTPException
from sqlalchemy.orm import Session

from ...models import EnrollmentRequest
from ...schemas import RuntimePolicyResponse
from ..policy.service import get_policy_data


class RuntimeService:

    @staticmethod
    def get_policy_for_agent(
        db: Session, agent_id: str | None, install_uuid: str | None
    ) -> RuntimePolicyResponse:
        if not agent_id and not install_uuid:
            raise HTTPException(
                status_code=400,
                detail={"code": "MISSING_IDENTIFIER", "message": "agent_id 또는 install_uuid 중 하나는 필수입니다."},
            )

        record: EnrollmentRequest | None = None
        if agent_id:
            record = (
                db.query(EnrollmentRequest)
                .filter(EnrollmentRequest.agent_id == agent_id)
                .first()
            )
        if record is None and install_uuid:
            record = (
                db.query(EnrollmentRequest)
                .filter(EnrollmentRequest.install_uuid == install_uuid)
                .first()
            )

        if record is None:
            raise HTTPException(
                status_code=404,
                detail={"code": "NOT_FOUND", "message": "에이전트를 찾을 수 없습니다."},
            )

        if record.status != "approved":
            raise HTTPException(
                status_code=403,
                detail={"code": "NOT_APPROVED", "message": f"승인되지 않은 에이전트입니다. (현재 상태: {record.status})"},
            )

        return RuntimePolicyResponse(
            policy_yaml=get_policy_data(),
            assigned_env=record.assigned_env,
            assigned_role=record.assigned_role,
        )
