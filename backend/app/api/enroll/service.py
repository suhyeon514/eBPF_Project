import uuid
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session

from ...models import Assets, EnrollmentRequest
from ...schemas import EnrollApproveRequest, EnrollRejectRequest, EnrollRequest
from ...core import ca
from ...core.slack import send_enroll_request_notification


def _upsert_asset_on_approval(db: Session, record: EnrollmentRequest) -> None:
    os_info = f"{record.os_id} {record.os_version}".strip()
    existing = db.query(Assets).filter(Assets.hostname == record.hostname).first()
    if existing is None:
        db.add(Assets(
            hostname=record.hostname,
            ip_address=record.ip_address or "N/A",
            os_info=os_info,
            status="오프라인",
        ))
    else:
        if existing.os_info is None:
            existing.os_info = os_info
        if record.ip_address and existing.ip_address in (None, "N/A"):
            existing.ip_address = record.ip_address


class EnrollService:

    @staticmethod
    def _generate_request_id(db: Session) -> str:
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        prefix = f"req-{today}-"
        count = (
            db.query(EnrollmentRequest)
            .filter(EnrollmentRequest.request_id.like(f"{prefix}%"))
            .count()
        )
        return f"{prefix}{count + 1:04d}"

    @staticmethod
    def create_enrollment_request(db: Session, payload: EnrollRequest) -> EnrollmentRequest:
        existing = (
            db.query(EnrollmentRequest)
            .filter(EnrollmentRequest.install_uuid == payload.install_uuid)
            .first()
        )
        if existing:
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "DUPLICATE_INSTALL_UUID",
                    "message": "동일한 install_uuid로 이미 등록 요청이 존재합니다.",
                    "existing_request_id": existing.request_id,
                },
            )

        request_id = EnrollService._generate_request_id(db)
        fp = payload.fingerprint

        record = EnrollmentRequest(
            request_id=request_id,
            host_id=payload.host_id,
            install_uuid=payload.install_uuid,
            machine_id=fp.machine_id,
            hostname=fp.hostname,
            ip_address=fp.ip_address,
            os_id=fp.os_id,
            os_version=fp.os_version,
            cloud_instance_id=fp.cloud_instance_id,
            csr_pem=payload.csr_pem,
            requested_env=payload.requested_env,
            requested_role=payload.requested_role,
            status="pending",
            approve_token=str(uuid.uuid4()),
            reject_token=str(uuid.uuid4()),
        )
        db.add(record)
        db.commit()
        db.refresh(record)

        send_enroll_request_notification(record)

        return record

    @staticmethod
    def get_enrollment_request(db: Session, request_id: str) -> EnrollmentRequest | None:
        return (
            db.query(EnrollmentRequest)
            .filter(EnrollmentRequest.request_id == request_id)
            .first()
        )

    @staticmethod
    def approve_enrollment_request(
        db: Session, request_id: str, body: EnrollApproveRequest
    ) -> EnrollmentRequest:
        record = EnrollService.get_enrollment_request(db, request_id)
        if record is None:
            raise HTTPException(
                status_code=404,
                detail={"error": "NOT_FOUND", "message": f"등록 요청 {request_id}을(를) 찾을 수 없습니다."},
            )
        if record.status != "pending":
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "INVALID_STATUS_TRANSITION",
                    "message": f"이미 처리된 요청입니다. (현재 상태: {record.status})",
                },
            )

        try:
            cert_pem = ca.sign_csr(record.csr_pem)
        except RuntimeError as e:
            raise HTTPException(status_code=500, detail={"error": "CA_NOT_INITIALIZED", "message": str(e)})
        except ValueError as e:
            raise HTTPException(status_code=422, detail={"error": "INVALID_CSR", "message": str(e)})

        record.certificate_pem = cert_pem
        record.status = "approved"
        record.agent_id = body.agent_id or record.install_uuid
        record.assigned_env = body.assigned_env or record.requested_env
        record.assigned_role = body.assigned_role or record.requested_role

        _upsert_asset_on_approval(db, record)
        db.commit()
        db.refresh(record)
        return record

    @staticmethod
    def approve_by_token(db: Session, token: str) -> EnrollmentRequest:
        record = (
            db.query(EnrollmentRequest)
            .filter(EnrollmentRequest.approve_token == token)
            .first()
        )
        if record is None:
            raise HTTPException(
                status_code=404,
                detail={"error": "INVALID_TOKEN", "message": "유효하지 않거나 이미 사용된 토큰입니다."},
            )
        if record.status != "pending":
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "INVALID_STATUS_TRANSITION",
                    "message": f"이미 처리된 요청입니다. (현재 상태: {record.status})",
                },
            )

        try:
            cert_pem = ca.sign_csr(record.csr_pem)
        except RuntimeError as e:
            raise HTTPException(status_code=500, detail={"error": "CA_NOT_INITIALIZED", "message": str(e)})
        except ValueError as e:
            raise HTTPException(status_code=422, detail={"error": "INVALID_CSR", "message": str(e)})

        record.certificate_pem = cert_pem
        record.status = "approved"
        record.agent_id = record.agent_id or record.install_uuid
        record.assigned_env = record.assigned_env or record.requested_env
        record.assigned_role = record.assigned_role or record.requested_role
        record.approve_token = None  # 일회성: 사용 후 무효화
        record.reject_token = None

        _upsert_asset_on_approval(db, record)
        db.commit()
        db.refresh(record)
        return record

    @staticmethod
    def reject_by_token(db: Session, token: str) -> EnrollmentRequest:
        record = (
            db.query(EnrollmentRequest)
            .filter(EnrollmentRequest.reject_token == token)
            .first()
        )
        if record is None:
            raise HTTPException(
                status_code=404,
                detail={"error": "INVALID_TOKEN", "message": "유효하지 않거나 이미 사용된 토큰입니다."},
            )
        if record.status != "pending":
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "INVALID_STATUS_TRANSITION",
                    "message": f"이미 처리된 요청입니다. (현재 상태: {record.status})",
                },
            )

        record.status = "rejected"
        record.reason_code = "admin_rejected"
        record.approve_token = None
        record.reject_token = None

        db.commit()
        db.refresh(record)
        return record

    @staticmethod
    def reject_enrollment_request(
        db: Session, request_id: str, body: EnrollRejectRequest
    ) -> EnrollmentRequest:
        record = EnrollService.get_enrollment_request(db, request_id)
        if record is None:
            raise HTTPException(
                status_code=404,
                detail={"error": "NOT_FOUND", "message": f"등록 요청 {request_id}을(를) 찾을 수 없습니다."},
            )
        if record.status != "pending":
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "INVALID_STATUS_TRANSITION",
                    "message": f"이미 처리된 요청입니다. (현재 상태: {record.status})",
                },
            )

        record.status = "rejected"
        record.reason_code = body.reason_code or "admin_rejected"
        db.commit()
        db.refresh(record)
        return record
