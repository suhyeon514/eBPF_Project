from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from typing import Optional

from ...database import get_db
from ...schemas import (
    EnrollApproveRequest,
    EnrollRejectRequest,
    EnrollRequest,
    EnrollResponse,
    EnrollResult,
    EnrollStatusResponse,
    EnrollmentRequestItem,
)
from ...models import EnrollmentRequest
from ...api.auth.service import get_current_user
from .service import EnrollService

router = APIRouter(prefix="/api/v1/enroll", tags=["에이전트 등록(Enrollment)"])


@router.get("/requests", response_model=dict)
def list_enrollment_requests(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=100),
    status: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """등록 요청 전체 목록 조회 (관리자 전용)."""
    q = db.query(EnrollmentRequest)
    if status:
        q = q.filter(EnrollmentRequest.status == status)
    total = q.count()
    items = q.order_by(EnrollmentRequest.created_at.desc()).offset((page - 1) * size).limit(size).all()
    return {
        "total": total,
        "page": page,
        "size": size,
        "items": [EnrollmentRequestItem.from_orm(item) for item in items],
    }


@router.post("/request", response_model=EnrollResponse, status_code=202)
def enroll_request(payload: EnrollRequest, db: Session = Depends(get_db)):
    """에이전트 등록 요청. 항상 pending(202) 반환."""
    record = EnrollService.create_enrollment_request(db, payload)
    return EnrollResponse(
        result=EnrollResult.pending,
        request_id=record.request_id,
        message="등록 요청이 접수되었습니다. 관리자 승인을 기다려 주세요.",
    )


@router.get("/requests/{request_id}", response_model=EnrollStatusResponse, status_code=200)
def get_enrollment_status(request_id: str, db: Session = Depends(get_db)):
    """등록 요청 상태 조회 (에이전트 폴링용)."""
    record = EnrollService.get_enrollment_request(db, request_id)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "NOT_FOUND", "message": f"등록 요청 {request_id}을(를) 찾을 수 없습니다."},
        )
    return EnrollStatusResponse(
        result=EnrollResult(record.status),
        request_id=record.request_id,
        reason_code=record.reason_code,
        agent_id=record.agent_id,
        certificate_pem=record.certificate_pem if record.status == "approved" else None,
        assigned_env=record.assigned_env,
        assigned_role=record.assigned_role,
    )


@router.get("/approve", response_class=HTMLResponse, include_in_schema=False)
def approve_by_token(token: str, db: Session = Depends(get_db)):
    """Slack 링크 클릭 시 토큰으로 승인 처리."""
    try:
        record = EnrollService.approve_by_token(db, token)
        return f"""
        <html><body style="font-family:sans-serif;text-align:center;padding:60px">
        <h2>✅ 승인 완료</h2>
        <p>요청 ID: <code>{record.request_id}</code></p>
        <p>호스트: <strong>{record.hostname}</strong> 이(가) 승인되었습니다.</p>
        </body></html>
        """
    except HTTPException as e:
        msg = e.detail.get("message", "처리 중 오류가 발생했습니다.") if isinstance(e.detail, dict) else str(e.detail)
        return HTMLResponse(content=f"""
        <html><body style="font-family:sans-serif;text-align:center;padding:60px">
        <h2>⚠️ 처리 실패</h2><p>{msg}</p>
        </body></html>
        """, status_code=e.status_code)


@router.get("/reject", response_class=HTMLResponse, include_in_schema=False)
def reject_by_token(token: str, db: Session = Depends(get_db)):
    """Slack 링크 클릭 시 토큰으로 거부 처리."""
    try:
        record = EnrollService.reject_by_token(db, token)
        return f"""
        <html><body style="font-family:sans-serif;text-align:center;padding:60px">
        <h2>❌ 거부 완료</h2>
        <p>요청 ID: <code>{record.request_id}</code></p>
        <p>호스트: <strong>{record.hostname}</strong> 이(가) 거부되었습니다.</p>
        </body></html>
        """
    except HTTPException as e:
        msg = e.detail.get("message", "처리 중 오류가 발생했습니다.") if isinstance(e.detail, dict) else str(e.detail)
        return HTMLResponse(content=f"""
        <html><body style="font-family:sans-serif;text-align:center;padding:60px">
        <h2>⚠️ 처리 실패</h2><p>{msg}</p>
        </body></html>
        """, status_code=e.status_code)


@router.patch("/requests/{request_id}/approve", response_model=EnrollStatusResponse, status_code=200)
def approve_enrollment(
    request_id: str,
    body: EnrollApproveRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """등록 요청 승인 (관리자 전용). CSR에 CA 서명 후 인증서 발급."""
    record = EnrollService.approve_enrollment_request(db, request_id, body)
    return EnrollStatusResponse(
        result=EnrollResult.approved,
        request_id=record.request_id,
        agent_id=record.agent_id,
        certificate_pem=record.certificate_pem,
        assigned_env=record.assigned_env,
        assigned_role=record.assigned_role,
    )


@router.patch("/requests/{request_id}/reject", response_model=EnrollStatusResponse, status_code=200)
def reject_enrollment(
    request_id: str,
    body: EnrollRejectRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """등록 요청 거부 (관리자 전용)."""
    record = EnrollService.reject_enrollment_request(db, request_id, body)
    return EnrollStatusResponse(
        result=EnrollResult.rejected,
        request_id=record.request_id,
        reason_code=record.reason_code,
        message=body.message,
    )
