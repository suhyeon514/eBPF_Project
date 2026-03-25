# app/api/assets/router.py
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from .service import AssetService
from ...database import get_db
from ..auth.service import get_current_user # 보안 적용

router = APIRouter(prefix="/api/v1/assets", tags=["자산 관리"])

@router.get("/")
def read_assets(
    search: str = Query(None, description="호스트명 또는 IP 검색"),
    status: str = Query(None, description="상태 필터 (정상, 주의, 위험 등)"),
    page: int = Query(1, ge=1),
    size: int = Query(10, ge=1),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user) # 로그인한 사용자만 접근 가능
):
    """
    자산(에이전트 서버) 목록을 검색, 필터링, 페이징하여 가져옵니다.
    """
    return AssetService.get_assets(db, search, status, page, size)