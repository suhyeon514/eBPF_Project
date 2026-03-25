# app/api/assets/service.py
from sqlalchemy.orm import Session
from sqlalchemy import or_
from ...models import Assets

class AssetService:
    @staticmethod
    def get_assets(db: Session, search: str = None, status: str = None, page: int = 1, size: int = 10):
        query = db.query(Assets)

        # 1. 검색 기능 (호스트명 또는 IP 주소)
        if search:
            query = query.filter(
                or_(
                    Assets.hostname.ilike(f"%{search}%"),
                    Assets.ip_address.ilike(f"%{search}%")
                )
            )

        # 2. 상세 필터 기능 (상태별)
        if status and status != "전체":
            query = query.filter(Assets.status == status)

        # 3. 페이징 처리
        total_count = query.count()
        offset = (page - 1) * size
        items = query.order_by(Assets.id.desc()).offset(offset).limit(size).all()

        return {
            "total": total_count,
            "items": items,
            "page": page,
            "size": size
        }