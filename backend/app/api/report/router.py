from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from .service import ReportService
import os
from ...schemas import ReportRequest

router = APIRouter(prefix="/api/v1/report", tags=["Report"])

@router.post("/generate")
async def generate_report(request: ReportRequest):
    try:
        # 서비스 호출 (PDF 파일 경로 반환)
        pdf_path = await ReportService.create_ai_report(request.exec_id)
        
        if not pdf_path or not os.path.exists(pdf_path):
            raise HTTPException(status_code=404, detail="관련 데이터를 찾을 수 없습니다.")

        # 생성된 PDF 반환 후 파일 관리는 별도로(예: temp 디렉토리 사용)
        return FileResponse(
            path=pdf_path,
            filename=f"K9_Report_{request.exec_id[:8]}.pdf",
            media_type="application/pdf"
        )
    except Exception as e:
        print(f"❌ [Report Router] 에러 발생: {str(e)}")
        raise HTTPException(status_code=500, detail="보고서 생성 중 내부 오류가 발생했습니다.")