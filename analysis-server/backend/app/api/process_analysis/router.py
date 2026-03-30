from fastapi import APIRouter, HTTPException
from .service import process_analysis_service

router = APIRouter(prefix="/api/v1/process_analysis", tags=["Process Analysis"])

@router.get("/graph")
@router.get("/graph/{exec_id}")
async def get_process_graph(exec_id: str = None):
    # ID가 없는 경우 자동 탐색
    if not exec_id:
        exec_id = process_analysis_service.get_top_threat_id()
        if not exec_id:
            return {"nodes": [], "links": [], "message": "최근 위험 프로세스가 없습니다."}
        # Fallback 성공 시 메시지 포함
        graph_data = process_analysis_service.get_process_full_graph(exec_id)
        if graph_data:
            graph_data["message"] = "최근 위험 프로세스가 없습니다."
            return graph_data

    # 특정 ID 조회
    graph_data = process_analysis_service.get_process_full_graph(exec_id)
    if not graph_data:
        raise HTTPException(status_code=404, detail="해당 프로세스 정보를 찾을 수 없습니다.")
        
    return graph_data