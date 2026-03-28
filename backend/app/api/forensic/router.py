# backend/app/api/forensic/router.py
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from sqlalchemy.orm import Session
from ... import schemas
from ...database import get_db
from ...models import EnrollmentRequest
from .websocket_manager import manager


router = APIRouter(
    prefix="/api/v1/forensic",
    tags=["포렌식 명령(Forensic Commands)"] 
)

# [신규] 에이전트 전용 웹소켓 연결 엔드포인트 (ws://localhost:8000/api/v1/forensic/ws/{agent_id})
@router.websocket("/ws/{agent_id}")
async def websocket_endpoint(websocket: WebSocket, agent_id: str):
    await manager.connect(websocket, agent_id)
    try:
        while True:
            # 에이전트가 연결을 유지하는 동안 대기합니다 (현재는 에이전트가 보내는 메시지는 무시)
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(agent_id)

# [수정] 프론트엔드 전용 수동 덤프 트리거 API
@router.post("/avml-dump")
async def trigger_avml_dump(payload: schemas.ForensicDumpRequest, db: Session = Depends(get_db)):
    # hostname으로 요청 온 경우 enrollment DB에서 실제 agent_id(UUID) 조회
    record = db.query(EnrollmentRequest).filter(
        EnrollmentRequest.hostname == payload.agent_id,
        EnrollmentRequest.status == "approved"
    ).order_by(EnrollmentRequest.created_at.desc()).first()
    agent_id = record.agent_id if record else payload.agent_id

    command = {"action": "avml_dump", "reason": payload.reason}
    is_sent = await manager.send_command(agent_id, command)
    
    if is_sent:
        return {"status": "success", "message": f"[{payload.agent_id}] 에이전트에 즉시 명령을 하달했습니다."}
    else:
        return {"status": "failed", "message": f"[{payload.agent_id}] 에이전트가 현재 오프라인(연결 끊김) 상태입니다."}