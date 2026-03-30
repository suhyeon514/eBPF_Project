# backend/app/api/forensic/router.py

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from .websocket_manager import manager
from . import service
import json

router = APIRouter(
    prefix="/api/v1/forensic",
    tags=["포렌식 명령(Forensic Commands)"]
)


# =========================
# 🔥 정책 평가 (서버 policy.yaml 기반)
# =========================
def evaluate_policy(event_type, raw):
    score = 0
    rule = "normal"

    policy = service.get_policy_list()

    deny_list = policy.get("deny", [])
    focus_list = policy.get("focus", [])

    # 🔴 프로세스 정책 (명령어 기반)
    if event_type == "process":
        for d in deny_list:
            if d in raw:
                score += 90
                rule = "deny_process"

    # 🔴 파일 정책
    elif event_type == "file":
        for path in deny_list:
            if path in raw:
                score += 90
                rule = "deny_path"

        for path in focus_list:
            if path in raw:
                score += 50
                rule = "focus_path"

    # 🔴 네트워크 정책 (확장 가능)
    elif event_type == "network":
        for d in deny_list:
            if d in raw:
                score += 80
                rule = "deny_network"

    return score, rule


# =========================
# 🔥 정책 수정 API (추가됨)
# =========================
from pydantic import BaseModel

class PolicyUpdateRequest(BaseModel):
    category: str   # deny / focus
    item: str
    action: str     # add / delete


@router.post("/policy/update")
def update_policy_api(req: PolicyUpdateRequest):
    service.update_policy(req.category, req.item, req.action)
    return {"msg": "updated"}


# =========================
# 기존 WebSocket (옵션)
# =========================
@router.websocket("/ws/{agent_id}")
async def websocket_endpoint(websocket: WebSocket, agent_id: str):
    await websocket.accept()
    await manager.connect(websocket, agent_id)

    print(f"✅ [WS] agent connected (path1): {agent_id}")

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(agent_id)
        print(f"❌ [WS] agent disconnected: {agent_id}")


# =========================
# 🔥 에이전트 연결 (핵심)
# =========================
@router.websocket("/websocket/agent")
async def agent_websocket(websocket: WebSocket):
    await websocket.accept()

    agent_id = "agent"
    await manager.connect(websocket, agent_id)

    print("✅ [WS] agent connected")

    try:
        while True:
            raw = await websocket.receive_text()

            print("\n🔥 RAW EVENT:", raw)

            try:
                data = json.loads(raw)
            except Exception as e:
                print("❌ JSON 파싱 실패:", e)
                continue

            # =========================
            # 이벤트 타입 판별
            # =========================
            event_type = None

            if "process_exec" in data:
                event_type = "process"

            elif "process_kprobe" in data:
                func = data["process_kprobe"].get("function_name", "")

                if func == "openat":
                    event_type = "file"
                elif func == "connect":
                    event_type = "network"
                else:
                    event_type = "unknown"

            if not event_type:
                print("❌ 이벤트 타입 판별 실패")
                continue

            print(f"🎯 EVENT TYPE: {event_type}")

            # =========================
            # 🔥 정책 적용 (핵심)
            # =========================
            score, rule = evaluate_policy(event_type, raw)

            print(f"🚨 POLICY RESULT → score: {score}, rule: {rule}")

    except WebSocketDisconnect:
        manager.disconnect(agent_id)
        print("❌ agent disconnected")
