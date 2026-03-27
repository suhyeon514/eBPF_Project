from fastapi import WebSocket

class ConnectionManager:
    def __init__(self):
        # agent_id를 Key로, 활성화된 WebSocket 객체를 Value로 저장합니다.
        self.active_connections: dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, agent_id: str):
        """에이전트가 처음 켜질 때 웹소켓 연결을 수락하고 명부에 등록합니다."""
        await websocket.accept()
        self.active_connections[agent_id] = websocket
        print(f"🔌 [WebSocket] 에이전트 연결 완료: {agent_id}")

    def disconnect(self, agent_id: str):
        """에이전트가 종료되거나 네트워크가 끊기면 명부에서 삭제합니다."""
        if agent_id in self.active_connections:
            del self.active_connections[agent_id]
            print(f"🔌 [WebSocket] 에이전트 연결 끊김: {agent_id}")

    async def send_command(self, agent_id: str, command: dict) -> bool:
        """프론트엔드 버튼 클릭 시, 명부를 뒤져 해당 에이전트에게 즉시 명령을 발송합니다."""
        websocket = self.active_connections.get(agent_id)
        if websocket:
            await websocket.send_json(command)
            return True
        return False

# 라우터에서 공통으로 사용할 전역 매니저 객체 생성
manager = ConnectionManager()