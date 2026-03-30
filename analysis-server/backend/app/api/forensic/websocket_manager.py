from fastapi import WebSocket

class ConnectionManager:
    def __init__(self):
        # agent_id -> WebSocket
        self.active_connections: dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, agent_id: str):
        """연결 등록 (accept는 router에서 처리)"""
        self.active_connections[agent_id] = websocket
        print(f"🔌 [WebSocket] 에이전트 연결 완료: {agent_id}")

    def disconnect(self, agent_id: str):
        """연결 해제"""
        if agent_id in self.active_connections:
            del self.active_connections[agent_id]
            print(f"🔌 [WebSocket] 에이전트 연결 끊김: {agent_id}")

    async def send_command(self, agent_id: str, command: dict) -> bool:
        """에이전트에게 명령 전송"""
        websocket = self.active_connections.get(agent_id)
        if websocket:
            await websocket.send_json(command)
            return True
        return False


# 전역 manager
manager = ConnectionManager()
