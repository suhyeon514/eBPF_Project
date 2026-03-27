# backend/app/api/forensic/service.py

def send_avml_dump_command(agent_id: str, reason: str) -> bool:
    """
    대상 에이전트에게 AVML 메모리 덤프 명령을 내립니다.
    (추후 WebSocket, Redis Pub/Sub, DB Polling 등을 이용해 실제 통신을 구현할 위치)
    """
    print(f"[분석 서버 Backend 측] AVML 덤프 명령 발생 - 대상 에이전트: {agent_id}, 사유: {reason}")
    
    # 지금은 테스트 단계이므로 항상 성공(True)을 반환합니다.
    return True