from ...main import os_client # main에 선언된 os_client 사용
from sqlalchemy.orm import Session
from ...models import TopAlert
from datetime import datetime
from ...core.config import os_client

class DashboardService:
    @staticmethod
    def sync_alerts_from_os(db: Session):
        """OpenSearch에서 고위험 로그를 가져와 DB에 동기화 (중복 제외)"""
        query = {
            "size": 10, # 여유있게 10개 가져옴
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "should": [
                        {"match": {"event_type": "edr.process.exec"}},
                        {"match": {"event_type": "edr.network.flow"}}
                    ],
                    "minimum_should_match": 1
                }
            }
        }
        
        response = os_client.search(index="ebpf-logs-*", body=query)
        
        for hit in response['hits']['hits']:
            src = hit['_source']
            eid = hit['_id']
            
            # 중복 체크
            exists = db.query(TopAlert).filter(TopAlert.event_id == eid).first()
            if not exists:
                # 목업처럼 한글 이름 매핑 (예시)
                name_map = {
                    "edr.process.exec": "미확인 프로세스 실행 탐지",
                    "edr.network.flow": "비정상 네트워크 커넥션",
                    "edr.auth.sudo": "권한 상승 시도 탐지"
                }
                
                new_alert = TopAlert(
                    event_id=eid,
                    severity="CRITICAL" if src.get("event_type") == "edr.process.exec" else "HIGH",
                    alert_name=name_map.get(src.get("event_type"), "의심 행위 탐지"),
                    host_info=f"{src['host']['hostname']} ({src['host']['host_id']})",
                    # ISO 포맷 시간을 Python datetime으로 변환
                    event_time=datetime.fromisoformat(src['@timestamp'].replace('Z', '+00:00'))
                )
                db.add(new_alert)
        
        db.commit()

    @staticmethod
    def get_top_5_alerts(db: Session):
        """DB에서 최신 고위험 알람 5개만 가져옴"""
        return db.query(TopAlert).order_by(TopAlert.event_time.desc()).limit(5).all()