from sqlalchemy.orm import Session
from ...models import TopAlert
from datetime import datetime, timezone
from ...core.config import os_client
from sqlalchemy import case

class DashboardService:
    @staticmethod
    def sync_alerts_from_os(db: Session):
        """
        OpenSearch에서 위험도가 높은 이벤트를 우선적으로 탐색하여 
        로컬 DB와 동기화합니다.
        """
        # 1. OpenSearch 쿼리 개선: 최신순이 아니라 '위험 점수'가 높은 것 위주로 더 많이 가져옴
        query = {
            "size": 100,  # 누락 방지를 위해 수집 수량을 늘림
            "sort": [
                {"risk_info.score": {"order": "desc"}}, # 점수 높은 순 우선
                {"processed_at": {"order": "desc"}}     # 그다음 최신순
            ],
            "query": { "match_all": {} }
        }
        
        try:
            response = os_client.search(index="security-alerts-*", body=query)
        except Exception as e:
            print(f"❌ OpenSearch 조회 오류: {e}")
            return

        for hit in response['hits']['hits']:
            src = hit['_source']
            eid = hit['_id'] 
            
            # DB 중복 체크 (이미 있는 이벤트는 건너뜀)
            exists = db.query(TopAlert).filter(TopAlert.event_id == eid).first()
            if not exists:
                risk = src.get("risk_info", {})
                host = src.get("host", {})
                
                # @timestamp 처리 (Unix Timestamp Float -> datetime)
                raw_ts = src.get("@timestamp", datetime.now(timezone.utc).timestamp())
                dt_object = datetime.fromtimestamp(raw_ts, tz=timezone.utc)

                new_alert = TopAlert(
                    event_id=eid,
                    severity=risk.get("severity", "LOW").upper(),
                    alert_name=risk.get("rule_name", "미분류 위협"),
                    # ip가 없을 경우 host_id나 hostname으로 대체
                    host_info=f"{host.get('hostname', 'unknown')} ({host.get('ip', host.get('host_id', '0.0.0.0'))})",
                    event_time=dt_object,
                    status="New" # 기본 상태값 추가
                )
                db.add(new_alert)
        
        try:
            db.commit()
        except Exception as e:
            db.rollback()
            print(f"❌ DB 저장 오류: {e}")

    @staticmethod
    def get_top_5_alerts(db: Session):
        """
        요청하신 정렬 기준 적용:
        1. Severity 우선순위: CRITICAL(1) -> HIGH(2) -> MEDIUM(3) -> LOW(4)
        2. 동일 등급 시: 최신 시간순(DESC)
        """
        priority_map = case(
            (TopAlert.severity == "CRITICAL", 1),
            (TopAlert.severity == "HIGH", 2),
            (TopAlert.severity == "MEDIUM", 3),
            (TopAlert.severity == "LOW", 4),
            else_=5
        )
        
        return db.query(TopAlert)\
                 .order_by(priority_map.asc(), TopAlert.event_time.desc())\
                 .limit(5)\
                 .all()