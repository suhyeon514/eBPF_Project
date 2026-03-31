from sqlalchemy.orm import Session
from ...models import TopAlert
from datetime import datetime, timezone, timedelta
from ...core.config import os_client
from sqlalchemy import case

class DashboardService:
    @staticmethod
    def sync_alerts_from_os(db: Session):
        sync_count = 0
        """
        OpenSearch에서 최근 24시간 이내의 위험도가 높은 이벤트를 
        우선적으로 탐색하여 로컬 DB와 동기화합니다.
        """
        # [수정] 24시간 이내의 데이터만 가져오도록 쿼리 개선
        time_limit = (datetime.now(timezone.utc) - timedelta(hours=24)).timestamp()

        query = {
            "size": 100,
            "sort": [
                {"risk_info.score": {"order": "desc"}},
                {"processed_at": {"order": "desc"}}
            ],
            "query": {
                "bool": {
                    "must": [
                        {"match_all": {}},
                        # [추가] OpenSearch 타임스탬프 기준 24시간 필터
                        {"range": {"@timestamp": {"gte": time_limit}}}
                    ]
                }
            }
        }
        
        try:
            response = os_client.search(index="security-alerts-*", body=query)
        except Exception as e:
            print(f"❌ OpenSearch 조회 오류: {e}")
            return

        for hit in response['hits']['hits']:
            src = hit['_source']
            eid = hit['_id'] 
            
            exists = db.query(TopAlert).filter(TopAlert.event_id == eid).first()
            if not exists:
                
                process_info = src.get("process", {})
                exec_id = process_info.get("exec_id")

                new_alert = TopAlert(
                    event_id=eid,
                    exec_id=exec_id,  # 👈 [저장] 이제 대시보드가 exec_id를 알게 됩니다.
                    severity=src.get("risk_info", {}).get("severity", "LOW").upper(),
                    alert_name=src.get("risk_info", {}).get("rule_name", "미분류 위협"),
                    host_info=f"{src.get('host', {}).get('hostname', 'unknown')}",
                    event_time=datetime.fromtimestamp(src.get("@timestamp"), tz=timezone.utc),
                    status="pending"
                )
                db.add(new_alert)
                sync_count += 1
        
        if sync_count > 0:
            try:
                db.commit()
                print(f"✅ [Sync] {sync_count}개의 새로운 위협 이벤트 동기화 완료")
            except Exception as e:
                db.rollback()
                print(f"❌ DB 저장 오류: {e}")

    @staticmethod
    def get_top_5_alerts(db: Session):
        """
        최근 24시간 이내의 데이터를 다음 기준으로 정렬하여 반환:
        1. Severity: CRITICAL -> HIGH -> MEDIUM -> LOW
        2. 시간: 최신순
        """
        # [추가] DB 조회 시에도 24시간 필터 적용
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

        priority_map = case(
            (TopAlert.severity == "CRITICAL", 1),
            (TopAlert.severity == "HIGH", 2),
            (TopAlert.severity == "MEDIUM", 3),
            (TopAlert.severity == "LOW", 4),
            else_=5
        )
        
        return db.query(TopAlert)\
                 .filter(TopAlert.event_time >= cutoff)\
                 .order_by(priority_map.asc(), TopAlert.event_time.desc())\
                 .limit(5)\
                 .all()