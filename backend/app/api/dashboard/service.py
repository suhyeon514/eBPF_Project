from sqlalchemy.orm import Session
from ...models import TopAlert
from datetime import datetime, timezone
from ...core.config import os_client  # core/config.py에 정의된 os_client 사용

class DashboardService:
    @staticmethod
    def sync_alerts_from_os(db: Session):
        """
        OpenSearch의 'security-alerts-*' 인덱스에서 
        위험도 연산이 완료된 실제 알람을 가져와 DB에 동기화합니다.
        """
        # 1. OpenSearch 쿼리: 최신 알람 10개를 가져옴
        query = {
            "size": 10,
            "sort": [{"processed_at": {"order": "desc"}}], # 처리 시간 기준 최신순
            "query": {
                "match_all": {} # security-alerts 인덱스 자체가 탐지된 것만 있으므로 전체 조회
            }
        }
        
        try:
            # 인덱스를 가짜 데이터(ebpf-logs)가 아닌 실제 알람 인덱스로 변경
            response = os_client.search(index="security-alerts-*", body=query)
        except Exception as e:
            print(f"❌ OpenSearch 조회 오류: {e}")
            return

        for hit in response['hits']['hits']:
            src = hit['_source']
            # OpenSearch 문서 ID를 고유값으로 사용 (중복 저장 방지)
            eid = hit['_id'] 
            
            # DB 중복 체크
            exists = db.query(TopAlert).filter(TopAlert.event_id == eid).first()
            if not exists:
                # risk_info 필드에서 계산된 데이터 추출
                risk = src.get("risk_info", {})
                host = src.get("host", {})
                
                # 타임스탬프 처리 (float 형태의 Unix Timestamp를 datetime으로 변환)
                raw_ts = src.get("@timestamp", datetime.now(timezone.utc).timestamp())
                dt_object = datetime.fromtimestamp(raw_ts, tz=timezone.utc)

                new_alert = TopAlert(
                    event_id=eid,
                    # 우리가 연산한 severity (Critical, High 등)를 그대로 대문자로 저장
                    severity=risk.get("severity", "LOW").upper(),
                    # 우리가 정한 rule_name을 알람명으로 사용
                    alert_name=risk.get("rule_name", "미분류 위협"),
                    # 호스트명과 IP를 합쳐서 가독성 있게 저장
                    host_info=f"{host.get('hostname', 'unknown')} ({host.get('ip', '0.0.0.0')})",
                    event_time=dt_object
                )
                db.add(new_alert)
        
        try:
            db.commit()
        except Exception as e:
            db.rollback()
            print(f"❌ DB 저장 오류: {e}")

    @staticmethod
    def get_top_5_alerts(db: Session):
        """DB에서 최신 고위험 알람 5개만 반환 (프론트엔드 이미지 규격)"""
        # Critical이 먼저 오고, 그 다음 최신순으로 정렬하여 상위 5개 추출
        return db.query(TopAlert)\
                 .order_by(TopAlert.severity == "CRITICAL", TopAlert.event_time.desc())\
                 .limit(5)\
                 .all()