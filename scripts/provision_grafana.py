"""
Grafana 데이터소스 + 보안 모니터링 대시보드 자동 프로비저닝 스크립트
실행: python scripts/provision_grafana.py
"""
import os
import json
import requests
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

GRAFANA_URL  = "http://localhost:3000"
GRAFANA_USER = "admin"
GRAFANA_PASS = os.getenv("GRAFANA_PASSWORD", "admin")
AUTH         = (GRAFANA_USER, GRAFANA_PASS)

# ──────────────────────────────────────────────
# 1. OpenSearch 데이터소스 생성 (or 기존 재사용)
# ──────────────────────────────────────────────
DS_PAYLOAD = {
    "name": "OpenSearch-K9",
    "type": "grafana-opensearch-datasource",
    "url": "http://opensearch:9200",   # 도커 내부 네트워크명
    "access": "proxy",
    "basicAuth": False,
    "jsonData": {
        "database": "security-alerts-*",
        "timeField": "processed_at",
        "version": "2.12.0",
        "flavor": "OpenSearch",
        "logLevelField": "risk_info.severity",
        "logMessageField": "risk_info.rule_name",
    },
}

def ensure_datasource():
    r = requests.get(f"{GRAFANA_URL}/api/datasources/name/OpenSearch-K9", auth=AUTH)
    if r.status_code == 200:
        existing = r.json()
        uid = existing["uid"]
        ds_id = existing["id"]
        requests.put(f"{GRAFANA_URL}/api/datasources/{ds_id}", auth=AUTH, json={**DS_PAYLOAD, "uid": uid})
        print(f"[datasource] 업데이트 완료: {uid}")
        return uid

    r = requests.post(f"{GRAFANA_URL}/api/datasources", auth=AUTH, json=DS_PAYLOAD)
    r.raise_for_status()
    uid = r.json()["datasource"]["uid"]
    print(f"[datasource] 생성 완료: {uid}")
    return uid


# ──────────────────────────────────────────────
# 2. 대시보드 JSON 정의
# ──────────────────────────────────────────────
def build_dashboard(ds_uid: str) -> dict:
    DS_REF = {"type": "grafana-opensearch-datasource", "uid": ds_uid}

    def ts_panel(pid, title, index, field, y, x, w=12, h=8):
        """시계열 패널 (이벤트 카운트)"""
        return {
            "id": pid, "type": "timeseries",
            "title": title, "gridPos": {"x": x, "y": y, "w": w, "h": h},
            "datasource": DS_REF,
            "targets": [{
                "refId": "A",
                "datasource": DS_REF,
                "query": "",
                "queryType": "lucene",
                "luceneQueryType": "Metric",
                "metrics": [{"id": "1", "type": "count"}],
                "timeField": "processed_at",
                "bucketAggs": [{
                    "id": "2", "type": "date_histogram", "field": "@timestamp",
                    "settings": {"interval": "30m", "min_doc_count": "0", "trimEdges": "0"},
                }],
                "alias": title,
            }],
            "options": {"tooltip": {"mode": "multi"}},
            "fieldConfig": {
                "defaults": {
                    "color": {"mode": "palette-classic"},
                    "custom": {"lineWidth": 2, "fillOpacity": 10},
                }
            },
        }

    def pie_panel(pid, title, index, field, y, x, w=8, h=8):
        """파이차트 패널 (필드별 분포)"""
        return {
            "id": pid, "type": "piechart",
            "title": title, "gridPos": {"x": x, "y": y, "w": w, "h": h},
            "datasource": DS_REF,
            "targets": [{
                "refId": "A",
                "datasource": DS_REF,
                "query": "",
                "queryType": "lucene",
                "luceneQueryType": "Metric",
                "metrics": [{"id": "1", "type": "count"}],
                "timeField": "processed_at",
                "bucketAggs": [{
                    "id": "2", "type": "terms", "field": field,
                    "settings": {"size": "10", "order": "desc", "orderBy": "1"},
                }],
            }],
            "options": {"pieType": "donut", "legend": {"displayMode": "table", "placement": "right"}},
        }

    def bar_panel(pid, title, index, field, y, x, w=12, h=8):
        """바차트 패널 (Top N)"""
        return {
            "id": pid, "type": "barchart",
            "title": title, "gridPos": {"x": x, "y": y, "w": w, "h": h},
            "datasource": DS_REF,
            "targets": [{
                "refId": "A",
                "datasource": DS_REF,
                "query": "",
                "queryType": "lucene",
                "luceneQueryType": "Metric",
                "metrics": [{"id": "1", "type": "count"}],
                "timeField": "processed_at",
                "bucketAggs": [{
                    "id": "2", "type": "terms", "field": field,
                    "settings": {"size": "10", "order": "desc", "orderBy": "1"},
                }],
            }],
            "options": {"xTickLabelRotation": -30},
            "fieldConfig": {
                "defaults": {"color": {"mode": "palette-classic"}},
            },
        }

    def stat_panel(pid, title, query_str, y, x, color, w=6, h=4):
        """단일 숫자 통계 패널"""
        return {
            "id": pid, "type": "stat",
            "title": title, "gridPos": {"x": x, "y": y, "w": w, "h": h},
            "datasource": DS_REF,
            "targets": [{
                "refId": "A",
                "datasource": DS_REF,
                "query": query_str,
                "queryType": "lucene",
                "luceneQueryType": "Metric",
                "metrics": [{"id": "1", "type": "count"}],
                "timeField": "processed_at",
                "bucketAggs": [{"id": "2", "type": "date_histogram", "field": "processed_at", "settings": {"interval": "1d", "min_doc_count": "0"}}],
            }],
            "options": {
                "reduceOptions": {"calcs": ["lastNotNull"]},
                "orientation": "auto", "textMode": "auto",
                "colorMode": "background",
            },
            "fieldConfig": {
                "defaults": {"color": {"mode": "fixed", "fixedColor": color}},
            },
        }

    panels = [
        # Row 1: 요약 통계
        stat_panel(1, "전체 보안 알람",   "",                       0, 0,  "purple"),
        stat_panel(2, "CRITICAL",         "risk_info.severity:CRITICAL", 0, 6,  "red"),
        stat_panel(3, "HIGH",             "risk_info.severity:HIGH",     0, 12, "orange"),
        stat_panel(4, "오늘 탐지 건수",   "",                       0, 18, "blue"),

        # Row 2: 시계열 + 심각도 분포
        ts_panel(5,  "보안 알람 발생 추이", "security-alerts-*", "@timestamp", 4, 0,  w=16, h=8),
        pie_panel(6, "심각도 분포",         "security-alerts-*", "risk_info.severity.keyword", 4, 16, w=8, h=8),

        # Row 3: 탐지 규칙 + 위협 호스트
        bar_panel(7, "Top 10 탐지 규칙",   "security-alerts-*", "risk_info.rule_name.keyword", 12, 0,  w=12, h=8),
        bar_panel(8, "Top 10 위협 호스트", "security-alerts-*", "host.hostname.keyword",        12, 12, w=12, h=8),
    ]

    return {
        "dashboard": {
            "uid": "k9-security-overview",
            "title": "K9 - 보안 모니터링 대시보드",
            "tags": ["k9", "security", "ebpf"],
            "timezone": "browser",
            "refresh": "30s",
            "time": {"from": "now-24h", "to": "now"},
            "panels": panels,
            "schemaVersion": 38,
            "version": 1,
        },
        "overwrite": True,
        "folderId": 0,
    }


# ──────────────────────────────────────────────
# 3. 대시보드 생성 및 URL 출력
# ──────────────────────────────────────────────
def create_dashboard(ds_uid: str):
    payload = build_dashboard(ds_uid)
    r = requests.post(f"{GRAFANA_URL}/api/dashboards/db", auth=AUTH, json=payload)
    r.raise_for_status()
    result = r.json()
    uid  = result["uid"]
    slug = result["slug"]
    url  = result["url"]
    print(f"\n[dashboard] 생성 완료!")
    print(f"  UID  : {uid}")
    print(f"  URL  : http://localhost:3000{url}")
    print(f"\n[.env] VITE_GRAFANA_URL에 아래 값을 설정하세요:")
    print(f"  VITE_GRAFANA_URL=http://localhost:3000/d/{uid}/{slug}?kiosk&orgId=1&from=now-24h&to=now")
    return uid, slug


if __name__ == "__main__":
    print("=== Grafana 프로비저닝 시작 ===")
    ds_uid = ensure_datasource()
    uid, slug = create_dashboard(ds_uid)
    print("\n완료!")
