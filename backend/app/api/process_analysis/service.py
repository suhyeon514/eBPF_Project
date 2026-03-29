import os
from neo4j import GraphDatabase
from datetime import datetime, timedelta

class ProcessAnalysisService:
    def __init__(self):
        # .env 환경변수 로드 및 일관성 유지
        self.uri = os.getenv("NEO4J_URI") or "bolt://localhost:7687"
        self.user = os.getenv("NEO4J_USER") or "neo4j"
        self.password = os.getenv("NEO4J_PASSWORD")
        #self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))

        try:
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            self.driver.verify_connectivity()
            print("✅ [AnalysisService] Neo4j 연결 성공")
        except Exception as e:
            print(f"❌ [AnalysisService] Neo4j 연결 실패: {e}")

    def get_top_threat_id(self):
        with self.driver.session() as session:
            # 1. 고위험군 검색 (exec_id와 last_updated가 있는 것만!)
            query_priority = """
            MATCH (p:Process)
            WHERE p.severity IN ['CRITICAL', 'HIGH'] 
              AND p.exec_id IS NOT NULL 
              AND p.last_updated IS NOT NULL
            RETURN p.exec_id AS threat_id
            ORDER BY p.last_updated DESC
            LIMIT 1
            """
            result = session.run(query_priority).single()
            if result: return result["threat_id"]

            # 2. 일반 프로세스 중 최신 검색
            query_latest = """
            MATCH (p:Process)
            WHERE p.exec_id IS NOT NULL 
              AND p.last_updated IS NOT NULL
            RETURN p.exec_id AS threat_id
            ORDER BY p.last_updated DESC
            LIMIT 1
            """
            result_latest = session.run(query_latest).single()
            
            # 디버깅 로그 추가: 실제로 어떤 ID를 가져오는지 터미널에서 확인하세요.
            if result_latest:
                print(f"✅ [Analysis] 최신 ID 발견: {result_latest['threat_id']}")
                return result_latest["threat_id"]
            
            print("❌ [Analysis] 유효한 exec_id를 가진 노드가 없습니다.")
            return None

    def get_process_full_graph(self, exec_id: str):
        """특정 프로세스를 중심으로 계층 구조 및 연관 파일 노드까지 포함한 그래프 반환"""
        with self.driver.session() as session:
            # 프로세스 계층(3단계) + 연관 파일(OPENED/CREATED) 관계 통합 쿼리
            query = """
            MATCH (p:Process {exec_id: $exec_id})
            OPTIONAL MATCH path = (ancestor:Process)-[:CHILDREN*0..5]->(p)-[:CHILDREN*0..5]->(descendant:Process)
            WITH p, collect(DISTINCT path) AS paths
            
            OPTIONAL MATCH (p)-[r:OPENED|CREATED]->(f:File)
            
            RETURN p AS target_node, 
                   paths,
                   collect(DISTINCT f) AS file_nodes
            """
            result = session.run(query, exec_id=exec_id).single()
            
            if not result or not result["target_node"]:
                return None

            nodes = {}
            links = []

            # 메인 및 계층 노드 처리
            p = result["target_node"]
            nodes[p["exec_id"]] = {"id": p["exec_id"], "label": p["comm"], "type": "process", "data": dict(p)}

            for path in result["paths"]:
                if path:
                    for n in path.nodes:
                        if n["exec_id"] not in nodes:
                            nodes[n["exec_id"]] = {"id": n["exec_id"], "label": n["comm"], "type": "process", "data": dict(n)}
                    for r in path.relationships:
                        links.append({"source": r.start_node["exec_id"], "target": r.end_node["exec_id"], "label": "CHILDREN"})

            # 파일 노드 처리
            for f in result["file_nodes"]:
                if f:
                    f_id = f["path"]
                    if f_id not in nodes:
                        nodes[f_id] = {"id": f_id, "label": f["name"], "type": "file", "data": dict(f)}
                        links.append({"source": exec_id, "target": f_id, "label": "FILE_ACCESS"})

            return {"nodes": list(nodes.values()), "links": links, "target_id": exec_id}

# 싱글톤 객체 생성
proces_analysis_service = ProcessAnalysisService()