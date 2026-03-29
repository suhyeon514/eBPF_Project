import os
from neo4j import GraphDatabase
from datetime import datetime

class ProcessAnalysisService:
    def __init__(self):
        self.uri = os.getenv("NEO4J_URI") or "bolt://localhost:7687"
        self.user = os.getenv("NEO4J_USER") or "neo4j"
        self.password = os.getenv("NEO4J_PASSWORD")

        try:
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            self.driver.verify_connectivity()
            print("✅ [ProcessAnalysisService] Neo4j 연결 성공")
        except Exception as e:
            print(f"❌ [ProcessAnalysisService] Neo4j 연결 실패: {e}")

    def get_top_threat_id(self):
        with self.driver.session() as session:
            # 위험도 가중치 정렬 (CRITICAL > HIGH > MEDIUM)
            query_priority = """
            MATCH (p:Process)
            WHERE p.exec_id IS NOT NULL 
              AND p.severity IN ['CRITICAL', 'HIGH', 'MEDIUM', 'Critical', 'High', 'Medium']
            RETURN p.exec_id AS threat_id
            ORDER BY 
              CASE p.severity 
                WHEN 'CRITICAL' THEN 1 WHEN 'Critical' THEN 1
                WHEN 'HIGH' THEN 2 WHEN 'High' THEN 2
                WHEN 'MEDIUM' THEN 3 WHEN 'Medium' THEN 3
                ELSE 4 
              END ASC, 
              p.last_updated DESC
            LIMIT 1
            """
            result = session.run(query_priority).single()
            if result: return result["threat_id"]

            query_latest = """
            MATCH (p:Process)
            WHERE p.exec_id IS NOT NULL
            RETURN p.exec_id AS threat_id
            ORDER BY p.last_updated DESC
            LIMIT 1
            """
            result_latest = session.run(query_latest).single()
            return result_latest["threat_id"] if result_latest else None

    def get_process_full_graph(self, exec_id: str):
        """노드의 모든 속성(Property Keys)을 포함하여 그래프 반환"""
        with self.driver.session() as session:
            # 로그의 경고를 방지하기 위해 존재하지 않는 관계(OPENED/CREATED) 및 라벨(File)은 
            # 실제 데이터가 쌓이기 전까지 쿼리를 더 안전하게 수정하거나 주석 처리합니다.
            query = """
            MATCH (p:Process {exec_id: $exec_id})
            OPTIONAL MATCH path = (ancestor:Process)-[:CHILDREN*0..5]->(p)-[:CHILDREN*0..5]->(descendant:Process)
            WITH p, collect(DISTINCT path) AS paths
            
            // 파일 관련 경고 방지를 위해 실제 데이터가 없을 경우를 대비한 유연한 매칭
            OPTIONAL MATCH (p)-[r]->(f)
            WHERE type(r) IN ['OPENED', 'CREATED'] AND 'File' IN labels(f)
            
            RETURN p AS target_node, 
                   paths,
                   collect(DISTINCT f) AS file_nodes
            """
            result = session.run(query, exec_id=exec_id).single()
            
            if not result or not result["target_node"]:
                return None

            nodes = {}
            links = []

            # 노드의 모든 데이터를 dict(n)으로 추출하여 'data' 필드에 담음
            # 이 과정에서 Neo4j에 저장된 모든 항목(mitre_id, risk_score 등)이 프론트로 전달됨
            p_node = result["target_node"]
            nodes[p_node["exec_id"]] = {
                "id": p_node["exec_id"], 
                "label": p_node.get("comm", "Unknown"), 
                "type": "process", 
                "data": dict(p_node) 
            }

            for path in result["paths"]:
                if path:
                    for n in path.nodes:
                        eid = n["exec_id"]
                        if eid not in nodes:
                            nodes[eid] = {
                                "id": eid, 
                                "label": n.get("comm", "Unknown"), 
                                "type": "process", 
                                "data": dict(n)
                            }
                    for r in path.relationships:
                        links.append({
                            "source": r.start_node["exec_id"], 
                            "target": r.end_node["exec_id"], 
                            "label": "CHILDREN"
                        })

            for f in result["file_nodes"]:
                if f:
                    f_id = f.get("path") or f.get("name")
                    if f_id not in nodes:
                        nodes[f_id] = {
                            "id": f_id, 
                            "label": f.get("name", "Unknown File"), 
                            "type": "file", 
                            "data": dict(f)
                        }
                        links.append({ "source": exec_id, "target": f_id, "label": "FILE_ACCESS" })

            return {"nodes": list(nodes.values()), "links": links, "target_id": exec_id}

process_analysis_service = ProcessAnalysisService()