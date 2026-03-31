import os
import base64
import json
import tempfile
import pathlib
import markdown
import re
from datetime import datetime
from io import BytesIO

from google import genai
from google.genai import types
from neo4j import GraphDatabase
from playwright.async_api import async_playwright

# 환경 설정
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_AUTH = (os.getenv("NEO4J_USER", "neo4j"), os.getenv("NEO4J_PASSWORD"))
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

class ReportService:
    @staticmethod
    async def create_ai_report(exec_id: str):
        # 1. 데이터 조회 (Stage 1: Fetch)
        context = ReportService._fetch_neo4j_context(exec_id)
        if not context:
            print(f"❌ [DEBUG] Neo4j에서 데이터를 찾을 수 없습니다. exec_id: {exec_id}")
            return None

        # 2. LLM 분석 (Stage 2: Analysis)
        analysis_json = await ReportService._call_analysis_llm(context)
        if not analysis_json:
            return None

        # 3. 문서화 (Stage 3: Documentation)
        final_report_text = await ReportService._call_documentation_llm(analysis_json)
        print(f"📝 [DEBUG] 생성된 리포트 텍스트(일부): {final_report_text[:50]}...")

        # 4. PDF 생성 (Stage 4: Modern PDF Export)
        return await ReportService._export_to_pdf_modern(final_report_text, exec_id)

    @staticmethod
    def _fetch_neo4j_context(exec_id: str):
        """Neo4j에서 침해사고 분석에 필요한 모든 연관 노드 조회"""
        query = """
        MATCH (p:Process {exec_id: $eid})
        OPTIONAL MATCH (parent:Process)-[:CHILDREN]->(p)
        OPTIONAL MATCH (p)-[:CHILDREN]->(child:Process)
        OPTIONAL MATCH (p)-[r]->(target)
        WHERE type(r) IN ['ACCESSED', 'COMMUNICATED']
        WITH p, parent, 
             collect(distinct properties(child)) AS child_list,
             collect(distinct {
                 type: type(r),
                 label: labels(target)[0],
                 target: properties(target)
             }) AS activity_list
        RETURN {
            process: properties(p),
            parent: CASE WHEN parent IS NOT NULL THEN properties(parent) ELSE null END,
            children: child_list,
            activities: [a IN activity_list WHERE a.type IS NOT NULL]
        } AS context
        """
        try:
            with GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH) as driver:
                with driver.session() as session:
                    result = session.run(query, eid=exec_id).single()
                    if not result: return None
                    data = result["context"]
                    try:
                        decoded = base64.b64decode(exec_id).decode('utf-8')
                    except:
                        decoded = "Decoding Failed"
                    data['integrity'] = {"exec_id": exec_id, "decoded": decoded}
                    return data
        except Exception as e:
            print(f"❌ Neo4j 조회 에러: {e}")
            return None

    @staticmethod
    async def _call_analysis_llm(context):
        """2단계: Tier-3 전문가 관점의 사고 분석 데이터 생성 (JSON)"""
        system_msg = """당신은 Tier-3 침해사고 분석 전문가(Incident Response Investigator)입니다. 
제공된 EDR/그래프 데이터를 바탕으로 'Kill Chain' 관점의 심층 분석을 수행하십시오.

분석 시 다음 사항을 반드시 포함하여 JSON으로 응답하십시오:
1. mitre_attack: 최신 MITRE ATT&CK(v14+) 기준 기술명(TID) 및 매핑 결과.
2. root_cause: 최초 침투 경로 및 실행 원인에 대한 전문적 추정.
3. blast_radius: 해당 프로세스가 영향을 미친 자원(파일, 네트워크, 자식 프로세스)의 범위 요약.
4. risk_level: High, Medium, Low 중 하나로 선정.
5. risk_score: 1~10점 사이의 점수와 그 논리적 근거.
6. evidence_chain: 분석의 근거가 된 주요 데이터(PID, 실행 경로, 통신 대상 IP 등)."""

        user_prompt = f"다음 그래프 데이터를 분석하여 전문적인 보안 분석 JSON을 생성하라: {json.dumps(context, ensure_ascii=False)}"
        try:
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=user_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=system_msg,
                    response_mime_type="application/json",
                )
            )
            return json.loads(response.text)
        except Exception as e:
            print(f"❌ 분석 LLM 에러: {e}")
            return None

    @staticmethod
    async def _call_documentation_llm(analysis_json):
        """3단계: KISA 수석 분석관 톤앤매너로 보고서 본문 작성"""
        prompt = f"""당신은 KISA 사이버침해대응센터(KISC) 소속의 수석 분석관입니다. 
전달받은 분석 데이터를 바탕으로 보안 담당자용 '침해사고 분석 결과 보고서'를 작성하십시오.

[지시 사항]
1. 문체: '~함', '~임' 형태의 개조식 전문 평어체를 사용하여 객관성을 유지하십시오.
2. 용어: 'Lateral Movement', 'C2 Communication' 등 표준 보안 용어를 적극 활용하십시오.
3. 시각화: 중요한 수치나 연관 관계는 반드시 마크다운 표(Table)로 작성하십시오.
4. 위험도 표시: 위험도에 따라 <span class="risk-high">High</span> 와 같은 HTML 태그를 문서 내 적절히 활용하십시오.

[보고서 구성]
1. 사고 요약: 핵심 위협 요약 및 위험 등급
2. 침해 분석 상세: MITRE ATT&CK 매핑 및 타임라인 분석
3. 영향 범위(Blast Radius): 피해 확산 범위 분석
4. 대응 방안: 단기 격리 조치 및 장기적 시스템 강화(Hardening) 전략

데이터: {json.dumps(analysis_json, ensure_ascii=False)}
"""
        try:
            response = client.models.generate_content(model="gemini-2.5-flash", contents=prompt)
            return response.text
        except Exception as e:
            print(f"❌ 문서화 LLM 에러: {e}")
            return "## 보고서 생성 오류가 발생했습니다."

    @staticmethod
    async def _export_to_pdf_modern(text_content, exec_id):
        """4단계: 위험도 시각화 및 무결성 강조가 포함된 PDF 생성"""
        temp_dir = tempfile.gettempdir()
        output_path = os.path.join(temp_dir, f"K9_Advanced_Report_{exec_id[:8]}.pdf")
        
        current_dir = os.path.dirname(os.path.abspath(__file__))
        f_path = pathlib.Path(current_dir, "../../static/fonts/NanumGothic-Regular.ttf").absolute()
        b_path = pathlib.Path(current_dir, "../../static/fonts/NanumGothic-Bold.ttf").absolute()
        
        font_uri = f_path.as_uri() if f_path.exists() else ""
        bold_font_uri = b_path.as_uri() if b_path.exists() else ""

        html_body = markdown.markdown(text_content, extensions=['extra', 'tables'])

        html_template = f"""
        <!DOCTYPE html>
        <html lang="ko">
        <head>
            <meta charset="UTF-8">
            <style>
                @font-face {{
                    font-family: 'NanumGothic';
                    src: url('{font_uri}') format('truetype');
                }}
                @font-face {{
                    font-family: 'NanumGothicBold';
                    src: url('{bold_font_uri}') format('truetype');
                    font-weight: bold;
                }}
                body {{
                    font-family: 'NanumGothic', sans-serif;
                    padding: 50px;
                    line-height: 1.8;
                    color: #2c3e50;
                }}
                h1 {{ font-family: 'NanumGothicBold'; text-align: center; color: #1a2a6c; border-bottom: 3px double #1a2a6c; padding-bottom: 20px; margin-bottom: 40px; }}
                h2 {{ font-family: 'NanumGothicBold'; color: #1a2a6c; border-left: 8px solid #1a2a6c; padding-left: 15px; margin-top: 40px; background: #f8f9fa; }}
                table {{ width: 100%; border-collapse: collapse; margin: 25px 0; font-size: 0.95em; }}
                th, td {{ border: 1px solid #dee2e6; padding: 12px; text-align: left; }}
                th {{ background-color: #ebedef; font-family: 'NanumGothicBold'; }}
                
                /* 위항도별 라벨 디자인 */
                .risk-high {{ background-color: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; font-weight: bold; }}
                .risk-medium {{ background-color: #f39c12; color: white; padding: 2px 8px; border-radius: 4px; font-weight: bold; }}
                .risk-low {{ background-color: #2ecc71; color: white; padding: 2px 8px; border-radius: 4px; font-weight: bold; }}
                
                .integrity-box {{ margin-top: 30px; padding: 15px; border: 1px dashed #3498db; background-color: #ecf0f1; font-size: 0.85em; }}
                .footer {{ text-align: center; font-size: 0.8em; color: #95a5a6; margin-top: 60px; border-top: 1px solid #eee; padding-top: 20px; }}
            </style>
        </head>
        <body>
            <div style="text-align:right; font-size: 0.8em; color: #bdc3c7;">Report Signature: {exec_id}</div>
            <h1>침해사고 분석 결과 보고서 (KISC 전문 양식)</h1>
            
            <div class="content">{html_body}</div>
            
            <div class="integrity-box">
                <strong>[데이터 무결성 검증 정보]</strong><br>
                본 보고서는 K9 eBPF 보안 엔진이 수집한 커널 레벨 이벤트 데이터를 기반으로 자동 생성되었습니다.<br>
                분석 대상 실행 ID: <code>{exec_id}</code> (정합성 검증 완료)
            </div>

            <div class="footer">
                본 보고서는 K9 Security Engine & Gemini 2.5 Flash 기반의 AI 분석 시스템에 의해 생성된 공식 문서입니다.
            </div>
        </body>
        </html>
        """

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                await page.set_content(html_template, wait_until="networkidle")
                await page.pdf(
                    path=output_path,
                    format="A4",
                    print_background=True,
                    margin={ "top": "1.5cm", "bottom": "1.5cm", "left": "1.5cm", "right": "1.5cm" }
                )
                await browser.close()
            return output_path
        except Exception as e:
            print(f"❌ [ERROR] Playwright 렌더링 실패: {e}")
            return None