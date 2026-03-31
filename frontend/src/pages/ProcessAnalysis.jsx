import React, { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import ForceGraph2D from 'react-force-graph-2d';
import ProcessDetailSidebar from '../components/ProcessDetailSidebar';
import apiClient from '../api/client';

const ProcessAnalysis = () => {
  const { execId } = useParams();
  const navigate = useNavigate();
  
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });
  const [selectedNode, setSelectedNode] = useState(null);
  const [loading, setLoading] = useState(false);
  const [infoMessage, setInfoMessage] = useState("");
  const [dimensions, setDimensions] = useState({ width: 0, height: 0 });

  const fgRef = useRef();
  const containerRef = useRef();

  // [디자인] 위험도별 색상 정의
  const SEVERITY_COLORS = {
    CRITICAL: '#e74c3c', // 빨강
    HIGH: '#e67e22',     // 주황
    MEDIUM: '#f1c40f',   // 노랑
    LOW: '#3498db',      // 파랑
    DEFAULT: '#6c5ce7'   // 기본 보라
  };

  const getSeverityColor = (node) => {
    // 파일 및 네트워크 기본색을 유지하되, 위험도(severity) 데이터가 있다면 해당 색상을 우선 적용
    const severity = node.data?.severity?.toUpperCase();
    if (SEVERITY_COLORS[severity]) return SEVERITY_COLORS[severity];

    if (node.label === 'File') return '#95a5a6'; // 회색
    if (node.label === 'NetworkEndpoint') return '#2ecc71'; // 초록색
    
    return SEVERITY_COLORS.DEFAULT;
  };

  // [수정] 범례: 실제 노드 모양 및 테두리 색상과 1:1 매칭
  const GraphLegend = () => {
    if (graphData.nodes.length === 0) return null;

    return (
      <div style={{
        position: 'absolute', top: '20px', left: '20px', backgroundColor: 'rgba(255, 255, 255, 0.95)',
        padding: '15px', borderRadius: '12px', border: '1px solid #e1e8f0', boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
        zIndex: 5, pointerEvents: 'none', minWidth: '180px'
      }}>
        <div style={{ fontSize: '11px', fontWeight: '800', color: '#94a3b8', marginBottom: '12px', letterSpacing: '0.8px' }}>OBJECT TYPE (SHAPE)</div>
        <ul style={{ listStyle: 'none', padding: 0, margin: '0 0 15px 0', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <li style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '12px', color: '#2c3e50' }}>
            <div style={{ width: '12px', height: '12px', borderRadius: '50%', border: '2px solid #666', backgroundColor: '#fff' }} /> 프로세스 (Circle)
          </li>
          <li style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '12px', color: '#2c3e50' }}>
            <div style={{ width: '11px', height: '11px', border: '2px solid #666', backgroundColor: '#fff' }} /> 파일 시스템 (Square)
          </li>
          <li style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '12px', color: '#2c3e50' }}>
            <div style={{ width: 0, height: 0, borderLeft: '6px solid transparent', borderRight: '6px solid transparent', borderBottom: '11px solid #666' }} /> 네트워크 (Triangle)
          </li>
        </ul>

        <div style={{ fontSize: '11px', fontWeight: '800', color: '#94a3b8', marginBottom: '10px', borderTop: '1px solid #eee', paddingTop: '10px' }}>SEVERITY (COLOR)</div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
            <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '10px', color: '#2c3e50' }}>
              <div style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: SEVERITY_COLORS[sev] }} /> {sev}
            </div>
          ))}
        </div>
      </div>
    );
  };

  useEffect(() => {
    const handleResize = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.offsetWidth,
          height: containerRef.current.offsetHeight,
        });
      }
    };
    handleResize();
    const timer = setTimeout(handleResize, 320); 
    window.addEventListener('resize', handleResize);
    return () => { window.removeEventListener('resize', handleResize); clearTimeout(timer); };
  }, [selectedNode]);

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        const savedUser = JSON.parse(localStorage.getItem('ebpf_user'));
        const token = savedUser?.access_token;
        const url = execId 
          ? `/api/v1/process_analysis/graph/${encodeURIComponent(execId)}` 
          : `/api/v1/process_analysis/graph`;

        const response = await apiClient.get(url, { headers: { 'Authorization': `Bearer ${token}` } });
        const data = response.data;
        
        setGraphData(data);
        setInfoMessage(data.message || "");
        if (!execId && data.target_id) navigate(`/process_analysis/${data.target_id}`, { replace: true });

        setTimeout(() => fgRef.current?.zoomToFit(400, 100), 500);
      } catch (err) { console.error("데이터 로드 실패:", err); }
      finally { setLoading(false); }
    };
    fetchData();
  }, [execId, navigate]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', backgroundColor: '#fff', overflow: 'hidden' }}>
      <div style={{ height: '60px', borderBottom: '1px solid #eee', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 30px', flexShrink: 0 }}>
        <h1 style={{ fontSize: '18px', fontWeight: 'bold', color: '#1a1a2e', margin: 0 }}>실시간 위협 그래프 분석</h1>
        {infoMessage && <div style={{ backgroundColor: '#fff9db', color: '#f08c00', padding: '6px 15px', borderRadius: '20px', fontSize: '13px', border: '1px solid #ffe066' }}>ℹ️ {infoMessage}</div>}
      </div>

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden', position: 'relative' }}>
        <div ref={containerRef} style={{ flex: 1, position: 'relative', backgroundColor: '#fcfcfd', minWidth: 0 }}>
          <GraphLegend />
          
          {dimensions.width > 0 && (
            <ForceGraph2D
              ref={fgRef}
              graphData={graphData}
              width={dimensions.width}
              height={dimensions.height}
              linkDirectionalArrowLength={5}
              linkDirectionalArrowRelPos={1}
              linkCurvature={0.2}
              linkWidth={1.5}
              linkColor={() => '#e2e8f0'}

              nodeCanvasObject={(node, ctx, globalScale) => {
                const label = node.label || 'Unknown';
                const isTarget = String(node.id) === String(execId);
                const nodeColor = getSeverityColor(node);
                
                // 크기 설정
                const radius = isTarget ? 20 / globalScale : 16 / globalScale;

                ctx.beginPath();
                
                // [수정] 타입별 도형 구분 그리기
                if (node.label === 'File') {
                  // 파일: 사각형
                  ctx.rect(node.x - radius, node.y - radius, radius * 2, radius * 2);
                } else if (node.label === 'NetworkEndpoint') {
                  // 네트워크: 삼각형
                  ctx.moveTo(node.x, node.y - radius);
                  ctx.lineTo(node.x - radius, node.y + radius);
                  ctx.lineTo(node.x + radius, node.y + radius);
                  ctx.closePath();
                } else {
                  // 프로세스: 원형
                  ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI, false);
                }

                // [수정] 모든 노드 공통: 내부 비우기(흰색) + 테두리 강조
                ctx.fillStyle = '#ffffff';
                ctx.fill();
                ctx.strokeStyle = nodeColor;
                
                // 테두리 두께 유지 (Target은 조금 더 두껍게 2.5, 일반은 1.5)
                ctx.lineWidth = (isTarget ? 2.5 : 1.5) / globalScale;
                ctx.stroke();

                // 라벨 텍스트 설정 (색상은 테두리 색상과 동일하게)
                const fontSize = 10 / globalScale;
                ctx.font = `${isTarget ? 'bold' : '500'} ${fontSize}px Prevendard, Sans-Serif`;
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillStyle = nodeColor;
                
                ctx.fillText(label, node.x, node.y);
              }}
              onNodeClick={(node) => setSelectedNode(node)}
              onBackgroundClick={() => setSelectedNode(null)}
            />
          )}
        </div>

        <div style={{ 
          width: selectedNode ? '450px' : '0px', 
          visibility: selectedNode ? 'visible' : 'hidden',
          transition: 'width 0.3s cubic-bezier(0.4, 0, 0.2, 1), visibility 0.3s', 
          overflow: 'hidden', 
          flexShrink: 0, 
          backgroundColor: 'white',
          borderLeft: selectedNode ? '1px solid #eee' : 'none',
          boxShadow: selectedNode ? '-5px 0 15px rgba(0,0,0,0.05)' : 'none',
          zIndex: 10
        }}>
          {selectedNode && (
            <ProcessDetailSidebar node={selectedNode} onClose={() => setSelectedNode(null)} />
          )}
        </div>
      </div>
    </div>
  );
};

export default ProcessAnalysis;