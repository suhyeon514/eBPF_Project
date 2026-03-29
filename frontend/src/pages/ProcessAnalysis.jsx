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

  // 위험도별 색상 맵핑 함수 (빨강, 주황, 노랑, 파랑)
  const getSeverityColor = (severity) => {
    const sev = severity?.toUpperCase();
    switch (sev) {
      case 'CRITICAL': return '#e74c3c'; // 빨강
      case 'HIGH': return '#e67e22';     // 주황
      case 'MEDIUM': return '#f1c40f';   // 노랑
      case 'LOW': return '#3498db';      // 파랑
      default: return '#6c5ce7';         // 기본 보라
    }
  };

  // 범례(Legend) 컴포넌트
  const GraphLegend = () => {
    const hasParent = graphData.nodes.some(n => String(n.id) === String(execId));
    const hasChild = graphData.nodes.some(n => String(n.id) !== String(execId));
    const hasAlert = graphData.nodes.some(n => ['CRITICAL', 'HIGH'].includes(n.data?.severity?.toUpperCase()));

    if (graphData.nodes.length === 0) return null;

    return (
      <div style={{
        position: 'absolute', top: '20px', left: '20px', backgroundColor: 'rgba(255, 255, 255, 0.9)',
        padding: '15px', borderRadius: '12px', border: '1px solid #e1e8f0', boxShadow: '0 4px 12px rgba(0,0,0,0.05)',
        zIndex: 5, pointerEvents: 'none', minWidth: '140px'
      }}>
        <div style={{ fontSize: '12px', fontWeight: 'bold', color: '#7f8c8d', marginBottom: '10px', letterSpacing: '0.5px' }}>GRAPH LEGEND</div>
        <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {hasParent && (
            <li style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '13px', color: '#2c3e50' }}>
              <div style={{ width: '12px', height: '12px', borderRadius: '50%', backgroundColor: '#6c5ce7' }} /> 부모 프로세스
            </li>
          )}
          {hasChild && (
            <li style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '13px', color: '#2c3e50' }}>
              <div style={{ width: '10px', height: '10px', borderRadius: '50%', border: '2px solid #6c5ce7', backgroundColor: '#fff' }} /> 자식 프로세스
            </li>
          )}
          {hasAlert && (
            <li style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '13px', color: '#2c3e50' }}>
              <div style={{ width: '10px', height: '10px', borderRadius: '50%', border: '2px solid #e74c3c', backgroundColor: '#fff' }} /> 의심 탐지
            </li>
          )}
        </ul>
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
        <h1 style={{ fontSize: '18px', fontWeight: 'bold', color: '#1a1a2e', margin: 0 }}>프로세스 분석</h1>
        {infoMessage && <div style={{ backgroundColor: '#fff9db', color: '#f08c00', padding: '6px 15px', borderRadius: '20px', fontSize: '13px', border: '1px solid #ffe066' }}>ℹ️ {infoMessage}</div>}
      </div>

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden', position: 'relative' }}>
        <div ref={containerRef} style={{ flex: 1, position: 'relative', backgroundColor: '#fcfcfd', minWidth: 0 }}>
          {/* 동적 범례 추가 */}
          <GraphLegend />
          
          {dimensions.width > 0 && (
            <ForceGraph2D
              ref={fgRef}
              graphData={graphData}
              width={dimensions.width}
              height={dimensions.height}
              linkDirectionalArrowLength={4}
              linkDirectionalArrowRelPos={1}
              linkCurvature={0.2}
              linkWidth={1.2}
              linkColor={() => '#dcdde1'}

              nodeCanvasObject={(node, ctx, globalScale) => {
                const label = node.label || 'Unknown';
                const isTarget = String(node.id) === String(execId); // 부모 노드 여부
                const severity = node.data?.severity;
                const nodeColor = getSeverityColor(severity);
                
                const radius = isTarget ? 22 / globalScale : 17 / globalScale;

                ctx.beginPath();
                ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI, false);

                if (isTarget) {
                  // 부모 노드: 색상 채우기
                  ctx.fillStyle = nodeColor;
                  ctx.fill();
                  ctx.strokeStyle = '#2f3542';
                  ctx.lineWidth = 2 / globalScale;
                  ctx.stroke();
                } else {
                  // 자식 노드: 테두리만 그리기
                  ctx.strokeStyle = nodeColor;
                  ctx.lineWidth = 2.5 / globalScale;
                  ctx.stroke();
                  ctx.fillStyle = '#fff'; // 내부 흰색 채우기 (가독성)
                  ctx.fill();
                }

                // 라벨 텍스트 설정
                const fontSize = 11 / globalScale;
                ctx.font = `${isTarget ? 'bold' : 'normal'} ${fontSize}px Prevendard, Sans-Serif`;
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';

                // 글자색 결정
                if (isTarget) {
                    // 채워진 노드일 경우 배경색에 맞춰 텍스트 색상 결정
                    ctx.fillStyle = (severity?.toUpperCase() === 'MEDIUM') ? '#2f3542' : '#fff';
                } else {
                    // 테두리만 있는 노드일 경우 테두리 색상과 동일하게
                    ctx.fillStyle = nodeColor;
                }
                
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