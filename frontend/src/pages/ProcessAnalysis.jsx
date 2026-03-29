import React, { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import ForceGraph2D from 'react-force-graph-2d';
import ProcessDetailSidebar from '../components/ProcessDetailSidebar';

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

  // 레이아웃 리사이징: 사이드바가 열릴 때 그래프 크기를 즉시 재계산
  useEffect(() => {
    const handleResize = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.offsetWidth,
          height: containerRef.current.offsetHeight,
        });
      }
    };
    window.addEventListener('resize', handleResize);
    handleResize();
    return () => window.removeEventListener('resize', handleResize);
  }, [selectedNode]); // 사이드바 상태 변화 감지

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        const savedUser = JSON.parse(localStorage.getItem('ebpf_user'));
        const token = savedUser?.access_token;
        const url = execId 
          ? `/process_analysis/graph/${encodeURIComponent(execId)}` 
          : `/process_analysis/graph`;

        const response = await fetch(url, { 
          headers: { 'Authorization': `Bearer ${token}` } 
        });
        const data = await response.json();
        
        setGraphData(data);
        setInfoMessage(data.message || "");
        if (!execId && data.target_id) {
          navigate(`/process_analysis/${data.target_id}`, { replace: true });
        }

        setTimeout(() => fgRef.current?.zoomToFit(400, 100), 500);
      } catch (err) { console.error("데이터 로드 실패:", err); }
      finally { setLoading(false); }
    };
    fetchData();
  }, [execId, navigate]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', backgroundColor: '#fff', overflow: 'hidden' }}>
      {/* 상단 헤더 */}
      <div style={{ height: '60px', borderBottom: '1px solid #eee', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 30px', flexShrink: 0 }}>
        <h1 style={{ fontSize: '18px', fontWeight: 'bold', color: '#1a1a2e', margin: 0 }}>프로세스 분석</h1>
        {infoMessage && <div style={{ backgroundColor: '#fff9db', color: '#f08c00', padding: '6px 15px', borderRadius: '20px', fontSize: '13px', border: '1px solid #ffe066' }}>ℹ️ {infoMessage}</div>}
      </div>

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        {/* 왼쪽: 그래프 영역 (minWidth: 0 이 핵심입니다) */}
        <div ref={containerRef} style={{ flex: 1, minWidth: 0, position: 'relative', backgroundColor: '#fcfcfd' }}>
          {dimensions.width > 0 && (
            <ForceGraph2D
              ref={fgRef}
              graphData={graphData}
              width={dimensions.width}
              height={dimensions.height}

              // --- [화살표 & 선 스타일 최종 수정] ---
              linkDirectionalArrowLength={4}      // 촉 크기를 적절하게 조절
              linkDirectionalArrowRelPos={1}      // 자식(Target) 노드 끝에 배치
              linkCurvature={0.2}                 // 관계선 곡선화
              linkWidth={1.2}                     // 선 굵기
              linkColor={() => '#a4b0be'}         // 선 색상을 진한 회색으로 변경 (잘 보이게)

              nodeCanvasObject={(node, ctx, globalScale) => {
                const label = node.label || 'Unknown';
                const isTarget = String(node.id) === String(execId);
                const isAlert = node.data?.severity === 'CRITICAL' || node.data?.severity === 'HIGH';
                const radius = 18 / globalScale;

                ctx.beginPath();
                ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI, false);
                if (isTarget) {
                  ctx.fillStyle = '#6c5ce7'; ctx.fill();
                  ctx.fillStyle = '#fff';
                } else {
                  ctx.fillStyle = '#fff'; ctx.fill();
                  ctx.strokeStyle = isAlert ? '#ff7675' : '#6c5ce7';
                  ctx.lineWidth = 2 / globalScale; ctx.stroke();
                  ctx.fillStyle = isAlert ? '#ff7675' : '#6c5ce7';
                }
                ctx.font = `${11 / globalScale}px Sans-Serif`;
                ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
                ctx.fillText(label, node.x, node.y);
              }}
              onNodeClick={(node) => setSelectedNode(node)}
              onBackgroundClick={() => setSelectedNode(null)}
            />
          )}
        </div>

        {/* 오른쪽: 사이드바 슬라이드 */}
        <div style={{ 
          width: selectedNode ? '450px' : '0px', 
          transition: 'width 0.3s cubic-bezier(0.4, 0, 0.2, 1)', 
          overflow: 'hidden', 
          flexShrink: 0, 
          backgroundColor: 'white',
          borderLeft: selectedNode ? '1px solid #eee' : 'none',
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