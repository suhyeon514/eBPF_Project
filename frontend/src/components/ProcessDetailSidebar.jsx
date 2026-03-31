import React, { useState } from 'react';
import apiClient from '../api/client';

const ProcessDetailSidebar = ({ node, onClose }) => {
  //로딩 상태 관리
  const [isGenerating, setIsGenerating] = useState(false);
  if (!node) return null;

  const { type, data } = node;

  const formatTimestamp = (ts) => {
  if (!ts || isNaN(ts)) return 'undefined';

  let numericTs = parseFloat(ts);

  // [핵심 로직] 유닉스 타임스탬프 단위 판별
  // 숫자가 10,000,000,000보다 작으면 '초(s)' 단위로 보고 1000을 곱합니다.
  // 그보다 크면 이미 '밀리초(ms)' 단위라고 판단합니다.
  if (numericTs < 10000000000) {
    numericTs *= 1000;
  }

  const date = new Date(numericTs);

  return date.toLocaleString('ko-KR', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  });
};

  // 정보 항목 렌더링용 도우미 컴포넌트
  const InfoItem = ({ label, value, color, isCode }) => (
    <div style={{ marginBottom: '12px' }}>
      <span style={{ color: '#94a3b8', fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
        {label}
      </span>
      <div style={{ 
        fontWeight: '500', 
        fontSize: '14px', 
        color: color || '#1e293b', 
        wordBreak: 'break-all',
        fontFamily: isCode ? 'JetBrains Mono, monospace' : 'inherit',
        backgroundColor: isCode ? '#f1f5f9' : 'transparent',
        padding: isCode ? '2px 6px' : '0',
        borderRadius: isCode ? '4px' : '0'
      }}>
        {value !== undefined && value !== null && value !== "" ? String(value) : 'undefined'}
      </div>
    </div>
  );

  // 위험도별 색상 맵핑
  const getSeverityColor = (sev) => {
    switch (sev?.toUpperCase()) {
      case 'CRITICAL': return '#e11d48';
      case 'HIGH': return '#f59e0b';
      case 'MEDIUM': return '#d97706';
      case 'LOW': return '#2563eb';
      default: return '#64748b';
    }
  };

  const handleGenerateReport = async () => {
    const execId = data.exec_id;
    if (!execId) {
      alert("유효한 Execution ID가 없습니다.");
      return;
    }

  setIsGenerating(true); // 로딩 시작

  try {
      // 1. 백엔드에 PDF 생성 요청 (바이너리 데이터를 받기 위해 responseType 설정 필수)
      const response = await apiClient.post('/api/v1/report/generate', 
        { exec_id: execId }, 
        { responseType: 'blob' } 
      );

      // 2. 브라우저 메모리에 PDF Blob 객체 생성
      const blob = new Blob([response.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);

      // 3. 임시 <a> 태그를 만들어 클릭 이벤트 트리거 (호스트 PC로 다운로드)
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `K9_Report_${execId.substring(0, 8)}.pdf`);
      document.body.appendChild(link);
      link.click();

      // 4. 메모리 정리
      link.parentNode.removeChild(link);
      window.URL.revokeObjectURL(url);

    } catch (err) {
      console.error("보고서 생성 실패:", err);
      alert("AI 보고서 생성 중 오류가 발생했습니다. 백엔드 서버 로그를 확인하세요.");
    } finally {
      setIsGenerating(false); // 로딩 종료
    }
  };

  return (
    <div style={{ 
      width: '450px', backgroundColor: 'white', height: '100%', 
      boxShadow: '-10px 0 25px rgba(0,0,0,0.05)', borderLeft: '1px solid #e2e8f0',
      display: 'flex', flexDirection: 'column', zIndex: 100, flexShrink: 0
    }}>
      {/* 헤더 세션 */}
      <div style={{ 
        padding: '25px 30px', borderBottom: '1px solid #f1f5f9', 
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        position: 'sticky', top: 0, backgroundColor: 'white', zIndex: 1
      }}>
        <h2 style={{ margin: 0, fontSize: '18px', fontWeight: '800', color: '#0f172a' }}>
          {type === 'process' ? 'Process Analysis' : 'File Context'}
        </h2>
        <button onClick={onClose} style={{ border: 'none', background: 'none', cursor: 'pointer', fontSize: '28px', color: '#cbd5e1', lineHeight: 1 }}>&times;</button>
      </div>

      <div style={{ padding: '30px', overflowY: 'auto', flex: 1 }}>
        
        {/* 1. Security Context (가장 중요한 보안 정보) */}
        <div style={{ 
          backgroundColor: '#fff1f2', padding: '20px', borderRadius: '12px', 
          border: '1px solid #ffe4e6', marginBottom: '25px' 
        }}>
          <div style={{ color: '#e11d48', fontSize: '11px', fontWeight: '800', marginBottom: '15px' }}>
            SECURITY ALERT CONTEXT
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
            <InfoItem label="Severity" value={data.severity} color={getSeverityColor(data.severity)} />
            <InfoItem label="Risk Score" value={data.risk_score} color="#e11d48" />
            <InfoItem label="MITRE ATT&CK ID" value={data.mitre_attack_id} color="#4338ca" isCode />
          </div>
        </div>

        {/* 2. Process Identification (기본 식별 정보) */}
        <section style={{ marginBottom: '30px' }}>
          <h3 style={{ fontSize: '13px', color: '#64748b', marginBottom: '15px', borderBottom: '1px solid #f1f5f9', paddingBottom: '5px' }}>Identification</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
            <InfoItem label="PID" value={data.pid} />
            <InfoItem label="User (UID)" value={data.uid === 0 ? 'root (0)' : `${data.uid}`} />
            <InfoItem label="Hostname" value={data.hostname} />
            <InfoItem label="IP Address" value={data.ip} />
          </div>
          <InfoItem label="Executable Path" value={data.exe_path} isCode />
        </section>

        {/* 3. Runtime Context (실행 및 타임라인) */}
        <section style={{ marginBottom: '30px' }}>
          <h3 style={{ fontSize: '13px', color: '#64748b', marginBottom: '15px', borderBottom: '1px solid #f1f5f9', paddingBottom: '5px' }}>Timeline & Network</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
            <InfoItem label="Start Time" value={formatTimestamp(data.start_time)} />
            <InfoItem label="Last Updated" value={formatTimestamp(data.last_updated)} />
            <InfoItem label="Network Port" value={data.port} />
            <InfoItem label="Protocol" value={data.protocol} />
          </div>
          <InfoItem label="Execution ID" value={data.exec_id} isCode />
        </section>

        {/* 4. Execution Details (명령어 라인) */}
        <div style={{ marginBottom: '30px' }}>
          <div style={{ color: '#64748b', fontSize: '11px', fontWeight: '600', marginBottom: '8px', textTransform: 'uppercase' }}>Full Command Line</div>
          <pre style={{ 
            backgroundColor: '#0f172a', color: '#38bdf8', padding: '15px', 
            borderRadius: '8px', whiteSpace: 'pre-wrap', fontSize: '12px', 
            margin: 0, border: '1px solid #1e293b', lineHeight: '1.6',
            fontFamily: 'JetBrains Mono, Fira Code, monospace'
          }}>
            {data.full_command_line || '정보 없음'}
          </pre>
        </div>

        {/* 5. Metadata */}
        <InfoItem label="Event ID" value={data.event_id} isCode />

        <div style={{ height: '20px' }} /> {/* 하단 여백 */}
      </div>

      {/* 액션 하단 바 */}
      <div style={{ padding: '20px 30px', borderTop: '1px solid #f1f5f9', backgroundColor: '#f8fafc' }}>
        <button 
          onClick={handleGenerateReport} // [수정] 클릭 이벤트 연결
          disabled={isGenerating}      // [추가] 생성 중일 때 버튼 비활성화
          style={{ 
            width: '100%', padding: '16px', 
            backgroundColor: isGenerating ? '#94a3b8' : '#6366f1', // 로딩 시 색상 변경
            color: 'white', 
            border: 'none', borderRadius: '12px', fontWeight: '700', fontSize: '14px',
            cursor: isGenerating ? 'not-allowed' : 'pointer', 
            transition: 'background 0.2s',
            display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px'
          }}
        >
          {isGenerating ? (
            <>
              <span className="animate-spin">⏳</span> 분석 보고서 생성 중...
            </>
          ) : (
            <>
              <span>✨</span> [AI 시나리오 보고서 생성]
            </>
          )}
        </button>
      </div>
    </div>
  );
};

export default ProcessDetailSidebar;