import React from 'react';

const ProcessDetailSidebar = ({ node, onClose }) => {
  if (!node) return null;

  const { type, data } = node;

  return (
    <div style={{ 
      width: '450px', backgroundColor: 'white', height: '100%', 
      boxShadow: '-4px 0 15px rgba(0,0,0,0.05)', borderLeft: '1px solid #eee',
      display: 'flex', flexDirection: 'column', zIndex: 100, flexShrink: 0
    }}>
      <div style={{ padding: '30px', overflowY: 'auto' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '30px' }}>
          <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 'bold', color: '#1a1a2e' }}>
            {type === 'process' ? '프로세스 상세 정보' : '파일 상세 정보'}
          </h2>
          <button onClick={onClose} style={{ border: 'none', background: 'none', cursor: 'pointer', fontSize: '24px', color: '#ccc' }}>×</button>
        </div>

        {/* 공통 식별 카드 */}
        <div style={{ backgroundColor: '#f9f8ff', padding: '20px', borderRadius: '12px', border: '1px solid #efecff', marginBottom: '25px' }}>
          <div style={{ color: '#6c5ce7', fontSize: '11px', fontWeight: 'bold', letterSpacing: '1px', marginBottom: '15px' }}>
            {type.toUpperCase()} IDENTIFICATION
          </div>
          
          {type === 'process' ? (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
              <div><span style={{ color: '#999', fontSize: '12px' }}>PID</span><div style={{ fontWeight: 'bold' }}>{data.pid}</div></div>
              <div><span style={{ color: '#999', fontSize: '12px' }}>COMM</span><div style={{ fontWeight: 'bold' }}>{data.comm}</div></div>
              <div><span style={{ color: '#999', fontSize: '12px' }}>Severity</span><div style={{ color: data.severity === 'CRITICAL' ? 'red' : 'inherit' }}>{data.severity}</div></div>
              <div><span style={{ color: '#999', fontSize: '12px' }}>User</span><div>{data.uid === 0 ? 'root' : 'user'}</div></div>
            </div>
          ) : (
            <div>
              <div style={{ marginBottom: '10px' }}><span style={{ color: '#999', fontSize: '12px' }}>FILE NAME</span><div style={{ fontWeight: 'bold' }}>{data.name}</div></div>
              <div><span style={{ color: '#999', fontSize: '12px' }}>FULL PATH</span><div style={{ fontSize: '13px', wordBreak: 'break-all' }}>{data.path}</div></div>
            </div>
          )}
        </div>

        {/* 프로세스일 경우에만 커맨드라인 표시 */}
        {type === 'process' && (
          <div style={{ marginBottom: '25px' }}>
            <div style={{ color: '#999', fontSize: '13px', marginBottom: '8px' }}>Command Line</div>
            <pre style={{ 
              backgroundColor: '#1a1a2e', color: '#55efc4', padding: '12px', 
              borderRadius: '8px', whiteSpace: 'pre-wrap', fontSize: '12px', margin: 0 
            }}>
              {data.full_command_line || '정보 없음'}
            </pre>
          </div>
        )}

        <button style={{ 
          width: '100%', padding: '15px', backgroundColor: '#6c5ce7', color: 'white', 
          border: 'none', borderRadius: '10px', fontWeight: 'bold', cursor: 'pointer', marginTop: '20px' 
        }}>
          ✨ [AI 시나리오 보고서 생성]
        </button>
      </div>
    </div>
  );
};

export default ProcessDetailSidebar;