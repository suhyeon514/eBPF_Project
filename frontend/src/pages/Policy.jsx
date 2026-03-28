import { useState, useEffect } from 'react';
import apiClient from '../api/client';

function Policy() {
  const [content, setContent] = useState('');
  const [hash, setHash] = useState('');
  const [loading, setLoading] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);

  const fetchPolicy = async () => {
    setLoading(true);
    try {
      const response = await apiClient.get('/api/v1/policy/content');
      setContent(response.data.content);
      setHash(response.data.hash);
      setLastUpdated(new Date());
    } catch (err) {
      console.error('정책 로드 실패:', err);
      setContent('# 정책 파일을 불러오지 못했습니다.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPolicy();
  }, []);

  return (
    <div>
      <header style={{ marginBottom: '30px' }}>
        <h4 style={{ color: '#888', margin: 0, fontSize: '12px' }}>Agent Configuration</h4>
        <h1 style={{ marginTop: '5px', fontSize: '24px' }}>에이전트 정책 설정</h1>
      </header>

      {/* 메타 정보 카드 */}
      <div style={{
        display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px', marginBottom: '24px'
      }}>
        <MetaCard icon="🔐" label="정책 해시 (SHA-256)" value={hash ? hash.slice(0, 16) + '…' : '-'} full={hash} />
        <MetaCard icon="🕐" label="마지막 조회" value={lastUpdated ? lastUpdated.toLocaleTimeString() : '-'} />
        <MetaCard
          icon="⚙️"
          label="상태"
          value={content ? '정상 로드됨' : '로드 실패'}
          valueColor={content ? '#2ed573' : '#ff4757'}
        />
      </div>

      {/* 정책 YAML 뷰어 */}
      <div style={{ backgroundColor: 'white', borderRadius: '16px', boxShadow: '0 4px 12px rgba(0,0,0,0.05)', overflow: 'hidden' }}>
        <div style={{
          padding: '16px 20px', borderBottom: '1px solid #f0f0f0',
          display: 'flex', justifyContent: 'space-between', alignItems: 'center'
        }}>
          <span style={{ fontWeight: 'bold', color: '#333', fontSize: '15px' }}>
            📄 policy.yaml
          </span>
          <button
            onClick={fetchPolicy}
            disabled={loading}
            style={{
              padding: '8px 16px', borderRadius: '8px', border: '1px solid #ddd',
              backgroundColor: loading ? '#f8f9fa' : 'white', cursor: loading ? 'not-allowed' : 'pointer',
              fontSize: '13px', color: '#666', fontWeight: 'bold',
            }}
          >
            {loading ? '로딩 중...' : '🔄 새로고침'}
          </button>
        </div>
        <pre style={{
          margin: 0, padding: '24px', backgroundColor: '#1e1e2e', color: '#cdd6f4',
          fontSize: '13px', lineHeight: '1.7', overflowX: 'auto',
          fontFamily: "'Consolas', 'Monaco', 'Courier New', monospace",
          maxHeight: '600px', overflowY: 'auto',
        }}>
          {loading ? '로딩 중...' : (content || '내용이 없습니다.')}
        </pre>
      </div>

      {/* 전체 해시 */}
      {hash && (
        <div style={{
          marginTop: '16px', padding: '12px 16px', backgroundColor: '#f8f9fa',
          borderRadius: '10px', fontSize: '12px', color: '#888', wordBreak: 'break-all'
        }}>
          <strong style={{ color: '#555' }}>전체 해시: </strong>{hash}
        </div>
      )}
    </div>
  );
}

function MetaCard({ icon, label, value, full, valueColor }) {
  return (
    <div style={{
      backgroundColor: 'white', borderRadius: '12px', padding: '18px',
      boxShadow: '0 2px 8px rgba(0,0,0,0.04)', border: '1px solid #f0f0f0'
    }}>
      <div style={{ fontSize: '20px', marginBottom: '8px' }}>{icon}</div>
      <div style={{ fontSize: '12px', color: '#aaa', marginBottom: '6px' }}>{label}</div>
      <div
        title={full || value}
        style={{ fontWeight: 'bold', color: valueColor || '#333', fontSize: '14px', wordBreak: 'break-all' }}
      >
        {value}
      </div>
    </div>
  );
}

export default Policy;
