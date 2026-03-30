import { useState, useEffect } from 'react';
import apiClient from '../api/client';

function Forensics() {
  const [assets, setAssets] = useState([]);
  const [total, setTotal] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [dumpStatus, setDumpStatus] = useState({}); // { hostname: { loading, result } }

  const pageSize = 10;

  const fetchAssets = async () => {
    try {
      const response = await apiClient.get('/api/v1/assets/', {
        params: { page: currentPage, size: pageSize },
      });
      setAssets(response.data.items);
      setTotal(response.data.total);
    } catch (err) {
      console.error('에이전트 목록 로드 실패:', err);
    }
  };

  useEffect(() => {
    fetchAssets();
  }, [currentPage]);

  const handleDump = async (asset) => {
    const key = asset.hostname;
    setDumpStatus(prev => ({ ...prev, [key]: { loading: true, result: null } }));
    try {
      const response = await apiClient.post('/api/v1/forensic/avml-dump', {
        agent_id: asset.hostname,
        reason: 'Manual Trigger via Web',
      });
      setDumpStatus(prev => ({
        ...prev,
        [key]: { loading: false, result: response.data },
      }));
    } catch (err) {
      setDumpStatus(prev => ({
        ...prev,
        [key]: { loading: false, result: { status: 'error', message: '요청 실패: 서버 오류' } },
      }));
    }
  };

  const totalPages = Math.ceil(total / pageSize);

  return (
    <div>
      <header style={{ marginBottom: '30px' }}>
        <h4 style={{ color: '#888', margin: 0, fontSize: '12px' }}>Memory Forensics</h4>
        <h1 style={{ marginTop: '5px', fontSize: '24px' }}>포렌식 덤프 저장소</h1>
      </header>

      {/* 안내 배너 */}
      <div style={{
        backgroundColor: '#f0eeff', borderRadius: '12px', padding: '16px 20px',
        marginBottom: '24px', display: 'flex', alignItems: 'center', gap: '12px',
        border: '1px solid #d6ccff'
      }}>
        <span style={{ fontSize: '20px' }}>💾</span>
        <div>
          <div style={{ fontWeight: 'bold', color: '#6c5ce7', marginBottom: '4px' }}>AVML 메모리 덤프</div>
          <div style={{ fontSize: '13px', color: '#636e72' }}>
            에이전트가 온라인 상태일 때만 덤프 명령이 전달됩니다. 오프라인 에이전트에는 명령이 실패합니다.
          </div>
        </div>
      </div>

      {/* 에이전트 테이블 */}
      <div style={tableContainerStyle}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={theadStyle}>
              <th style={{ padding: '15px' }}>상태</th>
              <th>호스트명</th>
              <th>IP 주소</th>
              <th>OS</th>
              <th>위험점수</th>
              <th style={{ textAlign: 'center', width: '220px' }}>덤프 명령</th>
            </tr>
          </thead>
          <tbody>
            {assets.map((asset) => {
              const ds = dumpStatus[asset.hostname];
              return (
                <tr key={asset.id} style={trStyle}>
                  <td style={{ padding: '15px' }}><StatusDot status={asset.status} /></td>
                  <td style={{ fontWeight: 'bold' }}>{asset.hostname}</td>
                  <td style={{ color: '#666' }}>{asset.ip_address}</td>
                  <td style={{ fontSize: '13px', color: '#555' }}>🐧 {asset.os_info}</td>
                  <td style={{ fontWeight: 'bold', color: getRiskColor(asset.risk_score), textAlign: 'center' }}>
                    {asset.risk_score}
                  </td>
                  <td style={{ textAlign: 'center', padding: '10px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '10px' }}>
                      <button
                        onClick={() => handleDump(asset)}
                        disabled={ds?.loading}
                        style={{
                          padding: '8px 16px', borderRadius: '8px', border: 'none',
                          backgroundColor: ds?.loading ? '#dfe6e9' : '#6c5ce7',
                          color: ds?.loading ? '#636e72' : 'white',
                          cursor: ds?.loading ? 'not-allowed' : 'pointer',
                          fontWeight: 'bold', fontSize: '13px',
                        }}
                      >
                        {ds?.loading ? '전송 중...' : '💾 AVML 덤프'}
                      </button>
                      {ds?.result && (
                        <span style={{
                          fontSize: '12px', fontWeight: 'bold',
                          color: ds.result.status === 'success' ? '#2ed573' : '#ff4757',
                        }}>
                          {ds.result.status === 'success' ? '✅ 전송됨' : '❌ 오프라인'}
                        </span>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
            {assets.length === 0 && (
              <tr>
                <td colSpan="6" style={{ padding: '60px', textAlign: 'center', color: '#aaa' }}>
                  등록된 에이전트가 없습니다.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* 페이지네이션 */}
      {totalPages > 1 && (
        <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'center', gap: '8px' }}>
          {Array.from({ length: totalPages }, (_, i) => (
            <button
              key={i + 1}
              onClick={() => setCurrentPage(i + 1)}
              style={{
                ...pageBtnStyle,
                backgroundColor: currentPage === i + 1 ? '#6c5ce7' : 'white',
                color: currentPage === i + 1 ? 'white' : '#333',
              }}
            >
              {i + 1}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function StatusDot({ status }) {
  const colors = { '정상': '#2ed573', '주의': '#ffa502', '위험': '#ff4757', '오프라인': '#a4b0be' };
  const color = colors[status] || '#a4b0be';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color, fontWeight: 'bold' }}>
      <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: color, display: 'inline-block' }} />
      {status}
    </div>
  );
}

const getRiskColor = (val) => val > 70 ? '#ff4757' : val > 30 ? '#ffa502' : '#2ed573';
const tableContainerStyle = { backgroundColor: 'white', borderRadius: '16px', boxShadow: '0 4px 12px rgba(0,0,0,0.05)', overflow: 'hidden' };
const theadStyle = { backgroundColor: '#f8f9fa', color: '#888', fontSize: '13px', textAlign: 'left' };
const trStyle = { borderBottom: '1px solid #f1f1f1' };
const pageBtnStyle = { padding: '8px 15px', border: '1px solid #ddd', borderRadius: '8px', cursor: 'pointer' };

export default Forensics;
