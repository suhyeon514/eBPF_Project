import { useState, useEffect } from 'react';
import apiClient from '../api/client';

function Analysis() {
  const [requests, setRequests] = useState([]);
  const [total, setTotal] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState('전체');
  const [actionLoading, setActionLoading] = useState({});

  const pageSize = 20;

  const fetchRequests = async () => {
    try {
      const response = await apiClient.get('/api/v1/enroll/requests', {
        params: {
          page: currentPage,
          size: pageSize,
          status: statusFilter === '전체' ? null : statusFilter,
        },
      });
      setRequests(response.data.items);
      setTotal(response.data.total);
    } catch (err) {
      console.error('등록 요청 로드 실패:', err);
    }
  };

  useEffect(() => {
    fetchRequests();
  }, [currentPage, statusFilter]);

  const handleApprove = async (requestId) => {
    setActionLoading(prev => ({ ...prev, [requestId]: true }));
    try {
      await apiClient.patch(`/api/v1/enroll/requests/${requestId}/approve`, {});
      await fetchRequests();
    } catch (err) {
      console.error('승인 실패:', err);
    } finally {
      setActionLoading(prev => ({ ...prev, [requestId]: false }));
    }
  };

  const handleReject = async (requestId) => {
    setActionLoading(prev => ({ ...prev, [requestId]: true }));
    try {
      await apiClient.patch(`/api/v1/enroll/requests/${requestId}/reject`, {});
      await fetchRequests();
    } catch (err) {
      console.error('거부 실패:', err);
    } finally {
      setActionLoading(prev => ({ ...prev, [requestId]: false }));
    }
  };

  const totalPages = Math.ceil(total / pageSize);
  const pendingCount = requests.filter(r => r.status === 'pending').length;

  return (
    <div>
      <header style={{ marginBottom: '30px' }}>
        <h4 style={{ color: '#888', margin: 0, fontSize: '12px' }}>Agent Enrollment</h4>
        <h1 style={{ marginTop: '5px', fontSize: '24px' }}>에이전트 등록 관리</h1>
      </header>

      {/* 요약 배지 */}
      {pendingCount > 0 && (
        <div style={{
          backgroundColor: '#fff9f0', border: '1px solid #ffa50233', borderRadius: '12px',
          padding: '14px 20px', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '12px'
        }}>
          <span style={{ fontSize: '20px' }}>⏳</span>
          <span style={{ fontWeight: 'bold', color: '#ffa502' }}>
            현재 {pendingCount}건의 승인 대기 중인 등록 요청이 있습니다.
          </span>
        </div>
      )}

      {/* 필터 바 */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        marginBottom: '20px', gap: '20px', backgroundColor: 'white',
        padding: '15px', borderRadius: '12px', boxShadow: '0 2px 8px rgba(0,0,0,0.02)'
      }}>
        <span style={{ fontSize: '14px', color: '#666' }}>
          총 <strong>{total}</strong>건
        </span>
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          <span style={{ fontSize: '14px', color: '#666' }}>상태 필터:</span>
          <select
            value={statusFilter}
            onChange={(e) => { setStatusFilter(e.target.value); setCurrentPage(1); }}
            style={selectStyle}
          >
            {['전체', 'pending', 'approved', 'rejected'].map(s => <option key={s}>{s}</option>)}
          </select>
        </div>
      </div>

      {/* 테이블 */}
      <div style={tableContainerStyle}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={theadStyle}>
              <th style={{ padding: '15px' }}>상태</th>
              <th>요청 ID</th>
              <th>호스트명</th>
              <th>OS</th>
              <th>요청 환경 / 역할</th>
              <th>할당 환경 / 역할</th>
              <th>요청 시간</th>
              <th style={{ textAlign: 'center', width: '160px' }}>액션</th>
            </tr>
          </thead>
          <tbody>
            {requests.map((req) => (
              <tr key={req.request_id} style={trStyle}>
                <td style={{ padding: '15px' }}><EnrollStatusBadge status={req.status} /></td>
                <td style={{ fontFamily: 'monospace', fontSize: '12px', color: '#555' }}>{req.request_id}</td>
                <td style={{ fontWeight: 'bold' }}>{req.hostname}</td>
                <td style={{ fontSize: '13px', color: '#666' }}>{req.os_id} {req.os_version}</td>
                <td style={{ fontSize: '13px', color: '#888' }}>
                  {req.requested_env || '-'} / {req.requested_role || '-'}
                </td>
                <td style={{ fontSize: '13px', color: req.assigned_env ? '#2ed573' : '#bbb' }}>
                  {req.assigned_env || '-'} / {req.assigned_role || '-'}
                </td>
                <td style={{ fontSize: '12px', color: '#aaa' }}>
                  {new Date(req.created_at).toLocaleString()}
                </td>
                <td style={{ textAlign: 'center', padding: '10px' }}>
                  {req.status === 'pending' ? (
                    <div style={{ display: 'flex', gap: '6px', justifyContent: 'center' }}>
                      <button
                        onClick={() => handleApprove(req.request_id)}
                        disabled={actionLoading[req.request_id]}
                        style={{ ...actionBtnStyle, backgroundColor: '#2ed573', color: 'white' }}
                      >
                        {actionLoading[req.request_id] ? '...' : '✅ 승인'}
                      </button>
                      <button
                        onClick={() => handleReject(req.request_id)}
                        disabled={actionLoading[req.request_id]}
                        style={{ ...actionBtnStyle, backgroundColor: '#ff4757', color: 'white' }}
                      >
                        {actionLoading[req.request_id] ? '...' : '❌ 거부'}
                      </button>
                    </div>
                  ) : (
                    <span style={{ fontSize: '12px', color: '#bbb' }}>처리 완료</span>
                  )}
                </td>
              </tr>
            ))}
            {requests.length === 0 && (
              <tr>
                <td colSpan="8" style={{ padding: '60px', textAlign: 'center', color: '#aaa' }}>
                  등록 요청이 없습니다.
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

function EnrollStatusBadge({ status }) {
  const map = {
    pending:  { bg: '#fff9f0', color: '#ffa502', label: '대기중' },
    approved: { bg: '#f0fff4', color: '#2ed573', label: '승인됨' },
    rejected: { bg: '#fff0f1', color: '#ff4757', label: '거부됨' },
  };
  const s = map[status] || { bg: '#f1f2f6', color: '#636e72', label: status };
  return (
    <span style={{
      padding: '4px 12px', borderRadius: '20px', fontSize: '11px', fontWeight: 'bold',
      backgroundColor: s.bg, color: s.color
    }}>
      {s.label}
    </span>
  );
}

const selectStyle = { padding: '10px 15px', borderRadius: '12px', border: '1px solid #ddd', backgroundColor: 'white' };
const tableContainerStyle = { backgroundColor: 'white', borderRadius: '16px', boxShadow: '0 4px 12px rgba(0,0,0,0.05)', overflow: 'hidden' };
const theadStyle = { backgroundColor: '#f8f9fa', color: '#888', fontSize: '13px', textAlign: 'left' };
const trStyle = { borderBottom: '1px solid #f1f1f1' };
const actionBtnStyle = { padding: '6px 12px', borderRadius: '6px', border: 'none', cursor: 'pointer', fontWeight: 'bold', fontSize: '12px' };
const pageBtnStyle = { padding: '8px 15px', border: '1px solid #ddd', borderRadius: '8px', cursor: 'pointer' };

export default Analysis;
