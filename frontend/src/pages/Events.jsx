import { useState, useEffect } from 'react';
import apiClient from '../api/client';

function Events() {
  const [alerts, setAlerts] = useState([]);
  const [total, setTotal] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('전체');
  const [statusFilter, setStatusFilter] = useState('전체');

  const pageSize = 20;

  const fetchAlerts = async () => {
    try {
      const response = await apiClient.get('/api/v1/dashboard/alerts', {
        params: {
          page: currentPage,
          size: pageSize,
          severity: severityFilter === '전체' ? null : severityFilter,
          status: statusFilter === '전체' ? null : statusFilter,
          search: search || null,
        },
      });
      setAlerts(response.data.items);
      setTotal(response.data.total);
    } catch (err) {
      console.error('이벤트 로그 로드 실패:', err);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [currentPage, severityFilter, statusFilter]);

  const totalPages = Math.ceil(total / pageSize);

  return (
    <div>
      <header style={{ marginBottom: '30px' }}>
        <h4 style={{ color: '#888', margin: 0, fontSize: '12px' }}>Security Events</h4>
        <h1 style={{ marginTop: '5px', fontSize: '24px' }}>이벤트 로그 저장소</h1>
      </header>

      {/* 검색 및 필터 바 */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        marginBottom: '20px', gap: '20px', backgroundColor: 'white',
        padding: '15px', borderRadius: '12px', boxShadow: '0 2px 8px rgba(0,0,0,0.02)'
      }}>
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', position: 'relative' }}>
          <span style={{ position: 'absolute', left: '15px', color: '#aaa' }}>🔍</span>
          <input
            type="text"
            placeholder="알람명 또는 호스트 검색..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') { setCurrentPage(1); fetchAlerts(); } }}
            style={{ ...inputStyle, paddingLeft: '45px' }}
          />
        </div>
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          <span style={{ fontSize: '14px', color: '#666', whiteSpace: 'nowrap' }}>심각도:</span>
          <select value={severityFilter} onChange={(e) => { setSeverityFilter(e.target.value); setCurrentPage(1); }} style={selectStyle}>
            {['전체', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => <option key={s}>{s}</option>)}
          </select>
          <span style={{ fontSize: '14px', color: '#666', whiteSpace: 'nowrap' }}>상태:</span>
          <select value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value); setCurrentPage(1); }} style={selectStyle}>
            {['전체', 'pending', 'analyzing', 'resolved'].map(s => <option key={s}>{s}</option>)}
          </select>
        </div>
      </div>

      {/* 요약 */}
      <div style={{ marginBottom: '12px', color: '#888', fontSize: '13px' }}>
        총 <strong style={{ color: '#333' }}>{total}</strong>건
      </div>

      {/* 테이블 */}
      <div style={tableContainerStyle}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={theadStyle}>
              <th style={{ padding: '15px' }}>심각도</th>
              <th>알람명</th>
              <th>호스트</th>
              <th>발생 시간</th>
              <th style={{ textAlign: 'center' }}>상태</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((alert) => (
              <tr key={alert.id} style={trStyle}>
                <td style={{ padding: '15px' }}><SeverityBadge severity={alert.severity} /></td>
                <td style={{ fontWeight: '600', color: '#333' }}>{alert.alert_name}</td>
                <td style={{ color: '#666', fontSize: '14px' }}>{alert.host_info}</td>
                <td style={{ color: '#888', fontSize: '13px' }}>{new Date(alert.event_time).toLocaleString()}</td>
                <td style={{ textAlign: 'center' }}><StatusBadge status={alert.status} /></td>
              </tr>
            ))}
            {alerts.length === 0 && (
              <tr>
                <td colSpan="5" style={{ padding: '60px', textAlign: 'center', color: '#aaa' }}>
                  이벤트 로그가 없습니다.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* 페이지네이션 */}
      {totalPages > 1 && (
        <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'center', gap: '8px' }}>
          <button
            onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
            disabled={currentPage === 1}
            style={{ ...pageBtnStyle, opacity: currentPage === 1 ? 0.4 : 1 }}
          >
            ‹
          </button>
          {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => i + 1).map(p => (
            <button
              key={p}
              onClick={() => setCurrentPage(p)}
              style={{
                ...pageBtnStyle,
                backgroundColor: currentPage === p ? '#6c5ce7' : 'white',
                color: currentPage === p ? 'white' : '#333',
              }}
            >
              {p}
            </button>
          ))}
          <button
            onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
            disabled={currentPage === totalPages}
            style={{ ...pageBtnStyle, opacity: currentPage === totalPages ? 0.4 : 1 }}
          >
            ›
          </button>
        </div>
      )}
    </div>
  );
}

function SeverityBadge({ severity }) {
  const map = {
    CRITICAL: { bg: '#fff0f1', color: '#ff4757', border: '#ff475733' },
    HIGH:     { bg: '#fff9f0', color: '#ffa502', border: '#ffa50233' },
    MEDIUM:   { bg: '#fffbe6', color: '#e6a817', border: '#e6a81733' },
    LOW:      { bg: '#f0fff4', color: '#2ed573', border: '#2ed57333' },
  };
  const s = map[severity] || { bg: '#f1f2f6', color: '#636e72', border: '#63636333' };
  return (
    <span style={{
      padding: '4px 12px', borderRadius: '20px', fontSize: '11px', fontWeight: 'bold',
      backgroundColor: s.bg, color: s.color, border: `1px solid ${s.border}`
    }}>
      {severity}
    </span>
  );
}

function StatusBadge({ status }) {
  const map = {
    pending:   { bg: '#fff9f0', color: '#ffa502', label: '대기중' },
    analyzing: { bg: '#f0f4ff', color: '#6c5ce7', label: '분석중' },
    resolved:  { bg: '#f0fff4', color: '#2ed573', label: '처리완료' },
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

const inputStyle = { width: '100%', padding: '12px 20px', borderRadius: '12px', border: '1px solid #ddd', outline: 'none' };
const selectStyle = { padding: '10px 15px', borderRadius: '12px', border: '1px solid #ddd', backgroundColor: 'white' };
const tableContainerStyle = { backgroundColor: 'white', borderRadius: '16px', boxShadow: '0 4px 12px rgba(0,0,0,0.05)', overflow: 'hidden' };
const theadStyle = { backgroundColor: '#f8f9fa', color: '#888', fontSize: '13px', textAlign: 'left' };
const trStyle = { borderBottom: '1px solid #f1f1f1' };
const pageBtnStyle = { padding: '8px 14px', border: '1px solid #ddd', borderRadius: '8px', cursor: 'pointer' };

export default Events;
