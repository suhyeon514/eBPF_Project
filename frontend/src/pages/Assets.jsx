import { useState, useEffect } from 'react';
import axios from 'axios';

function Assets() {
  const [assets, setAssets] = useState([]);
  const [total, setTotal] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("전체");

  const pageSize = 10;
  const API_URL = "http://localhost:8000/api/v1/assets/";

  // 데이터 가져오기 함수
  const fetchAssets = async () => {
    try {
      const response = await axios.get(API_URL, {
        params: {
          search: search,
          status: statusFilter === "전체" ? null : statusFilter,
          page: currentPage,
          size: pageSize
        },
        withCredentials: true
      });
      setAssets(response.data.items);
      setTotal(response.data.total);
    } catch (err) {
      console.error("자산 목록 로드 실패:", err);
    }
  };

  useEffect(() => {
    fetchAssets();
  }, [currentPage, statusFilter]); // 페이지나 필터가 바뀌면 자동 재로딩

  const totalPages = Math.ceil(total / pageSize);

  return (
  <div>
    <header style={{ marginBottom: '30px' }}>
      <h4 style={{ color: '#888', margin: 0, fontSize: '12px' }}>Inventory Management</h4>
      <h1 style={{ marginTop: '5px', fontSize: '24px' }}>자산 관리 - K9</h1> {/* 이름 변경 */}
    </header>

    {/* 검색 및 필터 바 (겹침 방지 레이아웃) */}
    <div style={{ 
      display: 'flex', 
      alignItems: 'center', 
      justifyContent: 'space-between', 
      marginBottom: '20px', 
      gap: '20px',
      backgroundColor: 'white',
      padding: '15px',
      borderRadius: '12px',
      boxShadow: '0 2px 8px rgba(0,0,0,0.02)'
    }}>
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', position: 'relative' }}>
        <span style={{ position: 'absolute', left: '15px', color: '#aaa' }}>🔍</span>
        <input 
          type="text" 
          placeholder="호스트명 또는 IP 주소 검색..." 
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && fetchAssets()}
          style={{ ...inputStyle, paddingLeft: '45px' }} // 아이콘 공간 확보
        />
      </div>
      
      <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
        <span style={{ fontSize: '14px', color: '#666', whiteSpace: 'nowrap' }}>상태 필터:</span>
        <select 
          value={statusFilter} 
          onChange={(e) => setStatusFilter(e.target.value)}
          style={selectStyle}
        >
          {["전체", "정상", "주의", "위험", "오프라인"].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <button style={csvBtnStyle}>📥 CSV 추출</button>
      </div>
    </div>

      {/* 자산 테이블 */}
      <div style={tableContainerStyle}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={theadStyle}>
              <th style={{ padding: '15px' }}>상태</th>
              <th>호스트명</th>
              <th>IP 주소</th>
              <th>OS 배포판</th>
              <th>미배정 알람</th>
              <th style={{ width: '150px' }}>CPU</th>
              <th style={{ width: '150px' }}>메모리</th>
              <th>위험점수</th>
              <th>액션</th>
            </tr>
          </thead>
          <tbody>
            {assets.map((asset) => (
              <tr key={asset.id} style={trStyle}>
                <td style={{ padding: '15px' }}><StatusBadge status={asset.status} /></td>
                <td style={{ fontWeight: 'bold' }}>{asset.hostname}</td>
                <td style={{ color: '#666' }}>{asset.ip_address}</td>
                <td><span style={{ fontSize: '12px', color: '#555' }}>🐧 {asset.os_info}</span></td>
                <td><span style={alertBadgeStyle}>{asset.unassigned_alerts_count}</span></td>
                <td><UsageBar value={asset.cpu_usage} color={getUsageColor(asset.cpu_usage)} /></td>
                <td><UsageBar value={asset.memory_usage} color={getUsageColor(asset.memory_usage)} /></td>
                <td style={{ fontWeight: 'bold', color: getRiskColor(asset.risk_score), textAlign: 'center' }}>{asset.risk_score}</td>
                <td style={{ textAlign: 'center', cursor: 'pointer' }}>⋮</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* 페이징 컨트롤 */}
      <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'center', gap: '10px' }}>
        {Array.from({ length: totalPages }, (_, i) => (
          <button 
            key={i + 1} 
            onClick={() => setCurrentPage(i + 1)}
            style={{
              ...pageBtnStyle,
              backgroundColor: currentPage === i + 1 ? '#6c5ce7' : 'white',
              color: currentPage === i + 1 ? 'white' : '#333'
            }}
          >
            {i + 1}
          </button>
        ))}
      </div>
    </div>
  );
}

// --- 보조 UI 컴포넌트 ---

function StatusBadge({ status }) {
  const colors = { "정상": "#2ed573", "주의": "#ffa502", "위험": "#ff4757", "오프라인": "#a4b0be" };
  const color = colors[status] || "#a4b0be";
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: color, fontWeight: 'bold' }}>
      <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: color }}></span>
      {status}
    </div>
  );
}

function UsageBar({ value, color }) {
  return (
    <div style={{ width: '100px' }}>
      <div style={{ fontSize: '10px', color: '#888', marginBottom: '20px' }}>{value}%</div>
      <div style={{ height: '6px', backgroundColor: '#eee', borderRadius: '3px', overflow: 'hidden' }}>
        <div style={{ width: `${value}%`, height: '100%', backgroundColor: color }}></div>
      </div>
    </div>
  );
}

// --- 스타일 및 헬퍼 함수 ---

const getUsageColor = (val) => val > 80 ? '#ff4757' : val > 50 ? '#ffa502' : '#6c5ce7';
const getRiskColor = (val) => val > 70 ? '#ff4757' : val > 30 ? '#ffa502' : '#2ed573';

const inputStyle = { width: '100%', padding: '12px 20px', borderRadius: '12px', border: '1px solid #ddd', outline: 'none' };
const selectStyle = { padding: '10px 20px', borderRadius: '12px', border: '1px solid #ddd', backgroundColor: 'white' };
const csvBtnStyle = { padding: '10px 20px', borderRadius: '12px', border: '1px solid #ddd', backgroundColor: 'white', cursor: 'pointer' };
const tableContainerStyle = { backgroundColor: 'white', borderRadius: '16px', boxShadow: '0 4px 12px rgba(0,0,0,0.05)', overflow: 'hidden', marginTop: '20px' };
const theadStyle = { backgroundColor: '#f8f9fa', color: '#888', fontSize: '13px', textAlign: 'left' };
const trStyle = { borderBottom: '1px solid #f1f1f1' };
const alertBadgeStyle = { backgroundColor: '#f1f2f6', padding: '2px 8px', borderRadius: '4px', fontSize: '12px', color: '#555' };
const pageBtnStyle = { padding: '8px 15px', border: '1px solid #ddd', borderRadius: '8px', cursor: 'pointer' };

export default Assets;