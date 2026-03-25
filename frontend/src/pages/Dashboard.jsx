import { useState, useEffect } from 'react';
import axios from 'axios';

axios.defaults.withCredentials = true;

function Dashboard() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({ 
    critical_alerts: 0, 
    unassigned_alerts: 0, 
    active_agents: 0, 
    status_score: 0 
  });

  // [중요] 본인의 실제 Grafana UID로 수정하세요
  const GRAFANA_URL = "http://localhost:3000/d/[Grafana UID]/ebpf-overview?kiosk&orgId=1&from=now-24h&to=now";
  const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

  useEffect(() => {
    const fetchData = async () => {
      try {
        // 1. 고위험 알람 Top 5 가져오기
        const alertsRes = await axios.get(`${API_BASE_URL}/api/v1/dashboard/top-alerts`);
        setAlerts(alertsRes.data);

        // 2. 상단 요약 지표 가져오기
        const statsRes = await axios.get(`${API_BASE_URL}/api/v1/dashboard/stats`);
        setStats(statsRes.data);
      } catch (err) {
        console.error("데이터 로드 실패:", err);
      }
    };

    fetchData();
    const timer = setInterval(fetchData, 10000); // 5초마다 갱신
    return () => clearInterval(timer);
  }, []);

  return (
    <div>
      {/* 1. 상단 요약 지표 (목업 반영) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '20px', marginBottom: '30px' }}>
        <SummaryCard title="심각 알람" value={stats.critical_alerts} subText="▲ 전일 대비 20% 증가" color="#ff4757" icon="⚠️" />
        <StatusCard title="미배정 알람" value={stats.unassigned_alerts} subText="즉시 대응 필요" color="#6c5ce7" icon="👤" />
        <SummaryCard title="활성 에이전트" value={stats.active_agents.toLocaleString()} subText="98.5% 온라인" color="#2ed573" icon="🛡️" />
        <SummaryCard title="상태 점수" value={`${stats.status_score}%`} subText="정상 가동 중" color="#1e90ff" icon="📈" />
      </div>

      {/* 2. 메인 차트 영역 (Grafana) - 창을 더 키웠습니다 */}
      <div style={{ 
        backgroundColor: 'white', borderRadius: '16px', boxShadow: '0 4px 20px rgba(0,0,0,0.05)', 
        marginBottom: '30px', overflow: 'hidden', border: '1px solid #eee'
      }}>
        <div style={{ padding: '20px', borderBottom: '1px solid #f0f0f0', fontWeight: 'bold', color: '#333' }}>
          📊 시스템 활동 로그 통계 (Real-time)
        </div>
        <iframe
          src={GRAFANA_URL}
          width="100%"
          height="500px" // 높이를 더 키웠습니다
          frameBorder="0"
          style={{ border: 'none', display: 'block' }}
          title="Grafana Dashboard"
        />
      </div>

      {/* 3. 하단 고위험 알람 테이블 */}
      <div style={{ backgroundColor: 'white', borderRadius: '16px', boxShadow: '0 4px 20px rgba(0,0,0,0.05)', padding: '25px', border: '1px solid #eee' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
          <h3 style={{ margin: 0, fontSize: '18px' }}>🚨 상위 5개 고위험 알람</h3>
          <span style={{ color: '#6c5ce7', fontSize: '14px', cursor: 'pointer', fontWeight: 'bold' }}>전체 보기 &gt;</span>
        </div>
        
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ textAlign: 'left', color: '#888', borderBottom: '2px solid #f8f9fa' }}>
              <th style={{ padding: '15px 10px' }}>심각도</th>
              <th>알람명</th>
              <th>호스트</th>
              <th>시간</th>
              <th style={{ textAlign: 'center' }}>관리</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((alert) => (
              <tr key={alert.id} style={{ borderBottom: '1px solid #f9f9f9' }}>
                <td style={{ padding: '15px 10px' }}><SeverityBadge severity={alert.severity} /></td>
                <td style={{ fontWeight: '600', color: '#333' }}>{alert.alert_name}</td>
                <td style={{ color: '#666', fontSize: '14px' }}>{alert.host_info}</td>
                <td style={{ color: '#888', fontSize: '14px' }}>{new Date(alert.event_time).toLocaleString()}</td>
                <td style={{ textAlign: 'center' }}>
                  <button style={{ 
                    padding: '8px 16px', borderRadius: '8px', border: 'none', 
                    backgroundColor: '#6c5ce7', color: 'white', cursor: 'pointer', fontWeight: 'bold' 
                  }}>
                    분석하기
                  </button>
                </td>
              </tr>
            ))}
            {alerts.length === 0 && (
              <tr><td colSpan="5" style={{ padding: '40px', textAlign: 'center', color: '#999' }}>탐지된 위협이 없습니다.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// --- Dashboard 내부에서만 사용하는 UI 컴포넌트들 ---

function SummaryCard({ title, value, subText, color, icon }) {
  return (
    <div style={{ backgroundColor: 'white', padding: '25px', borderRadius: '16px', boxShadow: '0 4px 12px rgba(0,0,0,0.03)', border: '1px solid #eee' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '15px' }}>
        <span style={{ color: '#888', fontSize: '14px', fontWeight: '500' }}>{title}</span>
        <span style={{ fontSize: '20px' }}>{icon}</span>
      </div>
      <div style={{ fontSize: '28px', fontWeight: 'bold', marginBottom: '8px', color: '#333' }}>{value}</div>
      <div style={{ fontSize: '12px', color: color, fontWeight: '600' }}>{subText}</div>
    </div>
  );
}

function StatusCard({ title, value, subText, color, icon }) {
    return <SummaryCard title={title} value={value} subText={subText} color={color} icon={icon} />;
}

function SeverityBadge({ severity }) {
  const isCritical = severity === 'CRITICAL';
  return (
    <span style={{ 
      padding: '4px 12px', borderRadius: '20px', fontSize: '11px', fontWeight: 'bold',
      backgroundColor: isCritical ? '#fff0f1' : '#fff9f0',
      color: isCritical ? '#ff4757' : '#ffa502',
      border: `1px solid ${isCritical ? '#ff4757' : '#ffa502'}33`
    }}>
      {severity}
    </span>
  );
}

export default Dashboard;