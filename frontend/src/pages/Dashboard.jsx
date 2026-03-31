import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import apiClient from '../api/client';

function Dashboard() {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({
    critical_alerts: 0,
    unassigned_alerts: 0,
    active_agents: 0,
    total_agents: 0,
    online_ratio: 0,
    status_score: 0,
  });

  const GRAFANA_URL = import.meta.env.VITE_GRAFANA_URL || 'http://localhost:3000';

  const handleAnalyze = async (execId) => {
    if (!execId) {
      alert("유효한 프로세스 실행 ID가 없습니다.");
      return;
    }

    // 분석 페이지 이동 전 Neo4j 데이터 존재 여부 체크 함수
    try {
      // 해당 ID로 그래프 데이터가 있는지 미리 확인 (백엔드 router의 404 로직 활용)
      await apiClient.get(`/api/v1/process_analysis/graph/${execId}`);
      
      // 데이터가 있으면 해당 페이지로 이동 (ID 포함)
      navigate(`/process_analysis/${execId}`);
    } catch (err) {
      if (err.response && err.response.status === 404) {
        alert("해당 프로세스는 현재 Neo4j 데이터베이스에 존재하지 않습니다.");
      } else {
        alert("서버 통신 중 오류가 발생했습니다.");
      }
    }
  };

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [alertsRes, statsRes] = await Promise.all([
          apiClient.get('/api/v1/dashboard/top-alerts'),
          apiClient.get('/api/v1/dashboard/stats'),
        ]);
        setAlerts(alertsRes.data);
        setStats(statsRes.data);
      } catch (err) {
        console.error("데이터 로드 실패:", err);
      }
    };

    fetchData();
    const timer = setInterval(fetchData, 10000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div>
      {/* 1. 상단 요약 지표 */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '20px', marginBottom: '30px' }}>
        <SummaryCard
          title="심각 알람"
          value={stats.critical_alerts}
          subText={stats.critical_alerts > 0 ? "즉시 조치 필요" : "위협 탐지 없음"}
          color={stats.critical_alerts > 0 ? "#ff4757" : "#2ed573"}
          icon="⚠️"
        />
        <SummaryCard
          title="미배정 알람"
          value={stats.unassigned_alerts}
          subText={stats.unassigned_alerts > 0 ? "즉시 대응 필요" : "전원 처리 완료"}
          color={stats.unassigned_alerts > 0 ? "#6c5ce7" : "#2ed573"}
          icon="👤"
        />
        <SummaryCard
          title="활성 에이전트"
          value={`${stats.active_agents} / ${stats.total_agents}`}
          subText={`${stats.online_ratio}% 온라인`}
          color={stats.online_ratio >= 80 ? "#2ed573" : stats.online_ratio >= 50 ? "#ffa502" : "#ff4757"}
          icon="🛡️"
        />
        <SummaryCard
          title="상태 점수"
          value={`${stats.status_score}점`}
          subText={stats.status_score >= 80 ? "정상 가동 중" : stats.status_score >= 60 ? "주의 필요" : "긴급 점검 필요"}
          color={stats.status_score >= 80 ? "#1e90ff" : stats.status_score >= 60 ? "#ffa502" : "#ff4757"}
          icon="📈"
        />
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
          height="500px"
          frameBorder="0"
          style={{ border: 'none', display: 'block' }}
          title="Grafana Dashboard"
        />
      </div>

      {/* 3. 하단 고위험 알람 테이블 */}
      <div style={{ backgroundColor: 'white', borderRadius: '16px', boxShadow: '0 4px 20px rgba(0,0,0,0.05)', padding: '25px', border: '1px solid #eee' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
          <h3 style={{ margin: 0, fontSize: '18px' }}>🚨 상위 5개 고위험 이벤트(24시간 이내)</h3>
          <span 
            onClick={() => navigate('/events')} 
              style={{ color: '#6c5ce7', fontSize: '14px', cursor: 'pointer', fontWeight: 'bold' }}>
              전체 보기 &gt;
          </span>
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
                  <button
                    onClick={() => handleAnalyze(alert.exec_id)}
                    style={{
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
  // 등급별 색상 및 스타일 매핑
  const severityConfig = {
    CRITICAL: {
      bg: '#fff0f1', // 아주 연한 빨강
      text: '#ff4757', // 진한 빨강
      border: '#ff4757',
      label: '🔴 CRITICAL'
    },
    HIGH: {
      bg: '#fff5f0', // 연한 주황
      text: '#ff7f50', // 주황 (Coral)
      border: '#ff7f50',
      label: '🟠 HIGH'
    },
    MEDIUM: {
      bg: '#fffbe6', // 연한 노랑
      text: '#ffa502', // 황금색 (Amber)
      border: '#ffa502',
      label: '🟡 MEDIUM'
    },
    LOW: {
      bg: '#f1f2f6', // 연한 회색/블루
      text: '#57606f', // 진한 회색 (Slate)
      border: '#57606f',
      label: '🔵 LOW'
    }
  };

  // 대문자로 변환하여 매핑 값 찾기 (기본값 LOW)
  const config = severityConfig[severity?.toUpperCase()] || severityConfig.LOW;

  return (
    <span style={{ 
      display: 'inline-flex',
      alignItems: 'center',
      padding: '4px 10px', 
      borderRadius: '6px', 
      fontSize: '11px', 
      fontWeight: '800',
      backgroundColor: config.bg,
      color: config.text,
      border: `1px solid ${config.border}44`, // 투명도 44 추가
      textTransform: 'uppercase',
      letterSpacing: '0.5px'
    }}>
      {config.label}
    </span>
  );
}

export default Dashboard;