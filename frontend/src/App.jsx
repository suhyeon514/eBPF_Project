import { useState, useEffect } from 'react'
import axios from 'axios'

function App() {
  const [health, setHealth] = useState({ postgresql: '🟡 확인 중...', opensearch: '🟡 확인 중...' })

  useEffect(() => {
    // 3초마다 자동으로 서버 상태를 체크합니다.
    const checkHealth = () => {
      axios.get('/api/health')
        .then(res => setHealth(res.data))
        .catch(() => setHealth({ postgresql: '🔴 서버 꺼짐', opensearch: '🔴 서버 꺼짐' }))
    }

    checkHealth()
    const timer = setInterval(checkHealth, 3000)
    return () => clearInterval(timer)
  }, [])

  return (
    <div style={{ padding: '40px', textAlign: 'center', backgroundColor: '#f8f9fa', minHeight: '100vh' }}>
      <h1>🛡️ eBPF Security Monitor</h1>
      <p>실시간 인프라 연동 상태</p>
      
      <div style={{ display: 'flex', justifyContent: 'center', gap: '20px', marginTop: '30px' }}>
        <StatusCard title="관리용 DB (PostgreSQL)" status={health.postgresql} />
        <StatusCard title="로그 저장소 (OpenSearch)" status={health.opensearch} />
      </div>
    </div>
  )
}

function StatusCard({ title, status }) {
  return (
    <div style={{ padding: '20px', border: '1px solid #ddd', borderRadius: '12px', backgroundColor: 'white', width: '250px', boxShadow: '0 4px 6px rgba(0,0,0,0.1)' }}>
      <h4>{title}</h4>
      <p style={{ fontSize: '1.2rem', fontWeight: 'bold' }}>{status}</p>
    </div>
  )
}

export default App