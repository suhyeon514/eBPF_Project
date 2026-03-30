import { Link, useLocation } from 'react-router-dom';

const menuItems = [
  { path: '/', label: '대시보드', icon: '📊' },
  { path: '/assets', label: '자산 관리', icon: '🖄' },
  { path: '/analysis', label: '프로세스 분석 및 시각화', icon: '📈' },
  { path: '/events', label: '이벤트 로그 저장소', icon: '📂' },
  { path: '/forensics', label: '포렌식 덤프 저장소', icon: '💾' },
  { path: '/policy', label: '에이전트 정책 설정', icon: '⚙️' },
];

function Sidebar() {
  const location = useLocation();

  return (
    <div style={{ width: '260px', backgroundColor: '#fff', height: '100vh', borderRight: '1px solid #eee', padding: '20px', flexShrink: 0 }}>
    <div style={{ fontSize: '28px', fontWeight: '900', color: '#6c5ce7', marginBottom: '40px', letterSpacing: '-1px' }}>
      🐧 K9 <span style={{ fontSize: '14px', fontWeight: '500', color: '#aaa' }}>Kernal 9</span>
    </div>
      <nav>
        {menuItems.map((item) => (
          <Link key={item.path} to={item.path} style={{
            display: 'flex', alignItems: 'center', padding: '12px 15px', marginBottom: '8px',
            borderRadius: '10px', textDecoration: 'none', color: location.pathname === item.path ? '#6c5ce7' : '#555',
            backgroundColor: location.pathname === item.path ? '#f0eeff' : 'transparent',
            fontWeight: location.pathname === item.path ? 'bold' : 'normal'
          }}>
            <span style={{ marginRight: '12px' }}>{item.icon}</span> {item.label}
          </Link>
        ))}
      </nav>
    </div>
  );
}
export default Sidebar;