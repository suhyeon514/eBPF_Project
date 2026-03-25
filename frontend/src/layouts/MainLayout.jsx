import { Outlet } from 'react-router-dom';
import Sidebar from '../components/Sidebar';

function MainLayout() {
  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden', backgroundColor: '#f8f9fa' }}>
      {/* 왼쪽 사이드바: 고정 */}
      <Sidebar />
      
      {/* 오른쪽 콘텐츠 영역: 여기서만 스크롤 발생 */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '30px' }}>
        <Outlet />
      </div>
    </div>
  );
}
export default MainLayout;