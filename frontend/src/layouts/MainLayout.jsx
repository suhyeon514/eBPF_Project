import { Outlet } from 'react-router-dom';
import Sidebar from '../components/Sidebar';

function MainLayout({ onLogout }) {
  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden', backgroundColor: '#f8f9fa' }}>
      <Sidebar onLogout={onLogout} />
      <div style={{ flex: 1, overflowY: 'auto', padding: '30px' }}>
        <Outlet />
      </div>
    </div>
  );
}
export default MainLayout;