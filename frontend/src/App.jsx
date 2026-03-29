import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import MainLayout from './layouts/MainLayout';
import Dashboard from './pages/Dashboard'; // 기존 App.jsx의 내용을 이쪽으로 옮깁니다.
import { useState, useEffect } from 'react';
import Login from './components/Login';
import Assets from './pages/Assets';
import ProcessAnalysis from './pages/ProcessAnalysis';

function App() {
  const [user, setUser] = useState(null);

  useEffect(() => {
    const savedUser = localStorage.getItem('ebpf_user');
    if (savedUser) setUser(JSON.parse(savedUser));
  }, []);

  const handleLoginSuccess = (userData) => {
    setUser(userData);
    localStorage.setItem('ebpf_user', JSON.stringify(userData));
  };

  return (
    <BrowserRouter>
      <Routes>
        {/* 로그인이 안 되어 있으면 /login으로 이동, 되어 있으면 대시보드 표시 */}
        <Route path="/login" element={!user ? <Login onLoginSuccess={handleLoginSuccess} /> : <Navigate to="/" />} />
        
        {/* 메인 레이아웃 적용 구역 */}
        <Route element={user ? <MainLayout /> : <Navigate to="/login" />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/assets" element={<Assets />} /> 
          <Route path="/process_analysis" element={<ProcessAnalysis />} />
          <Route path="/process_analysis/:execId" element={<ProcessAnalysis />} />
          {/* ... 나머지 페이지들 */}
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
export default App;