import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { useState, useEffect } from 'react';
import MainLayout from './layouts/MainLayout';
import Login from './components/Login';
import Dashboard from './pages/Dashboard';
import Assets from './pages/Assets';
import ProcessAnalysis from './pages/ProcessAnalysis';
import Events from './pages/Events';
import Forensics from './pages/Forensics';
import Policy from './pages/Policy';
import Analysis from './pages/Analysis';
import apiClient from './api/client';
import Analysis from './pages/Analysis';

function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true); // 로딩 상태 추가

  const handleLoginSuccess = (userData) => {
    setUser(userData);
    localStorage.setItem('ebpf_user', JSON.stringify(userData));
  };

  const handleLogout = async () => {
    try {
      await apiClient.post('/api/v1/auth/logout');
    } catch (_) {}
    localStorage.removeItem('ebpf_user');
    setUser(null);
  };

  // useEffect(() => {
  //   const savedUser = localStorage.getItem('ebpf_user');
  //   if (savedUser) {
  //     setUser(JSON.parse(savedUser));
  //   }
  //   setLoading(false); // 체크가 끝나면 로딩 완료
  // }, []);

  // // 유저 체크가 끝나기 전에는 아무것도 렌더링하지 않거나 로딩 스피너를 보여줌
  // if (loading) return null;

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={!user ? <Login onLoginSuccess={handleLoginSuccess} /> : <Navigate to="/" />} />
        <Route element={user ? <MainLayout onLogout={handleLogout} /> : <Navigate to="/login" />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/assets" element={<Assets />} /> 
          <Route path="/process_analysis" element={<ProcessAnalysis />} />
          <Route path="/process_analysis/:execId" element={<ProcessAnalysis />} />
          <Route path="/analysis" element={<Analysis />} />
          <Route path="/analysis/:execId" element={<Analysis />} />
          <Route path="/events" element={<Events />} />
          <Route path="/forensics" element={<Forensics />} />
          <Route path="/policy" element={<Policy />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
export default App;