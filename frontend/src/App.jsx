import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { useState, useEffect } from 'react';
import MainLayout from './layouts/MainLayout';
import Login from './components/Login';
import Dashboard from './pages/Dashboard';
import Assets from './pages/Assets';
import Events from './pages/Events';
import Forensics from './pages/Forensics';
import Policy from './pages/Policy';
import Analysis from './pages/Analysis';
import apiClient from './api/client';

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

  const handleLogout = async () => {
    try {
      await apiClient.post('/api/v1/auth/logout');
    } catch (_) {}
    localStorage.removeItem('ebpf_user');
    setUser(null);
  };

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={!user ? <Login onLoginSuccess={handleLoginSuccess} /> : <Navigate to="/" />} />
        <Route element={user ? <MainLayout onLogout={handleLogout} /> : <Navigate to="/login" />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/assets" element={<Assets />} />
          <Route path="/analysis" element={<Analysis />} />
          <Route path="/events" element={<Events />} />
          <Route path="/forensics" element={<Forensics />} />
          <Route path="/policy" element={<Policy />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
export default App;