import { useState } from 'react';
import apiClient from '../api/client';

function Login({ onLoginSuccess }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    try {
      const response = await apiClient.post('/api/v1/auth/login', {
        username,
        password
      });

      // 로그인 성공 시 부모 컴포넌트(App)에게 알림
      onLoginSuccess(response.data);
    } catch (err) {
      const errorMsg = err.response?.data?.detail || '아이디 또는 비밀번호를 확인해주세요.';
      setError(errorMsg);
    }
  };

  return (
    <div style={{ 
      maxWidth: '400px', 
      margin: '100px auto', 
      padding: '40px', 
      border: '1px solid #eee', 
      borderRadius: '20px', 
      backgroundColor: 'white',
      boxShadow: '0 10px 25px rgba(0,0,0,0.05)',
      textAlign: 'center'
    }}>
      <h2 style={{ marginBottom: '10px' }}>🛡️ eBPF Monitor</h2>
      <p style={{ color: '#666', marginBottom: '30px' }}>보안 대시보드 로그인이 필요합니다.</p>
      
      <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
        <input 
          type="text" 
          placeholder="Username" 
          value={username} 
          onChange={(e) => setUsername(e.target.value)} 
          style={{ padding: '12px', borderRadius: '8px', border: '1px solid #ddd', fontSize: '1rem' }} 
          required 
        />
        <input 
          type="password" 
          placeholder="Password" 
          value={password} 
          onChange={(e) => setPassword(e.target.value)} 
          style={{ padding: '12px', borderRadius: '8px', border: '1px solid #ddd', fontSize: '1rem' }} 
          required 
        />
        <button 
          type="submit" 
          style={{ 
            padding: '14px', 
            backgroundColor: '#3498db', 
            color: 'white', 
            border: 'none', 
            borderRadius: '8px', 
            cursor: 'pointer',
            fontSize: '1.1rem',
            fontWeight: 'bold',
            marginTop: '10px',
            transition: 'background-color 0.2s'
          }}
          onMouseOver={(e) => e.target.style.backgroundColor = '#2980b9'}
          onMouseOut={(e) => e.target.style.backgroundColor = '#3498db'}
        >
          로그인
        </button>
      </form>
      
      {error && (
        <div style={{ 
          marginTop: '20px', 
          padding: '10px', 
          backgroundColor: '#fff5f5', 
          color: '#e74c3c', 
          borderRadius: '6px',
          fontSize: '0.9rem' 
        }}>
          ⚠️ {error}
        </div>
      )}
    </div>
  );
}

export default Login;