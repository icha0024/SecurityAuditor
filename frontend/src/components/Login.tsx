import React, { useState } from 'react';
import axios from 'axios';
import './Login.css';

interface LoginProps {
  onLogin: (token: string) => void;
}

interface LoginResponse {
  access_token: string;
  message: string;
  user: string;
}

const API_URL = 'https://securityauditor-production.up.railway.app';

const Login: React.FC<LoginProps> = ({ onLogin }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await axios.post<LoginResponse>(`${API_URL}/api/auth/login`, {
        username,
        password
      });

      const { access_token } = response.data;
      localStorage.setItem('token', access_token);
      onLogin(access_token);
    } catch (err: any) {
      console.error('Login error:', err);
      if (err.response) {
        setError(err.response.data?.error || `HTTP ${err.response.status}: ${err.response.statusText}`);
      } else if (err.request) {
        setError('Cannot connect to server. Make sure backend is running.');
      } else {
        setError('Login failed: ' + err.message);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <div className="login-header">
          <h1>SecurityAuditor</h1>
          <p>Network Security Scanning Platform</p>
        </div>
        
        <form onSubmit={handleSubmit} className="login-form">
          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              type="text"
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              placeholder="Enter username"
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              placeholder="Enter password"
            />
          </div>
          
          {error && <div className="error-message">{error}</div>}
          
          <button type="submit" disabled={loading} className="login-button">
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>
        
        <div className="login-footer">
          <p>Enter your credentials to access the security platform</p>
        </div>
      </div>
    </div>
  );
};

export default Login;