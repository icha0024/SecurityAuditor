import React, { useState, useEffect } from 'react';
import Login from './components/Login';
import './App.css';

function App() {
  const [token, setToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check if user is already logged in
    const savedToken = localStorage.getItem('token');
    if (savedToken) {
      setToken(savedToken);
    }
    setLoading(false);
  }, []);

  const handleLogin = (newToken: string) => {
    setToken(newToken);
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    setToken(null);
  };

  if (loading) {
    return (
      <div className="loading-container">
        <div className="loading-spinner"></div>
        <p>Loading SecurityAuditor...</p>
      </div>
    );
  }

  if (!token) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <div className="app">
      <header className="app-header">
        <div className="header-content">
          <h1>SecurityAuditor Dashboard</h1>
          <button onClick={handleLogout} className="logout-button">
            Logout
          </button>
        </div>
      </header>
      
      <main className="app-main">
        <div className="dashboard-container">
          <h2>Welcome to SecurityAuditor</h2>
          <p>Network security scanning platform is ready!</p>
          
          <div className="quick-stats">
            <div className="stat-card">
              <h3>System Status</h3>
              <span className="status-indicator online">Online</span>
            </div>
            
            <div className="stat-card">
              <h3>API Status</h3>
              <span className="status-indicator active">Active</span>
            </div>
            
            <div className="stat-card">
              <h3>Scan Tools</h3>
              <span className="status-indicator ready">Ready</span>
            </div>
          </div>
          
          <div className="action-buttons">
            <button className="action-btn primary">Start Port Scan</button>
            <button className="action-btn secondary">Check SSL</button>
            <button className="action-btn secondary">Analyze Headers</button>
          </div>
        </div>
      </main>
    </div>
  );
}

export default App;