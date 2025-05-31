import React, { useState } from 'react';
import axios from 'axios';
import './Dashboard.css';

interface DashboardProps {
  token: string;
  onLogout: () => void;
}

interface PortScanResult {
  target: string;
  scan_time: string;
  open_ports: Array<{
    port: number;
    status: string;
    service: string;
    risk: string;
  }>;
  total_open: number;
  overall_risk: string;
}

interface SSLResult {
  domain: string;
  valid: boolean;
  issuer?: string;
  subject?: string;
  valid_from?: string;
  valid_until?: string;
  days_until_expiry?: number;
  risk: string;
  error?: string;
  scan_time: string;
}

interface HeadersResult {
  url: string;
  status_code?: number;
  security_headers: Record<string, string | null>;
  present_headers: string[];
  missing_headers: string[];
  risk: string;
  error?: string;
  scan_time: string;
}

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

const Dashboard: React.FC<DashboardProps> = ({ token, onLogout }) => {
  const [activeTab, setActiveTab] = useState<'ports' | 'ssl' | 'headers'>('ports');
  const [loading, setLoading] = useState(false);
  
  // Form states
  const [portTarget, setPortTarget] = useState('');
  const [sslDomain, setSslDomain] = useState('');
  const [headersUrl, setHeadersUrl] = useState('');
  
  // Results states
  const [portResults, setPortResults] = useState<PortScanResult | null>(null);
  const [sslResults, setSslResults] = useState<SSLResult | null>(null);
  const [headersResults, setHeadersResults] = useState<HeadersResult | null>(null);
  
  const [error, setError] = useState('');

  const axiosConfig = {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  };

  const handlePortScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!portTarget.trim()) return;
    
    setLoading(true);
    setError('');
    setPortResults(null);
    
    try {
      const response = await axios.post<PortScanResult>(
        `${API_URL}/api/scan/ports`,
        { target: portTarget },
        axiosConfig
      );
      setPortResults(response.data);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Port scan failed');
    } finally {
      setLoading(false);
    }
  };

  const handleSSLScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!sslDomain.trim()) return;
    
    setLoading(true);
    setError('');
    setSslResults(null);
    
    try {
      const response = await axios.post<SSLResult>(
        `${API_URL}/api/scan/ssl`,
        { domain: sslDomain },
        axiosConfig
      );
      setSslResults(response.data);
    } catch (err: any) {
      setError(err.response?.data?.error || 'SSL scan failed');
    } finally {
      setLoading(false);
    }
  };

  const handleHeadersScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!headersUrl.trim()) return;
    
    setLoading(true);
    setError('');
    setHeadersResults(null);
    
    try {
      const response = await axios.post<HeadersResult>(
        `${API_URL}/api/scan/headers`,
        { url: headersUrl },
        axiosConfig
      );
      setHeadersResults(response.data);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Headers scan failed');
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (risk: string) => {
    switch (risk.toUpperCase()) {
      case 'HIGH': return '#dc3545';
      case 'MEDIUM': return '#fd7e14';
      case 'LOW': return '#28a745';
      default: return '#6c757d';
    }
  };

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <div className="header-content">
          <h1>SecurityAuditor Dashboard</h1>
          <button onClick={onLogout} className="logout-button">
            Logout
          </button>
        </div>
      </header>

      <main className="dashboard-main">
        <div className="dashboard-container">
          <div className="scan-tabs">
            <button 
              className={`tab-button ${activeTab === 'ports' ? 'active' : ''}`}
              onClick={() => setActiveTab('ports')}
            >
              Port Scanner
            </button>
            <button 
              className={`tab-button ${activeTab === 'ssl' ? 'active' : ''}`}
              onClick={() => setActiveTab('ssl')}
            >
              SSL Checker
            </button>
            <button 
              className={`tab-button ${activeTab === 'headers' ? 'active' : ''}`}
              onClick={() => setActiveTab('headers')}
            >
              Security Headers
            </button>
          </div>

          {error && <div className="error-message">{error}</div>}

          {/* Port Scanner Tab */}
          {activeTab === 'ports' && (
            <div className="scan-section">
              <h2>Network Port Scanner</h2>
              <form onSubmit={handlePortScan} className="scan-form">
                <div className="form-group">
                  <label>Target IP Address or Domain</label>
                  <input
                    type="text"
                    value={portTarget}
                    onChange={(e) => setPortTarget(e.target.value)}
                    placeholder="e.g., 8.8.8.8 or google.com"
                    maxLength={100}
                    required
                  />
                  <small className="input-hint">{portTarget.length}/100 characters</small>
                </div>
                <button type="submit" disabled={loading} className="scan-button">
                  {loading ? 'Scanning...' : 'Start Port Scan'}
                </button>
              </form>

              {portResults && (
                <div className="results-section">
                  <h3>Scan Results</h3>
                  <div className="result-summary">
                    <div className="summary-item">
                      <span>Target:</span> {portResults.target}
                    </div>
                    <div className="summary-item">
                      <span>Open Ports:</span> {portResults.total_open}
                    </div>
                    <div className="summary-item">
                      <span>Risk Level:</span> 
                      <span className="risk-badge" style={{ backgroundColor: getRiskColor(portResults.overall_risk) }}>
                        {portResults.overall_risk}
                      </span>
                    </div>
                  </div>

                  {portResults.open_ports.length > 0 && (
                    <div className="ports-table">
                      <table>
                        <thead>
                          <tr>
                            <th>Port</th>
                            <th>Service</th>
                            <th>Status</th>
                            <th>Risk</th>
                          </tr>
                        </thead>
                        <tbody>
                          {portResults.open_ports.map((port, index) => (
                            <tr key={index}>
                              <td>{port.port}</td>
                              <td>{port.service}</td>
                              <td>
                                <span className="status-open">{port.status}</span>
                              </td>
                              <td>
                                <span className="risk-badge" style={{ backgroundColor: getRiskColor(port.risk) }}>
                                  {port.risk}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* SSL Scanner Tab */}
          {activeTab === 'ssl' && (
            <div className="scan-section">
              <h2>SSL Certificate Checker</h2>
              <form onSubmit={handleSSLScan} className="scan-form">
                <div className="form-group">
                  <label>Domain Name</label>
                  <input
                    type="text"
                    value={sslDomain}
                    onChange={(e) => setSslDomain(e.target.value)}
                    placeholder="e.g., google.com"
                    maxLength={100}
                    required
                  />
                  <small className="input-hint">{sslDomain.length}/100 characters</small>
                </div>
                <button type="submit" disabled={loading} className="scan-button">
                  {loading ? 'Checking...' : 'Check SSL Certificate'}
                </button>
              </form>

              {sslResults && (
                <div className="results-section">
                  <h3>SSL Certificate Results</h3>
                  {sslResults.valid ? (
                    <div className="ssl-details">
                      <div className="ssl-item">
                        <span>Domain:</span> {sslResults.domain}
                      </div>
                      <div className="ssl-item">
                        <span>Issuer:</span> {sslResults.issuer || 'Unknown'}
                      </div>
                      <div className="ssl-item">
                        <span>Valid Until:</span> {sslResults.valid_until}
                      </div>
                      <div className="ssl-item">
                        <span>Days Until Expiry:</span> {sslResults.days_until_expiry}
                      </div>
                      <div className="ssl-item">
                        <span>Risk Level:</span>
                        <span className="risk-badge" style={{ backgroundColor: getRiskColor(sslResults.risk) }}>
                          {sslResults.risk}
                        </span>
                      </div>
                    </div>
                  ) : (
                    <div className="ssl-error">
                      <p>SSL Certificate is invalid or could not be retrieved.</p>
                      {sslResults.error && <p>Error: {sslResults.error}</p>}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Headers Scanner Tab */}
          {activeTab === 'headers' && (
            <div className="scan-section">
              <h2>Security Headers Analyzer</h2>
              <form onSubmit={handleHeadersScan} className="scan-form">
                <div className="form-group">
                  <label>Website URL</label>
                  <input
                    type="text"
                    value={headersUrl}
                    onChange={(e) => setHeadersUrl(e.target.value)}
                    placeholder="e.g., https://example.com"
                    maxLength={200}
                    required
                  />
                  <small className="input-hint">{headersUrl.length}/200 characters</small>
                </div>
                <button type="submit" disabled={loading} className="scan-button">
                  {loading ? 'Analyzing...' : 'Analyze Security Headers'}
                </button>
              </form>

              {headersResults && !headersResults.error && (
                <div className="results-section">
                  <h3>Security Headers Analysis</h3>
                  <div className="headers-summary">
                    <div className="summary-item">
                      <span>URL:</span> {headersResults.url}
                    </div>
                    <div className="summary-item">
                      <span>Status Code:</span> {headersResults.status_code}
                    </div>
                    <div className="summary-item">
                      <span>Risk Level:</span>
                      <span className="risk-badge" style={{ backgroundColor: getRiskColor(headersResults.risk) }}>
                        {headersResults.risk}
                      </span>
                    </div>
                  </div>

                  <div className="headers-details">
                    <div className="headers-section">
                      <h4>Present Headers ({headersResults.present_headers?.length || 0})</h4>
                      {headersResults.present_headers?.map((header, index) => (
                        <div key={index} className="header-item present">
                          ✓ {header}
                        </div>
                      )) || <div className="no-headers">No headers present</div>}
                    </div>

                    <div className="headers-section">
                      <h4>Missing Headers ({headersResults.missing_headers?.length || 0})</h4>
                      {headersResults.missing_headers?.map((header, index) => (
                        <div key={index} className="header-item missing">
                          ✗ {header}
                        </div>
                      )) || <div className="no-headers">No missing headers</div>}
                    </div>
                  </div>
                </div>
              )}

              {headersResults && headersResults.error && (
                <div className="results-section">
                  <h3>Security Headers Analysis</h3>
                  <div className="ssl-error">
                    <p>Failed to analyze security headers.</p>
                    <p>Error: {headersResults.error}</p>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </main>
    </div>
  );
};

export default Dashboard;