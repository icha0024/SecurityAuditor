from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
import time
import socket
import threading
import ipaddress
import ssl
import requests

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

CORS(app)
jwt = JWTManager(app)

# Simple rate limiting
login_attempts = {}

class PortScanner:
    def __init__(self):
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 1433, 3306, 3389, 5432, 6379]
        self.results = []
    
    def scan_port(self, target, port, timeout=3):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            
            if result == 0:
                service_name = self.get_service_name(port)
                self.results.append({
                    'port': port,
                    'status': 'open',
                    'service': service_name,
                    'risk': self.get_port_risk(port)
                })
            sock.close()
        except Exception:
            pass
    
    def get_service_name(self, port):
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 443: 'HTTPS',
            993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis'
        }
        return services.get(port, 'Unknown')
    
    def get_port_risk(self, port):
        high_risk = [21, 23, 1433, 3389]
        medium_risk = [22, 25, 3306, 5432]
        
        if port in high_risk:
            return 'HIGH'
        elif port in medium_risk:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def scan(self, target):
        self.results = []
        
        try:
            ipaddress.ip_address(target)
        except ValueError:
            return {'error': 'Invalid IP address format'}
        
        threads = []
        for port in self.common_ports:
            thread = threading.Thread(target=self.scan_port, args=(target, port))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        risks = [r['risk'] for r in self.results]
        if 'HIGH' in risks:
            overall_risk = 'HIGH'
        elif 'MEDIUM' in risks:
            overall_risk = 'MEDIUM'
        elif self.results:
            overall_risk = 'LOW'
        else:
            overall_risk = 'NONE'
        
        return {
            'target': target,
            'scan_time': datetime.now().isoformat(),
            'open_ports': self.results,
            'total_open': len(self.results),
            'overall_risk': overall_risk
        }

class SSLChecker:
    def check_ssl(self, domain, port=443):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
            
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            days_until_expiry = (not_after - datetime.now()).days
            
            if days_until_expiry < 7:
                risk = 'HIGH'
            elif days_until_expiry < 30:
                risk = 'MEDIUM'
            else:
                risk = 'LOW'
            
            return {
                'domain': domain,
                'valid': True,
                'issuer': cert.get('issuer', [{}])[0].get('organizationName', 'Unknown'),
                'subject': cert.get('subject', [{}])[0].get('commonName', domain),
                'valid_from': cert['notBefore'],
                'valid_until': cert['notAfter'],
                'days_until_expiry': days_until_expiry,
                'risk': risk,
                'scan_time': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'domain': domain,
                'valid': False,
                'error': str(e),
                'risk': 'HIGH',
                'scan_time': datetime.now().isoformat()
            }

class SecurityHeaderChecker:
    def check_headers(self, url):
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            response = requests.get(url, timeout=10, allow_redirects=True)
            headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                'Content-Security-Policy': headers.get('Content-Security-Policy'),
                'X-Frame-Options': headers.get('X-Frame-Options'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                'X-XSS-Protection': headers.get('X-XSS-Protection'),
                'Referrer-Policy': headers.get('Referrer-Policy')
            }
            
            missing_headers = [name for name, value in security_headers.items() if not value]
            present_headers = [name for name, value in security_headers.items() if value]
            
            if len(missing_headers) >= 4:
                risk = 'HIGH'
            elif len(missing_headers) >= 2:
                risk = 'MEDIUM'
            else:
                risk = 'LOW'
            
            return {
                'url': url,
                'status_code': response.status_code,
                'security_headers': security_headers,
                'present_headers': present_headers,
                'missing_headers': missing_headers,
                'risk': risk,
                'scan_time': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'url': url,
                'error': str(e),
                'risk': 'UNKNOWN',
                'scan_time': datetime.now().isoformat()
            }

# Simple rate limiting
def check_rate_limit(ip):
    current_time = time.time()
    if ip not in login_attempts:
        login_attempts[ip] = []
    
    # Remove attempts older than 1 minute
    login_attempts[ip] = [attempt for attempt in login_attempts[ip] if current_time - attempt < 60]
    
    if len(login_attempts[ip]) >= 5:
        return False
    
    login_attempts[ip].append(current_time)
    return True

@app.route('/api/auth/login', methods=['POST'])
def login():
    ip = request.remote_addr
    
    if not check_rate_limit(ip):
        return jsonify({'error': 'Too many login attempts. Try again later.'}), 429
    
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    # Simple authentication (change this in production!)
    if username == 'admin' and password == 'securepass123':
        access_token = create_access_token(identity=username)
        return jsonify({
            'access_token': access_token,
            'message': 'Login successful',
            'user': username
        })
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/auth/verify', methods=['GET'])
@jwt_required()
def verify_token():
    current_user = get_jwt_identity()
    return jsonify({
        'valid': True,
        'user': current_user,
        'message': 'Token is valid'
    })

@app.route('/api/scan/ports', methods=['POST'])
@jwt_required()
def scan_ports():
    data = request.get_json()
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'error': 'Target IP address is required'}), 400
    
    scanner = PortScanner()
    results = scanner.scan(target)
    
    if 'error' in results:
        return jsonify(results), 400
    
    return jsonify(results)

@app.route('/api/scan/ssl', methods=['POST'])
@jwt_required()
def scan_ssl():
    data = request.get_json()
    domain = data.get('domain', '').strip()
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    checker = SSLChecker()
    results = checker.check_ssl(domain)
    
    return jsonify(results)

@app.route('/api/scan/headers', methods=['POST'])
@jwt_required()
def scan_headers():
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    checker = SecurityHeaderChecker()
    results = checker.check_headers(url)
    
    return jsonify(results)

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'message': 'SecurityAuditor API is running'
    })

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'message': 'SecurityAuditor Backend API',
        'version': '1.0.0',
        'endpoints': {
            'health': '/api/health',
            'login': '/api/auth/login',
            'verify': '/api/auth/verify',
            'port_scan': '/api/scan/ports',
            'ssl_scan': '/api/scan/ssl',
            'header_scan': '/api/scan/headers'
        }
    })

if __name__ == '__main__':
    print("Starting SecurityAuditor Backend...")
    print("Default login: admin / securepass123")
    print("API running on http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)