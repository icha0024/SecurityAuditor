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
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# Configuration from environment variables
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-default-secret-key-change-me')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(seconds=int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', '3600')))

jwt = JWTManager(app)

# Load credentials from environment
DEFAULT_USERNAME = os.getenv('DEFAULT_USERNAME', 'admin')
DEFAULT_PASSWORD = os.getenv('DEFAULT_PASSWORD', 'change-me-in-env')
API_VERSION = os.getenv('API_VERSION', '1.0.0')

# Simple user store (in production, use a proper database)
users = {DEFAULT_USERNAME: DEFAULT_PASSWORD}

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
        
        # Handle both domain names and IP addresses
        try:
            # Try to resolve domain name to IP address
            ip_address = socket.gethostbyname(target)
            if target != ip_address:
                # It was a domain name, use the resolved IP
                scan_target = ip_address
                display_target = f"{target} ({ip_address})"
            else:
                # It was already an IP address
                scan_target = target
                display_target = target
                # Validate IP format
                ipaddress.ip_address(target)
        except socket.gaierror:
            return {'error': f'Could not resolve domain name: {target}'}
        except ValueError:
            return {'error': 'Invalid IP address or domain name format'}
        except Exception as e:
            return {'error': f'Error resolving target: {str(e)}'}
        
        threads = []
        for port in self.common_ports:
            thread = threading.Thread(target=self.scan_port, args=(scan_target, port))
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
            'target': display_target,
            'resolved_ip': ip_address if target != ip_address else None,
            'scan_time': datetime.now().isoformat(),
            'open_ports': self.results,
            'total_open': len(self.results),
            'overall_risk': overall_risk
        }

class SSLChecker:
    def check_ssl(self, domain, port=443):
        try:
            # Clean up domain name
            domain = domain.strip().lower()
            # Remove protocol if present
            if domain.startswith('http://') or domain.startswith('https://'):
                domain = domain.split('://', 1)[1]
            # Remove path if present
            if '/' in domain:
                domain = domain.split('/', 1)[0]
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':', 1)[0]
            
            # Test DNS resolution first
            try:
                socket.gethostbyname(domain)
            except socket.gaierror:
                return {
                    'domain': domain,
                    'valid': False,
                    'error': f'Could not resolve domain name: {domain}',
                    'risk': 'HIGH',
                    'scan_time': datetime.now().isoformat()
                }
            
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
            
            # Parse issuer and subject safely
            issuer = 'Unknown'
            subject = domain
            
            if 'issuer' in cert and cert['issuer']:
                for item in cert['issuer']:
                    if isinstance(item, tuple) and len(item) >= 2:
                        if item[0] == 'organizationName':
                            issuer = item[1]
                            break
            
            if 'subject' in cert and cert['subject']:
                for item in cert['subject']:
                    if isinstance(item, tuple) and len(item) >= 2:
                        if item[0] == 'commonName':
                            subject = item[1]
                            break
            
            return {
                'domain': domain,
                'valid': True,
                'issuer': issuer,
                'subject': subject,
                'valid_from': cert['notBefore'],
                'valid_until': cert['notAfter'],
                'days_until_expiry': days_until_expiry,
                'risk': risk,
                'scan_time': datetime.now().isoformat()
            }
            
        except socket.gaierror as e:
            return {
                'domain': domain,
                'valid': False,
                'error': f'DNS resolution failed: {str(e)}',
                'risk': 'HIGH',
                'scan_time': datetime.now().isoformat()
            }
        except socket.timeout:
            return {
                'domain': domain,
                'valid': False,
                'error': 'Connection timeout - server may not support SSL/TLS',
                'risk': 'HIGH',
                'scan_time': datetime.now().isoformat()
            }
        except ssl.SSLError as e:
            return {
                'domain': domain,
                'valid': False,
                'error': f'SSL/TLS error: {str(e)}',
                'risk': 'HIGH',
                'scan_time': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'domain': domain,
                'valid': False,
                'error': f'Unexpected error: {str(e)}',
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
            
        except requests.exceptions.ConnectionError as e:
            error_msg = str(e)
            if 'getaddrinfo failed' in error_msg or 'Name or service not known' in error_msg:
                user_error = f"Could not find website '{url}'. Please check the URL is correct."
            elif 'Connection refused' in error_msg:
                user_error = f"Website '{url}' refused the connection."
            else:
                user_error = f"Could not connect to '{url}'. Please check the URL and try again."
            
            return {
                'url': url,
                'error': user_error,
                'risk': 'UNKNOWN',
                'scan_time': datetime.now().isoformat()
            }
        except requests.exceptions.Timeout:
            return {
                'url': url,
                'error': f"Website '{url}' took too long to respond. Please try again later.",
                'risk': 'UNKNOWN',
                'scan_time': datetime.now().isoformat()
            }
        except requests.exceptions.InvalidURL:
            return {
                'url': url,
                'error': f"Invalid URL format: '{url}'. Please enter a valid website URL.",
                'risk': 'UNKNOWN',
                'scan_time': datetime.now().isoformat()
            }
        except requests.exceptions.TooManyRedirects:
            return {
                'url': url,
                'error': f"Website '{url}' has too many redirects. Cannot analyze headers.",
                'risk': 'UNKNOWN',
                'scan_time': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'url': url,
                'error': f"Unable to analyze '{url}'. Please check the URL and try again.",
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
    
    # Check against environment-loaded credentials
    if username in users and users[username] == password:
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
        return jsonify({'error': 'Target IP address or domain name is required'}), 400
    
    if len(target) > 100:
        return jsonify({'error': 'Target name is too long (maximum 100 characters)'}), 400
    
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
    
    if len(domain) > 100:
        return jsonify({'error': 'Domain name is too long (maximum 100 characters)'}), 400
    
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
    
    if len(url) > 200:
        return jsonify({'error': 'URL is too long (maximum 200 characters)'}), 400
    
    checker = SecurityHeaderChecker()
    results = checker.check_headers(url)
    
    return jsonify(results)

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'message': 'SecurityAuditor API is running',
        'version': API_VERSION,
        'endpoints': {
            'health': '/api/health',
            'login': '/api/auth/login',
            'verify': '/api/auth/verify',
            'port_scan': '/api/scan/ports',
            'ssl_scan': '/api/scan/ssl',
            'header_scan': '/api/scan/headers'
        }
    })

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'message': 'SecurityAuditor Backend API',
        'version': API_VERSION,
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
    print(f"Default login: {DEFAULT_USERNAME} / {DEFAULT_PASSWORD}")
    print(f"API version: {API_VERSION}")
    
    # Get configuration from environment (updated for Render)
    host = '0.0.0.0'  # Listen on all interfaces
    port = int(os.environ.get('PORT', 5000))  # Render will set this automatically
    debug = False  # debug off 
    
    print(f"API running on http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)