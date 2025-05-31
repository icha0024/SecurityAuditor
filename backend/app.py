from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
import time

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

CORS(app)
jwt = JWTManager(app)

# Simple rate limiting
login_attempts = {}

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
            'verify': '/api/auth/verify'
        }
    })

if __name__ == '__main__':
    print("Starting SecurityAuditor Backend...")
    print("Default login: admin / securepass123")
    print("API running on http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)