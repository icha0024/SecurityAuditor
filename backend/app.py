from flask import Flask, jsonify
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__)
CORS(app)

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
            'health': '/api/health'
        }
    })

if __name__ == '__main__':
    print("Starting SecurityAuditor Backend...")
    print("API running on http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)