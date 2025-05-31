# SecurityAuditor

A comprehensive network security scanning platform built with React and Python Flask. SecurityAuditor provides penetration testers and security professionals with essential reconnaissance tools in a modern web interface.

![SecurityAuditor Dashboard](https://img.shields.io/badge/Status-Active-brightgreen) ![Flask](https://img.shields.io/badge/Flask-2.3.0-blue) ![React](https://img.shields.io/badge/React-18.0-blue) ![Python](https://img.shields.io/badge/Python-3.8+-blue)

## 🚀 Features

### Security Scanners
- **🔍 Port Scanner** - Discover open network services and assess security risks
- **🔒 SSL Certificate Checker** - Validate SSL/TLS certificates and check expiration dates  
- **🛡️ Security Headers Analyzer** - Analyze HTTP security headers and identify missing protections

### Platform Features
- **🔐 JWT Authentication** - Secure login system with rate limiting
- **📱 Responsive Design** - Mobile-friendly interface
- **⚡ Real-time Scanning** - Instant results
- **🎨 Risk Assessment** - Color-coded risk levels (HIGH, MEDIUM, LOW)
- **🔧 Input Validation** - Input sanitization and length limits
- **🌐 Domain Resolution** - Automatic domain-to-IP resolution for scans

## 🛠️ Technology Stack

### Backend
- **Python 3.8+** - Core application language
- **Flask** - Web framework and REST API
- **Flask-JWT-Extended** - JWT authentication
- **Flask-CORS** - Cross-origin resource sharing
- **python-dotenv** - Environment variable management
- **requests** - HTTP client for web scanning

### Frontend  
- **React 18** - User interface framework
- **TypeScript** - Type-safe JavaScript
- **Axios** - HTTP client for API calls
- **CSS3** - Modern styling with gradients and animations

### Security
- **JWT Tokens** - Stateless authentication
- **Rate Limiting** - Brute force protection
- **Input Validation** - SQL injection and XSS prevention
- **Environment Variables** - Secure credential management