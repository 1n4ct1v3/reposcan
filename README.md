# RepoScan Security Scanner

A comprehensive security scanning tool that combines SAST (Static Application Security Testing) and DAST (Dynamic Application Security Testing) capabilities.

## Features

- **SAST (Static Analysis)**
  - Gitleaks integration for secret detection
  - Semgrep for code analysis
  - Bearer for security policy checks

- **DAST (Dynamic Analysis)**
  - OWASP ZAP integration for web application scanning
  - Comprehensive vulnerability reporting

- **User Interface**
  - Modern web interface
  - Real-time scan progress tracking
  - Detailed PDF reports
  - User authentication and authorization

## Prerequisites

Before installing RepoScan, you need to install the following tools:

### 1. OWASP ZAP
```bash
sudo apt-get install zaproxy
```

### 2. Semgrep
```bash
# Install Semgrep
pip install semgrep

# Or using pipx (recommended)
pipx install semgrep
```

### 3. Gitleaks
```bash
wget https://github.com/zricethezav/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz
tar -xzf gitleaks_8.18.1_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/
```

### 4. Bearer
```bash
sudo apt-get install apt-transport-https
echo "deb [trusted=yes] https://apt.fury.io/bearer/ /" | sudo tee -a /etc/apt/sources.list.d/fury.list
sudo apt-get update
sudo apt-get install bearer
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/1n4ct1v3/reposcan.git
cd reposcan
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

## Usage

1. Start OWASP ZAP (required for DAST scanning):
```bash
# Start ZAP in daemon mode
/usr/share/zaproxy/zap.sh -daemon -host 127.0.0.1 -port 8080 -config api.key=your-key
```

2. Start the application:
```bash
uvicorn app.main:app --reload
```

3. Access the web interface at `http://localhost:8000`

4. Log in with your configured admin credentials

## Configuration

The application uses environment variables for configuration. Copy `.env.example` to `.env` and modify the following variables:

### User Configuration
- `ADMIN_USERNAME`: Admin user username
- `ADMIN_EMAIL`: Admin user email
- `ADMIN_PASSWORD`: Admin user password (change this!)

### Security Settings
- `SECRET_KEY`: Secret key for JWT tokens (change this!)
- `ACCESS_TOKEN_EXPIRE_MINUTES`: JWT token expiration time

### ZAP Configuration
- `ZAP_API_KEY`: API key for OWASP ZAP (change this!)
- `ZAP_API_URL`: URL where ZAP is running (default: http://localhost:8080)

### Database Configuration
- `DATABASE_URL`: Database connection URL

### Application Settings
- `DEBUG`: Debug mode (False in production)
- `ALLOWED_HOSTS`: Comma-separated list of allowed hosts

## Security Considerations

- **IMPORTANT**: Change the default admin password immediately after first login
- Use strong passwords for all user accounts
- Use HTTPS in production
- Keep all dependencies updated
- Regularly update the security scanning tools
- Review and adjust the security settings in `.env`
- Monitor the application logs for suspicious activities
- Regularly backup the database
- Consider implementing rate limiting for API endpoints
- Use a proper database in production (not SQLite)

## Development

### Running Tests
```bash
# Add test commands here when implemented
```

### Code Style
- Follow PEP 8 guidelines
- Use type hints
- Document functions and classes

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Acknowledgments

- OWASP ZAP
- Gitleaks
- Semgrep
- Bearer 
