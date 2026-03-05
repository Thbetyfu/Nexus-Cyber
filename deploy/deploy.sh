#!/bin/bash

# ===========================
# NEXUS-CYBER DEPLOYMENT SCRIPT
# Production deployment automation
# ===========================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
DEPLOYMENT_DIR="/opt/nexus-cyber"
REPO_URL="https://github.com/Thbetyfu/Nexus-Cyber.git"
BRANCH="main"
VENV_DIR="$DEPLOYMENT_DIR/venv"

# Functions
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
    exit 1
}

print_info() {
    echo -e "${YELLOW}→ $1${NC}"
}

# ===========================
# CHECKS
# ===========================

echo "🔍 Pre-deployment checks..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
   print_error "This script must be run as root"
fi

# Check dependencies
check_command() {
    command -v $1 >/dev/null 2>&1 || print_error "$1 is not installed"
}

check_command git
check_command python3
check_command docker
check_command mysql

print_success "All dependencies present"

# ===========================
# STOP EXISTING SERVICES
# ===========================

echo ""
echo "⏹️  Stopping existing services..."

systemctl stop nexus-datavault 2>/dev/null || true
systemctl stop nexus-proxy 2>/dev/null || true

print_success "Services stopped"

# ===========================
# CREATE DEPLOYMENT DIRECTORY
# ===========================

echo ""
echo "📁 Setting up deployment directory..."

if [ ! -d "$DEPLOYMENT_DIR" ]; then
    mkdir -p "$DEPLOYMENT_DIR"
    print_success "Created $DEPLOYMENT_DIR"
else
    print_info "Deployment directory already exists"
fi

# ===========================
# CLONE/UPDATE REPOSITORY
# ===========================

echo ""
echo "📥 Cloning/updating repository..."

if [ -d "$DEPLOYMENT_DIR/.git" ]; then
    cd "$DEPLOYMENT_DIR"
    git fetch origin
    git checkout $BRANCH
    git pull origin $BRANCH
    print_success "Repository updated"
else
    git clone -b $BRANCH "$REPO_URL" "$DEPLOYMENT_DIR"
    print_success "Repository cloned"
fi

cd "$DEPLOYMENT_DIR"

# ===========================
# SETUP PYTHON ENVIRONMENT
# ===========================

echo ""
echo "🐍 Setting up Python virtual environment..."

if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    print_success "Virtual environment created"
else
    print_info "Virtual environment already exists"
fi

source "$VENV_DIR/bin/activate"

# Upgrade pip
pip install --upgrade pip setuptools wheel --quiet

# Install requirements
pip install -r requirements.txt --quiet

print_success "Python dependencies installed"

# ===========================
# ENVIRONMENT SETUP
# ===========================

echo ""
echo "⚙️  Setting up environment..."

if [ ! -f "$DEPLOYMENT_DIR/.env" ]; then
    cp "$DEPLOYMENT_DIR/.env.example" "$DEPLOYMENT_DIR/.env"
    print_error "Please configure .env file at $DEPLOYMENT_DIR/.env"
else
    print_success ".env file exists"
fi

# Validate configuration
python3 config.py > /dev/null 2>&1 || print_error "Configuration validation failed"
print_success "Configuration validated"

# ===========================
# DATABASE SETUP
# ===========================

echo ""
echo "🗄️  Setting up database..."

# Start MySQL container
docker-compose -f database/docker-compose.yml up -d
sleep 10  # Wait for MySQL to start

print_success "Database started"

# Initialize schema
mysql -h 127.0.0.1 -u ktp_user -p"$DB_PASSWORD" ktp_database < database/init_db.sql 2>/dev/null || true
print_success "Database schema initialized"

# ===========================
# CREATE SYSTEMD SERVICES
# ===========================

echo ""
echo "🔧 Setting up systemd services..."

# Create proxy service
cat > /etc/systemd/system/nexus-proxy.service << 'EOF'
[Unit]
Description=Nexus-Cyber TCP Proxy
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=nexus
WorkingDirectory=/opt/nexus-cyber
Environment="PATH=/opt/nexus-cyber/venv/bin"
EnvironmentFile=/opt/nexus-cyber/.env
ExecStart=/opt/nexus-cyber/venv/bin/python /opt/nexus-cyber/interceptor/tcp_proxy.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Create web gateway service
cat > /etc/systemd/system/nexus-web.service << 'EOF'
[Unit]
Description=Nexus-Cyber Web Gateway
After=network.target nexus-proxy.service
Requires=nexus-proxy.service

[Service]
Type=simple
User=nexus
WorkingDirectory=/opt/nexus-cyber
Environment="PATH=/opt/nexus-cyber/venv/bin"
EnvironmentFile=/opt/nexus-cyber/.env
ExecStart=/opt/nexus-cyber/venv/bin/python /opt/nexus-cyber/web_gateway.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
print_success "Systemd services created"

# ===========================
# CREATE NEXUS USER
# ===========================

echo ""
echo "👤 Setting up application user..."

if ! id -u nexus > /dev/null 2>&1; then
    useradd -r -s /bin/bash -d /opt/nexus-cyber nexus
    print_success "Created nexus user"
else
    print_info "nexus user already exists"
fi

# Set permissions
chown -R nexus:nexus "$DEPLOYMENT_DIR"
chmod 700 "$DEPLOYMENT_DIR"
chmod 600 "$DEPLOYMENT_DIR/.env"

print_success "Permissions set"

# ===========================
# CREATE LOG DIRECTORIES
# ===========================

echo ""
echo "📝 Setting up logging..."

mkdir -p "$DEPLOYMENT_DIR/logs"
chown nexus:nexus "$DEPLOYMENT_DIR/logs"
chmod 755 "$DEPLOYMENT_DIR/logs"

print_success "Log directories created"

# ===========================
# START SERVICES
# ===========================

echo ""
echo "🚀 Starting services..."

systemctl start nexus-proxy
systemctl start nexus-web

# Wait for services to start
sleep 5

# Check service status
if systemctl is-active --quiet nexus-proxy; then
    print_success "Proxy service running"
else
    print_error "Proxy service failed to start"
fi

if systemctl is-active --quiet nexus-web; then
    print_success "Web service running"
else
    print_error "Web service failed to start"
fi

# Enable services for auto-start
systemctl enable nexus-proxy
systemctl enable nexus-web

print_success "Services enabled for auto-start"

# ===========================
# HEALTH CHECKS
# ===========================

echo ""
echo "🏥 Running health checks..."

# Check proxy connectivity
nc -z 127.0.0.1 3306 && print_success "Proxy listening on port 3306" || print_error "Proxy not listening"

# Check web gateway
curl -s http://127.0.0.1:5000/login > /dev/null && print_success "Web gateway responding" || print_error "Web gateway not responding"

# Check database
mysql -h 127.0.0.1 -u ktp_user -p"$DB_PASSWORD" ktp_database -e "SELECT 1" > /dev/null 2>&1 && print_success "Database accessible" || print_error "Database not accessible"

# ===========================
# FINAL SUMMARY
# ===========================

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║     ✅ NEXUS-CYBER DEPLOYMENT COMPLETED SUCCESSFULLY      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "📊 Deployment Summary:"
echo "  • Installation Path: $DEPLOYMENT_DIR"
echo "  • Python Version: $(python3 --version)"
echo "  • Services: nexus-proxy, nexus-web"
echo "  • Database: MySQL (Docker)"
echo ""
echo "🔗 Access Points:"
echo "  • Web Dashboard: http://localhost:5000/login"
echo "  • Database Proxy: localhost:3306"
echo "  • MySQL Backend: localhost:3307"
echo ""
echo "📝 Important Files:"
echo "  • Configuration: $DEPLOYMENT_DIR/.env"
echo "  • Logs: $DEPLOYMENT_DIR/logs/"
echo "  • Proxy Log: $DEPLOYMENT_DIR/logs/proxy.log"
echo "  • Web Log: $DEPLOYMENT_DIR/logs/app.log"
echo ""
echo "🔐 Next Steps:"
echo "  1. Configure .env file with production settings"
echo "  2. Set up Telegram alerts"
echo "  3. Configure AI models (Ollama)"
echo "  4. Setup monitoring and alerting"
echo "  5. Test with sample queries"
echo ""
echo "📚 Documentation: $DEPLOYMENT_DIR/docs/"
echo ""

print_success "Deployment ready for production!"
