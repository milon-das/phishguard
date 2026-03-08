#!/bin/bash

# PhishGuard Backend Deployment Script
# This script sets up the backend on a DigitalOcean droplet

set -e  # Exit on any error

echo "🚀 Starting PhishGuard deployment..."

# Update system
echo "📦 Updating system packages..."
sudo apt update
sudo apt upgrade -y

# Install Python 3.11
echo "🐍 Installing Python 3.11..."
sudo apt install -y python3.11 python3.11-venv python3-pip nginx git

# Create application directory
echo "📁 Setting up application directory..."
sudo mkdir -p /var/www/phishguard
sudo chown -R $USER:$USER /var/www/phishguard
cd /var/www/phishguard

# Clone repository (if not already cloned)
if [ ! -d ".git" ]; then
    echo "📥 Cloning repository..."
    read -p "Enter your GitHub repository URL: " REPO_URL
    git clone $REPO_URL .
else
    echo "📥 Pulling latest changes..."
    git pull origin main
fi

# Create virtual environment
echo "🔧 Setting up Python virtual environment..."
python3.11 -m venv venv
source venv/bin/activate

# Install dependencies
echo "📚 Installing Python dependencies..."
pip install --upgrade pip
pip install -r backend/requirements.txt

# Set up environment variables (optional - users bring their own VT keys)
echo "🔑 Setting up environment variables..."
if [ ! -f "backend/.env" ]; then
    echo "# VT API keys are provided by users in the app" > backend/.env
    echo "# No backend configuration needed for VT API" >> backend/.env
    echo "PORT=8000" >> backend/.env
    echo "ℹ️  VT API keys: Users will add their own keys in the app"
fi

# Create systemd service
echo "⚙️ Creating systemd service..."
sudo tee /etc/systemd/system/phishguard.service > /dev/null <<EOF
[Unit]
Description=PhishGuard FastAPI Backend
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/var/www/phishguard/backend
Environment="PATH=/var/www/phishguard/venv/bin"
EnvironmentFile=/var/www/phishguard/backend/.env
ExecStart=/var/www/phishguard/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --workers 2
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Configure Nginx
echo "🌐 Configuring Nginx..."
sudo tee /etc/nginx/sites-available/phishguard > /dev/null <<EOF
server {
    listen 80;
    server_name _;  # Replace with your domain if you have one

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # CORS headers
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range' always;
    }
}
EOF

# Enable Nginx site
sudo ln -sf /etc/nginx/sites-available/phishguard /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl restart nginx

# Configure firewall
echo "🔒 Configuring firewall..."
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # HTTP
sudo ufw allow 443/tcp  # HTTPS
sudo ufw --force enable

# Start services
echo "🎬 Starting services..."
sudo systemctl daemon-reload
sudo systemctl enable phishguard
sudo systemctl start phishguard
sudo systemctl enable nginx

# Check status
echo ""
echo "✅ Deployment complete!"
echo ""
echo "Service status:"
sudo systemctl status phishguard --no-pager -l
echo ""
echo "🌐 Your backend is now running at:"
echo "   http://$(curl -s ifconfig.me)"
echo ""
echo "📝 Useful commands:"
echo "   View logs:    sudo journalctl -u phishguard -f"
echo "   Restart:      sudo systemctl restart phishguard"
echo "   Stop:         sudo systemctl stop phishguard"
echo "   Check status: sudo systemctl status phishguard"
echo ""
echo "🔐 VirusTotal API Keys:"
echo "   Users bring their own VT API keys (free from virustotal.com)"
echo "   ML model provides free baseline protection for all users"
echo "   Your backend handles ML inference - no VT config needed!"
echo ""
