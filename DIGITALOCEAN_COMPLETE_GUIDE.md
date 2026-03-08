# Complete DigitalOcean Deployment Guide for PhishGuard ML Backend

Deploy your PhishGuard ML model to DigitalOcean in 15 minutes using GitHub Student Developer Pack (FREE $200 credit).

---

## 📋 What You Get

✅ **ML Model hosted 24/7** on DigitalOcean  
✅ **Free for 33+ months** ($200 student credit)  
✅ **Auto-deploys** when you push to GitHub  
✅ **Global access** - anyone can use your app  
✅ **No VT API key needed** - users bring their own

---

## 🏗️ Architecture

```
Flutter App (User's Phone)
    ↓
    ├─→ VirusTotal API (User's API key) ----→ Comprehensive scanning (95 vendors)
    │                                          ↓ (if rate limited or no key)
    └─→ Your DigitalOcean Server --------→ ML Model (99.78% accuracy)
                                              Always available, free for all users
```

**Key Features:**

- 🔑 Users add their own free VT API key (4 requests/min)
- 🧠 ML model provides free baseline protection
- 🆓 Both services work independently
- 🔄 Smart fallback: VT → ML Model → Offline

---

## Step 1: Activate GitHub Student Developer Pack

1. Go to [GitHub Education](https://education.github.com/pack)
2. Sign in with your GitHub account
3. Verify your student status (upload student ID or .edu email)
4. Get approved (usually within 24 hours)
5. Access DigitalOcean benefit: **$200 credit for 1 year**

---

## Step 2: Create DigitalOcean Account

1. Go to [DigitalOcean.com](https://www.digitalocean.com/)
2. Sign up with **GitHub Student Pack link** from your benefits page
3. Verify your email
4. $200 credit automatically applied ✅

---

## Step 3: Create a Droplet (Your Server)

### Create Droplet

1. Click **Create** → **Droplets** (top right)

2. **Choose Image:**
   - Distribution: **Ubuntu 22.04 LTS** (recommended)

3. **Choose Size:**
   - Plan: **Basic**
   - CPU: **Regular** - $6/month
   - Configuration: **1 GB RAM / 1 vCPU / 25 GB SSD**

   _(This is enough for your ML model + handles 1000+ requests/day)_

4. **Choose Datacenter:**
   - Pick closest to your target users
   - India users: **Bangalore**
   - US users: **New York / San Francisco**
   - Europe: **London / Frankfurt**

5. **Authentication:**

   **Option A: SSH Key (Recommended)**
   - Generate SSH key on your computer:

   ```bash
   # Windows (Git Bash/PowerShell)
   ssh-keygen -t ed25519 -C "your_email@example.com"
   # Press Enter 3 times (default location, no passphrase)

   # Copy public key
   cat ~/.ssh/id_ed25519.pub | clip
   ```

   ```bash
   # Mac
   ssh-keygen -t ed25519 -C "your_email@example.com"
   cat ~/.ssh/id_ed25519.pub | pbcopy
   ```

   ```bash
   # Linux
   ssh-keygen -t ed25519 -C "your_email@example.com"
   cat ~/.ssh/id_ed25519.pub
   # Copy the output manually
   ```

   - Click **New SSH Key** in DigitalOcean
   - Paste your public key
   - Name it "My Laptop"

   **Option B: Password**
   - DigitalOcean will email you a root password
   - Less secure, but easier for beginners

6. **Hostname:**
   - Name: `phishguard-ml-backend`

7. **Advanced Options (Optional):**
   - Enable IPv6: ✅
   - Monitoring: ✅ (free)

8. Click **Create Droplet**

9. **Note your droplet's IP address:** `xxx.xxx.xxx.xxx`

---

## Step 4: Connect to Your Droplet

### First Connection

```bash
# Replace xxx.xxx.xxx.xxx with your droplet IP
ssh root@xxx.xxx.xxx.xxx
```

**First time connection:**

- Type `yes` when asked about host authenticity
- If using password, check your email for the temporary password
- You'll be asked to change the password on first login

---

## Step 5: Deploy Backend (Automated)

### Option A: Clone Your Repository

**If you already pushed to GitHub:**

```bash
# On your droplet
cd /root
git clone https://github.com/YOUR_USERNAME/phishguard.git
cd phishguard
```

**If you haven't pushed to GitHub yet:**

```bash
# On your local computer
cd "D:/Documents/Flutter Project/flutter_application_2"

# Initialize git
git init

# Create .gitignore if it doesn't exist
cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
venv/
.env

# Flutter
.dart_tool/
build/

# IDE
.vscode/
.idea/
EOF

# Add files
git add backend/ src/ train/models/ README.md MODEL_DOCUMENTATION.md

# Commit
git commit -m "Initial commit: PhishGuard ML backend"

# Add remote (create repo on GitHub first)
git remote add origin https://github.com/YOUR_USERNAME/phishguard.git

# Push
git branch -M main
git push -u origin main
```

Then on droplet:

```bash
git clone https://github.com/YOUR_USERNAME/phishguard.git
cd phishguard
```

### Option B: Manual Deployment Script

**Run this complete setup script:**

```bash
# SSH into your droplet
ssh root@xxx.xxx.xxx.xxx

# Run deployment
curl -fsSL https://gist.githubusercontent.com/YOUR_GIST/deploy.sh | bash
```

**Or create the script manually:**

```bash
# Create deployment script
nano deploy.sh
```

Paste this content:

```bash
#!/bin/bash
set -e

echo "🚀 PhishGuard ML Backend Deployment"
echo "===================================="

# Update system
echo "📦 Updating system..."
apt update && apt upgrade -y

# Install Python 3.11 and dependencies
echo "🐍 Installing Python 3.11..."
apt install -y python3.11 python3.11-venv python3-pip git nginx ufw

# Create app directory
echo "📁 Setting up application..."
mkdir -p /var/www/phishguard
cd /var/www/phishguard

# Clone repository (if not already done)
if [ ! -d ".git" ]; then
    read -p "Enter GitHub repository URL: " REPO_URL
    git clone $REPO_URL .
fi

# Create virtual environment
echo "🔧 Creating virtual environment..."
python3.11 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo "📚 Installing Python packages..."
pip install --upgrade pip
pip install -r backend/requirements.txt

# Create systemd service
echo "⚙️ Creating systemd service..."
cat > /etc/systemd/system/phishguard.service << 'EOF'
[Unit]
Description=PhishGuard ML Backend
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/www/phishguard/backend
Environment="PATH=/var/www/phishguard/venv/bin"
ExecStart=/var/www/phishguard/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --workers 2
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Configure Nginx
echo "🌐 Configuring Nginx..."
cat > /etc/nginx/sites-available/phishguard << 'EOF'
server {
    listen 80;
    server_name _;

    # Increase body size for file uploads
    client_max_body_size 50M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # CORS headers for Flutter app
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range' always;
        add_header 'Access-Control-Expose-Headers' 'Content-Length,Content-Range' always;

        # Handle preflight
        if ($request_method = 'OPTIONS') {
            return 204;
        }
    }
}
EOF

# Enable site
ln -sf /etc/nginx/sites-available/phishguard /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test and restart Nginx
nginx -t
systemctl restart nginx
systemctl enable nginx

# Configure firewall
echo "🔒 Configuring firewall..."
ufw allow 22/tcp   # SSH
ufw allow 80/tcp   # HTTP
ufw allow 443/tcp  # HTTPS (for later)
echo "y" | ufw enable

# Start PhishGuard service
echo "🎬 Starting PhishGuard service..."
systemctl daemon-reload
systemctl enable phishguard
systemctl start phishguard

# Wait for service to start
sleep 3

# Check status
echo ""
echo "✅ Deployment Complete!"
echo "======================="
echo ""
echo "🌐 Your ML backend is running at:"
echo "   http://$(curl -s ifconfig.me)"
echo ""
echo "🧪 Test it:"
echo "   curl http://$(curl -s ifconfig.me)/health"
echo ""
echo "📊 Service status:"
systemctl status phishguard --no-pager -l
echo ""
echo "📝 Useful commands:"
echo "   View logs:    journalctl -u phishguard -f"
echo "   Restart:      systemctl restart phishguard"
echo "   Stop:         systemctl stop phishguard"
echo "   Status:       systemctl status phishguard"
echo ""
echo "🔐 VT API Keys: Users bring their own (no backend config needed)"
echo ""
EOF

# Make executable and run
chmod +x deploy.sh
./deploy.sh
```

**Enter when prompted:**

- Repository URL: `https://github.com/YOUR_USERNAME/phishguard.git`

---

## Step 6: Verify Deployment

### Test Backend is Running

```bash
# Test health endpoint
curl http://localhost:8000/health

# Should return:
# {"status":"healthy","ml_model_loaded":true,"vt_api_configured":false}
```

### Test from Your Computer

```bash
# Replace xxx.xxx.xxx.xxx with your droplet IP
curl http://xxx.xxx.xxx.xxx/health
```

### Test ML Model

```bash
curl -X POST http://xxx.xxx.xxx.xxx/check-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://phishing-site.tk/login"}'
```

✅ If you get JSON response with verdict, it's working!

---

## Step 7: Update Flutter App

### Update Backend URL

Edit `lib/main.dart`:

```dart
// Find around line 2500
String _backendUrl = 'http://10.0.2.2:8000';  // Old (localhost)

// Change to:
String _backendUrl = 'http://xxx.xxx.xxx.xxx';  // Your droplet IP
```

### Keep Settings Page

Your app already has backend settings - perfect! Users can:

- Use your default backend URL
- Or configure their own backend

---

## Step 8: Set Up Auto-Deploy (GitHub Actions)

### Add GitHub Secrets

1. Go to your GitHub repo
2. **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**

Add these 3 secrets:

| Name              | Value                    | How to Get              |
| ----------------- | ------------------------ | ----------------------- |
| `DROPLET_IP`      | `xxx.xxx.xxx.xxx`        | Your droplet IP address |
| `DROPLET_USER`    | `root`                   | SSH username            |
| `SSH_PRIVATE_KEY` | (content of private key) | See below               |

**Get your SSH private key:**

```bash
# Windows (Git Bash)
cat ~/.ssh/id_ed25519 | clip

# Mac
cat ~/.ssh/id_ed25519 | pbcopy

# Linux
cat ~/.ssh/id_ed25519
```

**⚠️ Important:** Copy the ENTIRE key including:

```
-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----
```

### Verify Workflow File

Check `.github/workflows/deploy.yml` exists. If not, create it:

```yaml
name: Deploy to DigitalOcean

on:
  push:
    branches: [main]
    paths:
      - "backend/**"
      - "src/**"
      - "train/models/**"
      - ".github/workflows/deploy.yml"

jobs:
  deploy:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Deploy to DigitalOcean
        uses: appleboy/ssh-action@master
        with:
          host: ${{ secrets.DROPLET_IP }}
          username: ${{ secrets.DROPLET_USER }}
          key: ${{ secrets.SSH_PRIVATE_KEY }}
          script: |
            cd /var/www/phishguard
            git pull origin main
            source venv/bin/activate
            pip install -r backend/requirements.txt
            sudo systemctl restart phishguard
            echo "✅ Deployment successful!"
```

### Test Auto-Deploy

```bash
# Make a small change
cd "D:/Documents/Flutter Project/flutter_application_2"
echo "# Test" >> README.md

# Commit and push
git add .
git commit -m "Test auto-deploy"
git push

# Watch deployment
# Go to GitHub → Your repo → Actions tab
# You should see the workflow running!
```

---

## Step 9: (Optional) Add Custom Domain

### Get Free Domain from Namecheap (Student Pack)

1. Go to [nc.me](https://nc.me/)
2. Register free `.me` domain (e.g., `phishguard.me`)
3. Activate with GitHub Student Pack

### Point Domain to Droplet

1. In Namecheap: **Domain List** → **Manage**
2. **Advanced DNS** → Add record:
   - Type: **A Record**
   - Host: **@**
   - Value: Your droplet IP
   - TTL: **Automatic**

3. Add www subdomain:
   - Type: **A Record**
   - Host: **www**
   - Value: Your droplet IP
   - TTL: **Automatic**

### Update Nginx

```bash
# SSH into droplet
ssh root@xxx.xxx.xxx.xxx

# Edit Nginx config
nano /etc/nginx/sites-available/phishguard

# Change this line:
server_name _;
# To:
server_name phishguard.me www.phishguard.me;

# Test and reload
nginx -t
systemctl reload nginx
```

### Add SSL Certificate (HTTPS)

```bash
# Install Certbot
apt install -y certbot python3-certbot-nginx

# Get SSL certificate (automatic!)
certbot --nginx -d phishguard.me -d www.phishguard.me

# Follow prompts:
# - Enter your email
# - Agree to terms
# - Choose: Redirect HTTP to HTTPS (option 2)

# Certbot auto-renews every 90 days ✅
```

**Your backend is now at:** `https://phishguard.me` 🎉

Update Flutter app:

```dart
String _backendUrl = 'https://phishguard.me';
```

---

## Step 10: VT API Key Management (User-Side)

### How It Works

✅ **Users bring their own free VT API key:**

1. User signs up at [VirusTotal.com](https://www.virustotal.com/)
2. Gets free API key (4 requests/minute)
3. Enters in your app's Settings page
4. App calls VT API directly from their phone

✅ **Your backend provides:**

- ML model for users without VT key
- Fallback when VT is rate-limited
- Always-available baseline protection

### No Backend Configuration Needed

Your backend (`backend/main.py`) already handles this:

```python
# VT API key comes from Flutter app in the request
class URLCheckRequest(BaseModel):
    url: str
    vt_api_key: Optional[str] = None  # User provides this
```

**You don't need to set `VIRUSTOTAL_API_KEY` on the server!**

---

## 📊 Server Management

### View Logs

```bash
# Real-time logs
journalctl -u phishguard -f

# Last 100 lines
journalctl -u phishguard -n 100

# Logs from last hour
journalctl -u phishguard --since "1 hour ago"
```

### Restart Backend

```bash
systemctl restart phishguard
```

### Check Status

```bash
systemctl status phishguard
```

### Monitor System Resources

```bash
# Install htop
apt install htop

# View resources
htop
```

### Update Backend Code

```bash
cd /var/www/phishguard
git pull origin main
source venv/bin/activate
pip install -r backend/requirements.txt
systemctl restart phishguard
```

---

## 🔒 Security Best Practices

### 1. Regular Updates

```bash
# Set up automatic security updates
apt install unattended-upgrades
dpkg-reconfigure --priority=low unattended-upgrades
```

### 2. Fail2Ban (Block Brute Force)

```bash
apt install fail2ban
systemctl enable fail2ban
systemctl start fail2ban
```

### 3. Change SSH Port (Optional)

```bash
nano /etc/ssh/sshd_config
# Change: Port 22 → Port 2222
systemctl restart sshd

# Update firewall
ufw allow 2222/tcp
ufw delete allow 22/tcp
```

### 4. Disable Root Login (After Creating User)

```bash
# Create non-root user
adduser phishguard
usermod -aG sudo phishguard

# Disable root login
nano /etc/ssh/sshd_config
# Set: PermitRootLogin no
systemctl restart sshd
```

---

## 📈 Monitoring & Uptime

### DigitalOcean Monitoring (Built-in)

1. Go to your droplet in DigitalOcean dashboard
2. Click **Graphs** tab
3. View:
   - CPU usage
   - Memory usage
   - Bandwidth
   - Disk I/O

### UptimeRobot (External Monitoring)

1. Sign up at [UptimeRobot.com](https://uptimerobot.com/) (FREE)
2. Add monitor:
   - Type: **HTTP(s)**
   - URL: `https://phishguard.me/health`
   - Interval: **5 minutes**
3. Get email alerts if backend goes down

---

## 💰 Cost Breakdown

| Item                 | Cost     | Duration  | Your Cost |
| -------------------- | -------- | --------- | --------- |
| DigitalOcean Droplet | $6/month | 33 months | **$0**    |
| Domain (.me)         | $20/year | 1 year    | **$0**    |
| SSL Certificate      | Free     | Forever   | **$0**    |
| GitHub Actions       | Free     | Unlimited | **$0**    |
| **Total**            | -        | -         | **$0**    |

**After 33 months:** $6/month for droplet (still very affordable)

---

## 🐛 Troubleshooting

### Backend Not Responding

```bash
# Check service status
systemctl status phishguard

# Check if port 8000 is listening
netstat -tulpn | grep 8000

# Check logs
journalctl -u phishguard -n 50

# Restart
systemctl restart phishguard
```

### "Connection Refused" from Flutter

```bash
# Check firewall
ufw status

# Ensure port 80 is open
ufw allow 80/tcp

# Check Nginx
systemctl status nginx
nginx -t
```

### GitHub Actions Deployment Failing

1. Check secrets are set correctly
2. Verify SSH key has no passphrase
3. Test SSH manually: `ssh root@YOUR_IP`
4. Check workflow logs in GitHub Actions tab

### ML Model Not Loading

```bash
# Check if model files exist
ls -lh /var/www/phishguard/train/models/

# Check Python can load models
cd /var/www/phishguard/backend
source ../venv/bin/activate
python -c "import joblib; print('OK')"
```

---

## 🚀 Scaling for More Users

### Current Setup Handles:

- ~1,000 requests/day
- ~10-20 concurrent users
- Perfect for personal/small project use

### If You Need More:

**Upgrade Droplet** ($12/month):

- 2 GB RAM / 1 vCPU
- Handles 5,000+ requests/day
- 50+ concurrent users

**Add More Workers** (free):

```bash
# Edit service file
nano /etc/systemd/system/phishguard.service

# Change:
--workers 2
# To:
--workers 4

# Restart
systemctl daemon-reload
systemctl restart phishguard
```

**Add Database Caching** (advanced):

```bash
apt install redis-server
pip install redis
# Implement caching in backend/main.py
```

---

## 🎉 Success Checklist

- ✅ Droplet created and running
- ✅ Backend deployed and accessible
- ✅ ML model loading correctly
- ✅ Nginx serving requests
- ✅ Firewall configured
- ✅ SSL certificate installed (if using domain)
- ✅ GitHub Actions auto-deploying
- ✅ Flutter app updated with backend URL
- ✅ Monitoring set up
- ✅ Users can add their own VT API keys

---

## 📚 Additional Resources

- **DigitalOcean Docs:** [docs.digitalocean.com](https://docs.digitalocean.com)
- **FastAPI Docs:** [fastapi.tiangolo.com](https://fastapi.tiangolo.com)
- **Let's Encrypt:** [letsencrypt.org](https://letsencrypt.org)
- **UptimeRobot:** [uptimerobot.com](https://uptimerobot.com)

---

## 🆘 Need Help?

1. Check logs: `journalctl -u phishguard -f`
2. Test locally: `curl http://localhost:8000/health`
3. Verify firewall: `ufw status`
4. Check service: `systemctl status phishguard`

Still stuck? Open an issue on your GitHub repo!

---

**Congratulations! Your PhishGuard ML backend is now live and serving users worldwide! 🌍🎉**
