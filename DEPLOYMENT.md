# PhishGuard Deployment Guide

## Deploy with GitHub Student Developer Pack (Free)

This guide shows you how to deploy PhishGuard backend so anyone can use your app worldwide with **auto-updates** when you push code changes.

---

## 🎓 What You Get Free with Student Pack

- **DigitalOcean**: $200 credit (1 year of hosting)
- **Namecheap**: 1 free domain + SSL certificate
- **GitHub**: Unlimited private repos + GitHub Actions
- **CloudFlare**: Pro plan for CDN & DDoS protection

---

## 📋 Prerequisites

1. ✅ GitHub Student Developer Pack activated
2. ✅ GitHub account
3. ✅ VirusTotal API key

---

## 🚀 Step-by-Step Deployment

### Step 1: Create DigitalOcean Account

1. Go to [DigitalOcean](https://www.digitalocean.com/)
2. Sign up using GitHub Student Pack link
3. Verify your student status
4. Get $200 credit applied

### Step 2: Create a Droplet (Server)

1. Click **Create** → **Droplets**
2. Choose:
   - **Image**: Ubuntu 22.04 LTS
   - **Plan**: Basic ($6/month)
   - **CPU**: Regular (1 GB RAM, 1 vCPU) - $6/month
   - **Datacenter**: Closest to your users (e.g., Bangalore for India)
   - **Authentication**: SSH Key (recommended) or Password
   - **Hostname**: `phishguard-backend`
3. Click **Create Droplet**
4. Note your droplet's IP address (e.g., `143.198.123.45`)

### Step 3: Set Up SSH Key (If Using SSH Authentication)

**On Windows:**

```bash
# Open Git Bash or PowerShell
ssh-keygen -t ed25519 -C "your_email@example.com"
# Press Enter 3 times (default location, no passphrase)

# Copy your public key
cat ~/.ssh/id_ed25519.pub | clip
```

**On Linux/Mac:**

```bash
ssh-keygen -t ed25519 -C "your_email@example.com"
cat ~/.ssh/id_ed25519.pub | pbcopy  # Mac
cat ~/.ssh/id_ed25519.pub           # Linux (copy manually)
```

Add this public key to DigitalOcean during droplet creation.

### Step 4: Connect to Your Droplet

```bash
# Replace with your droplet IP
ssh root@143.198.123.45
```

### Step 5: Deploy Backend Automatically

```bash
# On your droplet, run:
curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/backend/deploy.sh -o deploy.sh
chmod +x deploy.sh
./deploy.sh
```

The script will:

- ✅ Install Python, Nginx, dependencies
- ✅ Clone your repository
- ✅ Set up systemd service (auto-restart on crash)
- ✅ Configure Nginx reverse proxy
- ✅ Set up firewall
- ✅ Start the backend

**Enter when prompted:**

- GitHub repository URL: `https://github.com/YOUR_USERNAME/YOUR_REPO.git`
- VirusTotal API key: `your_vt_api_key`

### Step 6: Verify Deployment

```bash
# Check if backend is running
curl http://localhost:8000/health

# Should return: {"status":"healthy",...}
```

Your backend is now live at: `http://YOUR_DROPLET_IP`

---

## 🔄 Auto-Deploy on Code Changes

### Step 1: Set Up GitHub Secrets

1. Go to your GitHub repo → **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret** and add:

| Secret Name       | Value                            | Description             |
| ----------------- | -------------------------------- | ----------------------- |
| `DROPLET_IP`      | `143.198.123.45`                 | Your droplet IP address |
| `DROPLET_USER`    | `root`                           | SSH username            |
| `SSH_PRIVATE_KEY` | (content of `~/.ssh/id_ed25519`) | Your private SSH key    |

**To copy private key:**

```bash
# Windows (Git Bash)
cat ~/.ssh/id_ed25519 | clip

# Mac
cat ~/.ssh/id_ed25519 | pbcopy

# Linux
cat ~/.ssh/id_ed25519
```

### Step 2: Push Code to GitHub

```bash
cd "D:/Documents/Flutter Project/flutter_application_2"

# Initialize git (if not already done)
git init
git add .
git commit -m "Initial commit"

# Add remote repository
git remote add origin https://github.com/YOUR_USERNAME/phishguard.git
git branch -M main
git push -u origin main
```

### Step 3: Auto-Deploy Works! 🎉

Now whenever you push changes to `main` branch:

```bash
git add .
git commit -m "Fixed bug in ML model"
git push
```

**GitHub Actions will automatically:**

1. ✅ Connect to your droplet via SSH
2. ✅ Pull latest code
3. ✅ Install new dependencies
4. ✅ Restart backend service
5. ✅ Verify deployment

**Check deployment status:**

- Go to GitHub repo → **Actions** tab
- See real-time deployment logs

---

## 🌐 Optional: Add Custom Domain (Free with Student Pack)

### Step 1: Get Free Domain from Namecheap

1. Go to [Namecheap Student Pack](https://nc.me/)
2. Register a free `.me` domain (e.g., `phishguard.me`)

### Step 2: Point Domain to Droplet

1. In Namecheap, go to **Domain List** → **Manage**
2. **Advanced DNS** → Add records:
   - **Type**: A Record
   - **Host**: @
   - **Value**: Your droplet IP
   - **TTL**: Automatic

### Step 3: Update Nginx Configuration

```bash
# On your droplet
sudo nano /etc/nginx/sites-available/phishguard

# Change this line:
server_name _;
# To:
server_name phishguard.me www.phishguard.me;

# Save and restart
sudo nginx -t
sudo systemctl restart nginx
```

### Step 4: Add Free SSL (HTTPS)

```bash
# Install Certbot
sudo apt install -y certbot python3-certbot-nginx

# Get SSL certificate (automatic)
sudo certbot --nginx -d phishguard.me -d www.phishguard.me

# Follow prompts, enter your email
# SSL auto-renews every 90 days
```

Your backend is now at: `https://phishguard.me` 🎉

---

## 📱 Update Flutter App

### Update Backend URL in Flutter

Open `lib/main.dart` and change:

```dart
// Find this line (around line 2500)
String _backendUrl = 'http://YOUR_DROPLET_IP';

// Or if using domain:
String _backendUrl = 'https://phishguard.me';
```

**Make it user-configurable (recommended):**

Keep the settings page you already have - users can enter their own backend URL or use your default public server.

---

## 🛠️ Server Management Commands

### View Backend Logs

```bash
sudo journalctl -u phishguard -f
```

### Restart Backend

```bash
sudo systemctl restart phishguard
```

### Check Backend Status

```bash
sudo systemctl status phishguard
```

### Update Backend Manually

```bash
cd /var/www/phishguard
git pull origin main
source venv/bin/activate
pip install -r backend/requirements.txt
sudo systemctl restart phishguard
```

### Monitor System Resources

```bash
htop  # Install: sudo apt install htop
```

---

## 📊 Monitoring & Uptime

### Set Up UptimeRobot (Free)

1. Go to [UptimeRobot](https://uptimerobot.com/)
2. Add monitor:
   - **Type**: HTTP(s)
   - **URL**: `https://phishguard.me/health`
   - **Interval**: 5 minutes
3. Get email alerts if backend goes down

---

## 🔒 Security Best Practices

### 1. Change SSH Port (Optional)

```bash
sudo nano /etc/ssh/sshd_config
# Change: Port 22 → Port 2222
sudo systemctl restart sshd
```

### 2. Set Up Automatic Security Updates

```bash
sudo apt install unattended-upgrades
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

### 3. Enable Fail2Ban (Blocks brute-force attacks)

```bash
sudo apt install fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

### 4. Regular Backups

```bash
# Backup script
mkdir -p ~/backups
cd /var/www/phishguard
tar -czf ~/backups/phishguard-$(date +%Y%m%d).tar.gz backend/ src/ train/

# Schedule daily backups
(crontab -l 2>/dev/null; echo "0 2 * * * /path/to/backup-script.sh") | crontab -
```

---

## 💰 Cost Breakdown

| Service              | Cost     | Duration  | Your Cost               |
| -------------------- | -------- | --------- | ----------------------- |
| DigitalOcean Droplet | $6/month | 12 months | **$0** (Student credit) |
| Domain (.me)         | $20/year | 1 year    | **$0** (Student pack)   |
| SSL Certificate      | $0       | Forever   | **$0** (Let's Encrypt)  |
| GitHub Actions       | $0       | Unlimited | **$0** (Public/Student) |
| **Total**            |          |           | **$0**                  |

After 1 year: $6/month to continue

---

## 🐛 Troubleshooting

### Backend Not Responding

```bash
# Check if service is running
sudo systemctl status phishguard

# Check logs for errors
sudo journalctl -u phishguard -n 50

# Restart service
sudo systemctl restart phishguard
```

### Deployment Failed

```bash
# SSH into droplet manually
ssh root@YOUR_DROPLET_IP

# Check if Git can pull
cd /var/www/phishguard
git pull origin main

# Check if dependencies install
source venv/bin/activate
pip install -r backend/requirements.txt
```

### "Connection Refused" Error

```bash
# Check if port 8000 is open
sudo netstat -tulpn | grep 8000

# Check firewall
sudo ufw status

# Allow port 80
sudo ufw allow 80/tcp
```

---

## 🚀 Advanced: Scale for More Users

### Upgrade Droplet (If Needed)

- 2 GB RAM ($12/month) - Handles 1000+ users
- 4 GB RAM ($24/month) - Handles 10,000+ users

### Add Load Balancer

- Use DigitalOcean Load Balancer
- Run 2-3 droplets behind it
- Auto-scale based on traffic

### Add Database for Caching

```bash
# Install Redis for faster caching
sudo apt install redis-server
pip install redis

# Store rate limits and predictions in Redis
```

---

## 📞 Support

**GitHub Issues**: Create issue in your repo for help  
**DigitalOcean Docs**: [docs.digitalocean.com](https://docs.digitalocean.com)  
**FastAPI Docs**: [fastapi.tiangolo.com](https://fastapi.tiangolo.com)

---

## 🎉 You're Done!

Your PhishGuard backend is now:

- ✅ Hosted on DigitalOcean (free for 1 year)
- ✅ Auto-deploys when you push code
- ✅ Available worldwide 24/7
- ✅ Has SSL certificate (HTTPS)
- ✅ Auto-restarts on crashes
- ✅ Protected by firewall

Anyone can now download your Flutter app and use it globally! 🌍
