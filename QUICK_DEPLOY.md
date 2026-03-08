# 🚀 Quick Deployment Guide

Deploy PhishGuard backend in **5 minutes** using your GitHub Student Developer Pack!

---

## ⚡ Quick Start (First Time)

### 1️⃣ Create DigitalOcean Droplet

1. Sign up at [DigitalOcean](https://www.digitalocean.com/) with Student Pack
2. Create droplet: **Ubuntu 22.04**, **1GB RAM** ($6/month - Free with credit)
3. Note your droplet IP: `xxx.xxx.xxx.xxx`

### 2️⃣ Deploy Backend (One Command)

```bash
# SSH into your droplet
ssh root@YOUR_DROPLET_IP

# Run deployment script
curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/phishguard/main/backend/deploy.sh -o deploy.sh
chmod +x deploy.sh
./deploy.sh
```

**Enter when prompted:**

- Repository URL: `https://github.com/YOUR_USERNAME/phishguard.git`
- VirusTotal API key: `your_api_key_here`

Done! Your backend is live at `http://YOUR_DROPLET_IP`

### 3️⃣ Set Up Auto-Deploy (GitHub Actions)

**a) Add GitHub Secrets:**

Go to your repo → **Settings** → **Secrets** → **New secret**

Add these 3 secrets:

| Name              | Value                          |
| ----------------- | ------------------------------ |
| `DROPLET_IP`      | Your droplet IP address        |
| `DROPLET_USER`    | `root`                         |
| `SSH_PRIVATE_KEY` | Content of `~/.ssh/id_ed25519` |

**Get your SSH private key:**

```bash
# Windows (Git Bash)
cat ~/.ssh/id_ed25519 | clip

# Mac
cat ~/.ssh/id_ed25519 | pbcopy

# Linux
cat ~/.ssh/id_ed25519
```

**b) Push to GitHub:**

```bash
cd "D:/Documents/Flutter Project/flutter_application_2"
git init
git add .
git commit -m "Initial deployment"
git remote add origin https://github.com/YOUR_USERNAME/phishguard.git
git push -u origin main
```

**c) Done! 🎉**

Now whenever you push code:

```bash
git add .
git commit -m "Updated ML model"
git push
```

GitHub Actions automatically deploys to your server!

---

## 📱 Update Flutter App

Edit `lib/main.dart`:

```dart
// Find line ~2500
String _backendUrl = 'http://YOUR_DROPLET_IP';
```

Or keep the settings page so users can configure their own backend URL.

---

## 🌐 Optional: Add Free Domain

### With Namecheap (Student Pack)

1. Get free `.me` domain from [nc.me](https://nc.me)
2. Point to droplet IP in DNS settings
3. Add SSL:
   ```bash
   sudo certbot --nginx -d yourdomain.me
   ```

Now your backend is at: `https://yourdomain.me` 🎉

---

## 🛠️ Common Commands

```bash
# View logs
sudo journalctl -u phishguard -f

# Restart backend
sudo systemctl restart phishguard

# Check status
sudo systemctl status phishguard

# Update manually
cd /var/www/phishguard
git pull
source venv/bin/activate
pip install -r backend/requirements.txt
sudo systemctl restart phishguard
```

---

## 📊 What You Get

✅ **Backend hosted 24/7** (no cold starts)  
✅ **Auto-deploy on git push** (CI/CD pipeline)  
✅ **Free for 1 year** ($200 DigitalOcean credit)  
✅ **Global access** (anyone can use your app)  
✅ **Auto-restart on crash** (systemd service)  
✅ **SSL certificate** (free with Certbot)  
✅ **Firewall configured** (secure by default)

---

## 💡 Tips

- **Monitor uptime**: Use [UptimeRobot](https://uptimerobot.com) (free)
- **View metrics**: DigitalOcean dashboard shows CPU/RAM usage
- **Backup regularly**: Droplet snapshots ($1/month)
- **Scale up**: Upgrade to 2GB RAM if you get 1000+ users

---

## 🐛 Troubleshooting

**Backend not responding?**

```bash
ssh root@YOUR_DROPLET_IP
sudo systemctl status phishguard
sudo journalctl -u phishguard -n 50
```

**GitHub Actions failing?**

- Check secrets are set correctly
- Verify SSH key has no passphrase
- Check deployment logs in Actions tab

**Flutter app can't connect?**

- Check firewall: `sudo ufw status`
- Verify backend is running: `curl http://localhost:8000/health`
- Check if port 80 is open: `sudo ufw allow 80/tcp`

---

## 📚 Full Documentation

See [DEPLOYMENT.md](DEPLOYMENT.md) for comprehensive guide with:

- Security best practices
- Custom domain setup
- SSL configuration
- Monitoring and alerts
- Cost breakdown
- Advanced scaling

---

## 🎓 Student Pack Benefits Used

- ✅ DigitalOcean: $200 credit (33 months of hosting)
- ✅ Namecheap: Free `.me` domain
- ✅ GitHub: Unlimited Actions minutes
- ✅ Certbot: Free SSL certificates

**Total cost to you: $0** 🎉

---

**Questions?** Open an issue on GitHub or check [DEPLOYMENT.md](DEPLOYMENT.md)
