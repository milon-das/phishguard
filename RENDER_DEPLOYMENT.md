# Free Hosting Without Payment Method 🆓

Deploy PhishGuard ML backend **completely free** without credit card or payment method.

---

## 🌟 Best Option: Render.com

**Why Render:**

- ✅ No payment method required
- ✅ Deploy in 3 clicks from GitHub
- ✅ Free 750 hours/month
- ✅ Auto SSL certificate
- ✅ Auto deploys on git push

**Limitations:**

- Sleeps after 15 minutes of inactivity
- 30-second cold start when waking up
- Still better than no backend!

---

## 🚀 Deploy to Render (5 Minutes)

### Step 1: Push Code to GitHub

```bash
cd "D:/Documents/Flutter Project/flutter_application_2"

# Initialize git (if not done)
git init

# Create .gitignore
cat > .gitignore << 'EOF'
__pycache__/
*.py[cod]
venv/
.env
.dart_tool/
build/
.vscode/
.idea/
EOF

# Add files
git add .
git commit -m "PhishGuard ML Backend"

# Create repo on GitHub (do this first on github.com)
# Then connect:
git remote add origin https://github.com/YOUR_USERNAME/phishguard.git
git branch -M main
git push -u origin main
```

### Step 2: Deploy on Render

1. **Sign up:**
   - Go to [render.com](https://render.com)
   - Click **Get Started** → **Sign in with GitHub**
   - Authorize Render to access your repos

2. **Create Web Service:**
   - Click **New +** → **Web Service**
   - Connect your `phishguard` repository
   - Click **Connect**

3. **Configure Service:**

   **Basic Settings:**
   - **Name:** `phishguard-ml-backend`
   - **Region:** Singapore (or closest to your users)
   - **Branch:** `main`
   - **Root Directory:** `backend`

   **Build & Deploy:**
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`

   **Instance Type:**
   - Select **Free** (750 hours/month)

4. **Click "Create Web Service"**

5. **Wait 3-5 minutes** for deployment

6. **Your backend is live!**
   - URL: `https://phishguard-ml-backend.onrender.com`
   - Test: `https://phishguard-ml-backend.onrender.com/health`

### Step 3: Update Flutter App

Edit `lib/main.dart`:

```dart
// Around line 2500
String _backendUrl = 'https://phishguard-ml-backend.onrender.com';
```

---

## 🔥 Keep Backend Warm (Prevent Sleep)

Render free tier sleeps after 15 minutes. To keep it warm:

### Option 1: UptimeRobot (Free)

1. Sign up at [uptimerobot.com](https://uptimerobot.com)
2. Add Monitor:
   - **Type:** HTTP(s)
   - **URL:** `https://phishguard-ml-backend.onrender.com/health`
   - **Interval:** 5 minutes
3. It pings your backend every 5 minutes = stays warm!

### Option 2: Cron-job.org (Free)

1. Go to [cron-job.org](https://cron-job.org)
2. Create free account
3. Add cron job:
   - **URL:** Your Render URL + `/health`
   - **Interval:** Every 5 minutes
4. Enable job

### Option 3: GitHub Actions (Free)

Add `.github/workflows/keepalive.yml`:

```yaml
name: Keep Backend Alive

on:
  schedule:
    - cron: "*/5 * * * *" # Every 5 minutes
  workflow_dispatch: # Manual trigger

jobs:
  ping:
    runs-on: ubuntu-latest
    steps:
      - name: Ping Backend
        run: |
          curl -f https://phishguard-ml-backend.onrender.com/health || exit 0
```

---

## 🎯 Alternative Free Platforms

### Railway.app

**Pros:**

- No payment initially
- $5 free credit/month (~500 hours)
- Faster than Render
- No cold starts

**Cons:**

- Credit runs out if heavily used
- May ask for payment method eventually

**Deploy:**

1. Go to [railway.app](https://railway.app)
2. Sign in with GitHub
3. New Project → Deploy from GitHub repo
4. Select `phishguard` repo
5. Add start command: `cd backend && uvicorn main:app --host 0.0.0.0 --port $PORT`
6. Deploy!

---

### Fly.io

**Pros:**

- 3 free VMs
- No cold starts
- Global deployment

**Cons:**

- Requires CLI tool
- More complex setup

**Deploy:**

```bash
# Install flyctl (Windows PowerShell)
powershell -Command "iwr https://fly.io/install.ps1 -useb | iex"

# Or Git Bash/Mac/Linux
curl -L https://fly.io/install.sh | sh

# Login
fly auth login

# Deploy
cd "D:/Documents/Flutter Project/flutter_application_2/backend"
fly launch --name phishguard-ml
```

Follow prompts, choose free tier.

---

### PythonAnywhere

**Pros:**

- Absolutely no payment method
- Always on
- Web-based file editor

**Cons:**

- 100 CPU seconds/day limit
- Manual setup
- Good for testing only

**Deploy:**

1. Sign up at [pythonanywhere.com](https://www.pythonanywhere.com)
2. Go to **Files** → Upload your code
3. Open **Bash console**
4. Install dependencies:
   ```bash
   pip3.11 install --user -r requirements.txt
   ```
5. Go to **Web** → Add new web app
6. Choose **Manual configuration** → Python 3.11
7. Edit WSGI file:

   ```python
   import sys
   sys.path.append('/home/USERNAME/phishguard/backend')

   from main import app as application
   ```

8. Reload web app

URL: `https://USERNAME.pythonanywhere.com`

---

## 📊 Comparison Table

| Platform           | Payment Method | Free Tier    | Cold Starts  | Speed     | Best For        |
| ------------------ | -------------- | ------------ | ------------ | --------- | --------------- |
| **Render**         | ❌ Not needed  | 750h/month   | ✅ Yes (30s) | Fast      | **Recommended** |
| **Railway**        | ⚠️ Eventually  | $5/month     | ❌ No        | Very Fast | Heavy users     |
| **Fly.io**         | ❌ Not needed  | 3 VMs        | ❌ No        | Fast      | Advanced users  |
| **PythonAnywhere** | ❌ Not needed  | 100s CPU/day | ❌ No        | Slow      | Testing only    |

---

## 🎯 Recommended Setup

**For most users:** Use **Render + UptimeRobot**

1. Deploy backend on Render (free, no payment)
2. Set up UptimeRobot to ping every 5 minutes (keeps warm)
3. Update Flutter app with Render URL
4. Done!

**Total cost:** $0

**Uptime:** ~99% (30s wake-up time when cold)

---

## 🔧 Render.com Troubleshooting

### Backend not responding?

1. Check deploy logs on Render dashboard
2. Verify `backend/requirements.txt` exists
3. Check start command is correct:
   ```
   uvicorn main:app --host 0.0.0.0 --port $PORT
   ```

### Deploy failed?

Common issues:

- **Wrong Root Directory:** Should be `backend`
- **Missing requirements.txt:** Must be in `backend/` folder
- **Python version:** Render uses Python 3.11 by default

### Cold starts too slow?

- Set up UptimeRobot to keep warm
- Or upgrade to Render paid plan ($7/month, always on)
- Or use Railway.app instead

---

## 💡 Pro Tips

1. **Use environment variables** on Render:
   - Settings → Environment → Add Variable
   - Users still bring their own VT keys (no need to set)

2. **Monitor your app:**
   - Render dashboard shows logs, metrics, uptime
   - Free monitoring included

3. **Auto-deploys:**
   - Push to GitHub → Render auto-deploys
   - No manual updates needed!

4. **Custom domain (optional):**
   - Get free domain from Freenom
   - Add custom domain in Render settings
   - Free SSL certificate included

---

## 🎉 Success!

Once deployed on Render:

✅ Your ML backend is live and free  
✅ Auto-deploys on git push  
✅ Free SSL certificate (HTTPS)  
✅ No payment method required  
✅ Anyone can use your app worldwide

**Your backend URL:**

```
https://phishguard-ml-backend.onrender.com
```

**Test it:**

```bash
curl https://phishguard-ml-backend.onrender.com/health
```

**Update Flutter and ship your app! 🚀**

---

## 📚 Next Steps

1. Deploy to Render following steps above
2. Set up UptimeRobot to keep warm
3. Update Flutter app with Render URL
4. Test thoroughly
5. Publish to Play Store / App Store!

No payment method needed, completely free forever! 🎉
