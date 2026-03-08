# 🌐 Ngrok Setup Guide - Access Backend from Anywhere

This guide shows you how to use **ngrok** to expose your local FastAPI backend to the internet, allowing your Flutter app on any device (phone, tablet, other computers) to connect to your PC's backend.

---

## 📖 What is Ngrok?

Ngrok creates a secure tunnel from a public URL to your localhost, letting you:

- Test your app on real devices (Android/iOS phones)
- Share your backend with others
- Access from anywhere without complex router/firewall setup
- Get HTTPS automatically

---

## 🚀 Step-by-Step Setup

### Step 1: Install Ngrok

#### Option A: Download from Website (Recommended)

1. Go to: https://ngrok.com/download
2. Click **"Download for Windows"**
3. Extract the `ngrok.exe` file to a folder like:
   - `C:\ngrok\ngrok.exe`
   - Or `D:\Tools\ngrok.exe`

#### Option B: Using Chocolatey (if you have it)

```cmd
choco install ngrok
```

#### Option C: Using Scoop (if you have it)

```cmd
scoop install ngrok
```

---

### Step 2: Create Ngrok Account (Free)

1. Go to: https://dashboard.ngrok.com/signup
2. Sign up with email or GitHub
3. Confirm your email
4. You'll get a free account with:
   - 1 agent online
   - 40 connections/minute
   - Random URLs (changes each restart)

---

### Step 3: Get Your Auth Token

1. After signup, go to: https://dashboard.ngrok.com/get-started/your-authtoken
2. Copy your authtoken (looks like: `2abcDEF_1234567890ghijklmnop`)
3. Keep this safe - you'll need it once

---

### Step 4: Configure Ngrok

Open Command Prompt and run:

```cmd
cd C:\ngrok
ngrok config add-authtoken YOUR_AUTH_TOKEN_HERE
```

Replace `YOUR_AUTH_TOKEN_HERE` with your actual token from Step 3.

**Example:**

```cmd
cd C:\ngrok
ngrok config add-authtoken 2abcDEF_1234567890ghijklmnop
```

You should see: `Authtoken saved to configuration file`

---

### Step 5: Start Your Backend

Open **Terminal 1** (keep this running):

```cmd
cd "d:\Documents\Flutter Project\flutter_application_2\backend"
python main.py
```

Wait until you see:

```
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete.
```

✅ Keep this terminal open!

---

### Step 6: Start Ngrok Tunnel

Open **Terminal 2** (new Command Prompt):

```cmd
cd C:\ngrok
ngrok http 8000
```

Or if ngrok is in your PATH:

```cmd
ngrok http 8000
```

---

### Step 7: Get Your Ngrok URL

You'll see something like this:

```
ngrok

Session Status                online
Account                       Your Name (Plan: Free)
Version                       3.x.x
Region                        United States (us)
Latency                       23ms
Web Interface                 http://127.0.0.1:4040
Forwarding                    https://abc123.ngrok-free.app -> http://localhost:8000

Connections                   ttl     opn     rt1     rt5     p50     p90
                              0       0       0.00    0.00    0.00    0.00
```

**🎯 Your public URL is the "Forwarding" HTTPS address!**

Example: `https://abc123.ngrok-free.app`

✅ Copy this URL - you'll use it in your Flutter app!

---

## 📱 Configure Flutter App

### Method 1: Using App Settings (Recommended)

1. Open your PhishGuard app
2. Go to **"Check URL"**
3. Tap the ⚙️ **Settings icon** (top right)
4. Enter your ngrok URL: `https://abc123.ngrok-free.app`
5. Click **Save**
6. Try checking a URL!

### Method 2: Manual Code Update

Edit `lib/main.dart` and change the default URL:

```dart
String _backendUrl = 'https://abc123.ngrok-free.app'; // Your ngrok URL
```

---

## 🧪 Test Your Setup

### Test 1: Check Backend Through Ngrok

Open browser and visit: `https://abc123.ngrok-free.app/health`

You should see:

```json
{
  "status": "healthy",
  "ml_model_loaded": true,
  "vt_api_configured": false
}
```

### Test 2: Check from Your Phone

1. Make sure your phone has the app installed
2. Update the backend URL in app settings (see above)
3. Try checking a URL like `https://google.com`
4. Should see results with VT + ML analysis!

---

## 💡 Important Notes

### Ngrok URLs Change on Restart

Every time you restart ngrok (free plan), you get a **new random URL**:

- First time: `https://abc123.ngrok-free.app`
- After restart: `https://xyz789.ngrok-free.app` (different!)

**Solution:** Update the URL in your app each time you restart ngrok

### Keep Both Terminals Running

You need BOTH running simultaneously:

1. **Terminal 1:** Backend (`python main.py`)
2. **Terminal 2:** Ngrok (`ngrok http 8000`)

### Free Plan Limitations

- Random URLs (change on restart)
- 40 connections/minute
- Sleep timeout after inactivity

**To get a fixed URL:** Upgrade to paid plan ($8/month)

### Ngrok Warning Page

First-time visitors may see an ngrok warning page:

- Click **"Visit Site"** to continue
- This is normal for free ngrok URLs
- Won't appear with paid plan

---

## 🎯 Complete Workflow

### Every Time You Work on Your App:

1. **Start Backend:**

   ```cmd
   cd "d:\Documents\Flutter Project\flutter_application_2\backend"
   python main.py
   ```

2. **Start Ngrok (new terminal):**

   ```cmd
   cd C:\ngrok
   ngrok http 8000
   ```

3. **Copy the HTTPS URL** from ngrok output

4. **Update Flutter app:**
   - Open app → Check URL → Settings ⚙️
   - Enter the ngrok URL
   - Save

5. **Test it!** Try checking a URL

---

## 🔧 Advanced Tips

### Local Testing Still Works

Even with ngrok running, you can still use `http://localhost:8000` on the same PC.

### View Request Logs

Ngrok provides a web interface at: `http://127.0.0.1:4040`

- See all incoming requests
- Inspect request/response data
- Debug issues

### Run Ngrok in Background

To see less output:

```cmd
ngrok http 8000 --log=stdout > ngrok.log
```

### Use Config File for Easier Startup

Create `C:\ngrok\ngrok.yml`:

```yaml
version: "2"
authtoken: YOUR_AUTH_TOKEN
tunnels:
  phishguard:
    proto: http
    addr: 8000
```

Then run:

```cmd
ngrok start phishguard
```

---

## 🐛 Troubleshooting

### "Failed to connect to ngrok"

❌ **Problem:** Ngrok not running or wrong port

✅ **Solution:**

1. Make sure backend is running on port 8000
2. Restart ngrok: `ngrok http 8000`

### "Bad Gateway" or 502 Error

❌ **Problem:** Backend not running

✅ **Solution:**

1. Check Terminal 1 - is backend running?
2. Restart backend: `python backend/main.py`

### "Could not connect to localhost:8000"

❌ **Problem:** Backend crashed or wrong port

✅ **Solution:**

1. Check backend terminal for errors
2. Make sure it says "Uvicorn running on http://0.0.0.0:8000"

### "ERR_NGROK_3004"

❌ **Problem:** Auth token not configured

✅ **Solution:**

```cmd
ngrok config add-authtoken YOUR_TOKEN
```

### Flutter App Can't Reach Backend

❌ **Problem:** Wrong URL or HTTPS issue

✅ **Solution:**

1. Use HTTPS URL (not HTTP): `https://abc123.ngrok-free.app`
2. Don't include `/` at the end
3. Check URL in app settings

---

## 🎓 Common Commands Reference

### Start Backend

```cmd
cd "d:\Documents\Flutter Project\flutter_application_2\backend"
python main.py
```

### Start Ngrok

```cmd
ngrok http 8000
```

### Stop Ngrok

Press `Ctrl + C` in the ngrok terminal

### Check Ngrok Status

Visit: http://127.0.0.1:4040

### Update Backend URL in App

App → Check URL → ⚙️ Settings → Enter URL → Save

---

## 📊 Architecture When Using Ngrok

```
Flutter App (Your Phone)
        ↓ HTTPS
Ngrok Cloud (Public URL)
        ↓ Tunnel
Ngrok Client (Your PC)
        ↓ HTTP
FastAPI Backend (localhost:8000)
        ↓
Machine Learning Models + VirusTotal API
```

---

## 🔒 Security Notes

✅ **Safe:**

- Ngrok encrypts traffic with HTTPS
- Your auth token is private
- Close tunnel when not needed

⚠️ **Be Careful:**

- Don't share your ngrok URL publicly
- Anyone with the URL can access your backend
- Free URLs expire/change frequently
- Not recommended for production

---

## 💰 Upgrade Options (Optional)

### Free Plan:

- ✅ Perfect for testing
- ✅ Works for development
- ❌ Random URLs
- ❌ No custom domains

### Paid Plans ($8+/month):

- ✅ Fixed URLs (same every time)
- ✅ Custom domains
- ✅ No warning page
- ✅ More connections
- ✅ Better performance

Get it at: https://ngrok.com/pricing

---

## ✅ Quick Checklist

Before running your app remotely:

- [ ] Backend installed: `pip install -r requirements.txt`
- [ ] Ngrok downloaded and auth token configured
- [ ] Backend running: `python backend/main.py`
- [ ] Ngrok running: `ngrok http 8000`
- [ ] Copied HTTPS URL from ngrok
- [ ] Updated URL in Flutter app settings
- [ ] Tested with a safe URL (google.com)

---

## 🎉 Success!

Once everything is running:

1. ✅ Backend on your PC (Terminal 1)
2. ✅ Ngrok tunnel active (Terminal 2)
3. ✅ Flutter app connected via ngrok URL
4. ✅ Can check URLs from anywhere!

Your PhishGuard backend is now accessible from any device, anywhere in the world! 🌍

---

## 📞 Need Help?

Common checks:

1. Both terminals still running?
2. Ngrok URL starts with `https://`?
3. Backend URL in app matches ngrok URL exactly?
4. Try the URL in a web browser first: `https://your-url.ngrok-free.app/health`

If browser works but app doesn't:

- Check app's backend URL setting
- Make sure you saved the URL
- Restart the Flutter app
