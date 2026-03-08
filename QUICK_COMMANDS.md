# PhishGuard - Quick Command Reference

## 🚀 Starting the System

### Start Backend (Terminal 1)

```bash
cd "d:\Documents\Flutter Project\flutter_application_2\backend"
python main.py
```

**💡 Note:** No need to set VT API key in terminal! The app automatically uses the key already stored in your Flutter app settings.

### Start Flutter App (Terminal 2)

```bash
cd "d:\Documents\Flutter Project\flutter_application_2"
flutter run
```

### 🌐 Optional: Use Ngrok for Remote Access (Terminal 3)

```bash
# First time only: Configure your auth token from https://dashboard.ngrok.com
ngrok config add-authtoken YOUR_TOKEN

# Start tunnel (keep running)
ngrok http 8000
```

Then copy the HTTPS URL (e.g., `https://abc123.ngrok-free.app`) and update in:  
**App → Check URL → ⚙️ Settings → Enter URL → Save**

📖 **Full Ngrok Guide:** See [NGROK_SETUP.md](NGROK_SETUP.md)

---

## 🧪 Testing

### Test Backend

```bash
cd backend
python test_backend.py
```

### Test Individual URL via Command Line

```bash
cd "d:\Documents\Flutter Project\flutter_application_2"
python src/predict_url.py
# Then enter a URL when prompted
```

### Test via API (using curl)

```bash
# Health check
curl http://localhost:8000/health

# Check URL
curl -X POST http://localhost:8000/check-url ^
  -H "Content-Type: application/json" ^
  -d "{\"url\": \"https://google.com\"}"
```

---

## 📦 Installation Commands

### First Time Setup

```bash
# Backend dependencies
cd backend
pip install -r requirements.txt

# Flutter dependencies (if needed)
cd ..
flutter pub get
```

---

## 🛠️ Common Tasks

### Update Backend URL in App

1. Open app
2. Go to "Check URL"
3. Tap ⚙️ (Settings icon)
4. Enter new URL (e.g., `http://localhost:8000` or ngrok URL)
5. Save

### Update VirusTotal API Key

1. Open app
2. Go to "Settings" (home screen, top right)
3. Find "VirusTotal API Key" field
4. Enter your new API key
5. Save

**The backend automatically uses the key from your app!** ✨

- http://localhost:8000/docs
- http://localhost:8000/redoc

---

## 🔍 Debugging

### Check Backend Status

```bash
curl http://localhost:8000/health
```

### Check Backend Logs

Look at the terminal where you ran `python main.py`

### Check Flutter Logs

Look at the terminal where you ran `flutter run`

### Restart Everything

```bash
# Stop both terminals (Ctrl+C)
# Then restart:

# Terminal 1
cd backend
python main.py

# Terminal 2
cd ..
flutter run
```

---

## 📊 Test URLs

### Safe URLs:

- https://www.google.com
- https://github.com
- https://wikipedia.org

### Suspicious Patterns (ML will detect):

- http://192.168.1.1/login.php?verify=true
- http://paypal-verify.suspicious-domain.tk
- http://account-update-required.xyz/signin

---

## 🎯 Checklist

Before using the app:

- [ ] Backend running (`python backend/main.py`)
- [ ] See "Uvicorn running on http://0.0.0.0:8000" message
- [ ] VT API key set in app settings (optional but recommended)
- [ ] Flutter app running (`flutter run`)
- [ ] If using remote access: Ngrok tunnel running
- [ ] Test with `python backend/test_backend.py`

---

## 💡 Pro Tips

1. **Keep backend running** in a separate terminal
2. **Check backend terminal** for error messages
3. **VT API key** is automatically sent from app to backend (no terminal setup needed!)
4. **VT API rate limit:** 4 requests/minute (free tier)
5. **Without VT key:** ML model still works as fallback
6. **Test first** with known safe URLs like google.com
7. **Use Ngrok** to access backend from phone/other devices ([guide](NGROK_SETUP.md))

---

## 🆘 Quick Fixes

### "Connection refused"

→ Start backend: `python backend/main.py`

### "Module not found"

→ Install deps: `pip install -r backend/requirements.txt`

### "VT API error"

→ Check API key in app: Settings → VirusTotal API Key field  
→ Backend will automatically use the key from your app  
→ If no key set, ML model will work as fallback

### "Timeout"

→ Backend might be slow on first request (loading models)  
→ Wait 30 seconds and try again

### "Ngrok connection issues"

→ See [NGROK_SETUP.md](NGROK_SETUP.md) for troubleshooting  
→ Make sure both backend and ngrok are running  
→ Use HTTPS URL (not HTTP) from ngrok
