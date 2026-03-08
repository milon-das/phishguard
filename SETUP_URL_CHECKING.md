# PhishGuard - URL Checking Setup Guide

## 🎯 Overview

PhishGuard now has a **two-layer URL defense system**:

1. **VirusTotal API** - Primary defense (80+ security vendors)
2. **ML Model** - Secondary defense (98.17% accuracy)

The FastAPI backend handles both checks and provides a combined verdict.

---

## 📋 Prerequisites

- Python 3.8 or higher
- Flutter SDK
- VirusTotal API Key (free tier available)

---

## 🚀 Quick Start

### Step 1: Set Up the Backend

1. **Navigate to backend directory:**

   ```bash
   cd "d:\Documents\Flutter Project\flutter_application_2\backend"
   ```

2. **Install Python dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

3. **Start the backend server:**

   ```bash
   python main.py
   ```

   You should see:

   ```
   INFO:     Uvicorn running on http://0.0.0.0:8000
   INFO:     Application startup complete.
   ```

**✨ Note:** No need to set the VirusTotal API key in terminal! The backend automatically uses the key you've already stored in your Flutter app's Settings page. The app sends the key with each request.

### Step 2: Run the Flutter App

1. **Open a new terminal** (keep backend running)

2. **Navigate to project root:**

   ```bash
   cd "d:\Documents\Flutter Project\flutter_application_2"
   ```

3. **Run the Flutter app:**

   ```bash
   flutter run
   ```

   Or if you have multiple devices:

   ```bash
   flutter run -d windows
   ```

### Step 3: Test the URL Checker

1. **In the app:**
   - Click on "Check URL" button
   - Enter a URL (e.g., `https://google.com` for safe test)
   - Click "Check URL"
   - View the detailed results!

2. **Test with known phishing sites** (safely):
   - `http://phishing-test.com` (if exists)
   - Or use any suspicious URL you've received

---

## 🔧 Configuration

### Backend URL Setting

If your backend is running on a different address:

1. In the CheckURLPage, tap the **Settings icon** (⚙️) in top right
2. Enter your backend URL (e.g., `http://192.168.1.100:8000`)
3. Click Save

Default: `http://localhost:8000`

---

## 📊 How It Works

### Detection Flow:

1. **User enters URL** → Flutter app sends to FastAPI backend

2. **Backend Layer 1 - VirusTotal Check:**
   - Submits URL to VirusTotal API
   - Gets results from 80+ security vendors
   - If ≥3 vendors flag it → **Malicious**
   - If 1-2 vendors flag it → Continue to Layer 2

3. **Backend Layer 2 - ML Model:**
   - Extracts 25 handcrafted features from URL
   - Applies TF-IDF (character and word level)
   - Random Forest classifier predicts
   - Provides malicious probability

4. **Combined Verdict:**
   - High VT detections → Malicious
   - Moderate VT + High ML probability → Malicious
   - Low VT + High ML probability → Suspicious
   - Both agree it's safe → Safe

5. **Result sent back to Flutter app** with:
   - Verdict (Safe/Suspicious/Malicious)
   - Confidence score
   - Detailed breakdown
   - Method used

---

## 🧪 Testing Examples

### Test Safe URLs:

```
https://google.com
https://github.com
https://wikipedia.org
```

### Test Your Own URLs:

- Any suspicious email links
- Shortened URLs (bit.ly, tinyurl)
- URLs from unknown sources

---

## 🐛 Troubleshooting

### "Request timed out" or "Connection refused"

**Problem:** Backend not running or wrong URL

**Solution:**

1. Make sure backend is running: `python backend/main.py`
2. Check the terminal shows "Uvicorn running on..."
3. In app, go to Settings → verify Backend URL is `http://localhost:8000`

### "VirusTotal API unavailable"

**Problem:** API key not set or invalid

**Solution:**

1. Check your VT API key in the Flutter app: Settings → VirusTotal API Key
2. Get a free key from: https://www.virustotal.com/gui/my-apikey
3. Enter it in the app settings and save
4. The backend will automatically receive and use the key from your app
5. Note: The ML model will still work as fallback even without VT!

### Backend crashes on startup

**Problem:** Missing dependencies or model files

**Solution:**

1. Reinstall dependencies: `pip install -r requirements.txt`
2. Verify model files exist:
   - `model/unified_char_tfidf.pkl`
   - `model/unified_word_tfidf.pkl`
   - `model/unified_rf.pkl`
3. Verify src files exist:
   - `src/url_features.py`
   - `src/predict_url.py`

### "ModuleNotFoundError: No module named 'url_features'"

**Problem:** Python can't find the src module

**Solution:**
The backend/main.py automatically adds the src directory to the path. Make sure you're running from the backend directory:

```bash
cd backend
python main.py
```

---

## 📁 Project Structure

```
flutter_application_2/
├── backend/                    ← FastAPI backend
│   ├── main.py                ← Main API server
│   ├── requirements.txt       ← Python dependencies
│   ├── .env.example          ← API key template
│   └── README.md             ← Backend docs
│
├── model/                     ← Trained ML models
│   ├── unified_char_tfidf.pkl
│   ├── unified_word_tfidf.pkl
│   └── unified_rf.pkl
│
├── src/                       ← ML utility scripts
│   ├── url_features.py       ← Feature extraction
│   └── predict_url.py        ← Prediction script
│
└── lib/
    └── main.dart             ← Flutter app (with CheckURLPage)
```

---

## 🎓 API Documentation

Once backend is running, visit:

- **Interactive API docs:** http://localhost:8000/docs
- **Alternative docs:** http://localhost:8000/redoc
- **Health check:** http://localhost:8000/health

---

## 💡 Tips

1. **Free VirusTotal API** has rate limits:
   - 4 requests per minute
   - 500 requests per day
2. **Without VT API:**
   - The system still works!
   - Falls back to ML model only
   - Still provides accurate predictions

3. **For better results:**
   - Always use the full URL (including http:// or https://)
   - Test suspicious links in a safe environment
   - Check the confidence score

4. **Production deployment:**
   - Use environment variables for API keys
   - Deploy backend on a server (AWS, Heroku, etc.)
   - Update Flutter app's backend URL setting

---

## 🔒 Security Notes

- Never share your VirusTotal API key
- The backend logs errors but not sensitive data
- URLs checked are sent to VirusTotal (their privacy policy applies)
- ML model runs locally on your backend server

---

## ✅ Success Checklist

- [ ] Backend server running (`python backend/main.py`)
- [ ] VirusTotal API key configured (optional but recommended)
- [ ] Flutter app running (`flutter run`)
- [ ] Can access Check URL page in app
- [ ] Can enter URL and get results
- [ ] Results show both VT and ML analysis

---

## 📞 Need Help?

Check the error messages in:

1. **Backend terminal** - Shows API errors, model errors
2. **Flutter app** - Shows connection errors, UI issues
3. **Backend logs** - Check console output for detailed errors

Common log locations:

- Backend: Terminal where you ran `python main.py`
- Flutter: Terminal where you ran `flutter run`

---

## 🎉 You're All Set!

Your PhishGuard app now has enterprise-grade URL protection with dual-layer defense. Stay safe from phishing! 🛡️
