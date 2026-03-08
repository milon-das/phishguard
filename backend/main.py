"""
PhishGuard FastAPI Backend
Integrates VirusTotal API (primary defense) and ML Model (secondary defense)
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
import requests
import os
import sys
import joblib
import scipy.sparse as sp
from typing import Optional
from datetime import datetime, timedelta
from collections import deque
from datetime import datetime, timedelta
from collections import deque

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))
from url_features import extract_features_batch

app = FastAPI(title="PhishGuard API", version="1.0.0")

# CORS middleware for Flutter app
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# VirusTotal API Configuration
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
VIRUSTOTAL_URL_REPORT = "https://www.virustotal.com/api/v3/urls/{}"
VIRUSTOTAL_ANALYSIS_REPORT = "https://www.virustotal.com/api/v3/analyses/{}"

# Rate Limit Tracking (VirusTotal free tier: 4 requests per minute)
rate_limit_requests = deque()  # Store timestamps of requests
RATE_LIMIT_MAX = 4  # Max requests per minute
RATE_LIMIT_WINDOW = 60  # Time window in seconds
rate_limit_reset_time = None  # When the rate limit will reset

# Rate Limit Tracking (VirusTotal free tier: 4 requests per minute)
rate_limit_requests = deque()  # Store timestamps of requests
RATE_LIMIT_MAX = 4  # Max requests per minute
RATE_LIMIT_WINDOW = 60  # Time window in seconds
rate_limit_reset_time = None  # When the rate limit will reset

# Load ML Models - Using PhiUSIIL (best performance: 99.78% accuracy, 0.44% false positive rate)
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'models')
char_tfidf = joblib.load(os.path.join(MODEL_DIR, "PhiUSIIL_Phishing_URL_Dataset_char_tfidf.pkl"))
word_tfidf = joblib.load(os.path.join(MODEL_DIR, "PhiUSIIL_Phishing_URL_Dataset_word_tfidf.pkl"))
ml_model = joblib.load(os.path.join(MODEL_DIR, "PhiUSIIL_Phishing_URL_Dataset_rf.pkl"))

print("=" * 80)
print("PhishGuard Backend - ML Model Loaded")
print("=" * 80)
print(f"Model: PhiUSIIL Phishing URL Dataset")
print(f"Performance: 99.78% accuracy, 0.44% false positive rate")
print(f"Training: 235,370 URLs (134,850 malicious, 100,520 benign)")
print("=" * 80)


class URLCheckRequest(BaseModel):
    url: str
    vt_api_key: Optional[str] = None  # Optional: Use API key from Flutter app


class URLCheckResponse(BaseModel):
    url: str
    verdict: str  # "Safe", "Suspicious", "Malicious"
    confidence: float  # 0.0 to 1.0
    vt_result: Optional[dict]
    ml_result: Optional[dict]
    method_used: str  # "VirusTotal", "ML Model", "Combined"
    details: str


def check_rate_limit():
    """Check if rate limit is exceeded and clean old requests"""
    global rate_limit_reset_time
    now = datetime.now()
    
    # Remove requests older than the time window
    while rate_limit_requests and (now - rate_limit_requests[0]) > timedelta(seconds=RATE_LIMIT_WINDOW):
        rate_limit_requests.popleft()
    
    # Check if rate limit exceeded
    if len(rate_limit_requests) >= RATE_LIMIT_MAX:
        # Set reset time to when the oldest request expires
        if rate_limit_requests:
            oldest_request = rate_limit_requests[0]
            rate_limit_reset_time = oldest_request + timedelta(seconds=RATE_LIMIT_WINDOW)
        return True  # Rate limit exceeded
    
    rate_limit_reset_time = None
    return False  #OK to proceed

def add_request_to_rate_limit():
    """Record a new request timestamp"""
    rate_limit_requests.append(datetime.now())


def check_virustotal(url: str, api_key: Optional[str] = None):
    """
    Check URL with VirusTotal API
    Returns: dict with results, "RATE_LIMITED" string if rate limited, or None if API unavailable/failed
    """
    # Use provided API key or fall back to environment variable
    vt_key = api_key if api_key else VIRUSTOTAL_API_KEY
    
    if not vt_key or vt_key == "":
        print(f"[DEBUG] VT API key not provided - skipping VT check")
        return None
    
    # Check rate limit before making request
    if check_rate_limit():
        print(f"[WARNING] VirusTotal rate limit exceeded (4 requests/minute)")
        return "RATE_LIMITED"
    
    print(f"[DEBUG] Checking URL with VirusTotal: {url}")
    add_request_to_rate_limit()  # Record this request
    
    headers = {
        "x-apikey": vt_key,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    try:
        # Submit URL for scanning
        response = requests.post(
            VIRUSTOTAL_URL_SCAN,
            headers=headers,
            data={"url": url},
            timeout=10
        )
        
        print(f"[DEBUG] VT scan response status: {response.status_code}")
        
        if response.status_code == 429:
            print(f"[WARNING] VirusTotal rate limit exceeded (429 response)")
            return "RATE_LIMITED"
        elif response.status_code == 200:
            scan_data = response.json()
            # Get the analysis ID from the scan response
            analysis_id = scan_data.get("data", {}).get("id", "")
            
            print(f"[DEBUG] VT Analysis ID: {analysis_id}")
            
            if analysis_id:
                # Get analysis results using the analysis endpoint
                report_response = requests.get(
                    VIRUSTOTAL_ANALYSIS_REPORT.format(analysis_id),
                    headers={"x-apikey": vt_key},
                    timeout=10
                )
                
                print(f"[DEBUG] VT report fetch status: {report_response.status_code}")
                
                print(f"[DEBUG] VT report fetch status: {report_response.status_code}")
                
                if report_response.status_code == 200:
                    report_data = report_response.json()
                    # Get stats from the analysis response
                    stats = report_data.get("data", {}).get("attributes", {}).get("stats", {})
                    results = report_data.get("data", {}).get("attributes", {}).get("results", {})
                    
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)
                    total = malicious + suspicious + harmless + undetected
                    
                    # Extract which vendors flagged it
                    flagged_vendors = []
                    for vendor, result in results.items():
                        category = result.get("category", "")
                        if category in ["malicious", "suspicious"]:
                            flagged_vendors.append({
                                "vendor": vendor,
                                "category": category,
                                "result": result.get("result", "malicious")
                            })
                    
                    print(f"[DEBUG] VT Results - Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}, Total: {total}")
                    print(f"[DEBUG] Flagged by {len(flagged_vendors)} vendors: {[v['vendor'] for v in flagged_vendors[:5]]}")
                    
                    return {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": harmless,
                        "undetected": undetected,
                        "total": total,
                        "detection_rate": f"{malicious + suspicious}/{total}",
                        "flagged_vendors": flagged_vendors  # List of vendors that flagged it
                    }
                else:
                    print(f"[DEBUG] VT report fetch failed: {report_response.status_code}")
                    print(f"[DEBUG] VT error response: {report_response.text}")
        
        return None
    except Exception as e:
        print(f"VirusTotal API Error: {e}")
        return None


def check_ml_model(url: str):
    """
    Check URL with ML Model
    Returns: dict with prediction and probability
    """
    try:
        url_lower = url.strip().lower()
        
        # Extract features
        features = extract_features_batch([url_lower])
        print(f"[DEBUG] Extracted features for URL: {features[0][:10]}... (showing first 10 of 25)")
        
        x_char = char_tfidf.transform([url_lower])
        x_word = word_tfidf.transform([url_lower])
        x_feat = sp.csr_matrix(features)
        
        # Combine features and predict
        x = sp.hstack([x_char, x_word, x_feat])
        pred = ml_model.predict(x)[0]
        prob = ml_model.predict_proba(x)[0]
        
        malicious_prob = float(prob[1])
        benign_prob = float(prob[0])
        
        print(f"[DEBUG] ML Model - Prediction: {'Malicious' if pred == 1 else 'Benign'}, Malicious Prob: {malicious_prob:.2%}, Benign Prob: {benign_prob:.2%}")
        
        return {
            "prediction": "Malicious" if pred == 1 else "Benign",
            "malicious_probability": malicious_prob,
            "benign_probability": benign_prob,
            "confidence": max(malicious_prob, benign_prob)
        }
    except Exception as e:
        print(f"ML Model Error: {e}")
        return None


def determine_verdict(vt_result, ml_result):
    """
    Simplified verdict logic - NO mixing of VT and ML decisions
    
    Priority 1: If VirusTotal has results, use VT ONLY
      - Any flags (1+): Suspicious or Malicious based on count
      - No flags: Safe
    
    Priority 2: If VT unavailable, use ML Model ONLY
      - High probability: Malicious
      - Medium probability: Suspicious  
      - Low probability: Safe
    """
    verdict = "Unknown"
    confidence = 0.0
    method = "Unknown"
    details = ""
    
    # PRIORITY 1: VirusTotal (if available AND has actual results, use VT ONLY - ignore ML)
    if vt_result:
        malicious = vt_result.get("malicious", 0)
        suspicious = vt_result.get("suspicious", 0)
        total = vt_result.get("total", 0)
        flagged = malicious + suspicious
        
        # If no vendors analyzed it (not in VT database), treat as VT unavailable - fall back to ML
        if total == 0:
            pass  # Skip VT, fall through to ML check below
        
        # If 3+ vendors flagged: MALICIOUS
        elif flagged >= 3:
            verdict = "Malicious"
            confidence = 1.0  # VT gives definitive answers
            method = "VirusTotal"
            details = f"{flagged} out of {total} security vendors flagged this URL."
            return verdict, confidence, method, details
        
        # If 1-2 vendors flagged: SUSPICIOUS
        elif flagged >= 1:
            verdict = "Suspicious"
            confidence = 1.0  # VT gives definitive answers
            method = "VirusTotal"
            details = f"{flagged} out of {total} security vendors flagged this URL."
            return verdict, confidence, method, details
        
        # If 0 vendors flagged: SAFE
        elif total > 0:
            verdict = "Safe"
            confidence = 1.0  # VT gives definitive answers
            method = "VirusTotal"
            details = f"No threats detected by {total} security vendors."
            return verdict, confidence, method, details
    
    # PRIORITY 2: ML Model (used if VT unavailable or returned 0/0)
    if ml_result:
        ml_prob = ml_result.get("malicious_probability", 0)
        
        # High risk: MALICIOUS
        if ml_prob > 0.7:
            verdict = "Malicious"
            confidence = ml_prob
            method = "ML Model"
            details = f"ML model detected high-risk patterns with {ml_prob:.1%} confidence."
        
        # Medium risk: SUSPICIOUS
        elif ml_prob > 0.5:
            verdict = "Suspicious"
            confidence = ml_prob
            method = "ML Model"
            details = f"ML model detected suspicious patterns with {ml_prob:.1%} confidence."
        
        # Low risk: SAFE
        else:
            verdict = "Safe"
            confidence = 1.0 - ml_prob
            method = "ML Model"
            details = f"ML model found no significant threats (malicious probability: {ml_prob:.1%})."
    
    # Neither VT nor ML available
    else:
        verdict = "Unknown"
        confidence = 0.0
        method = "None"
        details = "Unable to analyze URL. Both VirusTotal API and ML model unavailable."
    
    return verdict, confidence, method, details


@app.get("/")
async def root():
    return {
        "service": "PhishGuard API",
        "version": "1.0.0",
        "status": "running",
        "ml_model": "PhiUSIIL (99.78% accuracy, 0.44% FPR)",
        "vt_api_available": bool(VIRUSTOTAL_API_KEY)
    }


@app.post("/check-url", response_model=URLCheckResponse)
async def check_url(request: URLCheckRequest):
    """
    Check URL using two-layer defense:
    1. VirusTotal API (primary)
    2. ML Model (secondary/fallback)
    """
    url = request.url.strip()
    
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    
    print(f"\n[DEBUG] === NEW URL CHECK REQUEST ===")
    print(f"[DEBUG] URL: {url}")
    print(f"[DEBUG] VT API Key provided in request: {bool(request.vt_api_key)}")
    
    # Layer 1: VirusTotal Check (PRIMARY)
    vt_result = check_virustotal(url, request.vt_api_key)
    print(f"[DEBUG] VT Result: {vt_result}")
    
    # Check if rate limited
    is_rate_limited = (vt_result == "RATE_LIMITED")
    if is_rate_limited:
        vt_result = None  # Treat as unavailable
    
    # Layer 2: ML Model Check (used if VT unavailable, rate limited, or returned 0/0)
    ml_result = None
    should_use_ml = (
        vt_result is None or 
        (isinstance(vt_result, dict) and vt_result.get('total', 0) == 0)
    )
    
    if should_use_ml:
        if is_rate_limited:
            print(f"[DEBUG] VT rate limited, falling back to ML model")
        elif vt_result is None:
            print(f"[DEBUG] VT unavailable, falling back to ML model")
        else:
            print(f"[DEBUG] VT returned 0/0 (URL not scanned), falling back to ML model")
        ml_result = check_ml_model(url)
        print(f"[DEBUG] ML Result: {ml_result}")
        # Clear VT result if it was 0/0 so verdict logic uses ML only
        if vt_result and vt_result.get('total', 0) == 0:
            vt_result = None
    else:
        print(f"[DEBUG] VT result available with {vt_result.get('total', 0)} vendors, skipping ML model")
    
    # Determine final verdict
    verdict, confidence, method, details = determine_verdict(vt_result, ml_result)
    print(f"[DEBUG] Final Verdict: {verdict}, Method: {method}, Confidence: {confidence:.2%}")
    print(f"[DEBUG] === END REQUEST ===\n")
    
    return URLCheckResponse(
        url=url,
        verdict=verdict,
        confidence=confidence,
        vt_result=vt_result,
        ml_result=ml_result,
        method_used=method,
        details=details
    )


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "ml_model_loaded": ml_model is not None,
        "vt_api_configured": bool(VIRUSTOTAL_API_KEY)
    }


@app.get("/rate-limit-status")
async def rate_limit_status():
    """Check current rate limit status"""
    now = datetime.now()
    
    # Clean old requests
    while rate_limit_requests and (now - rate_limit_requests[0]) > timedelta(seconds=RATE_LIMIT_WINDOW):
        rate_limit_requests.popleft()
    
    requests_used = len(rate_limit_requests)
    requests_remaining = max(0, RATE_LIMIT_MAX - requests_used)
    is_limited = requests_used >= RATE_LIMIT_MAX
    
    # Calculate time until reset
    seconds_until_reset = 0
    if is_limited and rate_limit_requests:
        oldest_request = rate_limit_requests[0]
        reset_time = oldest_request + timedelta(seconds=RATE_LIMIT_WINDOW)
        seconds_until_reset = max(0, int((reset_time - now).total_seconds()))
    
    return {
        "rate_limited": is_limited,
        "requests_used": requests_used,
        "requests_remaining": requests_remaining,
        "max_requests": RATE_LIMIT_MAX,
        "window_seconds": RATE_LIMIT_WINDOW,
        "seconds_until_reset": seconds_until_reset
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
