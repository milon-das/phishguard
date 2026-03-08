"""
PhishGuard FastAPI Backend
Integrates VirusTotal API (primary defense) and ML Model (secondary defense)
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
import requests
import os
import sys
import joblib
import scipy.sparse as sp
from typing import Optional
from datetime import datetime, timedelta
from collections import deque
import threading

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))
from url_features import extract_features_batch

app = FastAPI(title="PhishGuard API", version="1.0.0", docs_url=None, redoc_url=None, openapi_url=None)

# CORS middleware — restrict to mobile app traffic (no browser origin for mobile apps)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # Mobile apps don't send an Origin header; this is safe
    allow_credentials=False,
    allow_methods=["GET", "POST", "HEAD"],
    allow_headers=["Content-Type"],
)

# VirusTotal API Configuration
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
VIRUSTOTAL_URL_REPORT = "https://www.virustotal.com/api/v3/urls/{}"
VIRUSTOTAL_ANALYSIS_REPORT = "https://www.virustotal.com/api/v3/analyses/{}"

# Rate Limit Tracking (VirusTotal free tier: 4 requests per minute)
_rate_limit_lock = threading.Lock()
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


MAX_URL_LENGTH = 2048
VT_API_KEY_PATTERN_LEN = 64  # VT keys are exactly 64 hex chars


class URLCheckRequest(BaseModel):
    url: str
    vt_api_key: Optional[str] = None

    @field_validator('url')
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError('URL is required')
        if len(v) > MAX_URL_LENGTH:
            raise ValueError(f'URL exceeds maximum length of {MAX_URL_LENGTH} characters')
        if not (v.startswith('http://') or v.startswith('https://')):
            raise ValueError('URL must start with http:// or https://')
        return v

    @field_validator('vt_api_key')
    @classmethod
    def validate_vt_key(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v.strip() == '':
            return None
        v = v.strip()
        if len(v) != VT_API_KEY_PATTERN_LEN or not v.isalnum():
            raise ValueError('Invalid VirusTotal API key format')
        return v


class URLCheckResponse(BaseModel):
    url: str
    verdict: str  # "Safe", "Suspicious", "Malicious"
    confidence: float  # 0.0 to 1.0
    vt_result: Optional[dict]
    ml_result: Optional[dict]
    method_used: str  # "VirusTotal", "ML Model", "Combined"
    details: str


def check_rate_limit():
    """Check if rate limit is exceeded and clean old requests (thread-safe)"""
    global rate_limit_reset_time
    now = datetime.now()
    with _rate_limit_lock:
        while rate_limit_requests and (now - rate_limit_requests[0]) > timedelta(seconds=RATE_LIMIT_WINDOW):
            rate_limit_requests.popleft()
        if len(rate_limit_requests) >= RATE_LIMIT_MAX:
            if rate_limit_requests:
                rate_limit_reset_time = rate_limit_requests[0] + timedelta(seconds=RATE_LIMIT_WINDOW)
            return True
        rate_limit_reset_time = None
        return False


def add_request_to_rate_limit():
    """Record a new request timestamp (thread-safe)"""
    with _rate_limit_lock:
        rate_limit_requests.append(datetime.now())


def check_virustotal(url: str, api_key: Optional[str] = None):
    """
    Check URL with VirusTotal API
    Returns: dict with results, "RATE_LIMITED" string if rate limited, or None if API unavailable/failed
    """
    # Use provided API key or fall back to environment variable
    vt_key = api_key if api_key else VIRUSTOTAL_API_KEY
    
    if not vt_key:
        return None

    # Check rate limit before making request
    if check_rate_limit():
        return "RATE_LIMITED"

    add_request_to_rate_limit()
    
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
        
        if response.status_code == 429:
            return "RATE_LIMITED"
        elif response.status_code == 200:
            scan_data = response.json()
            analysis_id = scan_data.get("data", {}).get("id", "")
            if analysis_id:
                report_response = requests.get(
                    VIRUSTOTAL_ANALYSIS_REPORT.format(analysis_id),
                    headers={"x-apikey": vt_key},
                    timeout=10
                )
                if report_response.status_code == 200:
                    report_data = report_response.json()
                    stats = report_data.get("data", {}).get("attributes", {}).get("stats", {})
                    results = report_data.get("data", {}).get("attributes", {}).get("results", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)
                    total = malicious + suspicious + harmless + undetected
                    flagged_vendors = [
                        {"vendor": vendor, "category": r.get("category"), "result": r.get("result", "malicious")}
                        for vendor, r in results.items()
                        if r.get("category") in ("malicious", "suspicious")
                    ]
                    return {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": harmless,
                        "undetected": undetected,
                        "total": total,
                        "detection_rate": f"{malicious + suspicious}/{total}",
                        "flagged_vendors": flagged_vendors,
                    }
        return None
    except Exception:
        return None


def check_ml_model(url: str):
    """
    Check URL with ML Model
    Returns: dict with prediction and probability
    """
    try:
        url_lower = url.strip().lower()
        features = extract_features_batch([url_lower])
        x_char = char_tfidf.transform([url_lower])
        x_word = word_tfidf.transform([url_lower])
        x_feat = sp.csr_matrix(features)
        x = sp.hstack([x_char, x_word, x_feat])
        pred = ml_model.predict(x)[0]
        prob = ml_model.predict_proba(x)[0]
        malicious_prob = float(prob[1])
        benign_prob = float(prob[0])
        return {
            "prediction": "Malicious" if pred == 1 else "Benign",
            "malicious_probability": malicious_prob,
            "benign_probability": benign_prob,
            "confidence": max(malicious_prob, benign_prob),
        }
    except Exception:
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
    return {"service": "PhishGuard API", "status": "running"}


@app.post("/check-url", response_model=URLCheckResponse)
async def check_url(request: URLCheckRequest):
    """
    Check URL using two-layer defense:
    1. VirusTotal API (primary)
    2. ML Model (secondary/fallback)
    """
    url = request.url  # already validated and stripped by pydantic

    # Layer 1: VirusTotal Check (PRIMARY)
    vt_result = check_virustotal(url, request.vt_api_key)

    is_rate_limited = (vt_result == "RATE_LIMITED")
    if is_rate_limited:
        vt_result = None

    # Layer 2: ML Model Check (fallback)
    ml_result = None
    should_use_ml = (
        vt_result is None or
        (isinstance(vt_result, dict) and vt_result.get('total', 0) == 0)
    )

    if should_use_ml:
        ml_result = check_ml_model(url)
        if vt_result and vt_result.get('total', 0) == 0:
            vt_result = None

    # Determine final verdict
    verdict, confidence, method, details = determine_verdict(vt_result, ml_result)
    
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
@app.head("/health")
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
