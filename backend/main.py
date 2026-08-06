"""
PhishGuard FastAPI Backend - ML fallback only.

VirusTotal URL requests are performed directly by the Flutter application
using the user's own API key. This Render service performs only the local
machine-learning fallback when VirusTotal is unavailable or has no usable
report.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
import asyncio
import joblib
import os
import scipy.sparse as sp
from typing import Optional, Tuple, Dict

from url_features import extract_features_batch

app = FastAPI(
    title="PhishGuard ML Fallback API",
    version="2.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "HEAD"],
    allow_headers=["Content-Type"],
)

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
char_tfidf = joblib.load(
    os.path.join(MODEL_DIR, "PhiUSIIL_Phishing_URL_Dataset_char_tfidf.pkl")
)
word_tfidf = joblib.load(
    os.path.join(MODEL_DIR, "PhiUSIIL_Phishing_URL_Dataset_word_tfidf.pkl")
)
ml_model = joblib.load(
    os.path.join(MODEL_DIR, "PhiUSIIL_Phishing_URL_Dataset_rf.pkl")
)

print("=" * 80, flush=True)
print("PhishGuard ML fallback backend loaded", flush=True)
print("Model: PhiUSIIL Random Forest", flush=True)
print("Mode: ML fallback only; VirusTotal is called directly by Flutter", flush=True)
print("Training set: 235,370 unique URLs", flush=True)
print("=" * 80, flush=True)

MAX_URL_LENGTH = 2048
_MAX_CONCURRENT = 8
_active_requests = 0


class URLCheckRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("URL is required")
        if len(normalized) > MAX_URL_LENGTH:
            raise ValueError(
                f"URL exceeds maximum length of {MAX_URL_LENGTH} characters"
            )
        if not (
            normalized.startswith("http://")
            or normalized.startswith("https://")
        ):
            raise ValueError("URL must start with http:// or https://")
        return normalized


class URLCheckResponse(BaseModel):
    url: str
    verdict: str
    confidence: float
    vt_result: Optional[dict] = None
    ml_result: Optional[dict]
    method_used: str
    details: str


def check_ml_model(url: str) -> Optional[Dict]:
    """Run the trained URL classifier and return class probabilities."""
    try:
        normalized_url = url.strip().lower()
        lexical_features = extract_features_batch([normalized_url])
        character_features = char_tfidf.transform([normalized_url])
        word_features = word_tfidf.transform([normalized_url])
        numeric_features = sp.csr_matrix(lexical_features)
        feature_matrix = sp.hstack(
            [character_features, word_features, numeric_features]
        )

        prediction = ml_model.predict(feature_matrix)[0]
        probabilities = ml_model.predict_proba(feature_matrix)[0]

        malicious_probability = float(probabilities[1])
        benign_probability = float(probabilities[0])

        return {
            "prediction": "Malicious" if prediction == 1 else "Benign",
            "malicious_probability": malicious_probability,
            "benign_probability": benign_probability,
            "confidence": max(malicious_probability, benign_probability),
        }
    except Exception as error:
        print(
            f"[ML] Prediction failed: {type(error).__name__}: {error}",
            flush=True,
        )
        return None


def determine_ml_verdict(ml_result: Optional[Dict]) -> Tuple[str, float, str]:
    if ml_result is None:
        return (
            "Unknown",
            0.0,
            "The ML fallback could not analyze this URL.",
        )

    malicious_probability = ml_result.get("malicious_probability", 0.0)

    if malicious_probability > 0.70:
        return (
            "Malicious",
            malicious_probability,
            "The ML model detected high-risk URL patterns "
            f"with a malicious probability of {malicious_probability:.1%}.",
        )

    if malicious_probability > 0.50:
        return (
            "Suspicious",
            malicious_probability,
            "The ML model detected suspicious URL patterns "
            f"with a malicious probability of {malicious_probability:.1%}.",
        )

    return (
        "Safe",
        1.0 - malicious_probability,
        "The ML model found a low malicious-pattern probability "
        f"of {malicious_probability:.1%}.",
    )


@app.get("/")
async def root():
    return {
        "service": "PhishGuard ML Fallback API",
        "status": "running",
        "mode": "ml_fallback_only",
    }


@app.post("/check-url", response_model=URLCheckResponse)
async def check_url(request: URLCheckRequest):
    global _active_requests

    if _active_requests >= _MAX_CONCURRENT:
        raise HTTPException(
            status_code=503,
            detail="Server is busy. Please retry in a few seconds.",
            headers={"Retry-After": "10"},
        )

    _active_requests += 1
    try:
        print(
            f"[REQUEST] POST /check-url | url={request.url} | mode=ml_only",
            flush=True,
        )

        ml_result = await asyncio.to_thread(check_ml_model, request.url)
        verdict, confidence, details = determine_ml_verdict(ml_result)

        print(
            f"[REQUEST] Final result | method=ML Model | "
            f"verdict={verdict} | confidence={confidence:.4f}",
            flush=True,
        )

        return URLCheckResponse(
            url=request.url,
            verdict=verdict,
            confidence=confidence,
            vt_result=None,
            ml_result=ml_result,
            method_used="ML Model",
            details=details,
        )
    finally:
        _active_requests -= 1


@app.get("/health")
@app.head("/health")
async def health():
    return {
        "status": "healthy",
        "ml_model_loaded": ml_model is not None,
        "mode": "ml_fallback_only",
        "virus_total_handled_by": "flutter_client",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
