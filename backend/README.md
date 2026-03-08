# PhishGuard Backend API

FastAPI backend for URL analysis with two-layer defense:

1. **VirusTotal API** (Primary Defense)
2. **ML Model** (Secondary Defense)

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure VirusTotal API

1. Get your free API key from: https://www.virustotal.com/gui/my-apikey
2. Create a `.env` file in this directory:

```
VIRUSTOTAL_API_KEY=your_actual_api_key
```

### 3. Run the Server

```bash
# Development mode
python main.py

# Production mode
uvicorn main:app --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`

## API Endpoints

### POST /check-url

Check a URL for phishing/malicious content

**Request:**

```json
{
  "url": "https://example.com"
}
```

**Response:**

```json
{
  "url": "https://example.com",
  "verdict": "Safe",
  "confidence": 0.95,
  "vt_result": {
    "malicious": 0,
    "suspicious": 0,
    "harmless": 75,
    "undetected": 5,
    "total": 80,
    "detection_rate": "0/80"
  },
  "ml_result": {
    "prediction": "Benign",
    "malicious_probability": 0.05,
    "benign_probability": 0.95,
    "confidence": 0.95
  },
  "method_used": "Combined (VT + ML)",
  "details": "No threats detected by 80 security vendors. ML model confirms safety (malicious probability: 5.00%)."
}
```

### GET /health

Check API health status

### GET /

API information

## Verdict Logic

1. **If ≥3 VT engines flag as malicious** → Verdict: **Malicious**
2. **If 1-2 VT engines flag** → Check ML model:
   - ML probability >70% → **Malicious**
   - ML probability ≤70% → **Suspicious**
3. **If VT clean but ML probability >85%** → **Suspicious** (potential false negative)
4. **If both VT and ML agree it's safe** → **Safe**
5. **If VT unavailable** → Use ML model only

## Notes

- Free VirusTotal API has rate limits (4 requests/minute)
- ML model is used as fallback and for validation
- Confidence score ranges from 0.0 to 1.0
