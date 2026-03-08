# Malicious URL Detection Model — Full Documentation

## Overview

This project trains a machine learning model to detect malicious and phishing URLs.
The model uses a combination of TF-IDF text features and handcrafted URL features,
fed into a Random Forest classifier.

The final model (`unified`) was trained on **2,272,035 unique URLs** from 8 different
real-world data sources and achieves:

- **Accuracy:** 98.17%
- **Recall:** 98.98% (catches 99 out of every 100 malicious URLs)
- **F1 Score:** 0.9881
- **ROC-AUC:** 0.9959

---

## Project Folder Structure

```
train/
├── data/                          ← Raw input datasets
│   ├── malicious_phish.csv
│   ├── dataset_phishing.csv
│   ├── PhiUSIIL_Phishing_URL_Dataset.csv
│   ├── ALL-phishing-links.lst
│   ├── ALL-phishing-domains.lst
│   ├── phishing-links-ACTIVE.txt
│   ├── phishing-domains-ACTIVE.txt
│   └── phishing-IPs-ACTIVE.txt
│
├── models/                        ← Trained model files (.pkl)
│   ├── unified_char_tfidf.pkl     ← Character-level TF-IDF vectorizer
│   ├── unified_word_tfidf.pkl     ← Word-level TF-IDF vectorizer
│   └── unified_rf.pkl             ← Random Forest classifier
│
├── outputs/                       ← Training outputs and metrics
│   ├── unified_cleaned.csv
│   ├── unified_train_80.csv
│   ├── unified_test_20.csv
│   ├── unified_metrics.txt
│   └── evaluation_summary.csv
│
└── src/                           ← All Python source code
    ├── url_features.py            ← Handcrafted URL feature extractor
    ├── train_all_datasets.py      ← Cleaning + training pipeline
    ├── train_unified_only.py      ← Trains only the unified model
    ├── predict_url.py             ← Prediction script (CLI)
    └── evaluate_models.py         ← Full evaluation with metrics
```

---

## Data Sources

### Labelled CSV Datasets (0 = benign, 1 = malicious)

| File                                | Rows    | Labels                                   |
| ----------------------------------- | ------- | ---------------------------------------- |
| `malicious_phish.csv`               | 641,119 | benign / phishing / malware / defacement |
| `dataset_phishing.csv`              | 11,429  | legitimate / phishing                    |
| `PhiUSIIL_Phishing_URL_Dataset.csv` | 235,370 | 0 / 1                                    |

### Phishing-Database Threat Intelligence Files (all malicious, label=1)

Source: https://github.com/Phishing-Database

| File                          | Rows    | Content                              |
| ----------------------------- | ------- | ------------------------------------ |
| `ALL-phishing-links.lst`      | 784,039 | Full phishing URLs (http/https)      |
| `ALL-phishing-domains.lst`    | 809,407 | Bare phishing domain names           |
| `phishing-links-ACTIVE.txt`   | 95,841  | Currently active phishing URLs       |
| `phishing-domains-ACTIVE.txt` | 147,224 | Currently active phishing domains    |
| `phishing-IPs-ACTIVE.txt`     | 8,652   | Raw IPv4 addresses used for phishing |

**Total after merging and deduplication: 2,272,035 URLs**

- Malicious (label=1): 1,740,805
- Benign (label=0): 531,230

---

## Data Cleaning

Each data source goes through a dedicated cleaning function in `train_all_datasets.py`.

### Steps applied to all sources:

1. **Keep only needed columns** — extract `url` and `label` columns only
2. **Drop null/empty rows** — remove entries with missing URL or label
3. **Normalise text** — strip whitespace, lowercase everything
4. **Map labels to binary integers** — all variants mapped to `0` (benign) or `1` (malicious):
   - `benign`, `legitimate`, `0` → `0`
   - `phishing`, `malware`, `defacement`, `1` → `1`
5. **Add URL scheme to bare entries:**
   - Domain files: `evil.com` → `http://evil.com`
   - IP files: `192.168.1.1` → `http://192.168.1.1`
6. **Filter link files** — keep only `http://` and `https://` URLs, drop `ftp://`
7. **Remove duplicate rows** — exact duplicate entries removed
8. **Remove duplicate URLs** — if a URL appears multiple times, keep the most malicious label

### Unified dataset merge strategy:

All 8 cleaned sources are concatenated into one dataframe, then:

- All URLs are lowercased
- Global deduplication is applied (2,733,081 → 2,272,035)
- If a URL appears in both a benign and malicious source, the malicious label wins

---

## Feature Engineering

Each URL is converted into **50,025 numerical features** before being fed to the model.
Features are computed in `src/url_features.py` and the TF-IDF vectorizers in
`src/train_all_datasets.py`.

### Feature Block 1 — Character N-gram TF-IDF (40,000 features)

The URL is sliced into overlapping character chunks of length 2–5:

```
"login.paypal.xyz" → "lo", "og", "gi", ..., "log", "ogi", ..., "login", ...
```

TF-IDF scores each chunk by how informative it is: high score = appears often
in malicious URLs but rarely in benign ones.

**Captures:** Suspicious TLDs (`.xyz`, `.tk`), encoded characters (`%2f`, `%40`),
keyword fragments (`log`, `ayl`), structural patterns (`.php`, `/wp-`).

**Settings:**

- `analyzer="char_wb"` — character n-grams with word boundaries
- `ngram_range=(2, 5)` — chunk sizes 2 to 5 characters
- `max_features=40,000` — keep the 40,000 most informative chunks
- `sublinear_tf=True` — compress high frequency counts (log scale)
- `min_df=3` — a chunk must appear in at least 3 URLs to be included

### Feature Block 2 — Word N-gram TF-IDF (10,000 features)

The URL is tokenised into words by splitting on non-alphanumeric characters:

```
"http://secure-paypal-login.verify.xyz/account/confirm"
→ ["http", "secure", "paypal", "login", "verify", "xyz", "account", "confirm"]
```

**Captures:** Brand impersonation (`paypal`, `amazon`, `apple`), urgency keywords
(`login`, `verify`, `secure`, `confirm`, `update`), suspicious TLDs as words (`xyz`, `tk`).

**Settings:**

- `analyzer="word"`
- `ngram_range=(1, 2)` — single words and word pairs
- `token_pattern=r"[a-z0-9]+"` — split on all URL delimiters
- `max_features=10,000`
- `sublinear_tf=True`
- `min_df=3`

### Feature Block 3 — Handcrafted URL Features (25 features)

These are manually engineered numerical signals based on known phishing research.
All computed in `src/url_features.py`:

| #   | Feature Name            | Description                                   |
| --- | ----------------------- | --------------------------------------------- |
| 1   | `url_length`            | Total character count of URL                  |
| 2   | `domain_length`         | Character count of domain part only           |
| 3   | `path_length`           | Character count of path part                  |
| 4   | `query_length`          | Character count of query string               |
| 5   | `num_dots`              | Count of `.` in full URL                      |
| 6   | `num_hyphens`           | Count of `-` in full URL                      |
| 7   | `num_underscores`       | Count of `_` in full URL                      |
| 8   | `num_slashes`           | Count of `/` in full URL                      |
| 9   | `num_question_marks`    | Count of `?`                                  |
| 10  | `num_equals`            | Count of `=`                                  |
| 11  | `num_ampersands`        | Count of `&`                                  |
| 12  | `num_at`                | Count of `@` (used in redirect tricks)        |
| 13  | `num_percent_encoded`   | Count of `%` (obfuscation)                    |
| 14  | `num_hash`              | Count of `#`                                  |
| 15  | `num_digits`            | Count of digit characters                     |
| 16  | `num_alpha`             | Count of alphabetic characters                |
| 17  | `digit_ratio`           | Digits / total length                         |
| 18  | `alpha_ratio`           | Alpha chars / total length                    |
| 19  | `has_ip`                | 1 if domain is a raw IPv4 address, else 0     |
| 20  | `subdomain_depth`       | Number of dot-separated parts in domain       |
| 21  | `path_depth`            | Number of `/`-separated segments in path      |
| 22  | `has_https`             | 1 if scheme is `https`, else 0                |
| 23  | `entropy`               | Shannon entropy of URL character distribution |
| 24  | `num_params`            | Number of query string parameters             |
| 25  | `suspicious_word_count` | Count of words from suspicious keyword list   |

**Suspicious keyword list:**
`login, signin, secure, account, update, free, verify, bank, paypal, password,
confirm, webscr, ebay, amazon, support, billing, wallet, credential`

**Shannon Entropy formula:**

$$H = -\sum_{c} p(c) \log_2 p(c)$$

Where $p(c)$ is the probability of character $c$ in the URL.
High entropy → random-looking URL → likely auto-generated by attackers.

### Final Feature Matrix

All three blocks are horizontally stacked using `scipy.sparse.hstack`:

```
[40,000 char TF-IDF] + [10,000 word TF-IDF] + [25 handcrafted] = 50,025 features per URL
```

---

## Model Architecture

### Algorithm: Random Forest Classifier

A Random Forest trains many decision trees independently and aggregates their votes.
Each tree asks a series of yes/no questions about the URL features to reach a prediction.

**Final parameters (unified model):**

```python
RandomForestClassifier(
    n_estimators    = 150,        # number of individual decision trees
    class_weight    = "balanced", # compensates for class imbalance (more malicious than benign)
    min_samples_leaf= 2,          # minimum examples per leaf node (prevents overfitting)
    max_features    = "sqrt",     # each tree sees sqrt(50025) ≈ 224 random features
    random_state    = 42,
    n_jobs          = 1,          # single process (RAM constraint on large datasets)
)
```

### Training Split

- **80%** of data → training (the model learns from this)
- **20%** of data → testing (the model is evaluated on this, never seen during training)
- Split is **stratified** — both halves maintain the same class ratio

### Memory Management

Due to RAM constraints on a standard PC, the unified training set is
**downsampled to 350,000 rows** (stratified) from the full 1,817,628 training rows.
350,000 rows still provides enormous diversity across all 8 data sources.

---

## Model Evaluation Results

All 4 models were evaluated against their held-out 20% test sets.

### Summary Table

| Model              | Test Size   | Accuracy   | Precision  | Recall     | F1         | ROC-AUC    | Miss Rate | False Alarm |
| ------------------ | ----------- | ---------- | ---------- | ---------- | ---------- | ---------- | --------- | ----------- |
| `malicious_phish`  | 128,224     | 98.42%     | 98.57%     | 96.63%     | 0.9759     | 0.9981     | 3.37%     | 0.70%       |
| `dataset_phishing` | 2,286       | 91.47%     | 92.25%     | 90.55%     | 0.9139     | 0.9741     | 9.45%     | 7.61%       |
| `PhiUSIIL`         | 47,074      | 99.78%     | 99.67%     | 99.94%     | 0.9981     | 0.9992     | 0.06%     | 0.44%       |
| **`unified`**      | **454,407** | **98.17%** | **98.64%** | **98.98%** | **0.9881** | **0.9959** | **1.02%** | **4.49%**   |

### Metric Definitions

- **Accuracy** — % of all URLs correctly labelled
- **Precision** — when model says malicious, % of time it is correct
- **Recall** — % of all truly malicious URLs that were caught
- **F1 Score** — harmonic mean of precision and recall (best single quality metric)
- **ROC-AUC** — rank separation ability (1.0 = perfect, 0.5 = random)
- **Miss Rate (FNR)** — % of malicious URLs that slipped through undetected (security risk)
- **False Alarm Rate (FPR)** — % of safe URLs that were wrongly blocked (user experience)

### Recommended Model for Production: `unified`

The `unified` model offers the best real-world coverage:

- Trained on data from 8 different sources including **live threat feeds**
- Lowest miss rate among multi-source models (1.02%)
- Covers **all attack types**: phishing, malware, defacement, bare domains, IP-based attacks
- The higher false alarm rate (4.49%) can be reduced by raising the decision threshold

---

## Prediction Pipeline (How to Use the Model)

### Step-by-step prediction for a single URL:

```python
import joblib
import scipy.sparse as sp
import sys, os

sys.path.insert(0, "path/to/src")
from url_features import extract_features_batch

# Load the three model components
char_tfidf = joblib.load("models/unified_char_tfidf.pkl")
word_tfidf = joblib.load("models/unified_word_tfidf.pkl")
model      = joblib.load("models/unified_rf.pkl")

def predict_url(url: str):
    url_lower = url.strip().lower()              # 1. normalise

    x_char = char_tfidf.transform([url_lower])   # 2. char TF-IDF → sparse matrix
    x_word = word_tfidf.transform([url_lower])   # 3. word TF-IDF → sparse matrix
    x_feat = sp.csr_matrix(                      # 4. handcrafted features → sparse matrix
        extract_features_batch([url_lower])
    )

    x = sp.hstack([x_char, x_word, x_feat])      # 5. combine all features

    pred = model.predict(x)[0]                   # 6. predict class (0 or 1)
    prob = model.predict_proba(x)[0][1]          # 7. get malicious probability (0.0–1.0)

    label = "Malicious" if pred == 1 else "Benign"
    return label, prob
```

### Output format:

```python
label, prob = predict_url("http://paypal-secure-login.verify.xyz/account/confirm")
# label = "Malicious"
# prob  = 0.94   ← 94% confidence it is malicious
```

### Decision threshold:

The default threshold is **0.5** — if `prob >= 0.5` the URL is malicious.

For **fewer false alarms** (safer experience): raise threshold to `0.65` or `0.70`
For **maximum security** (catch everything): lower threshold to `0.35` or `0.40`

---

## Required Python Dependencies

```
scikit-learn >= 1.3
pandas >= 2.0
numpy >= 1.24
scipy >= 1.10
joblib >= 1.3
```

Install with:

```bash
pip install scikit-learn pandas numpy scipy joblib
```

---

## Files to Bring to Your Flutter App

To integrate this model into a Flutter application, you need a **Python backend API**
that wraps the model. Flutter talks to this API over HTTP.

### Files required from this project:

```
COPY THESE FILES TO YOUR BACKEND:

models/
├── unified_char_tfidf.pkl    ← required (char vectorizer)
├── unified_word_tfidf.pkl    ← required (word vectorizer)
└── unified_rf.pkl            ← required (classifier)

src/
├── url_features.py           ← required (feature extractor, used at prediction time)
└── predict_url.py            ← use as reference for the prediction logic
```

### Do NOT copy:

```
data/           ← raw datasets, not needed at runtime (large files, training only)
outputs/        ← training artifacts, not needed at runtime
src/train_all_datasets.py     ← training code, not needed at runtime
src/train_unified_only.py     ← training code, not needed at runtime
src/evaluate_models.py        ← evaluation code, not needed at runtime
```

---

## Recommended Backend API Structure for Flutter Integration

Build a lightweight Python REST API (Flask or FastAPI) that wraps the model.
Flutter sends a URL via HTTP POST and receives a JSON prediction back.

### Suggested API endpoint:

**Request:**

```
POST /predict
Content-Type: application/json

{
  "url": "http://paypal-secure-login.verify.xyz/account/confirm"
}
```

**Response:**

```json
{
  "url": "http://paypal-secure-login.verify.xyz/account/confirm",
  "label": "Malicious",
  "probability": 0.94,
  "is_malicious": true,
  "confidence": "high"
}
```

### Confidence levels (suggested):

| Probability | `is_malicious` | `confidence` | Suggested UI        |
| ----------- | -------------- | ------------ | ------------------- |
| 0.00 – 0.30 | false          | high         | Green — Safe        |
| 0.30 – 0.50 | false          | low          | Yellow — Caution    |
| 0.50 – 0.65 | true           | low          | Orange — Suspicious |
| 0.65 – 1.00 | true           | high         | Red — Dangerous     |

### Minimal Flask API example (for the backend):

```python
from flask import Flask, request, jsonify
import joblib
import scipy.sparse as sp
import sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from url_features import extract_features_batch

app = Flask(__name__)

char_tfidf = joblib.load("models/unified_char_tfidf.pkl")
word_tfidf = joblib.load("models/unified_word_tfidf.pkl")
model      = joblib.load("models/unified_rf.pkl")

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    url  = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "url is required"}), 400

    url_lower = url.lower()
    x_char    = char_tfidf.transform([url_lower])
    x_word    = word_tfidf.transform([url_lower])
    x_feat    = sp.csr_matrix(extract_features_batch([url_lower]))
    x         = sp.hstack([x_char, x_word, x_feat])

    pred      = int(model.predict(x)[0])
    prob      = float(model.predict_proba(x)[0][1])

    if prob >= 0.65:
        confidence = "high"
    elif prob >= 0.35:
        confidence = "low"
    else:
        confidence = "high"

    return jsonify({
        "url":          url,
        "label":        "Malicious" if pred == 1 else "Benign",
        "probability":  round(prob, 4),
        "is_malicious": pred == 1,
        "confidence":   confidence,
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

### Flutter side (calling the API):

```dart
import 'dart:convert';
import 'package:http/http.dart' as http;

Future<Map<String, dynamic>> checkUrl(String url) async {
  final response = await http.post(
    Uri.parse('https://your-api-domain.com/predict'),
    headers: {'Content-Type': 'application/json'},
    body: jsonEncode({'url': url}),
  );

  if (response.statusCode == 200) {
    return jsonDecode(response.body);
  } else {
    throw Exception('Failed to check URL');
  }
}

// Usage:
// final result = await checkUrl('http://suspicious-link.xyz/login');
// result['is_malicious']  → true/false
// result['probability']   → 0.94
// result['label']         → "Malicious"
// result['confidence']    → "high"
```

---

## Model Limitations

1. **URL-only detection** — the model only analyses the URL string itself. It cannot:
   - Follow redirects to check the final destination
   - Analyse page content or JavaScript
   - Check SSL certificate validity
   - Verify domain age via WHOIS

2. **Training data cutoff** — all training data was collected before March 2026.
   Newly generated phishing domains after this date may have unfamiliar patterns.

3. **False positives on legitimate-looking domains** — some clean domains with
   high entropy or suspicious keywords may be incorrectly flagged.

4. **Recommended use** — combine this model with additional signals in production:
   - Google Safe Browsing API
   - Domain age check (WHOIS)
   - SSL certificate check
   - Page content analysis

---

## Retraining the Model

To retrain on new data:

1. Add new datasets to the `data/` folder
2. Add a cleaner function in `train_all_datasets.py` if the format is new
3. Add the new source to `build_unified_dataset()` in `train_all_datasets.py`
4. Run:
   ```bash
   python src/train_unified_only.py
   ```
5. Evaluate:
   ```bash
   python src/evaluate_models.py
   ```
6. Replace the three `.pkl` files in your backend with the new ones from `models/`

---

_Generated: March 2026 | Model version: unified v1 | Training data: 2,272,035 URLs_
