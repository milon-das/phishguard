"""
Handcrafted URL feature extraction.
Shared by train_all_datasets.py and predict_url.py.
"""
import re
import math
from urllib.parse import urlparse

import numpy as np

# ── feature names (same order as extract_url_features) ─────────────────────
FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "path_length",
    "query_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_question_marks",
    "num_equals",
    "num_ampersands",
    "num_at",
    "num_percent_encoded",
    "num_hash",
    "num_digits",
    "num_alpha",
    "digit_ratio",
    "alpha_ratio",
    "has_ip",
    "subdomain_depth",
    "path_depth",
    "has_https",
    "entropy",
    "num_params",
    "suspicious_word_count",
]

_IP_PATTERN = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")

_SUSPICIOUS_WORDS = [
    "login", "signin", "secure", "account", "update",
    "free", "verify", "bank", "paypal", "password",
    "confirm", "webscr", "ebay", "amazon", "support",
    "billing", "wallet", "credential",
]


def extract_url_features(url: str) -> list:
    """Return a list of 25 numerical features for a single URL."""
    url = str(url)
    features = []

    try:
        parsed = urlparse(url)
        netloc = parsed.netloc or ""
        path   = parsed.path   or ""
        query  = parsed.query  or ""
        scheme = parsed.scheme or ""
    except Exception:
        netloc = path = query = scheme = ""

    n = max(len(url), 1)

    # ── length features ──────────────────────────────────────────────────────
    features.append(len(url))
    features.append(len(netloc))
    features.append(len(path))
    features.append(len(query))

    # ── character count features ─────────────────────────────────────────────
    features.append(url.count("."))
    features.append(url.count("-"))
    features.append(url.count("_"))
    features.append(url.count("/"))
    features.append(url.count("?"))
    features.append(url.count("="))
    features.append(url.count("&"))
    features.append(url.count("@"))
    features.append(url.count("%"))
    features.append(url.count("#"))

    # ── digit / alpha stats ──────────────────────────────────────────────────
    digit_count = sum(c.isdigit() for c in url)
    alpha_count = sum(c.isalpha() for c in url)
    features.append(digit_count)
    features.append(alpha_count)
    features.append(digit_count / n)
    features.append(alpha_count / n)

    # ── structural features ──────────────────────────────────────────────────
    features.append(int(bool(_IP_PATTERN.search(netloc))))       # has raw IP
    features.append(len(netloc.split(".")))                      # subdomain depth
    features.append(len([p for p in path.split("/") if p]))      # path depth
    features.append(int(scheme == "https"))                      # uses HTTPS

    # ── Shannon entropy of URL ───────────────────────────────────────────────
    probs   = [url.count(c) / n for c in set(url)]
    entropy = -sum(p * math.log2(p) for p in probs if p > 0)
    features.append(entropy)

    # ── query params ─────────────────────────────────────────────────────────
    features.append(len(query.split("&")) if query else 0)

    # ── suspicious keyword count ─────────────────────────────────────────────
    url_lower = url.lower()
    features.append(sum(1 for w in _SUSPICIOUS_WORDS if w in url_lower))

    return features


def extract_features_batch(urls) -> np.ndarray:
    """Vectorised version – returns (N, 25) float array."""
    return np.array([extract_url_features(u) for u in urls], dtype=float)
