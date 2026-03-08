#!/usr/bin/env python3
"""
Download ML models during deployment.
Fallback: If GitHub Release not available, use pre-uploaded smaller models.
"""
import os
import sys
import hashlib
import urllib.request

MODEL_DIR = os.path.join(os.path.dirname(__file__), 'models')
os.makedirs(MODEL_DIR, exist_ok=True)

# Large model to download (42 MB - too big for git)
LARGE_MODEL_URL = "https://github.com/milon-das/phishguard/releases/download/v1.0/PhiUSIIL_Phishing_URL_Dataset_rf.pkl"
LARGE_MODEL_PATH = os.path.join(MODEL_DIR, "PhiUSIIL_Phishing_URL_Dataset_rf.pkl")
LARGE_MODEL_SHA256 = "32ec0480cfb8789d0b5e4155cb4e3de3724ca0e271fa4e7f3fc7288749d64d43"

def sha256_of(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()

def download_file(url, destination, expected_sha256=None):
    """Download file and verify integrity"""
    try:
        print(f"Downloading {os.path.basename(destination)}...")
        urllib.request.urlretrieve(url, destination)
        if expected_sha256:
            actual = sha256_of(destination)
            if actual != expected_sha256:
                os.remove(destination)
                print(f"✗ Integrity check FAILED (got {actual})")
                return False
            print(f"✓ Integrity verified")
        print(f"✓ Downloaded {os.path.basename(destination)}")
        return True
    except Exception as e:
        print(f"✗ Failed to download: {e}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("PhishGuard Model Setup")
    print("=" * 60)
    
    # Check if large model exists
    if os.path.exists(LARGE_MODEL_PATH):
        print(f"✓ Model already exists: {os.path.basename(LARGE_MODEL_PATH)}")
        sys.exit(0)
    
    # Download from GitHub Release
    print(f"\nDownloading large model from GitHub Release...")
    success = download_file(LARGE_MODEL_URL, LARGE_MODEL_PATH, expected_sha256=LARGE_MODEL_SHA256)
    
    if success:
        print("\n✓ All models ready!")
        sys.exit(0)
    else:
        print("\n⚠ Warning: Could not download large model.")
        print("Upload models to GitHub Release:")
        print("1. Go to: https://github.com/milon-das/phishguard/releases/new")
        print("2. Tag: v1.0")
        print("3. Upload: PhiUSIIL_Phishing_URL_Dataset_rf.pkl")
        print("4. Redeploy on Render")
        sys.exit(1)
