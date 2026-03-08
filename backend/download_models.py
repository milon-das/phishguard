#!/usr/bin/env python3
"""
Download ML models during deployment.
Fallback: If GitHub Release not available, use pre-uploaded smaller models.
"""
import os
import sys
import urllib.request

MODEL_DIR = os.path.join(os.path.dirname(__file__), 'models')
os.makedirs(MODEL_DIR, exist_ok=True)

# Large model to download (42 MB - too big for git)
LARGE_MODEL_URL = "https://github.com/milon-das/phishguard/releases/download/v1.0/PhiUSIIL_Phishing_URL_Dataset_rf.pkl"
LARGE_MODEL_PATH = os.path.join(MODEL_DIR, "PhiUSIIL_Phishing_URL_Dataset_rf.pkl")

def download_file(url, destination):
    """Download file with progress"""
    try:
        print(f"Downloading {os.path.basename(destination)}...")
        urllib.request.urlretrieve(url, destination)
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
    success = download_file(LARGE_MODEL_URL, LARGE_MODEL_PATH)
    
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
