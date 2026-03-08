"""
Test script for PhishGuard URL Checking Backend
Run this to verify your backend is working correctly
"""
import requests
import json

BACKEND_URL = "http://localhost:8000"

def test_health():
    """Test if backend is running"""
    print("🔍 Testing backend health...")
    try:
        response = requests.get(f"{BACKEND_URL}/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print("✅ Backend is running!")
            print(f"   - ML Model Loaded: {data.get('ml_model_loaded', False)}")
            print(f"   - VT API Configured: {data.get('vt_api_configured', False)}")
            return True
        else:
            print(f"❌ Backend returned status code: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to backend. Is it running?")
        print("   Run: python backend/main.py")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_check_url(url):
    """Test URL checking endpoint"""
    print(f"\n🔍 Testing URL: {url}")
    try:
        response = requests.post(
            f"{BACKEND_URL}/check-url",
            json={"url": url},
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            print("✅ URL check successful!")
            print(f"\n📊 Results:")
            print(f"   Verdict: {result['verdict']}")
            print(f"   Confidence: {result['confidence']:.2%}")
            print(f"   Method: {result['method_used']}")
            print(f"   Details: {result['details']}")
            
            if result.get('vt_result'):
                vt = result['vt_result']
                print(f"\n   VirusTotal:")
                print(f"   - Malicious: {vt.get('malicious', 0)}")
                print(f"   - Suspicious: {vt.get('suspicious', 0)}")
                print(f"   - Detection Rate: {vt.get('detection_rate', 'N/A')}")
            
            if result.get('ml_result'):
                ml = result['ml_result']
                print(f"\n   ML Model:")
                print(f"   - Prediction: {ml.get('prediction', 'N/A')}")
                print(f"   - Malicious Probability: {ml.get('malicious_probability', 0):.2%}")
            
            return True
        else:
            print(f"❌ Request failed with status: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
            
    except requests.exceptions.Timeout:
        print("❌ Request timed out (>30s)")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def main():
    print("=" * 60)
    print("PhishGuard Backend Test Suite")
    print("=" * 60)
    
    # Test 1: Health check
    if not test_health():
        print("\n⚠️  Backend is not running. Start it with:")
        print("   cd backend")
        print("   python main.py")
        return
    
    # Test 2: Check a safe URL
    print("\n" + "=" * 60)
    print("Test 1: Safe URL")
    print("=" * 60)
    test_check_url("https://www.google.com")
    
    # Test 3: Check a potentially suspicious URL pattern
    print("\n" + "=" * 60)
    print("Test 2: Suspicious URL Pattern")
    print("=" * 60)
    test_check_url("http://192.168.1.1/login-verify-account.php?user=admin")
    
    print("\n" + "=" * 60)
    print("✨ Testing Complete!")
    print("=" * 60)
    print("\nIf all tests passed, your backend is ready to use!")
    print("Now run your Flutter app with: flutter run")

if __name__ == "__main__":
    main()
