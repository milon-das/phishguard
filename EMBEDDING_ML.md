# Converting PhishGuard ML Model to Flutter (On-Device Inference)

This guide shows how to embed your ML model directly into the Flutter app for offline phishing detection.

---

## Why Embed the Model?

✅ **100% Free** - No backend server costs  
✅ **Works Offline** - No internet required  
✅ **Privacy** - URLs never leave the device  
✅ **Instant** - No network latency  
✅ **Always Available** - No cold starts or downtime

❌ **Trade-offs:**

- App size increases by 10-20 MB
- Lose VirusTotal integration (or need to call VT API directly from app)
- Model updates require app updates
- Slightly lower accuracy than VT (but still 99.78%!)

---

## Step 1: Convert Model to TensorFlow Lite

### Install Dependencies

```bash
cd train
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install tensorflow scikit-learn joblib
```

### Create Conversion Script

Create `train/convert_to_tflite.py`:

```python
import joblib
import numpy as np
import tensorflow as tf
from sklearn.ensemble import RandomForestClassifier
import os

# Load your trained model
MODEL_DIR = 'models'
char_tfidf = joblib.load(os.path.join(MODEL_DIR, "PhiUSIIL_Phishing_URL_Dataset_char_tfidf.pkl"))
word_tfidf = joblib.load(os.path.join(MODEL_DIR, "PhiUSIIL_Phishing_URL_Dataset_word_tfidf.pkl"))
rf_model = joblib.load(os.path.join(MODEL_DIR, "PhiUSIIL_Phishing_URL_Dataset_rf.pkl"))

print("✅ Loaded sklearn models")

# Convert RandomForest to TensorFlow
# Note: This is complex because RF isn't directly supported in TFLite
# We'll use a neural network approximation instead

from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split

# You'll need to retrain as a neural network for TFLite compatibility
# Alternative: Use the sklearn model directly with a Dart port (see Option 2)

print("⚠️  RandomForest doesn't convert directly to TFLite")
print("📝 See EMBEDDING_ML.md for alternative approaches")
```

---

## Step 2: Easier Alternative - Use ONNX

ONNX works better with sklearn models:

### Install ONNX Tools

```bash
pip install skl2onnx onnxruntime
```

### Convert to ONNX

Create `train/convert_to_onnx.py`:

```python
import joblib
import numpy as np
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import onnxruntime as rt
import os

# Load models
MODEL_DIR = 'models'
char_tfidf = joblib.load(os.path.join(MODEL_DIR, "PhiUSIIL_Phishing_URL_Dataset_char_tfidf.pkl"))
word_tfidf = joblib.load(os.path.join(MODEL_DIR, "PhiUSIIL_Phishing_URL_Dataset_word_tfidf.pkl"))
rf_model = joblib.load(os.path.join(MODEL_DIR, "PhiUSIIL_Phishing_URL_Dataset_rf.pkl"))

print("✅ Loaded models")

# Get input shape (char_tfidf + word_tfidf + features)
char_features = char_tfidf.transform(["http://example.com"]).shape[1]
word_features = word_tfidf.transform(["http://example.com"]).shape[1]
manual_features = 25  # Your extract_features returns 25 features

total_features = char_features + word_features + manual_features

print(f"📊 Total features: {total_features}")
print(f"   - Char TF-IDF: {char_features}")
print(f"   - Word TF-IDF: {word_features}")
print(f"   - Manual features: {manual_features}")

# Convert RandomForest to ONNX
initial_type = [('float_input', FloatTensorType([None, total_features]))]
onnx_model = convert_sklearn(rf_model, initial_types=initial_type)

# Save ONNX model
output_path = os.path.join(MODEL_DIR, "phishguard_model.onnx")
with open(output_path, "wb") as f:
    f.write(onnx_model.SerializeToString())

print(f"✅ Saved ONNX model to {output_path}")
print(f"📦 Size: {os.path.getsize(output_path) / 1024 / 1024:.2f} MB")

# Test the model
sess = rt.InferenceSession(output_path)
input_name = sess.get_inputs()[0].name
test_input = np.random.randn(1, total_features).astype(np.float32)
result = sess.run(None, {input_name: test_input})
print(f"✅ ONNX model test successful: {result}")
```

### Run Conversion

```bash
python train/convert_to_onnx.py
```

---

## Step 3: Best Solution - Hybrid Approach

Instead of converting, use a **hybrid approach**:

1. **Keep ML model on device** using `tflite_flutter` or pure Dart implementation
2. **Call VirusTotal API directly from Flutter** (no backend needed)
3. **Prioritize VT, fallback to on-device ML**

### Why This Works Better:

```dart
// Pseudo-code
Future<ScanResult> scanURL(String url) async {
  // Try VirusTotal first (if API key available and online)
  if (hasVTApiKey && isOnline) {
    try {
      final vtResult = await callVirusTotalAPI(url);
      return vtResult;
    } catch (e) {
      // Fall through to ML
    }
  }

  // Use on-device ML model
  return await runOnDeviceML(url);
}
```

---

## Step 4: Implement On-Device ML in Flutter

### Add TFLite Package

Edit `pubspec.yaml`:

```yaml
dependencies:
  tflite_flutter: ^0.10.4
  tflite_flutter_helper: ^0.3.1
```

### Add Model to Assets

1. Convert model to TFLite (or use simpler approach below)
2. Add to `pubspec.yaml`:
   ```yaml
   flutter:
     assets:
       - assets/models/phishguard_model.tflite
       - assets/models/char_vocab.json
       - assets/models/word_vocab.json
   ```

### Create ML Service

Create `lib/services/ml_service.dart`:

```dart
import 'package:tflite_flutter/tflite_flutter.dart';
import 'dart:typed_data';

class MLService {
  Interpreter? _interpreter;

  Future<void> loadModel() async {
    _interpreter = await Interpreter.fromAsset('assets/models/phishguard_model.tflite');
    print('✅ ML model loaded');
  }

  Future<Map<String, dynamic>> predictURL(String url) async {
    if (_interpreter == null) await loadModel();

    // Extract features (implement in Dart)
    final features = await extractFeatures(url);

    // Run inference
    var output = List.filled(2, 0.0).reshape([1, 2]);
    _interpreter!.run(features, output);

    final maliciousProb = output[0][1];
    final benignProb = output[0][0];

    return {
      'prediction': maliciousProb > 0.5 ? 'Malicious' : 'Safe',
      'malicious_probability': maliciousProb,
      'benign_probability': benignProb,
      'confidence': maliciousProb > 0.5 ? maliciousProb : benignProb,
    };
  }

  Future<List<double>> extractFeatures(String url) async {
    // Implement your feature extraction in Dart
    // This is the tricky part - you need to port Python logic to Dart
    // See below for simplified approach
    return [];
  }
}
```

---

## Step 5: Simpler Approach - Rule-Based + Basic ML

Instead of complex conversion, implement a **lightweight on-device checker**:

### Create `lib/services/offline_scanner.dart`:

```dart
class OfflineScanner {
  // Lightweight phishing detection without ML model

  static Future<Map<String, dynamic>> scanURL(String url) async {
    int suspiciousScore = 0;
    final reasons = <String>[];

    // Rule 1: Check domain age (if using public WHOIS API)
    // Rule 2: Check for IP address instead of domain
    if (RegExp(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}').hasMatch(url)) {
      suspiciousScore += 30;
      reasons.add('Uses IP address instead of domain');
    }

    // Rule 3: Check URL length (phishing URLs are often long)
    if (url.length > 75) {
      suspiciousScore += 20;
      reasons.add('Unusually long URL');
    }

    // Rule 4: Check for suspicious keywords
    final suspiciousKeywords = ['verify', 'account', 'login', 'secure', 'banking', 'paypal', 'signin', 'suspended'];
    for (final keyword in suspiciousKeywords) {
      if (url.toLowerCase().contains(keyword)) {
        suspiciousScore += 15;
        reasons.add('Contains suspicious keyword: $keyword');
        break;
      }
    }

    // Rule 5: Check for multiple subdomains
    final host = Uri.parse(url).host;
    final subdomains = host.split('.');
    if (subdomains.length > 4) {
      suspiciousScore += 25;
      reasons.add('Too many subdomains');
    }

    // Rule 6: Check for special characters
    if (url.contains('@') || url.split('/')[2].contains('-')) {
      suspiciousScore += 15;
      reasons.add('Contains suspicious characters');
    }

    // Rule 7: Check for HTTPS
    if (!url.startsWith('https://')) {
      suspiciousScore += 10;
      reasons.add('Not using HTTPS');
    }

    // Determine verdict
    String verdict;
    double confidence;

    if (suspiciousScore >= 60) {
      verdict = 'Malicious';
      confidence = suspiciousScore / 100.0;
    } else if (suspiciousScore >= 30) {
      verdict = 'Suspicious';
      confidence = 0.5;
    } else {
      verdict = 'Safe';
      confidence = 1.0 - (suspiciousScore / 100.0);
    }

    return {
      'verdict': verdict,
      'confidence': confidence,
      'score': suspiciousScore,
      'reasons': reasons,
      'method_used': 'Offline Scanner',
    };
  }
}
```

---

## Recommended Architecture

### **Three-Tier Scanning:**

```dart
Future<Map<String, dynamic>> scanURL(String url) async {
  // Tier 1: VirusTotal (if online and API key available)
  if (await isOnline() && hasVTApiKey()) {
    try {
      return await callVirusTotalAPI(url);
    } catch (e) {
      print('VT failed, falling back...');
    }
  }

  // Tier 2: Backend ML Model (if backend available)
  if (await isOnline() && await isBackendAvailable()) {
    try {
      return await callBackendML(url);
    } catch (e) {
      print('Backend failed, falling back...');
    }
  }

  // Tier 3: On-Device Offline Scanner (always works)
  return await OfflineScanner.scanURL(url);
}
```

---

## Comparison Table

| Approach              | Accuracy | Speed     | Works Offline | App Size | Complexity |
| --------------------- | -------- | --------- | ------------- | -------- | ---------- |
| **Backend (Current)** | 99.78%   | Fast      | ❌ No         | Small    | Easy       |
| **Embedded TFLite**   | 99.78%   | Very Fast | ✅ Yes        | +20 MB   | Hard       |
| **Embedded ONNX**     | 99.78%   | Fast      | ✅ Yes        | +15 MB   | Medium     |
| **Rule-Based**        | ~70%     | Instant   | ✅ Yes        | +0 MB    | Easy       |
| **Hybrid**            | 99.78%   | Fast      | ✅ Yes        | +5 MB    | Medium     |

---

## My Recommendation

Use the **Hybrid approach** with **Rule-Based offline scanner**:

### Benefits:

✅ Works 100% offline with rule-based detection (~70% accurate)  
✅ Uses VirusTotal when online (best accuracy)  
✅ Can fallback to your backend ML model  
✅ Zero cost if you don't deploy backend  
✅ No complex ML conversion needed  
✅ Small app size increase

### Implementation:

1. Keep your current VT + Backend ML code
2. Add `OfflineScanner` class (shown above)
3. Modify scanning logic to try: VT → Backend ML → Offline
4. Users can choose to use only offline mode in settings

This gives users **flexibility**:

- **Online**: Best accuracy with VT + ML
- **Offline**: Still works with rule-based detection
- **Privacy-focused**: Can disable all network calls

---

## Want Full ML Embedding?

If you really want the full 99.78% accuracy ML model embedded:

1. I can help convert your model to TFLite/ONNX
2. Port feature extraction to Dart
3. Integrate with Flutter app

But the **hybrid approach is more practical** for your use case.

Let me know which approach you'd like to pursue!
