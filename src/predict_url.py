import os
import sys
import joblib
import scipy.sparse as sp

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from url_features import extract_features_batch

# ── choose which trained model to use ────────────────────────────────────────
# Options: "unified" | "malicious_phish" | "dataset_phishing" | "PhiUSIIL_Phishing_URL_Dataset"
DATASET_NAME = "unified"

char_tfidf = joblib.load(f"models/{DATASET_NAME}_char_tfidf.pkl")
word_tfidf = joblib.load(f"models/{DATASET_NAME}_word_tfidf.pkl")
model      = joblib.load(f"models/{DATASET_NAME}_rf.pkl")


def predict_url(url: str):
    url_lower = url.strip().lower()

    x_char = char_tfidf.transform([url_lower])
    x_word = word_tfidf.transform([url_lower])
    x_feat = sp.csr_matrix(extract_features_batch([url_lower]))

    x    = sp.hstack([x_char, x_word, x_feat])
    pred = model.predict(x)[0]
    prob = model.predict_proba(x)[0][1]

    label = "Malicious" if pred == 1 else "Benign"
    return label, prob


if __name__ == "__main__":
    url = input("Enter URL: ").strip()
    label, prob = predict_url(url)
    print("Prediction:", label)
    print("Malicious probability:", round(prob, 4))