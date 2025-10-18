# scanner.py
import os
import joblib
import pandas as pd
from typing import Dict, Any
from extract_features import extract_features_from_file

MODEL_PKL = "trojan_detector.pkl"
DEFAULT_FEATURES = 25

# load model once
try:
    model, threshold = joblib.load(MODEL_PKL)
    feature_count = getattr(model, "n_features_in_", DEFAULT_FEATURES)
    print(f"[scanner] Model loaded (threshold={threshold}, features={feature_count})")
except Exception as e:
    print(f"[scanner] Failed to load model: {e}")
    raise

def predict_file(filepath: str) -> Dict[str, Any]:
    """
    Extract features, run model and return dictionary with:
       filename, prediction ("Trojan Detected"/"Clean"), confidence (float 0-100),
       is_trojan (bool)
    """
    try:
        features = extract_features_from_file(filepath)
    except Exception as e:
        return {"status": "error", "message": f"feature_extraction_failed: {e}", "filename": os.path.basename(filepath)}

    if not features:
        return {"status": "error", "message": "no_features_extracted", "filename": os.path.basename(filepath)}

    # align vector length
    if len(features) < feature_count:
        features += [0] * (feature_count - len(features))
    elif len(features) > feature_count:
        features = features[:feature_count]

    df = pd.DataFrame([features], columns=[f"feature_{i+1}" for i in range(feature_count)])
    try:
        y_prob = float(model.predict_proba(df)[0][1])
    except Exception as e:
        return {"status": "error", "message": f"prediction_failed: {e}", "filename": os.path.basename(filepath)}

    pred = 1 if y_prob >= threshold else 0
    return {
        "status": "success",
        "filename": os.path.basename(filepath),
        "prediction": "Trojan Detected" if pred == 1 else "Clean",
        "confidence": round(float(y_prob * 100), 2),
        "is_trojan": bool(pred)
    }
