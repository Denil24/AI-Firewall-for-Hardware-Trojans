import os
import shutil
import joblib
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
from extract_features import extract_features_from_file
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time

# -----------------------------
# Flask App Setup
# -----------------------------
app = Flask(__name__)
CORS(app)  # allow frontend to connect

# -----------------------------
# Load Model + Threshold
# -----------------------------
try:
    model, threshold = joblib.load("trojan_detector.pkl")
    feature_count = getattr(model, "n_features_in_", 25)
    print(f"✅ Model loaded successfully (threshold={threshold}, features={feature_count})")
except Exception as e:
    print(f"❌ Failed to load model: {e}")
    raise SystemExit

# -----------------------------
# Directories
# -----------------------------
UPLOAD_DIR = "uploads"
APPROVED_DIR = "approved"
QUARANTINE_DIR = "quarantine"
HISTORY_FILE = "scan_history.csv"

for folder in [UPLOAD_DIR, APPROVED_DIR, QUARANTINE_DIR]:
    os.makedirs(folder, exist_ok=True)

# -----------------------------
# Core Prediction Function
# -----------------------------
def predict_file(filepath: str):
    """Extract features & predict Trojan presence."""
    try:
        features = extract_features_from_file(filepath)
    except Exception as e:
        return {"status": "error", "message": f"Feature extraction failed: {e}"}

    if not features:
        return {"status": "error", "message": "No features extracted"}

    # Align feature vector with model input
    if len(features) < feature_count:
        features += [0] * (feature_count - len(features))
    elif len(features) > feature_count:
        features = features[:feature_count]

    # Predict
    df = pd.DataFrame([features], columns=[f"feature_{i+1}" for i in range(feature_count)])
    y_prob = model.predict_proba(df)[0][1]
    prediction = 1 if y_prob >= threshold else 0

    return {
        "status": "success",
        "filename": os.path.basename(filepath),
        "prediction": "Trojan Detected" if prediction == 1 else "Clean",
        "confidence": round(float(y_prob * 100), 2),
        "is_trojan": bool(prediction),
    }

# -----------------------------
# Save History
# -----------------------------
def save_history(record: dict):
    """Append scan result to persistent history file."""
    row = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "filename": record.get("filename"),
        "prediction": record.get("prediction"),
        "confidence": record.get("confidence"),
        "action": record.get("action"),
        "final_location": record.get("final_location"),
    }

    if not os.path.exists(HISTORY_FILE):
        pd.DataFrame([row]).to_csv(HISTORY_FILE, index=False)
    else:
        df = pd.DataFrame([row])
        df.to_csv(HISTORY_FILE, mode="a", header=False, index=False)

# -----------------------------
# Process & Move File
# -----------------------------
def process_file(filepath: str):
    """Run prediction, move file, update history."""
    result = predict_file(filepath)
    if result.get("status") != "success":
        print(f"❌ Error scanning {filepath}: {result.get('message')}")
        return

    try:
        if result["is_trojan"]:
            dest = os.path.join(QUARANTINE_DIR, result["filename"])
            shutil.move(filepath, dest)
            result["final_location"] = dest
            result["action"] = "quarantined"
            print(f"🚫 Trojan detected → moved {result['filename']} to quarantine/")
        else:
            dest = os.path.join(APPROVED_DIR, result["filename"])
            shutil.move(filepath, dest)
            result["final_location"] = dest
            result["action"] = "approved"
            print(f"✅ Clean file → moved {result['filename']} to approved/")
    except Exception as e:
        print(f"❌ Failed to move file {filepath}: {e}")
        return

    save_history(result)

# -----------------------------
# Watchdog Event Handler
# -----------------------------
class NewFileHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory or not event.src_path.endswith(".v"):
            return
        time.sleep(1)  # wait until file is fully written
        process_file(event.src_path)

# -----------------------------
# API Endpoint: Manual Scan
# -----------------------------
@app.route("/scan", methods=["POST"])
def scan_file():
    """Scan an uploaded Verilog file manually."""
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file uploaded"}), 400

    file = request.files["file"]
    filepath = os.path.join(UPLOAD_DIR, file.filename)
    file.save(filepath)

    # Let watchdog process it
    return jsonify({"status": "success", "message": f"File {file.filename} uploaded and will be scanned"}), 200

# -----------------------------
# API Endpoint: Get History
# -----------------------------
@app.route("/history", methods=["GET"])
def get_history():
    """Return full scan history (latest first)."""
    if not os.path.exists(HISTORY_FILE):
        return jsonify({"status": "success", "history": []}), 200

    df = pd.read_csv(HISTORY_FILE)
    df = df.iloc[::-1].reset_index(drop=True)  # latest first
    return jsonify({"status": "success", "history": df.to_dict(orient="records")}), 200

# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    print("🚀 Trojan Firewall API Server running with Real-Time Monitoring...")
    print(f"📂 Upload dir: {UPLOAD_DIR}")
    print(f"🟢 Approved dir: {APPROVED_DIR}")
    print(f"🔴 Quarantine dir: {QUARANTINE_DIR}")

    # Start watchdog
    observer = Observer()
    observer.schedule(NewFileHandler(), UPLOAD_DIR, recursive=False)
    observer.start()

    try:
        app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
