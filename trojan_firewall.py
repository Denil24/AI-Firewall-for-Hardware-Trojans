#!/usr/bin/env python3
"""
trojan_firewall.py

Monitor an incoming folder for Verilog files, run the trained trojan_detector,
and quarantine or approve files automatically.

Usage:
    python trojan_firewall.py

Requires:
    - joblib
    - pandas
    - extract_features.extract_features_from_file (your extractor wrapper)
    - watchdog (optional, for real-time file events). If not present, fallback to polling.

Behavior:
    - Moves suspicious files to QUARANTINE_DIR
    - Moves clean files to APPROVED_DIR
    - Logs to firewall_log.csv
    - Respects whitelist.txt (one sha256 per line)
"""

import os
import sys
import time
import shutil
import hashlib
import signal
import joblib
import pandas as pd
from datetime import datetime
from extract_features import extract_features_from_file

# Optional import
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except Exception:
    WATCHDOG_AVAILABLE = False

# ----------------------------
# Config (edit as needed)
# ----------------------------
MODEL_PATH = "trojan_detector.pkl"   # trained model file
WHITELIST_PATH = "whitelist.txt"     # optional sha256 whitelist (one per line)
INCOMING_DIR = "incoming"            # watch this dir for new files
QUARANTINE_DIR = "quarantine"        # move suspicious files here
APPROVED_DIR = "approved"            # move clean files here
LOG_CSV = "firewall_log.csv"         # event log
POLL_INTERVAL = 5                    # seconds (used when watchdog is unavailable)
VERBOSE = True

# ----------------------------
# Utilities
# ----------------------------
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def load_whitelist(path=WHITELIST_PATH):
    if not os.path.exists(path):
        return set()
    with open(path, "r") as f:
        return set(line.strip() for line in f if line.strip())

def ensure_dirs(*dirs):
    for d in dirs:
        os.makedirs(d, exist_ok=True)

def safe_move(src, dst_dir):
    ensure_dirs(dst_dir)
    base = os.path.basename(src)
    dst = os.path.join(dst_dir, base)
    # avoid overwriting: append timestamp if exists
    if os.path.exists(dst):
        name, ext = os.path.splitext(base)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        dst = os.path.join(dst_dir, f"{name}_{ts}{ext}")
    shutil.move(src, dst)
    return dst

def log_event(row: dict):
    df = pd.DataFrame([row])
    header = not os.path.exists(LOG_CSV)
    df.to_csv(LOG_CSV, mode="a", index=False, header=header)

def verbose_print(*args, **kwargs):
    if VERBOSE:
        print(*args, **kwargs)

# ----------------------------
# Load model + infer features
# ----------------------------
def load_model(path=MODEL_PATH):
    try:
        model, threshold = joblib.load(path)
    except Exception as e:
        raise RuntimeError(f"Failed to load model from {path}: {e}")
    return model, float(threshold)

def infer_feature_count(model):
    n = getattr(model, "n_features_in_", None)
    if n is not None:
        return int(n)
    # fallback: try dataset.csv
    if os.path.exists("dataset.csv"):
        try:
            df = pd.read_csv("dataset.csv")
            return max(1, df.shape[1] - 1)
        except Exception:
            return None
    return None

# ----------------------------
# File processing
# ----------------------------
def process_file(path, model, threshold, whitelist, feature_count=None):
    event_time = datetime.utcnow().isoformat()
    result = {
        "timestamp": event_time,
        "filepath": path,
        "sha256": None,
        "decision": None,
        "reason": None,
        "probability": None,
        "moved_to": None
    }

    if not os.path.exists(path):
        result["decision"] = "MISSING"
        result["reason"] = "file_not_found"
        log_event(result)
        return result

    # compute hash and check whitelist
    try:
        file_hash = sha256_file(path)
        result["sha256"] = file_hash
        if file_hash in whitelist:
            result["decision"] = "APPROVED"
            result["reason"] = "whitelist"
            dst = safe_move(path, APPROVED_DIR)
            result["moved_to"] = dst
            log_event(result)
            verbose_print(f"[WHITELIST] {path} -> {dst}")
            return result
    except Exception as e:
        result["decision"] = "MANUAL_REVIEW"
        result["reason"] = f"hash_error:{e}"
        log_event(result)
        return result

    # Extract features (use your wrapper that pads/truncates)
    try:
        feats = extract_features_from_file(path, expected_features=feature_count or 0)
        if feats is None:
            raise ValueError("extractor returned None")
    except Exception as e:
        result["decision"] = "MANUAL_REVIEW"
        result["reason"] = f"extract_failed:{e}"
        log_event(result)
        verbose_print(f"[EXTRACT ERROR] {path}: {e}")
        return result

    # Align features to feature_count
    if feature_count:
        if len(feats) < feature_count:
            feats += [0] * (feature_count - len(feats))
        else:
            feats = feats[:feature_count]

    # Predict
    try:
        import pandas as pd
        df = pd.DataFrame([feats], columns=[f"feature_{i+1}" for i in range(len(feats))])
        if hasattr(model, "predict_proba"):
            prob = float(model.predict_proba(df)[0][1])
        else:
            # fallback: model without predict_proba -> deterministic predict
            pred = int(model.predict(df)[0])
            prob = 1.0 if pred == 1 else 0.0
        result["probability"] = prob
        # decision based on threshold
        if prob >= threshold:
            result["decision"] = "QUARANTINE"
            result["reason"] = "prob>=threshold"
            dst = safe_move(path, QUARANTINE_DIR)
            result["moved_to"] = dst
            verbose_print(f"[QUARANTINE] {path} (p={prob:.4f}) -> {dst}")
        else:
            result["decision"] = "APPROVED"
            result["reason"] = "prob<threshold"
            dst = safe_move(path, APPROVED_DIR)
            result["moved_to"] = dst
            verbose_print(f"[APPROVED] {path} (p={prob:.4f}) -> {dst}")

    except Exception as e:
        result["decision"] = "MANUAL_REVIEW"
        result["reason"] = f"predict_failed:{e}"
        verbose_print(f"[PREDICT ERROR] {path}: {e}")

    log_event(result)
    return result

# ----------------------------
# Watcher (watchdog) or Polling fallback
# ----------------------------
class NewFileHandler(FileSystemEventHandler):
    def __init__(self, model, threshold, whitelist, feature_count):
        super().__init__()
        self.model = model
        self.threshold = threshold
        self.whitelist = whitelist
        self.feature_count = feature_count

    def on_created(self, event):
        # sometimes temporary files are created first; handle files only
        if not event.is_directory and event.src_path.endswith(".v"):
            # wait briefly to allow file to be fully written
            time.sleep(0.5)
            try:
                process_file(event.src_path, self.model, self.threshold, self.whitelist, self.feature_count)
            except Exception as e:
                verbose_print(f"[WATCH ERROR] processing {event.src_path}: {e}")

def poll_folder(folder, model, threshold, whitelist, feature_count, seen):
    """Simple polling: process .v files not in 'seen' set."""
    for root, _, files in os.walk(folder):
        for f in files:
            if not f.endswith(".v"):
                continue
            path = os.path.join(root, f)
            # avoid processing files in approved/quarantine folders
            if os.path.commonpath([os.path.abspath(path), os.path.abspath(APPROVED_DIR)]) == os.path.abspath(APPROVED_DIR):
                continue
            if os.path.commonpath([os.path.abspath(path), os.path.abspath(QUARANTINE_DIR)]) == os.path.abspath(QUARANTINE_DIR):
                continue
            # skip files already processed
            if path in seen:
                continue
            # skip hidden/temp files
            if f.startswith(".") or f.endswith("~"):
                continue
            # ensure file is stable (size unchanged)
            try:
                size1 = os.path.getsize(path)
                time.sleep(0.2)
                size2 = os.path.getsize(path)
                if size1 != size2:
                    # file still being written
                    continue
            except Exception:
                continue
            # process file
            try:
                process_file(path, model, threshold, whitelist, feature_count)
                seen.add(path)
            except Exception as e:
                verbose_print(f"[POLL ERROR] {path}: {e}")

# ----------------------------
# Main
# ----------------------------
def main():
    ensure_dirs(INCOMING_DIR, QUARANTINE_DIR, APPROVED_DIR)
    whitelist = load_whitelist()
    verbose_print(f"Loaded whitelist entries: {len(whitelist)}")

    model, threshold = load_model(MODEL_PATH)
    verbose_print(f"Loaded model with threshold={threshold:.4f}")

    feature_count = infer_feature_count(model)
    verbose_print(f"Inferred feature_count = {feature_count}")

    # process existing files in incoming dir once
    seen = set()
    verbose_print("Processing existing files in incoming directory...")
    poll_folder(INCOMING_DIR, model, threshold, whitelist, feature_count, seen)

    stop_requested = False

    def _signal_handler(sig, frame):
        nonlocal stop_requested
        verbose_print("Shutdown requested, stopping watcher...")
        stop_requested = True

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    if WATCHDOG_AVAILABLE:
        verbose_print("Watchdog available — using event-driven monitoring.")
        event_handler = NewFileHandler(model, threshold, whitelist, feature_count)
        observer = Observer()
        observer.schedule(event_handler, INCOMING_DIR, recursive=True)
        observer.start()
        try:
            while not stop_requested:
                time.sleep(1)
        finally:
            observer.stop()
            observer.join()
    else:
        verbose_print("Watchdog not available — falling back to polling.")
        try:
            while not stop_requested:
                poll_folder(INCOMING_DIR, model, threshold, whitelist, feature_count, seen)
                time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            verbose_print("KeyboardInterrupt — stopping.")

    verbose_print("Firewall stopped.")

if __name__ == "__main__":
    main()
