# monitor.py
import os
import time
import json
import shutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileMovedEvent
from scanner import predict_file

# Directories (create if missing)
BASE_DIR = os.path.abspath(".")
INCOMING = os.path.join(BASE_DIR, "incoming")
APPROVED = os.path.join(BASE_DIR, "approved")
QUARANTINE = os.path.join(BASE_DIR, "quarantine")
HISTORY_FILE = os.path.join(BASE_DIR, "scan_history.json")

for d in (INCOMING, APPROVED, QUARANTINE):
    os.makedirs(d, exist_ok=True)

# helper to append to history file
def append_history(entry):
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                history = json.load(f)
        except Exception:
            history = []
    history.insert(0, entry)  # newest first
    # keep last 200 entries
    history = history[:200]
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)

class IncomingHandler(FileSystemEventHandler):
    def _process(self, path):
        # wait briefly for file to be fully written
        time.sleep(0.3)
        if not os.path.isfile(path):
            return
        if not path.lower().endswith(".v"):
            return

        print(f"[monitor] Detected file: {path}")
        res = predict_file(path)
        if res.get("status") != "success":
            res_record = {
                "filename": res.get("filename", os.path.basename(path)),
                "prediction": "ERROR",
                "confidence": 0,
                "action": "error",
                "size": f"{os.path.getsize(path)/1024:.1f} KB",
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "message": res.get("message")
            }
            append_history(res_record)
            print(f"[monitor] Error scanning {path}: {res.get('message')}")
            return

        # build record
        size_kb = f"{os.path.getsize(path)/1024:.1f} KB"
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        if res["is_trojan"]:
            dest = os.path.join(QUARANTINE, res["filename"])
            action = "quarantined"
        else:
            dest = os.path.join(APPROVED, res["filename"])
            action = "approved"

        # move file (overwrite if exists)
        try:
            if os.path.exists(dest):
                os.remove(dest)
            shutil.move(path, dest)
            print(f"[monitor] Moved {path} → {dest}")
        except Exception as e:
            print(f"[monitor] Failed to move file: {e}")
            action = "move_error"
            dest = path

        res_record = {
            "filename": res["filename"],
            "prediction": res["prediction"],
            "confidence": res["confidence"],
            "action": action,
            "final_location": dest,
            "size": size_kb,
            "time": timestamp
        }
        append_history(res_record)

    def on_created(self, event):
        if isinstance(event, FileCreatedEvent):
            self._process(event.src_path)

    def on_moved(self, event):
        if isinstance(event, FileMovedEvent):
            # handle moved-to incoming
            self._process(event.dest_path)

if __name__ == "__main__":
    print("[monitor] Starting monitor. Watching:", INCOMING)
    observer = Observer()
    handler = IncomingHandler()
    observer.schedule(handler, INCOMING, recursive=False)
    observer.start()
    try:
        # process existing files at startup
        for fname in os.listdir(INCOMING):
            full = os.path.join(INCOMING, fname)
            handler._process(full)

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
