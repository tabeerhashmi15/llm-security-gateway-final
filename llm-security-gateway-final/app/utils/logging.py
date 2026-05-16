# utils/logging.py
# Audit logger — appends one JSON line per request

import json
import os
from datetime import datetime

LOG_FILE = os.path.join(
    os.path.dirname(__file__), "../../results/audit_log.jsonl"
)


def log_request(entry: dict):
    """Append one audit entry as a JSON line."""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    entry["timestamp"] = datetime.utcnow().isoformat() + "Z"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
