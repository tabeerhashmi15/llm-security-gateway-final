# app/main.py
# LLM Security Gateway - Lab Final
# Author: Tabeer Hashmi

import time
import uuid
from flask import Flask, request, jsonify

from detectors.rule_detector import detect_injection
from detectors.semantic_detector import detect_semantic, retrain_model
from pii.presidio_custom import detect_pii, mask_pii, get_pii_summary
from policy.policy_engine import decide
from utils.language import detect_language
from utils.logging import log_request

app = Flask(__name__)


# ── Home ──────────────────────────────────────────────────────────────────────
@app.route("/")
def home():
    return jsonify({
        "status": "running",
        "message": "LLM Security Gateway is active.",
        "endpoints": ["/analyze", "/health", "/retrain"]
    })


# ── Health ────────────────────────────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# ── Main Analysis Endpoint ────────────────────────────────────────────────────
@app.route("/analyze", methods=["POST"])
def analyze():
    start_time = time.time()

    data = request.get_json()
    if not data or "input" not in data:
        return jsonify({"error": "Missing 'input' field"}), 400

    text = data["input"]
    input_id = data.get("id", str(uuid.uuid4())[:8])

    # Step 1: Language Detection
    language = detect_language(text)

    # Step 2: Rule-based Detection
    rule_result = detect_injection(text)
    rule_score = rule_result["rule_score"]

    # Step 3: Semantic / ML Detection
    semantic_result = detect_semantic(text)
    semantic_score = semantic_result["semantic_score"]

    # Step 4: PII Detection
    pii_results = detect_pii(text)
    pii_summary = get_pii_summary(pii_results)

    # Step 5: Policy Decision
    policy = decide(rule_score, semantic_score, pii_summary)
    decision = policy["decision"]
    final_risk = policy["final_risk"]
    reason_codes = policy["reason_codes"]

    # Step 6: Build safe output
    safe_text = None
    if decision == "MASK":
        safe_text = mask_pii(text, pii_results)
    elif decision == "ALLOW":
        safe_text = text

    latency_ms = round((time.time() - start_time) * 1000, 2)

    response = {
        "input_id": input_id,
        "language": language,
        "rule_score": round(rule_score, 4),
        "matched_patterns": rule_result["matched_patterns"],
        "semantic_score": round(semantic_score, 4),
        "pii_entities": pii_summary,
        "final_risk": final_risk,
        "decision": decision,
        "safe_text": safe_text,
        "reason_codes": reason_codes,
        "latency_ms": latency_ms,
    }

    # Step 7: Audit Log
    log_request({
        "input_id": input_id,
        "language": language,
        "rule_score": rule_score,
        "semantic_score": semantic_score,
        "final_risk": final_risk,
        "decision": decision,
        "reason_codes": reason_codes,
        "latency_ms": latency_ms,
    })

    return jsonify(response)


# ── Retrain Endpoint ──────────────────────────────────────────────────────────
@app.route("/retrain", methods=["POST"])
def retrain():
    data = request.get_json()
    extra = data.get("samples", []) if data else []
    result = retrain_model(extra)
    return jsonify(result)


# ── Batch Analysis ────────────────────────────────────────────────────────────
@app.route("/batch", methods=["POST"])
def batch():
    data = request.get_json()
    if not data or "inputs" not in data:
        return jsonify({"error": "Missing 'inputs' array"}), 400

    results = []
    for item in data["inputs"]:
        with app.test_request_context(
            "/analyze",
            method="POST",
            json=item,
            content_type="application/json",
        ):
            pass
    # Simple loop approach
    for item in data["inputs"]:
        with app.test_client() as c:
            r = c.post("/analyze", json=item)
            results.append(r.get_json())

    return jsonify({"results": results})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
