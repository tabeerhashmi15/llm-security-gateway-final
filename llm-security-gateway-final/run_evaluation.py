# run_evaluation.py
# Runs the full evaluation on data/final_eval.csv
# Produces results/evaluation_results.csv and results/metrics_summary.json

import csv
import json
import os
import sys
import time

# Add app directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "app"))

from detectors.rule_detector import detect_injection
from detectors.semantic_detector import detect_semantic
from pii.presidio_custom import detect_pii, get_pii_summary
from policy.policy_engine import decide
from utils.language import detect_language

DATA_PATH = "data/final_eval.csv"
RESULTS_PATH = "results/evaluation_results.csv"
METRICS_PATH = "results/metrics_summary.json"

os.makedirs("results", exist_ok=True)


def run_single(text):
    start = time.time()
    language = detect_language(text)
    rule_result = detect_injection(text)
    semantic_result = detect_semantic(text)
    pii_results = detect_pii(text)
    pii_summary = get_pii_summary(pii_results)
    policy = decide(rule_result["rule_score"], semantic_result["semantic_score"], pii_summary)
    latency = round((time.time() - start) * 1000, 2)
    return {
        "language": language,
        "rule_score": rule_result["rule_score"],
        "semantic_score": semantic_result["semantic_score"],
        "final_risk": policy["final_risk"],
        "decision": policy["decision"],
        "reason_codes": "|".join(policy["reason_codes"]),
        "latency_ms": latency,
    }


def compute_metrics(rows, mode="hybrid"):
    tp = fp = tn = fn = 0
    for r in rows:
        expected = r["expected_policy"].upper()
        predicted = r[f"{mode}_decision"].upper()
        is_attack = expected == "BLOCK"
        predicted_attack = predicted == "BLOCK"
        if is_attack and predicted_attack:
            tp += 1
        elif not is_attack and predicted_attack:
            fp += 1
        elif not is_attack and not predicted_attack:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (tp + tn) / len(rows) if rows else 0

    return {
        "mode": mode,
        "total": len(rows),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def rule_only_decision(rule_score, pii_summary):
    """Simulate midterm rule-only system for comparison."""
    raw_count = round(rule_score * 3)
    if raw_count >= 2:
        return "BLOCK"
    elif len(pii_summary) > 0:
        return "MASK"
    return "ALLOW"


def main():
    if not os.path.exists(DATA_PATH):
        print(f"ERROR: {DATA_PATH} not found. Please place the dataset file there.")
        sys.exit(1)

    rows = []
    latencies = []

    with open(DATA_PATH, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        dataset = list(reader)

    print(f"Evaluating {len(dataset)} samples...")

    for row in dataset:
        text = row["prompt"]
        result = run_single(text)

        # Rule-only baseline
        rule_r = detect_injection(text)
        pii_r = get_pii_summary(detect_pii(text))
        rule_dec = rule_only_decision(rule_r["rule_score"], pii_r)

        combined = {
            **row,
            "detected_language": result["language"],
            "rule_score": result["rule_score"],
            "semantic_score": result["semantic_score"],
            "final_risk": result["final_risk"],
            "hybrid_decision": result["decision"],
            "rule_only_decision": rule_dec,
            "reason_codes": result["reason_codes"],
            "latency_ms": result["latency_ms"],
            "hybrid_correct": "YES" if result["decision"].upper() == row["expected_policy"].upper() else "NO",
            "rule_correct": "YES" if rule_dec.upper() == row["expected_policy"].upper() else "NO",
        }
        rows.append(combined)
        latencies.append(result["latency_ms"])

    # Write results CSV
    fieldnames = list(rows[0].keys())
    with open(RESULTS_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    # Compute metrics
    hybrid_metrics = compute_metrics(rows, "hybrid")
    rule_metrics = compute_metrics(rows, "rule_only")

    # Per-language breakdown
    langs = {}
    for r in rows:
        lang = r.get("language", "en")
        if lang not in langs:
            langs[lang] = []
        langs[lang].append(r)
    lang_metrics = {lang: compute_metrics(samples, "hybrid") for lang, samples in langs.items()}

    # Latency stats
    sorted_lat = sorted(latencies)
    n = len(sorted_lat)
    lat_stats = {
        "mean_ms": round(sum(sorted_lat) / n, 2),
        "median_ms": round(sorted_lat[n // 2], 2),
        "p95_ms": round(sorted_lat[int(0.95 * n)], 2),
        "min_ms": round(sorted_lat[0], 2),
        "max_ms": round(sorted_lat[-1], 2),
    }

    summary = {
        "hybrid_metrics": hybrid_metrics,
        "rule_only_metrics": rule_metrics,
        "per_language_metrics": lang_metrics,
        "latency": lat_stats,
    }

    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print("\n=== EVALUATION COMPLETE ===")
    print(f"Results saved to: {RESULTS_PATH}")
    print(f"Metrics saved to: {METRICS_PATH}")
    print(f"\nHybrid  → Accuracy: {hybrid_metrics['accuracy']}  F1: {hybrid_metrics['f1']}")
    print(f"Rule-only→ Accuracy: {rule_metrics['accuracy']}  F1: {rule_metrics['f1']}")
    print(f"\nLatency → Mean: {lat_stats['mean_ms']}ms  p95: {lat_stats['p95_ms']}ms")


if __name__ == "__main__":
    main()
