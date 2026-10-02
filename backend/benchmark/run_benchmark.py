"""
run_benchmark.py — Automated accuracy validation benchmark runner.

Loads a local labeled dataset (labeled_data.json) and calculates
precision, recall, F1-score, and accuracy for the detection engine
across each AttackType category.

Makes actual live API calls using the credentials configured in settings.
"""

import json
import os
import sys
import time

# Ensure backend directory is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import settings
from contracts import AttackType
from detection_engine.detector import detect

BENCHMARK_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BENCHMARK_DIR, "labeled_data.json")


def run_benchmark():
    if not os.path.exists(DATA_FILE):
        print("No benchmark dataset available. Exiting.")
        return

    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            samples = json.load(f)
    except Exception as exc:
        print(f"Failed to read benchmark data file: {exc}")
        return

    print(f"Loaded {len(samples)} benchmark samples.")
    print("Evaluating detection engine accuracy using live API configuration...")
    print(f"Key configured: {settings.OPENAI_API_KEY[:8]}...{settings.OPENAI_API_KEY[-4:] if len(settings.OPENAI_API_KEY) > 4 else ''}")
    print("-" * 75)

    results_by_type = {}
    start_time = time.time()

    for idx, s in enumerate(samples):
        att_type = AttackType(s["attack_type"])
        payload = s.get("payload", "")
        response = s.get("response", "")
        expected = bool(s.get("expected_success", False))

        # Output progress for latency visualization
        sample_start = time.time()
        detection = detect(att_type, payload, response, scan_id=None)
        latency = time.time() - sample_start

        actual = bool(detection["success"])
        verdict_reason = detection.get("reason", "")[:60] + "..."

        print(
            f"[{idx+1}/{len(samples)}] Type: {att_type.value:<20} | Expected: {str(expected):<5} | "
            f"Actual: {str(actual):<5} | Latency: {latency:.2f}s | Reason: {verdict_reason}"
        )

        if att_type not in results_by_type:
            results_by_type[att_type] = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}

        counts = results_by_type[att_type]
        if expected and actual:
            counts["tp"] += 1
        elif not expected and actual:
            counts["fp"] += 1
        elif not expected and not actual:
            counts["tn"] += 1
        elif expected and not actual:
            counts["fn"] += 1

    total_time = time.time() - start_time
    print("-" * 75)
    print(f"Completed evaluation of {len(samples)} samples in {total_time:.2f} seconds.")
    print("-" * 75)

    # Print summary metrics table
    print(f"{'Attack Type':<25} | {'Acc':<6} | {'Prec':<6} | {'Recall':<6} | {'F1':<6} | {'Samples':<7}")
    print("-" * 65)

    total_tp = total_fp = total_tn = total_fn = 0

    for att_type, counts in results_by_type.items():
        tp, fp, tn, fn = counts["tp"], counts["fp"], counts["tn"], counts["fn"]
        total = tp + fp + tn + fn
        total_tp += tp
        total_fp += fp
        total_tn += tn
        total_fn += fn

        acc = (tp + tn) / total if total > 0 else 0.0
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

        print(f"{att_type.value:<25} | {acc:.3f} | {prec:.3f} | {rec:.3f} | {f1:.3f} | {total:<7}")

    grand_total = total_tp + total_fp + total_tn + total_fn
    if grand_total > 0:
        overall_acc = (total_tp + total_tn) / grand_total
        overall_prec = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
        overall_rec = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
        overall_f1 = 2 * overall_prec * overall_rec / (overall_prec + overall_rec) if (overall_prec + overall_rec) > 0 else 0.0

        print("-" * 65)
        print(f"{'OVERALL AGGREGATE':<25} | {overall_acc:.3f} | {overall_prec:.3f} | {overall_rec:.3f} | {overall_f1:.3f} | {grand_total:<7}")


if __name__ == "__main__":
    run_benchmark()
