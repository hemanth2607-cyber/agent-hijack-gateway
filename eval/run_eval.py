"""Evaluation benchmark runner for Agent Hijack Shield.

Computes:
- Recall (Attack Detection Rate)
- False Positive Rate (FPR)
- Precision & F1 Score
- Confusion Matrix (TP, FP, TN, FN)
- Latency percentiles (p50, p95, p99, max)
- Per-category metrics breakdown
- Complete diagnostic trace of every False Positive and False Negative
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Tuple

# Ensure project root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Ensure UTF-8 console output for multilingual symbols
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app.shield.detector import Detector
from app.shield.trust import TrustLevel


def load_dataset(file_path: str) -> List[Dict[str, Any]]:
    """Loads a JSON dataset file."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Dataset file not found: {file_path}")
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def evaluate_set(
    detector: Detector,
    dataset: List[Dict[str, Any]],
    is_attack: bool,
    default_trust_level: TrustLevel = TrustLevel.EXTERNAL,
) -> Dict[str, Any]:
    """Runs detector over a dataset and collects predictions and latencies."""
    results = []
    latencies = []

    for item in dataset:
        text = item["text"]
        cat = item.get("category", "unknown")
        item_id = item.get("id", "unknown")

        # For educational hard negatives, test under USER trust level
        if "educational" in cat or "benign" in cat:
            trust_lvl = TrustLevel.USER
        else:
            trust_lvl = default_trust_level

        t0 = time.perf_counter()
        scan_res = detector.scan_text(text, trust_level=trust_lvl)
        lat_ms = (time.perf_counter() - t0) * 1000.0

        latencies.append(lat_ms)
        is_detected = scan_res.verdict in ("BLOCK", "FLAG")

        results.append(
            {
                "id": item_id,
                "category": cat,
                "text": text,
                "is_attack": is_attack,
                "verdict": scan_res.verdict,
                "risk_score": scan_res.risk_score,
                "is_detected": is_detected,
                "reasons": scan_res.reason_codes,
                "findings": [f.model_dump() for f in scan_res.findings],
                "latency_ms": lat_ms,
            }
        )

    return {"results": results, "latencies": latencies}


def run_benchmark(
    split: str = "train",
    detector: Optional[Detector] = None,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Executes the full evaluation pipeline and prints formatted reports."""
    det = detector or Detector()
    base_dir = os.path.dirname(__file__)

    # 1. Load Attack Set based on split
    if split == "train":
        attacks_file = os.path.join(base_dir, "attacks_train.json")
    elif split == "heldout":
        attacks_file = os.path.join(base_dir, "attacks_heldout.json")
    elif split == "adaptive":
        attacks_file = os.path.join(base_dir, "adaptive_attacks.json")
    elif split == "all":
        # Combine all attacks
        attacks_file = None
    else:
        raise ValueError(f"Unknown split: {split}")

    benign_file = os.path.join(base_dir, "benign.json")

    if split == "all":
        attacks = (
            load_dataset(os.path.join(base_dir, "attacks_train.json"))
            + load_dataset(os.path.join(base_dir, "attacks_heldout.json"))
            + load_dataset(os.path.join(base_dir, "adaptive_attacks.json"))
        )
    else:
        attacks = load_dataset(attacks_file)

    benign = load_dataset(benign_file)

    print(f"\n=======================================================")
    print(f"  RUNNING SHIELD EVALUATION (Split: {split.upper()})")
    print(f"  Attacks: {len(attacks)} | Benign: {len(benign)}")
    print(f"=======================================================\n")

    # 2. Run Inferences
    attack_eval = evaluate_set(det, attacks, is_attack=True)
    benign_eval = evaluate_set(det, benign, is_attack=False)

    all_latencies = sorted(attack_eval["latencies"] + benign_eval["latencies"])

    # 3. Calculate Confusion Matrix
    tp = sum(1 for r in attack_eval["results"] if r["is_detected"])
    fn = len(attacks) - tp

    fp = sum(1 for r in benign_eval["results"] if r["is_detected"])
    tn = len(benign) - fp

    total = len(attacks) + len(benign)
    recall = (tp / (tp + fn)) * 100.0 if (tp + fn) > 0 else 0.0
    fpr = (fp / (fp + tn)) * 100.0 if (fp + tn) > 0 else 0.0
    precision = (tp / (tp + fp)) * 100.0 if (tp + fp) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = ((tp + tn) / total) * 100.0

    p50 = all_latencies[int(len(all_latencies) * 0.50)]
    p95 = all_latencies[int(len(all_latencies) * 0.95)]
    p99 = all_latencies[int(len(all_latencies) * 0.99)]
    max_lat = all_latencies[-1]

    # 4. Per-Category Breakdown & Verdict Breakdown
    attack_verdicts = {"BLOCK": 0, "FLAG": 0, "ALLOW": 0}
    for r in attack_eval["results"]:
        attack_verdicts[r["verdict"]] = attack_verdicts.get(r["verdict"], 0) + 1

    benign_verdicts = {"ALLOW": 0, "FLAG": 0, "BLOCK": 0}
    for r in benign_eval["results"]:
        benign_verdicts[r["verdict"]] = benign_verdicts.get(r["verdict"], 0) + 1

    category_metrics: Dict[str, Dict[str, Any]] = {}
    for r in attack_eval["results"]:
        cat = r["category"]
        if cat not in category_metrics:
            category_metrics[cat] = {"total": 0, "detected": 0, "block": 0, "flag": 0}
        category_metrics[cat]["total"] += 1
        if r["is_detected"]:
            category_metrics[cat]["detected"] += 1
        if r["verdict"] == "BLOCK":
            category_metrics[cat]["block"] += 1
        elif r["verdict"] == "FLAG":
            category_metrics[cat]["flag"] += 1

    for cat, data in category_metrics.items():
        data["recall"] = round((data["detected"] / data["total"]) * 100.0, 1)

    # 5. Missed Attacks and False Positives
    missed_attacks = [r for r in attack_eval["results"] if not r["is_detected"]]
    false_positives = [r for r in benign_eval["results"] if r["is_detected"]]

    # Print Summary Table
    print(f"+---------------------------------------------+")
    print(f"| METRIC                   | VALUE            |")
    print(f"+--------------------------+------------------+")
    print(f"| Total Samples Evaluated  | {total:<16} |")
    print(f"| Recall (Detection Rate)  | {recall:>6.2f}%          |")
    print(f"| False Positive Rate(FPR) | {fpr:>6.2f}%          |")
    print(f"| Precision                | {precision:>6.2f}%          |")
    print(f"| F1-Score                 | {f1:>6.2f}%          |")
    print(f"| Accuracy                 | {accuracy:>6.2f}%          |")
    print(f"+--------------------------+------------------+")
    print(f"| True Positives (TP)      | {tp:<16} |")
    print(f"| False Negatives (FN)     | {fn:<16} |")
    print(f"| True Negatives (TN)      | {tn:<16} |")
    print(f"| False Positives (FP)     | {fp:<16} |")
    print(f"+--------------------------+------------------+")
    print(f"| Latency p50 / p95        | {p50:.2f}ms / {p95:.2f}ms  |")
    print(f"| Latency p99 / Max        | {p99:.2f}ms / {max_lat:.2f}ms  |")
    print(f"+---------------------------------------------+\n")

    print(f"--- Verdict Breakdown ---")
    print(f"  * Attacks (n={len(attacks)}): BLOCK={attack_verdicts['BLOCK']} ({attack_verdicts['BLOCK']/len(attacks)*100:.1f}%), FLAG={attack_verdicts['FLAG']} ({attack_verdicts['FLAG']/len(attacks)*100:.1f}%), ALLOW={attack_verdicts['ALLOW']} ({attack_verdicts['ALLOW']/len(attacks)*100:.1f}%)")
    print(f"  * Benign  (n={len(benign)}): ALLOW={benign_verdicts['ALLOW']} ({benign_verdicts['ALLOW']/len(benign)*100:.1f}%), FLAG={benign_verdicts['FLAG']} ({benign_verdicts['FLAG']/len(benign)*100:.1f}%), BLOCK={benign_verdicts['BLOCK']} ({benign_verdicts['BLOCK']/len(benign)*100:.1f}%)")
    print(f"  * Note on Detection: Both BLOCK (hard refuse) and FLAG (step-up approval / session taint) count as detected.")

    print(f"\n--- Per-Category Attack Recall ---")
    for cat, data in sorted(category_metrics.items()):
        print(f"  * {cat:<26}: {data['detected']}/{data['total']} ({data['recall']}%) [BLOCK: {data['block']}, FLAG: {data['flag']}]")

    print(f"\n--- Diagnostics ---")
    print(f"  Missed Attacks (FN): {len(missed_attacks)}")
    for ma in missed_attacks:
        print(f"    - [{ma['id']}] ({ma['category']}): {ma['text'][:65]}... (score: {ma['risk_score']})")

    print(f"  False Positives (FP): {len(false_positives)}")
    for fpos in false_positives:
        print(f"    - [{fpos['id']}] ({fpos['category']}): {fpos['text'][:65]}... (score: {fpos['risk_score']}, reasons: {fpos['reasons'][:2]})")

    report = {
        "split": split,
        "total_samples": total,
        "metrics": {
            "recall": round(recall, 2),
            "false_positive_rate": round(fpr, 2),
            "precision": round(precision, 2),
            "f1_score": round(f1, 2),
            "accuracy": round(accuracy, 2),
            "confusion_matrix": {"tp": tp, "fn": fn, "tn": tn, "fp": fp},
            "latencies_ms": {"p50": round(p50, 2), "p95": round(p95, 2), "p99": round(p99, 2), "max": round(max_lat, 2)},
        },
        "verdict_breakdown": {
            "attacks": attack_verdicts,
            "benign": benign_verdicts,
        },
        "per_category": category_metrics,
        "missed_attacks": missed_attacks,
        "false_positives": false_positives,
    }

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\nSaved evaluation report to: {output_path}")

    return report


def evaluate_benign_standalone(
    benign_path: str,
    detector: Optional[Detector] = None,
) -> Dict[str, Any]:
    """Runs evaluation on a standalone benign set to compute FPR and identify false positives."""
    det = detector or Detector()
    samples = load_dataset(benign_path)
    eval_res = evaluate_set(det, samples, is_attack=False)

    fps = [r for r in eval_res["results"] if r["is_detected"]]
    fpr = (len(fps) / len(samples)) * 100.0 if samples else 0.0

    print(f"\n=======================================================")
    print(f"  RUNNING BENIGN EVALUATION: {os.path.basename(benign_path)}")
    print(f"  Total Benign Samples: {len(samples)}")
    print(f"=======================================================\n")
    print(f"False Positive Rate (FPR): {fpr:.2f}% ({len(fps)} / {len(samples)})")
    if fps:
        print("\n--- False Positives Detected ---")
        for fp in fps:
            print(f"  - [{fp['id']}]: {fp['text'][:60]}... (score: {fp['risk_score']:.1f}, reasons: {fp['reasons']})")
    else:
        print("\n--- Diagnostics: 0 False Positives Identified! (Zero FPR) ---")

    return {
        "dataset": os.path.basename(benign_path),
        "total_samples": len(samples),
        "false_positive_count": len(fps),
        "false_positive_rate": fpr,
        "false_positives": [
            {
                "id": r["id"],
                "text": r["text"],
                "verdict": r["verdict"],
                "risk_score": r["risk_score"],
                "reasons": r["reasons"],
            }
            for r in fps
        ],
    }


def run_full_suite_and_save_results(output_file: str = "eval/results.json"):
    """Runs evaluation across heldout, adaptive, train sets, and benign_heldout, saving full results to eval/results.json."""
    det = Detector()
    base_dir = os.path.dirname(__file__)

    print("\n" + "=" * 60)
    print("  RUNNING COMPREHENSIVE BENCHMARK SUITE")
    print("=" * 60)

    heldout_report = run_benchmark(split="heldout", detector=det)
    adaptive_report = run_benchmark(split="adaptive", detector=det)
    train_report = run_benchmark(split="train", detector=det)
    benign_heldout_report = evaluate_benign_standalone(
        os.path.join(base_dir, "benign_heldout.json"), detector=det
    )

    combined_results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "counting_methodology": {
            "description": "Detection counts both BLOCK (hard refuse, risk >= 60 external / 75 user) and FLAG (taint/approval escalation, risk >= 30 external / 40 user). Misses are samples that evaluate to ALLOW.",
            "is_detected": "verdict in ('BLOCK', 'FLAG')",
        },
        "splits": {
            "heldout": heldout_report,
            "adaptive": adaptive_report,
            "train": train_report,
            "benign_heldout": benign_heldout_report,
        },
    }

    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(combined_results, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Successfully saved all benchmark results to: {output_file}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Agent Hijack Shield Benchmark Runner")
    parser.add_argument(
        "--split",
        choices=["train", "heldout", "adaptive", "all", "suite", "benign_heldout"],
        default="suite",
    )
    parser.add_argument("--output", type=str, default="eval/results.json")
    args = parser.parse_args()

    if args.split == "suite":
        run_full_suite_and_save_results(output_file=args.output)
    elif args.split == "benign_heldout":
        evaluate_benign_standalone(os.path.join(os.path.dirname(__file__), "benign_heldout.json"))
    else:
        run_benchmark(split=args.split, output_path=args.output)

