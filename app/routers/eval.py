"""Evaluation Benchmark API Router for Agent Hijack Shield."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Query

from app.security.auth import AuthenticatedUser, require_role
from app.shield.detector import Detector
from app.shield.trust import TrustLevel

router = APIRouter(prefix="/v1/eval", tags=["Evaluation & Benchmarks"])

RESULTS_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "eval", "results.json"))
EVAL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "eval"))


@router.get("", summary="Get Latest Evaluation Benchmark Results")
async def get_eval_results(
    user: AuthenticatedUser = Depends(require_role("analyst")),
) -> Dict[str, Any]:
    """Returns stored benchmark evaluation results across all splits."""
    if not os.path.exists(RESULTS_FILE):
        raise HTTPException(status_code=404, detail="No evaluation results found. Run evaluation first.")
    try:
        with open(RESULTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to read evaluation results: {exc}")


@router.post("/run", summary="Trigger On-Demand Evaluation Run")
async def run_evaluation(
    split: str = Query("train", enum=["train", "heldout", "adaptive", "benign_heldout", "adversarial_benign"]),
    user: AuthenticatedUser = Depends(require_role("admin")),
) -> Dict[str, Any]:
    """Runs synchronous benchmark evaluation for the selected dataset split."""
    detector = Detector()

    file_mapping = {
        "train": "attacks_train.json",
        "heldout": "attacks_heldout.json",
        "adaptive": "adaptive_attacks.json",
        "benign_heldout": "benign_heldout.json",
        "adversarial_benign": "adversarial_benign.json",
    }
    filename = file_mapping.get(split)
    filepath = os.path.join(EVAL_DIR, filename)

    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail=f"Dataset file {filename} not found")

    with open(filepath, "r", encoding="utf-8") as f:
        samples = json.load(f)

    is_attack_split = split in ("train", "heldout", "adaptive")
    results = []
    blocks = 0
    flags = 0
    allows = 0

    for item in samples:
        text = item["text"]
        trust = TrustLevel.USER if ("educational" in item.get("category", "") or not is_attack_split) else TrustLevel.EXTERNAL
        res = detector.scan_text(text, trust_level=trust)
        if res.verdict == "BLOCK":
            blocks += 1
        elif res.verdict == "FLAG":
            flags += 1
        else:
            allows += 1

        results.append({
            "id": item.get("id"),
            "category": item.get("category"),
            "verdict": res.verdict,
            "risk_score": res.risk_score,
            "reasons": res.reason_codes,
        })

    total = len(samples)
    detected = blocks + flags

    if is_attack_split:
        recall = round((detected / total) * 100.0, 2) if total > 0 else 0.0
        return {
            "split": split,
            "total_samples": total,
            "recall_percent": recall,
            "breakdown": {"BLOCK": blocks, "FLAG": flags, "ALLOW": allows},
            "misses_count": allows,
        }
    else:
        fpr = round((detected / total) * 100.0, 2) if total > 0 else 0.0
        return {
            "split": split,
            "total_samples": total,
            "false_positive_rate_percent": fpr,
            "breakdown": {"ALLOW": allows, "FLAG": flags, "BLOCK": blocks},
            "false_positives_count": detected,
        }
