"""
PhishLens (ScamShield AI) — Evaluation Benchmark Runner (PRD Section 10)
Owner: AVIKA (Risk Scoring Engine & Evaluation Lead)

Evaluates the multi-agent detection pipeline against the 60-message curated benchmark
dataset (35 Indian scam payloads, 25 benign messages).

Target Metrics:
  - Scam Detection Rate: >= 85%
  - Benign False Positive Rate: <= 10%
  - Explanation Coverage: 100%
  - Median Pipeline Latency: < 1000ms
"""

import sys
import os
import json
import time
import asyncio
import statistics
from pathlib import Path
from typing import List, Dict, Any

# Ensure stdout handles UTF-8 on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Ensure backend directory is in sys.path
backend_dir = Path(__file__).resolve().parent.parent
repo_root = backend_dir.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from shared.models import ScanRequest, ScanResponse, PrdVerdictEnum, RiskTierEnum
from core.orchestrator import run_pipeline


async def evaluate_benchmark(dataset_path: Path):
    if not dataset_path.exists():
        print(f"Error: Dataset not found at {dataset_path}")
        sys.exit(1)

    with open(dataset_path, "r", encoding="utf-8") as f:
        cases: List[Dict[str, Any]] = json.load(f)

    print("\n" + "=" * 80)
    print(" [SHIELD] PHISHLENS (SCAMSHIELD AI) - AUTOMATED BENCHMARK EVALUATION (PRD Sec 10)")
    print(f" Dataset: {dataset_path.name} ({len(cases)} Curated Payloads)")
    print("=" * 80 + "\n")

    results = []
    latencies = []
    scam_total = 0
    scam_detected = 0
    benign_total = 0
    benign_false_positives = 0
    explanation_verified = 0

    print(f"{'ID':<11} | {'Category':<32} | {'Expected':<12} | {'Actual':<12} | {'Score':<5} | {'Latency':<8} | {'Status'}")
    print("-" * 96)

    for case in cases:
        case_id = case["id"]
        category = case["category"]
        expected_verdict = case["expected_verdict"]
        payload_data = case["payload"]

        req = ScanRequest(
            content=payload_data["content"],
            sender=payload_data.get("sender"),
            extracted_url=payload_data.get("extracted_url"),
            channel=payload_data.get("channel", "sms")
        )

        start = time.perf_counter()
        resp: ScanResponse = await run_pipeline(req)
        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        latencies.append(duration_ms)

        actual_verdict = resp.verdict_category.value
        score = resp.overall_risk_score

        # Check explanation coverage
        has_reasons = bool(resp.reasons and len(resp.reasons) > 0)
        has_evidence = bool(resp.evidence and len(resp.evidence) > 0)
        if has_reasons and has_evidence:
            explanation_verified += 1

        is_scam_case = expected_verdict in ["LIKELY_SCAM", "SUSPICIOUS"]
        is_pass = False

        if is_scam_case:
            scam_total += 1
            # For scam cases: detection counts if predicted LIKELY_SCAM or SUSPICIOUS
            if actual_verdict in ["LIKELY_SCAM", "SUSPICIOUS"]:
                scam_detected += 1
                is_pass = True
        else:
            benign_total += 1
            # For benign cases: must be SAFE (score <= 30)
            if actual_verdict == "SAFE":
                is_pass = True
            else:
                benign_false_positives += 1

        status_icon = "[PASS]" if is_pass else "[FAIL]"
        cat_disp = category[:30] + ".." if len(category) > 32 else category
        print(f"{case_id:<11} | {cat_disp:<32} | {expected_verdict:<12} | {actual_verdict:<12} | {score:<5} | {duration_ms:>6.1f}ms | {status_icon}")

        results.append({
            "id": case_id,
            "category": category,
            "expected": expected_verdict,
            "actual": actual_verdict,
            "score": score,
            "pass": is_pass,
            "latency_ms": duration_ms
        })

    # Metric calculations
    detection_rate = (scam_detected / scam_total * 100) if scam_total > 0 else 0.0
    fp_rate = (benign_false_positives / benign_total * 100) if benign_total > 0 else 0.0
    explanation_rate = (explanation_verified / len(cases) * 100) if cases else 0.0
    median_latency = statistics.median(latencies) if latencies else 0.0
    mean_latency = statistics.mean(latencies) if latencies else 0.0
    p95_latency = statistics.quantiles(latencies, n=20)[18] if len(latencies) >= 20 else max(latencies)

    print("\n" + "=" * 80)
    print(" EXECUTIVE EVALUATION SCORECARD (PRD Sec 10 COMPLIANCE REPORT)")
    print("=" * 80)
    print(f" Total Cases Evaluated   : {len(cases)}")
    print(f"   - Scam Payloads Tested : {scam_total}")
    print(f"   - Benign Alerts Tested : {benign_total}")
    print("-" * 80)

    det_status = "PASSED (Target >= 85%)" if detection_rate >= 85.0 else "BELOW TARGET"
    fp_status = "PASSED (Target <= 10%)" if fp_rate <= 10.0 else "ABOVE TARGET"
    exp_status = "PASSED (Target = 100%)" if explanation_rate >= 99.0 else "INCOMPLETE"
    lat_status = "PASSED (Target < 1000ms)" if median_latency < 1000.0 else "HIGH LATENCY"

    print(f" 1. Scam Detection Rate    : {detection_rate:6.2f}% ({scam_detected}/{scam_total})   [{det_status}]")
    print(f" 2. Benign False Positive  : {fp_rate:6.2f}% ({benign_false_positives}/{benign_total})   [{fp_status}]")
    print(f" 3. Explanation Coverage   : {explanation_rate:6.2f}% ({explanation_verified}/{len(cases)})   [{exp_status}]")
    print(f" 4. Median Pipeline Latency: {median_latency:6.1f} ms                      [{lat_status}]")
    print(f" 5. Mean Latency / P95     : {mean_latency:6.1f} ms / {p95_latency:6.1f} ms")
    print("=" * 80 + "\n")

    return {
        "detection_rate": detection_rate,
        "false_positive_rate": fp_rate,
        "explanation_coverage": explanation_rate,
        "median_latency_ms": median_latency,
        "all_passed": (detection_rate >= 85.0 and fp_rate <= 10.0 and explanation_rate >= 99.0)
    }


if __name__ == "__main__":
    benchmark_file = repo_root / "datasets" / "benchmark_60.json"
    scorecard = asyncio.run(evaluate_benchmark(benchmark_file))
    if not scorecard["all_passed"]:
        print("Benchmark completed with some threshold warnings.")
    else:
        print("[SUCCESS] All PRD Section 10 Hackathon Success Metrics MET!")
