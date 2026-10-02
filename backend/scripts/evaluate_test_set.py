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

Artifact Export:
  - Generates evaluation_report.json with timestamp, commit SHA, latency percentiles,
    and category-by-category scorecard for judge evaluation & slide deck integration.
"""

import sys
import os
import json
import time
import asyncio
import statistics
import argparse
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

# Ensure stdout handles UTF-8 on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Ensure backend directory is in sys.path
backend_dir = Path(__file__).resolve().parent.parent
repo_root = backend_dir.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

# Enforce deterministic, offline evaluation for reproducible benchmarking
os.environ.setdefault("OSINT_OFFLINE", "1")

from shared.models import ScanRequest, ScanResponse, PrdVerdictEnum, RiskTierEnum
from core.orchestrator import run_pipeline


def _get_git_commit_sha() -> str:
    """Safely retrieve the current git commit SHA."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=5
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except Exception:
        pass
    return "unknown"


def _calc_percentile(data: List[float], p: float) -> float:
    """Calculate percentile using linear interpolation between nearest ranks."""
    if not data:
        return 0.0
    sorted_data = sorted(data)
    idx = (len(sorted_data) - 1) * p
    lower = int(idx)
    upper = lower + 1
    weight = idx - lower
    if upper >= len(sorted_data):
        return round(sorted_data[lower], 2)
    return round(sorted_data[lower] * (1 - weight) + sorted_data[upper] * weight, 2)


async def evaluate_benchmark(dataset_path: Path, export_json_path: Optional[Path] = None) -> Dict[str, Any]:
    if not dataset_path.exists():
        print(f"Error: Dataset not found at {dataset_path}")
        sys.exit(1)

    with open(dataset_path, "r", encoding="utf-8") as f:
        cases: List[Dict[str, Any]] = json.load(f)

    commit_sha = _get_git_commit_sha()
    eval_timestamp = datetime.now(timezone.utc).isoformat()

    print("\n" + "=" * 80)
    print(" [SHIELD] PHISHLENS (SCAMSHIELD AI) - AUTOMATED BENCHMARK EVALUATION (PRD Sec 10)")
    print(f" Dataset : {dataset_path.name} ({len(cases)} Curated Payloads)")
    print(f" Commit  : {commit_sha[:10] if commit_sha != 'unknown' else 'N/A'}")
    print(f" Time    : {eval_timestamp}")
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

        # Check explanation coverage (both reasons and evidence must exist)
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
            "latency_ms": duration_ms,
            "reasons": resp.reasons[:3] if resp.reasons else [],
            "action_required": resp.action_required.value if resp.action_required else None
        })

    # Metric calculations
    detection_rate = round((scam_detected / scam_total * 100) if scam_total > 0 else 0.0, 2)
    fp_rate = round((benign_false_positives / benign_total * 100) if benign_total > 0 else 0.0, 2)
    explanation_rate = round((explanation_verified / len(cases) * 100) if cases else 0.0, 2)
    
    # Latency percentiles
    p50_latency = _calc_percentile(latencies, 0.50)
    p90_latency = _calc_percentile(latencies, 0.90)
    p95_latency = _calc_percentile(latencies, 0.95)
    p99_latency = _calc_percentile(latencies, 0.99)
    mean_latency = round(statistics.mean(latencies), 2) if latencies else 0.0
    min_latency = round(min(latencies), 2) if latencies else 0.0
    max_latency = round(max(latencies), 2) if latencies else 0.0

    # Category-by-category breakdown
    category_stats: Dict[str, Dict[str, Any]] = {}
    for r in results:
        cat = r["category"]
        if cat not in category_stats:
            category_stats[cat] = {
                "category": cat,
                "expected_verdict": r["expected"],
                "total": 0,
                "passed": 0,
                "failed": 0,
                "scores": [],
                "latencies": []
            }
        category_stats[cat]["total"] += 1
        if r["pass"]:
            category_stats[cat]["passed"] += 1
        else:
            category_stats[cat]["failed"] += 1
        category_stats[cat]["scores"].append(r["score"])
        category_stats[cat]["latencies"].append(r["latency_ms"])

    category_breakdown = []
    for cat, stats in sorted(category_stats.items()):
        cat_mean_lat = round(statistics.mean(stats["latencies"]), 2) if stats["latencies"] else 0.0
        cat_pass_rate = round((stats["passed"] / stats["total"]) * 100, 2) if stats["total"] > 0 else 0.0
        cat_avg_score = round(statistics.mean(stats["scores"]), 1) if stats["scores"] else 0.0
        category_breakdown.append({
            "category": cat,
            "expected_verdict": stats["expected_verdict"],
            "total_cases": stats["total"],
            "passed_cases": stats["passed"],
            "failed_cases": stats["failed"],
            "pass_rate_percent": cat_pass_rate,
            "mean_latency_ms": cat_mean_lat,
            "avg_risk_score": cat_avg_score
        })

    all_passed = bool(
        detection_rate >= 85.0
        and fp_rate <= 10.0
        and explanation_rate >= 99.0
        and p50_latency < 1000.0
    )

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
    lat_status = "PASSED (Target < 1000ms)" if p50_latency < 1000.0 else "HIGH LATENCY"

    print(f" 1. Scam Detection Rate    : {detection_rate:6.2f}% ({scam_detected}/{scam_total})   [{det_status}]")
    print(f" 2. Benign False Positive  : {fp_rate:6.2f}% ({benign_false_positives}/{benign_total})   [{fp_status}]")
    print(f" 3. Explanation Coverage   : {explanation_rate:6.2f}% ({explanation_verified}/{len(cases)})   [{exp_status}]")
    print(f" 4. Median Pipeline Latency: {p50_latency:6.1f} ms                      [{lat_status}]")
    print(f" 5. Latency Percentiles    : P50={p50_latency}ms | P90={p90_latency}ms | P95={p95_latency}ms | P99={p99_latency}ms")
    print(f" 6. Mean / Min / Max Latency: {mean_latency}ms / {min_latency}ms / {max_latency}ms")
    print("=" * 80 + "\n")

    report_data = {
        "report_version": "2.0",
        "system_name": "PhishLens (ScamShield AI)",
        "timestamp_utc": eval_timestamp,
        "git_commit_sha": commit_sha,
        "dataset_name": dataset_path.name,
        "summary": {
            "total_cases_evaluated": len(cases),
            "scam_cases_total": scam_total,
            "scam_cases_detected": scam_detected,
            "scam_detection_rate_percent": detection_rate,
            "benign_cases_total": benign_total,
            "benign_cases_clean": benign_total - benign_false_positives,
            "benign_false_positives": benign_false_positives,
            "false_positive_rate_percent": fp_rate,
            "explanation_coverage_percent": explanation_rate,
            "all_prd_targets_met": all_passed
        },
        "target_benchmarks": {
            "scam_detection_rate": ">= 85.0%",
            "false_positive_rate": "<= 10.0%",
            "explanation_coverage": "100.0%",
            "median_latency": "< 1000.0ms"
        },
        "latency_percentiles_ms": {
            "p50_median": p50_latency,
            "p90": p90_latency,
            "p95": p95_latency,
            "p99": p99_latency,
            "mean": mean_latency,
            "min": min_latency,
            "max": max_latency
        },
        "category_breakdown": category_breakdown,
        "case_evaluations": results
    }

    if export_json_path:
        export_json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(export_json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        print(f"[EXPORT] Evaluation Scorecard successfully exported to: {export_json_path}\n")

    return report_data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PhishLens PRD Sec 10 Benchmark Evaluation Runner")
    parser.add_argument(
        "--dataset",
        type=str,
        default=str(repo_root / "datasets" / "benchmark_60.json"),
        help="Path to evaluation dataset JSON"
    )
    parser.add_argument(
        "--export-json",
        nargs="?",
        const=str(repo_root / "evaluation_report.json"),
        default=str(repo_root / "evaluation_report.json"),
        help="Export evaluation scorecard to specified JSON path (default: evaluation_report.json at repo root)"
    )

    args = parser.parse_args()
    benchmark_file = Path(args.dataset)
    export_file = Path(args.export_json) if args.export_json else None

    report = asyncio.run(evaluate_benchmark(benchmark_file, export_file))
    if not report["summary"]["all_prd_targets_met"]:
        print("Benchmark completed with some threshold warnings.")
        sys.exit(1)
    else:
        print("[SUCCESS] All PRD Section 10 Hackathon Success Metrics MET!")
