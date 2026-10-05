"""
backend/scripts/refresh_dlt_registry.py
----------------------------------------
DLT Registry Nightly Refresh & NNP Prefix Mismatch Detector.
Author  : AVNI - Sender Identity & TRAI DLT Agent
Module  : PhishLens v1.0 (Sprint 2)
"""
from __future__ import annotations
import argparse
import json
import logging
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False

_SCRIPT_DIR = Path(__file__).resolve().parent
_BACKEND_DIR = _SCRIPT_DIR.parent
_DATA_DIR = _BACKEND_DIR / "data"
_REGISTRY_PATH = _DATA_DIR / "trai_dlt_registry.json"
_CIRCLE_PREFIX_PATH = _DATA_DIR / "trai_circle_prefix_registry.json"
_AUDIT_OUTPUT_PATH = _DATA_DIR / "dlt_refresh_audit.json"

_TRAI_DLT_API_URLS: List[str] = [
    "https://smsheader.trai.gov.in/api/public/header/list?format=json&page=1&page_size=5000",
    "https://smsheader.trai.gov.in/api/public/principal-entity/headers?format=json",
]
_REQUEST_TIMEOUT_S: float = 20.0
_USER_AGENT: str = (
    "PhishLens-DLT-Refresh/1.0 (ScamShield AI; "
    "contact=security@phishlens.in; "
    "purpose=anti-fraud-dlt-validation)"
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("dlt_refresh")


def _load_registry(path: Path) -> Dict[str, Any]:
    """Load a JSON file from path; return empty dict on failure."""
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        log.warning("Could not load %s: %s", path, exc)
        return {}


def _atomic_write_json(path: Path, data: Dict[str, Any]) -> None:
    """Write data as JSON to path atomically via a temp file + rename."""
    dir_ = path.parent
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", suffix=".json.tmp",
        dir=dir_, delete=False
    ) as tmp:
        json.dump(data, tmp, ensure_ascii=False, indent=2)
        tmp_path = Path(tmp.name)
    try:
        tmp_path.replace(path)
        log.info("Registry written to %s", path)
    except Exception as exc:
        tmp_path.unlink(missing_ok=True)
        raise RuntimeError(f"Atomic write to {path} failed: {exc}") from exc


def _validate_fetched_registry(raw: Any) -> Optional[Dict[str, dict]]:
    """Validate the fetched payload structure. Accepts both dict and list formats."""
    if isinstance(raw, dict) and "registry" in raw:
        reg = raw["registry"]
        if isinstance(reg, dict) and len(reg) > 0:
            return reg
    if isinstance(raw, list) and len(raw) > 0:
        converted: Dict[str, dict] = {}
        for item in raw:
            if not isinstance(item, dict):
                continue
            header = item.get("header") or item.get("sender_id") or ""
            parts = header.split("-", 1)
            if len(parts) != 2 or len(parts[1]) != 6:
                continue
            entity_code = parts[1].upper()
            prefix = parts[0].upper()
            if entity_code not in converted:
                converted[entity_code] = {
                    "brand_name": item.get("brand") or item.get("brand_name") or entity_code,
                    "category": item.get("category", "Unknown"),
                    "operator_prefixes": [],
                }
            if prefix and prefix not in converted[entity_code]["operator_prefixes"]:
                converted[entity_code]["operator_prefixes"].append(prefix)
        if converted:
            return converted
    return None


def _fetch_dlt_registry_sync() -> Optional[Dict[str, dict]]:
    """Attempt to fetch the DLT registry from the TRAI portal synchronously."""
    if not _HAS_HTTPX:
        log.warning("httpx not installed. Install: pip install httpx")
        return None

    hdrs = {"User-Agent": _USER_AGENT, "Accept": "application/json"}
    for url in _TRAI_DLT_API_URLS:
        try:
            log.info("Fetching DLT registry from %s", url)
            with httpx.Client(timeout=_REQUEST_TIMEOUT_S, follow_redirects=True) as client:
                resp = client.get(url, headers=hdrs)
            if resp.status_code == 200:
                raw = resp.json()
                reg = _validate_fetched_registry(raw)
                if reg:
                    log.info("Fetched %d entity codes from %s", len(reg), url)
                    return reg
                log.warning("Payload from %s failed validation", url)
            else:
                log.warning("HTTP %d from %s", resp.status_code, url)
        except Exception as exc:
            log.warning("Request to %s failed: %s", url, exc)
    return None


def refresh_registry(dry_run: bool = False, verbose: bool = False) -> Dict[str, Any]:
    """Main registry refresh routine. Returns a structured audit dict."""
    audit: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "local_only",
        "new_entries_added": 0,
        "updated_entries": 0,
        "circle_mismatches": [],
        "errors": [],
    }

    existing_data = _load_registry(_REGISTRY_PATH)
    existing_reg: Dict[str, dict] = existing_data.get("registry", {})
    existing_meta: Dict[str, Any] = existing_data.get("_meta", {})

    fetched_reg: Optional[Dict[str, dict]] = None
    try:
        fetched_reg = _fetch_dlt_registry_sync()
    except Exception as exc:
        audit["errors"].append(f"Remote fetch exception: {exc}")
        log.error("Remote fetch failed: %s", exc)

    if fetched_reg:
        audit["source"] = "remote"
        merged: Dict[str, dict] = dict(existing_reg)
        new_entries = 0
        updated_entries = 0
        for entity_code, entry in fetched_reg.items():
            if entity_code not in merged:
                new_entries += 1
            else:
                existing_prefixes = set(merged[entity_code].get("operator_prefixes", []))
                new_prefixes = set(entry.get("operator_prefixes", []))
                if new_prefixes != existing_prefixes:
                    updated_entries += 1
            merged[entity_code] = entry

        audit["new_entries_added"] = new_entries
        audit["updated_entries"] = updated_entries
        log.info("Merge: %d new, %d updated entity codes", new_entries, updated_entries)

        if not dry_run:
            merged_data = {
                "_meta": {
                    **existing_meta,
                    "last_updated": datetime.now(timezone.utc).date().isoformat(),
                    "last_refresh_source": "TRAI DLT Portal (automated nightly refresh)",
                    "entry_count": len(merged),
                },
                "registry": merged,
            }
            _atomic_write_json(_REGISTRY_PATH, merged_data)
    else:
        merged = existing_reg
        log.info("Remote unavailable -- running NNP audit on local registry only")

    mismatches = run_nnp_prefix_mismatch_audit(merged, verbose=verbose)
    audit["circle_mismatches"] = mismatches

    if not dry_run:
        _atomic_write_json(_AUDIT_OUTPUT_PATH, audit)

    return audit


# ===========================================================================
# Offline NNP Prefix Circle-Mismatch Parser (AVNI Sprint 2)
# ===========================================================================

_PAN_INDIA_CATEGORIES: Set[str] = {
    "Banking", "Government", "UIDAI", "IRCTC", "EPFO",
    "Payments Bank", "Insurance", "E-Commerce", "Finance",
}

_SINGLE_CIRCLE_PREFIXES: Dict[str, str] = {
    "NE": "North East",
    "HP": "Himachal Pradesh",
}


def run_nnp_prefix_mismatch_audit(
    registry: Dict[str, dict],
    verbose: bool = False,
) -> List[Dict[str, Any]]:
    """
    Offline NNP Prefix Circle-Mismatch Parser.

    Iterates every entry in registry and checks:
    1. Prefixes listed in the known-invalid registry (CRITICAL).
    2. Prefixes absent from the valid circle registry (HIGH).
    3. National-entity using a single-circle-only prefix (MEDIUM).
    4. Active entries using an inactive prefix (MEDIUM).

    Returns a list of mismatch dicts:
    {
        "entity_code": str,
        "brand_name": str,
        "suspect_prefix": str,
        "circle": str,
        "severity": "CRITICAL" | "HIGH" | "MEDIUM",
        "reason": str
    }
    """
    circle_reg_raw = _load_registry(_CIRCLE_PREFIX_PATH)
    valid_prefixes: Dict[str, dict] = circle_reg_raw.get("valid_prefixes", {})
    invalid_prefixes: Dict[str, dict] = circle_reg_raw.get(
        "known_invalid_or_unregistered_prefixes", {}
    )

    mismatches: List[Dict[str, Any]] = []

    for entity_code, entry in registry.items():
        brand_name: str = entry.get("brand_name", entity_code)
        category: str = entry.get("category", "Unknown")
        op_prefixes: List[str] = entry.get("operator_prefixes", [])
        is_national = category in _PAN_INDIA_CATEGORIES

        for prefix in op_prefixes:
            prefix_upper = prefix.upper()

            # Check 1: Known-invalid prefix
            if prefix_upper in invalid_prefixes:
                inv_entry = invalid_prefixes[prefix_upper]
                mismatches.append({
                    "entity_code": entity_code,
                    "brand_name": brand_name,
                    "suspect_prefix": prefix_upper,
                    "circle": "N/A -- INVALID PREFIX",
                    "severity": "CRITICAL",
                    "reason": (
                        f"Entity '{brand_name}' ({entity_code}) has prefix '{prefix_upper}' "
                        f"which is KNOWN INVALID. Note: {inv_entry.get('note', '')}"
                    ),
                })
                if verbose:
                    log.warning("[CRITICAL] %s -> invalid prefix '%s'", entity_code, prefix_upper)
                continue

            # Check 2: Single-circle / regional prefix used by national entity
            prefix_info = valid_prefixes.get(prefix_upper, {})
            prefix_circles = prefix_info.get("circles", [])
            is_restricted = (
                prefix_upper in _SINGLE_CIRCLE_PREFIXES
                or (prefix_upper in valid_prefixes and "All India" not in prefix_circles and len(prefix_circles) <= 3)
            )
            if is_national and is_restricted:
                circle = _SINGLE_CIRCLE_PREFIXES.get(prefix_upper) or ", ".join(prefix_circles or ["Regional"])
                mismatches.append({
                    "entity_code": entity_code,
                    "brand_name": brand_name,
                    "suspect_prefix": prefix_upper,
                    "circle": circle,
                    "severity": "MEDIUM",
                    "reason": (
                        f"National entity '{brand_name}' ({category}) uses "
                        f"single-circle prefix '{prefix_upper}' ({circle}). "
                        "May indicate fraudulent or stale registration."
                    ),
                })
                if verbose:
                    log.info("[MEDIUM] %s -> single-circle prefix '%s' for national entity",
                             entity_code, prefix_upper)
                continue

            # Check 3: Prefix not in valid registry
            if prefix_upper not in valid_prefixes:
                mismatches.append({
                    "entity_code": entity_code,
                    "brand_name": brand_name,
                    "suspect_prefix": prefix_upper,
                    "circle": "N/A -- UNREGISTERED PREFIX",
                    "severity": "HIGH",
                    "reason": (
                        f"Entity '{brand_name}' ({entity_code}) references unregistered "
                        f"operator prefix '{prefix_upper}' not in the TRAI circle registry."
                    ),
                })
                if verbose:
                    log.warning("[HIGH] %s -> unregistered prefix '%s'", entity_code, prefix_upper)
                continue

            # Check 4: Inactive prefix
            prefix_entry = valid_prefixes.get(prefix_upper, {})
            if prefix_entry and not prefix_entry.get("active", True):
                mismatches.append({
                    "entity_code": entity_code,
                    "brand_name": brand_name,
                    "suspect_prefix": prefix_upper,
                    "circle": ", ".join(prefix_entry.get("circles", ["Unknown"])),
                    "severity": "MEDIUM",
                    "reason": (
                        f"Entity '{brand_name}' ({entity_code}) uses prefix '{prefix_upper}' "
                        "which is marked INACTIVE in the TRAI circle registry."
                    ),
                })
                if verbose:
                    log.warning("[INACTIVE] %s -> inactive prefix '%s'", entity_code, prefix_upper)

    log.info(
        "NNP Prefix Mismatch Audit complete: %d mismatches in %d registry entries",
        len(mismatches), len(registry),
    )
    return mismatches


# ===========================================================================
# CLI Entry Point
# ===========================================================================

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PhishLens DLT Registry Nightly Refresh & NNP Prefix Mismatch Detector",
    )
    parser.add_argument("--dry-run", action="store_true", default=False,
                        help="Fetch and audit but do NOT write any files.")
    parser.add_argument("--verbose", "-v", action="store_true", default=False,
                        help="Print all mismatch details to stdout.")
    parser.add_argument("--nnp-only", action="store_true", default=False,
                        help="Skip remote fetch; audit local registry only.")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)

    log.info("=== PhishLens DLT Registry Refresh ===")
    log.info("Mode: %s%s",
             "DRY RUN -- " if args.dry_run else "",
             "NNP audit only" if args.nnp_only else "Full refresh + NNP audit")

    t0 = time.perf_counter()

    if args.nnp_only:
        registry_data = _load_registry(_REGISTRY_PATH)
        registry = registry_data.get("registry", {})
        mismatches = run_nnp_prefix_mismatch_audit(registry, verbose=args.verbose)
        audit: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "local_only",
            "new_entries_added": 0,
            "updated_entries": 0,
            "circle_mismatches": mismatches,
            "errors": [],
        }
        if not args.dry_run:
            _atomic_write_json(_AUDIT_OUTPUT_PATH, audit)
    else:
        audit = refresh_registry(dry_run=args.dry_run, verbose=args.verbose)

    elapsed = round(time.perf_counter() - t0, 3)

    print("\n=== Refresh Summary ===")
    print(f"  Source            : {audit['source']}")
    print(f"  New entries       : {audit['new_entries_added']}")
    print(f"  Updated entries   : {audit['updated_entries']}")
    print(f"  Circle mismatches : {len(audit['circle_mismatches'])}")
    if audit["errors"]:
        print(f"  Errors            : {len(audit['errors'])}")
        for err in audit["errors"]:
            print(f"    - {err}")
    print(f"  Elapsed           : {elapsed}s")

    if audit["circle_mismatches"]:
        print(f"\n--- Circle Mismatch Details ({len(audit['circle_mismatches'])} total) ---")
        for m in audit["circle_mismatches"]:
            sev = m.get("severity", "UNKNOWN")
            print(f"  [{sev}] {m['entity_code']} ({m['brand_name']}) "
                  f"-- prefix '{m['suspect_prefix']}': {m['reason'][:110]}...")

    if args.dry_run:
        print("\n[DRY RUN] No files written.")
    else:
        print(f"\nAudit report: {_AUDIT_OUTPUT_PATH}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
