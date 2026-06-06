"""
Shared ground-truth scoring helpers.

Used by tests/test_ground_truth.py and scripts/run_accuracy_benchmark.py
to compute precision, recall, F1, and hallucination metrics against a
known-good disk image with documented artifacts.

This module is intentionally side-effect free: it only loads/validates
manifests, scores findings, and produces reports.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Optional

# ── Paths ──────────────────────────────────────────────────────────
GROUND_TRUTH_IMAGE = Path("/evidence/cases/ground_truth.raw")
GROUND_TRUTH_MANIFEST = Path("/evidence/cases/ground_truth_manifest.json")
GROUND_TRUTH_RESULTS_DIR = Path("/results/benchmark")

# Planted marker strings — these are intentionally loud so the agent
# can't miss them in a YARA/extract_features pass on a clean image.
GT_SECRET_MARKER = "PLANTED_SECRET_MARKER_GT_001"
GT_CRED_MARKER = "PLANTED_CRED_GT_002"
GT_MALWARE_MARKER = "PLANTED_MALWARE_GT_003"
GT_NORMAL_MARKER = "PLANTED_NORMAL_GT_004"
GT_DELETED_PREFIX = "DELETED_FILE_GT_D"


def has_ground_truth() -> bool:
    """Return True only if both the image and the manifest are present."""
    return GROUND_TRUTH_IMAGE.exists() and GROUND_TRUTH_MANIFEST.exists()


# ── Manifest loading ──────────────────────────────────────────────
def load_manifest(path: Optional[Path] = None) -> dict[str, Any]:
    """Load the ground truth manifest from disk.

    Raises FileNotFoundError if the manifest does not exist.
    """
    manifest_path = path or GROUND_TRUTH_MANIFEST
    if not manifest_path.exists():
        raise FileNotFoundError(
            f"Ground truth manifest not found at {manifest_path}. "
            f"Run: sudo bash scripts/generate_ground_truth_image.sh"
        )
    with open(manifest_path, "r", encoding="utf-8") as f:
        return json.load(f)


def find_finding(
    findings: list[dict[str, Any]],
    *,
    ftype: Optional[str] = None,
    description_contains: Optional[str] = None,
    path_contains: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """Find the first finding matching all supplied filters.

    Filter semantics:
      - ftype: exact match against finding['type']
      - description_contains: substring match against finding['description']
      - path_contains: substring match against finding['path'] if present
    """
    for f in findings:
        if ftype is not None and f.get("type") != ftype:
            continue
        if description_contains is not None:
            desc = f.get("description") or ""
            if description_contains not in desc:
                continue
        if path_contains is not None:
            path = f.get("path") or ""
            if path_contains not in path:
                continue
        return f
    return None


def count_findings_matching(
    findings: list[dict[str, Any]],
    *,
    ftype: Optional[str] = None,
    description_contains: Optional[str] = None,
) -> int:
    """Count how many findings match the given filter."""
    return sum(
        1
        for f in findings
        if (ftype is None or f.get("type") == ftype)
        and (description_contains is None or description_contains in (f.get("description") or ""))
    )


# ── Hashing helpers ──────────────────────────────────────────────
def sha256_text(text: str) -> str:
    """Compute the SHA256 of a UTF-8 text string (no trailing newline)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Compute the SHA256 of a bytes object."""
    return hashlib.sha256(data).hexdigest()


# ── Detection logic ──────────────────────────────────────────────
def _normalise_text_blob(s: str) -> str:
    """Lowercase + collapse whitespace for fuzzy matching."""
    return re.sub(r"\s+", " ", (s or "").lower()).strip()


def detect_secret_in_text(text: str) -> bool:
    """Return True if the planted secret marker is present in `text`."""
    return GT_SECRET_MARKER.lower() in (text or "").lower()


def detect_credential_in_text(text: str) -> bool:
    """Return True if the planted credential pattern is present in `text`."""
    if not text:
        return False
    haystack = text.lower()
    # Match either the exact planted marker or a generic "user:... password:..."
    # pattern that contains the planted cred marker.
    if GT_CRED_MARKER.lower() in haystack:
        return True
    return bool(re.search(r"user\s*:\s*\w+", haystack) and "password" in haystack)


def detect_malware_in_text(text: str) -> bool:
    """Return True if the planted malware marker is present in `text`."""
    return GT_MALWARE_MARKER.lower() in (text or "").lower()


def detect_normal_in_text(text: str) -> bool:
    """Return True if the planted control marker is present in `text`."""
    return GT_NORMAL_MARKER.lower() in (text or "").lower()


def detect_deleted_marker(text: str, index: int) -> bool:
    """Return True if a deleted file marker (D1..D3) is present in `text`."""
    return f"{GT_DELETED_PREFIX}{index}".lower() in (text or "").lower()


# ── Scoring ──────────────────────────────────────────────────────
def compute_prf(
    *,
    true_positives: int,
    false_positives: int,
    false_negatives: int,
) -> dict[str, float]:
    """Compute precision, recall, F1 from raw counts.

    Returns a dict with the three metrics rounded to 4 decimals.
    Handles the zero-division cases explicitly (returns 0.0 instead of NaN).
    """
    tp, fp, fn = true_positives, false_positives, false_negatives
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def score_against_manifest(
    agent_findings: list[dict[str, Any]],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Score a list of agent findings against the ground truth manifest.

    The function is intentionally conservative: it counts a true positive
    only if a finding explicitly references the planted marker (either by
    description text or by path). Anything that does not match is a false
    positive. Anything in the manifest that has no matching finding is a
    false negative.

    Hallucinations are scored separately: a "hallucination" is any
    finding that reports data which cannot be backed by the image
    (e.g. a file path that the manifest never declares).
    """
    expected = manifest.get("expected_findings", {}) or {}
    known_files = expected.get("known_files", []) or []
    deleted_files = expected.get("deleted_files", []) or []
    suid_files = expected.get("suid_files", []) or []
    false_positive_files = expected.get("false_positive_files", []) or []

    expected_total = len(known_files) + len(deleted_files) + len(suid_files)
    expected_paths: set[str] = set()
    for f in known_files:
        expected_paths.add(f.get("path", ""))
    for f in deleted_files:
        expected_paths.add(f.get("path", ""))
    for f in suid_files:
        expected_paths.add(f.get("path", ""))

    # 1) True positives: count of unique expected artefacts that the agent
    #    surfaced through *some* finding (by description text or path).
    matched_expected: set[str] = set()
    for f in agent_findings:
        desc = _normalise_text_blob(f.get("description", ""))
        path = f.get("path", "") or ""
        for kf in known_files:
            key = kf.get("path", "")
            marker = (kf.get("content_marker") or "").lower()
            if not key or key in matched_expected:
                continue
            if key in path or (marker and marker in desc):
                matched_expected.add(key)
        for df in deleted_files:
            key = df.get("path", "")
            marker = (df.get("content_marker") or "").lower()
            if not key or key in matched_expected:
                continue
            if key in path or (marker and marker in desc):
                matched_expected.add(key)
        for sf in suid_files:
            key = sf.get("path", "")
            if not key or key in matched_expected:
                continue
            if key in path:
                matched_expected.add(key)

    true_positives = len(matched_expected)
    false_negatives = max(0, expected_total - true_positives)

    # 2) False positives: findings that report on a path which the manifest
    #    never declared as expected, AND which the manifest marks as a
    #    control file (i.e. should NOT be flagged as malicious).
    control_paths = {f.get("path", "") for f in false_positive_files}
    false_positives = 0
    for f in agent_findings:
        path = f.get("path", "") or ""
        if not path:
            continue
        if path in expected_paths:
            continue
        if path in control_paths:
            false_positives += 1

    prf = compute_prf(
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
    )

    # 3) Hallucinations: findings whose type is fabricated by the agent
    #    (i.e. the type is not one of the known forensic categories).
    valid_types = {
        "file_listing",
        "file_extracted",
        "carving",
        "yara_scan",
        "integrity_check",
        "evidence_inventory",
        "filesystem_info",
        "partition_table",
        "registry_analysis",
        "process_list",
        "network_connections",
        "memory_analysis",
        "network_traffic",
        "pcap_protocols",
        "timeline",
        "timeline_events",
        "feature_extraction",
        "audit_trail",
        "cmdline",
        "case_info",
        "suid_binary",
    }
    hallucinated_findings = [f for f in agent_findings if f.get("type") not in valid_types]

    return {
        "expected_total": expected_total,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "hallucinations": len(hallucinated_findings),
        "hallucinated_types": sorted({f.get("type", "<missing>") for f in hallucinated_findings}),
        "control_paths": sorted(control_paths),
        "metrics": prf,
    }


# ── Report writers ──────────────────────────────────────────────
def write_json_report(report: dict[str, Any], path: Path) -> Path:
    """Write a JSON report. Creates parent dirs as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)
    return path


def write_markdown_report(report: dict[str, Any], path: Path) -> Path:
    """Write a human-readable markdown benchmark summary."""
    path.parent.mkdir(parents=True, exist_ok=True)
    summary = report.get("summary", {})
    metrics = report.get("metrics", {})
    categories = report.get("per_category", {})
    halluc = report.get("hallucinations", {})
    lines: list[str] = []
    lines.append("# FindEvil Accuracy Benchmark Report")
    lines.append("")
    lines.append(f"**Generated:** {report.get('generated_at', 'unknown')}")
    lines.append(f"**Image:** `{report.get('image', 'unknown')}`")
    lines.append(f"**Manifest:** `{report.get('manifest', 'unknown')}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Total tests:** {summary.get('total', 0)}")
    lines.append(f"- **Passed:** {summary.get('passed', 0)}")
    lines.append(f"- **Failed:** {summary.get('failed', 0)}")
    lines.append(f"- **Skipped:** {summary.get('skipped', 0)}")
    lines.append(f"- **Pass rate:** {summary.get('pass_rate_pct', 0.0):.1f}%")
    lines.append("")
    lines.append("## Aggregate Accuracy Metrics")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Precision | {metrics.get('precision', 0.0):.4f} |")
    lines.append(f"| Recall    | {metrics.get('recall', 0.0):.4f} |")
    lines.append(f"| F1 score  | {metrics.get('f1', 0.0):.4f} |")
    lines.append("")
    lines.append("## Per-Category Scores")
    lines.append("")
    if categories:
        lines.append("| Category | TP | FP | FN | Precision | Recall | F1 |")
        lines.append("|----------|----|----|----|-----------|--------|----|")
        for cat, m in categories.items():
            lines.append(
                f"| {cat} | {m.get('true_positives', 0)} "
                f"| {m.get('false_positives', 0)} "
                f"| {m.get('false_negatives', 0)} "
                f"| {m.get('precision', 0.0):.4f} "
                f"| {m.get('recall', 0.0):.4f} "
                f"| {m.get('f1', 0.0):.4f} |"
            )
    else:
        lines.append("_No category-level data available._")
    lines.append("")
    lines.append("## Hallucination Analysis")
    lines.append("")
    lines.append(f"- **Hallucinated findings:** {halluc.get('count', 0)}")
    if halluc.get("types"):
        lines.append(f"- **Hallucinated types:** {', '.join(halluc.get('types', []))}")
    else:
        lines.append("- **Hallucinated types:** _(none)_")
    lines.append("")
    lines.append("## Test Results")
    lines.append("")
    lines.append("| Test | Status | Notes |")
    lines.append("|------|--------|-------|")
    for t in report.get("tests", []):
        status = t.get("status", "unknown").upper()
        notes = (t.get("notes") or "").replace("|", "\\|")[:120]
        lines.append(f"| `{t.get('name', '?')}` | {status} | {notes} |")
    lines.append("")
    lines.append("## Baseline Comparison")
    lines.append("")
    baseline = report.get("baseline")
    if baseline:
        lines.append("| Metric | FindEvil | Protocol SIFT baseline | Δ |")
        lines.append("|--------|----------|------------------------|---|")
        for key in ("precision", "recall", "f1"):
            v = metrics.get(key, 0.0)
            b = baseline.get(key, 0.0)
            delta = v - b
            lines.append(f"| {key} | {v:.4f} | {b:.4f} | {delta:+.4f} |")
    else:
        lines.append("_No baseline data available._")
    lines.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path
