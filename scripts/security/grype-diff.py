#!/usr/bin/env python3
"""
grype-diff.py — Compare two Grype JSON outputs and emit only net-new findings.

Usage:
    # Produce diff JSON:
    python3 scripts/security/grype-diff.py diff \\
        --baseline grype-baseline.json \\
        --pr       grype-pr.json \\
        --output   grype-diff.json

    # Check diff JSON for findings at or above a severity and exit non-zero if any:
    python3 scripts/security/grype-diff.py check \\
        --input    grype-diff.json \\
        --severity high

A finding is considered "net-new" if its (vuln_id, package_name, package_version) triple
does not appear in the baseline scan.  This intentionally ignores location/path changes —
the same CVE in the same package is the same finding regardless of which lockfile entry
references it.
"""

import argparse
import json
import sys
from pathlib import Path

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "negligible": 4,
    "unknown": 5,
}


def finding_key(match: dict) -> str:
    vuln = match.get("vulnerability") or {}
    art = match.get("artifact") or {}
    vuln_id = vuln.get("id", "")
    pkg = art.get("name", "")
    ver = art.get("version", "")
    return f"{vuln_id}::{pkg}::{ver}"


def load_grype(path: Path) -> dict:
    if not path.exists():
        print(f"[grype-diff] WARNING: {path} not found — treating as empty scan", file=sys.stderr)
        return {"matches": []}
    return json.loads(path.read_text(encoding="utf-8"))


def diff(baseline_path: Path, pr_path: Path, output_path: Path) -> int:
    baseline = load_grype(baseline_path)
    pr = load_grype(pr_path)

    baseline_keys = {finding_key(m) for m in baseline.get("matches", [])}
    new_matches = [m for m in pr.get("matches", []) if finding_key(m) not in baseline_keys]

    # Build output doc preserving top-level metadata from PR scan
    out = dict(pr)
    out["matches"] = new_matches

    output_path.write_text(json.dumps(out, indent=2), encoding="utf-8")

    baseline_count = len(baseline.get("matches", []))
    pr_count = len(pr.get("matches", []))
    new_count = len(new_matches)

    print(f"[grype-diff] Baseline findings : {baseline_count}")
    print(f"[grype-diff] PR findings       : {pr_count}")
    print(f"[grype-diff] Net-new findings  : {new_count}")

    if new_count:
        print("[grype-diff] Net-new findings:")
        for m in new_matches:
            vuln = m.get("vulnerability") or {}
            art = m.get("artifact") or {}
            sev = (vuln.get("severity") or "unknown").lower()
            vuln_id = vuln.get("id", "?")
            pkg = art.get("name", "?")
            ver = art.get("version", "?")
            print(f"  [{sev.upper():10}] {vuln_id} — {pkg}@{ver}")

    return new_count


def check(input_path: Path, min_severity: str) -> int:
    """Exit non-zero if any finding in input_path meets or exceeds min_severity."""
    doc = load_grype(input_path)
    min_rank = SEVERITY_ORDER.get(min_severity.lower(), 5)

    failing = [
        m
        for m in doc.get("matches", [])
        if SEVERITY_ORDER.get(
            ((m.get("vulnerability") or {}).get("severity") or "unknown").lower(), 5
        )
        <= min_rank
    ]

    if failing:
        print(
            f"[grype-diff] FAIL — {len(failing)} net-new finding(s) at severity "
            f">= {min_severity.upper()}:",
            file=sys.stderr,
        )
        for m in failing:
            vuln = m.get("vulnerability") or {}
            art = m.get("artifact") or {}
            sev = (vuln.get("severity") or "unknown").upper()
            vuln_id = vuln.get("id", "?")
            pkg = art.get("name", "?")
            ver = art.get("version", "?")
            print(f"  [{sev:10}] {vuln_id} — {pkg}@{ver}", file=sys.stderr)
        return 1

    total = len(doc.get("matches", []))
    print(
        f"[grype-diff] PASS — no net-new findings at severity >= {min_severity.upper()} "
        f"({total} total net-new finding(s) below threshold)"
    )
    return 0


def main():
    parser = argparse.ArgumentParser(description="Diff two Grype JSON outputs")
    sub = parser.add_subparsers(dest="command")

    # diff sub-command
    p_diff = sub.add_parser("diff", help="Produce diff JSON")
    p_diff.add_argument("--baseline", required=True, help="Baseline Grype JSON (base branch)")
    p_diff.add_argument("--pr", required=True, help="PR branch Grype JSON")
    p_diff.add_argument("--output", required=True, help="Output diff JSON path")

    # check sub-command
    p_check = sub.add_parser("check", help="Fail if diff JSON has findings above threshold")
    p_check.add_argument("--input", required=True, help="Diff Grype JSON to check")
    p_check.add_argument(
        "--severity",
        default="high",
        choices=["critical", "high", "medium", "low", "negligible"],
        help="Minimum severity to fail on (default: high)",
    )

    args = parser.parse_args()

    if args.command == "diff":
        diff(Path(args.baseline), Path(args.pr), Path(args.output))
        sys.exit(0)  # diff itself never fails; use check to gate

    if args.command == "check":
        sys.exit(check(Path(args.input), args.severity))

    parser.print_help()
    sys.exit(1)


if __name__ == "__main__":
    main()
