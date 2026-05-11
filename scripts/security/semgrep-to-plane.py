#!/usr/bin/env python3
"""
semgrep-to-plane.py — Push Semgrep SAST findings to a Plane project board.

Usage:
    python3 scripts/security/semgrep-to-plane.py \\
        --input semgrep-results.sarif \\
        --codeowners .github/CODEOWNERS

Required env vars:
    PLANE_API_KEY   plane_api_...

Optional env vars / CLI args:
    PLANE_BASE_URL  https://plane-tracker.internal.quizizz.com
    PLANE_SLUG      bugs
    PLANE_PROJECT   <uuid>

Labels created automatically per issue:
    rule:<short-name>   e.g. rule:avoid-v-html
    owner:<combo>       e.g. owner:@quizizz/engagement-frontend
    priority:<tier>     urgent / high / medium / low / none

Priority formula (mirrors Semgrep AppSec Platform):
    urgent = ERROR + confidence HIGH
    high   = ERROR + confidence MEDIUM
    medium = ERROR + confidence LOW
    low    = WARNING
    none   = NOTE / INFO

Deduplication: ext_id = <rule_id>::<file_path>::<line>
SARIF fingerprints are not unique (Semgrep CLI uses placeholder); always uses rule+file+line.
"""

import argparse
import html as html_lib
import json
import os
import re
import sys
import time
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Config defaults
# ---------------------------------------------------------------------------
DEFAULT_BASE_URL = "https://plane-tracker.internal.quizizz.com"
DEFAULT_SLUG = "bugs"
DEFAULT_PROJECT = "9e6e639b-4545-436a-b4a8-d220755fd9ed"
DEFAULT_STATE_TODO = "5ecaf216-1caf-41cc-aba4-57b716b0e2e8"
EXTERNAL_SOURCE = "semgrep"
REQUEST_DELAY_S = 1.1
REQUEST_TIMEOUT = (10, 30)

REPO_LABEL_COLOR = "#a78bfa"
RULE_LABEL_COLOR = "#7b8dff"
OWNER_LABEL_COLOR = "#4ff1cc"
PRIORITY_LABEL_COLORS = {
    "priority:urgent": "#ff4d6d",
    "priority:high": "#ff8a5b",
    "priority:medium": "#ffd166",
    "priority:low": "#6ab4ff",
    "priority:none": "#95a7cf",
}


def esc(v):
    return html_lib.escape(str(v)) if v is not None else ""


# ---------------------------------------------------------------------------
# Priority formula
# ---------------------------------------------------------------------------


def compute_priority(level: str, confidence: str) -> str:
    lvl = (level or "").lower()
    conf = (confidence or "").upper()
    if lvl in ("error", "high", "critical"):
        if conf == "HIGH":
            return "urgent"
        if conf == "MEDIUM":
            return "high"
        return "medium"
    if lvl in ("warning", "medium"):
        return "low"
    return "none"


PRIORITY_TO_PLANE = {
    "urgent": "urgent",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "none": "none",
}


# ---------------------------------------------------------------------------
# CODEOWNERS
# ---------------------------------------------------------------------------


def load_codeowners(path: Path):
    try:
        from codeowners import CodeOwners  # type: ignore

        for candidate in [path, path.parent.parent / "CODEOWNERS"]:
            if candidate.exists():
                return CodeOwners(candidate.read_text(encoding="utf-8"))
    except ImportError:
        print(
            "WARNING: `codeowners` package not installed. pip install codeowners",
            flush=True,
        )
    return None


def resolve_owner(file_path: str, co) -> str:
    if co is None:
        return "unowned"
    owners = co.of(file_path)
    return " ".join(o for _, o in owners) if owners else "unowned"


# ---------------------------------------------------------------------------
# SARIF parsing
# ---------------------------------------------------------------------------


def collect_rules(run: dict) -> dict:
    rule_map = {}
    for rule in run.get("tool", {}).get("driver", {}).get("rules") or []:
        rid = rule.get("id")
        if rid:
            rule_map[rid] = {
                "name": rule.get("name") or "",
                "help_uri": rule.get("helpUri") or "",
                "level": (rule.get("defaultConfiguration") or {}).get("level", "warning"),
            }
    return rule_map


def parse_sarif(sarif_path: Path, codeowners, json_input_path: Path | None = None) -> list:
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))

    # Load JSON for confidence/likelihood/impact — keyed by (rule_id, file, line)
    json_path = json_input_path or (sarif_path.parent / sarif_path.name.replace(".sarif", ".json"))
    json_meta: dict = {}
    if json_path.exists():
        doc = json.loads(json_path.read_text(encoding="utf-8"))
        for r in doc.get("results", []) or []:
            rid = r.get("check_id", "")
            fpath = r.get("path", "")
            ln = str(r.get("start", {}).get("line", ""))
            meta = r.get("extra", {}).get("metadata", {})
            json_meta[(rid, fpath, ln)] = {
                "confidence": (meta.get("confidence") or "").upper(),
                "likelihood": (meta.get("likelihood") or "").upper(),
                "impact": (meta.get("impact") or "").upper(),
            }

    rows = []
    for run in sarif.get("runs", []):
        rule_map = collect_rules(run)
        for result in run.get("results", []) or []:
            rid = result.get("ruleId", "")
            rule_meta = rule_map.get(rid, {})
            raw_level = result.get("level") or rule_meta.get("level", "warning")
            level = raw_level.lower()
            msg = (result.get("message") or {}).get("text", "")

            locs = result.get("locations") or []
            file_uri = line = col = snippet = ""
            if locs:
                phys = locs[0].get("physicalLocation", {})
                file_uri = phys.get("artifactLocation", {}).get("uri", "")
                region = phys.get("region", {})
                line = str(region.get("startLine", "")) if region.get("startLine") else ""
                col = str(region.get("startColumn", "")) if region.get("startColumn") else ""
                snippet = (region.get("snippet") or {}).get("text", "")

            meta = json_meta.get((rid, file_uri, line), {})
            confidence = meta.get("confidence", "")
            priority = compute_priority(level, confidence)
            owner = resolve_owner(file_uri, codeowners)
            short_rule = rid.split(".")[-1] if rid else "unknown"

            # Always use rule+file+line — SARIF fingerprints are placeholder strings
            ext_id = f"{rid}::{file_uri}::{line}"

            rows.append(
                {
                    "level": level,
                    "priority": priority,
                    "confidence": confidence,
                    "likelihood": meta.get("likelihood", ""),
                    "impact": meta.get("impact", ""),
                    "rule_id": rid,
                    "short_rule": short_rule,
                    "rule_name": rule_meta.get("name", ""),
                    "help_uri": rule_meta.get("help_uri", ""),
                    "message": msg,
                    "file": file_uri,
                    "line": line,
                    "col": col,
                    "snippet": snippet,
                    "owner": owner,
                    "ext_id": ext_id,
                }
            )
    return rows


# ---------------------------------------------------------------------------
# Description builder (HTML-escaped)
# ---------------------------------------------------------------------------


def build_description(row: dict) -> str:
    file_line = esc(f"{row['file']}:{row['line']}" if row["line"] else row["file"])
    snippet_html = (
        f"<pre style='font-size:12px;background:rgba(0,0,0,.3);padding:8px;border-radius:6px;"
        f"white-space:pre-wrap;color:#8de1ff;'>{esc(row['snippet'])}</pre>"
        if row["snippet"]
        else ""
    )
    help_uri = row.get("help_uri", "")
    help_html = (
        f"<p><strong>Rule docs</strong>: <a href='{esc(help_uri)}'>{esc(help_uri)}</a></p>"
        if help_uri
        else ""
    )
    return (
        f"<p>{esc(row['message'])}</p><hr/>"
        f"<table>"
        f"<tr><td><strong>Rule</strong></td><td><code>{esc(row['rule_id'])}</code></td></tr>"
        f"<tr><td><strong>File</strong></td><td><code>{file_line}</code></td></tr>"
        f"<tr><td><strong>Severity</strong></td><td>{esc(row['level'].upper())}</td></tr>"
        f"<tr><td><strong>Confidence</strong></td><td>{esc(row.get('confidence', '') or '—')}</td></tr>"
        f"<tr><td><strong>Likelihood</strong></td><td>{esc(row.get('likelihood', '') or '—')}</td></tr>"
        f"<tr><td><strong>Impact</strong></td><td>{esc(row.get('impact', '') or '—')}</td></tr>"
        f"<tr><td><strong>Priority</strong></td><td>{esc(row['priority'].upper())}</td></tr>"
        f"<tr><td><strong>Owner</strong></td><td>{esc(row['owner'])}</td></tr>"
        f"</table>"
        f"{snippet_html}{help_html}"
    )


# ---------------------------------------------------------------------------
# Plane API
# ---------------------------------------------------------------------------


class _TimeoutSession(requests.Session):
    """Session subclass that applies a default timeout to every request."""

    def request(self, *args, **kwargs):
        kwargs.setdefault("timeout", REQUEST_TIMEOUT)
        return super().request(*args, **kwargs)


def make_session(api_key: str) -> _TimeoutSession:
    s = _TimeoutSession()
    s.headers.update({"X-API-Key": api_key, "Content-Type": "application/json"})
    return s


def ensure_label(session, base_url, slug, project_id, name, color, cache: dict) -> str:
    if name in cache:
        return cache[name]
    url = f"{base_url}/api/v1/workspaces/{slug}/projects/{project_id}/labels/"
    resp = session.post(url, json={"name": name, "color": color})
    if resp.status_code == 409:
        _cursor = None
        while True:
            _params = {"per_page": 500}
            if _cursor:
                _params["cursor"] = _cursor
            _resp = session.get(url, params=_params)
            _data = _resp.json()
            for lbl in _data.get("results", []):
                cache[lbl["name"]] = lbl["id"]
            if not _data.get("next_page_results"):
                break
            _cursor = _data.get("next_cursor")
    else:
        resp.raise_for_status()
        cache[name] = resp.json()["id"]
    return cache.get(name, "")


def bootstrap_labels(session, base_url, slug, project_id, rows: list, repo: str = "") -> dict:
    cache = {}
    url = f"{base_url}/api/v1/workspaces/{slug}/projects/{project_id}/labels/"
    cursor = None
    while True:
        params = {"per_page": 500}
        if cursor:
            params["cursor"] = cursor
        resp = session.get(url, params=params)
        resp.raise_for_status()
        data = resp.json()
        for lbl in data.get("results", []):
            cache[lbl["name"]] = lbl["id"]
        if not data.get("next_page_results"):
            break
        cursor = data.get("next_cursor")

    needed_rules = {f"rule:{r['short_rule']}" for r in rows}
    needed_owners = {f"owner:{r['owner']}" for r in rows}
    needed_priority = {f"priority:{r['priority']}" for r in rows}

    if repo:
        repo_label = f"repo:{repo}"
        if repo_label not in cache:
            ensure_label(session, base_url, slug, project_id, repo_label, REPO_LABEL_COLOR, cache)
            time.sleep(0.3)

    print(f"  Creating {len(needed_rules - set(cache))} new rule labels...")
    for name in sorted(needed_rules):
        if name not in cache:
            ensure_label(session, base_url, slug, project_id, name, RULE_LABEL_COLOR, cache)
            time.sleep(0.3)

    print(f"  Creating {len(needed_owners - set(cache))} new owner labels...")
    for name in sorted(needed_owners):
        if name not in cache:
            ensure_label(session, base_url, slug, project_id, name, OWNER_LABEL_COLOR, cache)
            time.sleep(0.3)

    print(f"  Creating {len(needed_priority - set(cache))} new priority labels...")
    for name in sorted(needed_priority):
        if name not in cache:
            ensure_label(
                session,
                base_url,
                slug,
                project_id,
                name,
                PRIORITY_LABEL_COLORS.get(name, "#95a7cf"),
                cache,
            )
            time.sleep(0.3)

    return cache


def get_existing_ext_ids(session, base_url, slug, project_id) -> set:
    ids, cursor = set(), None
    url = f"{base_url}/api/v1/workspaces/{slug}/projects/{project_id}/work-items/"
    while True:
        params = {"per_page": 100, "fields": "external_id"}
        if cursor:
            params["cursor"] = cursor
        resp = session.get(url, params=params)
        resp.raise_for_status()
        data = resp.json()
        for item in data.get("results", []):
            eid = item.get("external_id")
            if eid:
                ids.add(eid)
        if not data.get("next_page_results"):
            break
        cursor = data.get("next_cursor")
    return ids


def push_item(session, base_url, slug, project_id, state_id, row, label_ids):
    short_file = row["file"].split("/")[-1] if row["file"] else "(no file)"
    safe_rule = re.sub(r"<[^>]+>", "", row["short_rule"])
    safe_file = re.sub(r"<[^>]+>", "", short_file)
    safe_line = re.sub(r"<[^>]+>", "", row["line"])
    safe_msg = re.sub(r"<[^>]+>", "", row["message"])
    name = f"[{safe_rule}] {safe_file}:{safe_line} — {safe_msg[:80]}"
    if len(name) > 255:
        name = name[:252] + "..."

    payload = {
        "name": name,
        "description_html": build_description(row),
        "priority": PRIORITY_TO_PLANE.get(row["priority"], "none"),
        "state": state_id,
        "labels": label_ids,
        "external_id": row["ext_id"],
        "external_source": EXTERNAL_SOURCE,
    }
    resp = session.post(
        f"{base_url}/api/v1/workspaces/{slug}/projects/{project_id}/work-items/",
        json=payload,
    )
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Push Semgrep SARIF findings to Plane")
    parser.add_argument("--input", required=True, help="Semgrep SARIF file")
    parser.add_argument(
        "--repo",
        default=os.environ.get("PLANE_REPO", ""),
        help="Repository name — used in labels, description, and ext_id",
    )
    parser.add_argument("--codeowners", default=".github/CODEOWNERS")
    parser.add_argument(
        "--json-input",
        default=None,
        help="Semgrep JSON output (for confidence/likelihood/impact metadata)",
    )
    parser.add_argument(
        "--default-owner",
        default="",
        help="Fallback owner when CODEOWNERS is missing or returns unowned",
    )

    parser.add_argument("--base-url", default=os.environ.get("PLANE_BASE_URL", DEFAULT_BASE_URL))
    parser.add_argument("--slug", default=os.environ.get("PLANE_SLUG", DEFAULT_SLUG))
    parser.add_argument("--project", default=os.environ.get("PLANE_PROJECT", DEFAULT_PROJECT))
    parser.add_argument("--state", default=DEFAULT_STATE_TODO)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    api_key = os.environ.get("PLANE_API_KEY", "")
    if not api_key:
        sys.exit("Error: PLANE_API_KEY env var is required.")

    repo = args.repo
    sarif_path = Path(args.input)
    codeowners_path = sarif_path.parent / args.codeowners
    codeowners = load_codeowners(codeowners_path)
    print(
        f"CODEOWNERS: loaded from {codeowners_path}"
        if codeowners
        else "CODEOWNERS: not found — all files will be unowned"
    )

    json_input_path = Path(args.json_input) if args.json_input else None
    rows = parse_sarif(sarif_path, codeowners, json_input_path=json_input_path)

    if args.default_owner:
        for r in rows:
            if r["owner"] == "unowned":
                r["owner"] = args.default_owner

    if repo:
        for r in rows:
            r["ext_id"] = f"{repo}::{r['ext_id']}"

    print(f"Findings parsed: {len(rows)}")

    if args.offset or args.limit:
        start = args.offset
        end = (args.offset + args.limit) if args.limit else len(rows)
        rows = rows[start:end]
        print(f"Batch: [{start}–{end}) → {len(rows)} items")

    if args.dry_run:
        from collections import Counter

        print("\nDry run — first 20:")
        for r in rows[:20]:
            print(
                f"  [{r['level']:8}] priority:{r['priority']:8} rule:{r['short_rule']:35} owner:{r['owner']}"
            )
        print("\nOwner distribution:")
        for owner, cnt in Counter(r["owner"] for r in rows).most_common():
            print(f"  {cnt:4d}  {owner}")
        return

    session = make_session(api_key)

    print("\nBootstrapping labels...")
    label_cache = bootstrap_labels(session, args.base_url, args.slug, args.project, rows, repo=repo)
    print(f"  {len(label_cache)} labels ready.")

    print("\nFetching existing work items to skip duplicates...")
    existing = get_existing_ext_ids(session, args.base_url, args.slug, args.project)
    print(f"  {len(existing)} existing item(s) found.")

    pushed = skipped = errors = 0
    for i, row in enumerate(rows, 1):
        if row["ext_id"] in existing:
            skipped += 1
            continue

        repo_lid = label_cache.get(f"repo:{repo}") if repo else None
        rule_lid = label_cache.get(f"rule:{row['short_rule']}")
        owner_lid = label_cache.get(f"owner:{row['owner']}")
        pri_lid = label_cache.get(f"priority:{row['priority']}")
        label_ids = [lid for lid in [repo_lid, rule_lid, owner_lid, pri_lid] if lid]

        try:
            result = push_item(
                session,
                args.base_url,
                args.slug,
                args.project,
                args.state,
                row,
                label_ids,
            )
            print(
                f"  [{i}/{len(rows)}] OK    #{result.get('sequence_id', '?')} [{row['level']}] {row['short_rule']} {row['file']}:{row['line']}"
            )
            pushed += 1
        except requests.HTTPError as e:
            status = e.response.status_code
            if status in (401, 403):
                print(
                    f"\nFATAL: {status} Unauthorized. Check PLANE_API_KEY.",
                    file=sys.stderr,
                )
                sys.exit(1)
            elif status == 404:
                print(
                    f"\nFATAL: {status} Not Found. Check --project and --slug.",
                    file=sys.stderr,
                )
                sys.exit(1)
            else:
                print(
                    f"  [{i}/{len(rows)}] ERROR {row['ext_id']}: {status} {e.response.text[:100]}"
                )
                errors += 1
        time.sleep(REQUEST_DELAY_S)

    print(f"\nDone. Pushed: {pushed} | Skipped: {skipped} | Errors: {errors}")
    if errors > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
