#!/usr/bin/env python3
"""
grype-to-plane.py — Push Grype dependency findings to a Plane project board.

Usage:
    python3 scripts/security/grype-to-plane.py \\
        --input grype-results.json \\
        --repo  frontend

Required env vars:
    PLANE_API_KEY   plane_api_...

Optional env vars / CLI args:
    PLANE_BASE_URL  https://plane-tracker.internal.quizizz.com
    PLANE_SLUG      bugs
    PLANE_PROJECT   <uuid>

Labels created automatically per issue:
    priority:<band>   urgent / high / medium / low
    pkg:<name>        package name without version
    fix:available     or fix:unavailable
    kev               only on CISA KEV-confirmed findings

Risk score formula (0–160):
    KEV×100 + EPSS×50 + CVSS×1
    Bands: Urgent ≥ 110 | High ≥ 10 | Medium > 9 | Low ≤ 9

Deduplication: ext_id = <repo>::<vuln_id>::<package>::<version>
Re-runs skip existing issues. 409 responses treated as skips.
"""

import argparse
import html as html_lib
import json
import os
import sys
import time
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Config defaults
# ---------------------------------------------------------------------------
DEFAULT_BASE_URL = "https://plane-tracker.internal.quizizz.com"
DEFAULT_SLUG = "bugs"
DEFAULT_PROJECT = "5a63a066-7f1c-47a0-95eb-4149d02f57bf"
DEFAULT_STATE_TODO = "cb143247-86c1-4211-baa3-2c10b73a061f"
EXTERNAL_SOURCE = "grype"
REQUEST_DELAY_S = 1.1
REQUEST_TIMEOUT = (10, 30)

RISK_TO_PRIORITY = {
    "urgent": "urgent",
    "high": "high",
    "medium": "medium",
    "low": "low",
}

LABEL_COLORS = {
    "priority": "#ff8a5b",
    "pkg": "#7b8dff",
    "kev": "#ff4d6d",
    "fix": "#4ff1cc",
}

# ---------------------------------------------------------------------------
# Risk helpers
# ---------------------------------------------------------------------------
RISK_KEV_BONUS = 100
RISK_EPSS_WEIGHT = 50
RISK_CVSS_WEIGHT = 10

SEVERITY_CVSS_FALLBACK = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "low": 2.0,
    "negligible": 0.5,
    "unknown": 0.0,
}


def esc(v):
    return html_lib.escape(str(v)) if v is not None else ""


def compute_risk(kev, epss, cvss):
    return round(
        (RISK_KEV_BONUS if kev else 0)
        + (epss or 0) * RISK_EPSS_WEIGHT
        + ((cvss or 0) / 10.0) * RISK_CVSS_WEIGHT,
        2,
    )


def risk_band(score):
    if score >= 110:
        return "urgent"
    if score >= 10:
        return "high"
    if score > 9:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Field extractors
# ---------------------------------------------------------------------------


def get_cvss(vuln, match=None):
    for c in vuln.get("cvss") or []:
        if c.get("type") == "Primary":
            return (c.get("metrics") or {}).get("baseScore")
    cvss = vuln.get("cvss") or []
    if cvss:
        return (cvss[0].get("metrics") or {}).get("baseScore")
    if match:
        for rv in match.get("relatedVulnerabilities") or []:
            for c in rv.get("cvss") or []:
                if c.get("type") == "Primary":
                    return (c.get("metrics") or {}).get("baseScore")
            rvc = rv.get("cvss") or []
            if rvc:
                return (rvc[0].get("metrics") or {}).get("baseScore")
    sev = (vuln.get("severity") or "unknown").lower()
    return SEVERITY_CVSS_FALLBACK.get(sev, 0.0)


def get_epss(vuln):
    e = (vuln.get("epss") or [{}])[0]
    return e.get("epss"), e.get("percentile")


def get_kev(vuln):
    k = vuln.get("knownExploited") or []
    return k[0] if k else None


def get_cwes(vuln):
    return [c.get("cwe", "") for c in (vuln.get("cwes") or []) if c.get("cwe")]


def vuln_title(vuln):
    t = vuln.get("title", "")
    if t:
        return t
    desc = (vuln.get("description") or "").strip()
    if not desc:
        return vuln.get("id", "")
    return desc.split(". ")[0].strip()[:140]


def first_fix(match):
    fix = (match.get("vulnerability") or {}).get("fix") or {}
    versions = fix.get("versions") or []
    if versions:
        return versions[0]
    available = fix.get("available") or []
    if available:
        v = (available[0] or {}).get("version")
        if v:
            return str(v)
    for d in match.get("matchDetails", []) or []:
        sv = (((d.get("searchedBy") or {}).get("found") or {}).get("fix") or {}).get(
            "suggestedVersion"
        )
        if sv:
            return str(sv)
    return ""


def fix_state(match):
    return ((match.get("vulnerability") or {}).get("fix") or {}).get("state", "")


# ---------------------------------------------------------------------------
# Grype JSON parsing
# ---------------------------------------------------------------------------


def flatten(doc):
    rows = []
    for m in doc.get("matches", []) or []:
        vuln = m.get("vulnerability") or {}
        art = m.get("artifact") or {}
        locs = art.get("locations") or []
        loc = (locs[0] or {}).get("path", "") if locs else ""

        cvss = get_cvss(vuln, m)
        epss, pct = get_epss(vuln)
        kev = get_kev(vuln)
        score = compute_risk(kev, epss, cvss)

        related = [
            {
                "id": rv.get("id", ""),
                "dataSource": rv.get("dataSource", ""),
                "description": (rv.get("description") or "").strip(),
            }
            for rv in (m.get("relatedVulnerabilities") or [])
            if rv.get("id")
        ]

        rows.append(
            {
                "vuln_id": vuln.get("id", ""),
                "title": vuln_title(vuln),
                "description": (vuln.get("description") or "").strip(),
                "severity": (vuln.get("severity") or "unknown").lower(),
                "package": art.get("name", ""),
                "version": art.get("version", ""),
                "pkg_type": art.get("type", ""),
                "location": loc,
                "fix_version": first_fix(m),
                "fix_state": fix_state(m),
                "data_source": vuln.get("dataSource", ""),
                "cvss": cvss,
                "epss": epss,
                "epss_pct": pct,
                "kev": kev,
                "cwes": get_cwes(vuln),
                "related": related,
                "risk_score": score,
                "risk_band": risk_band(score),
            }
        )
    rows.sort(key=lambda r: -r["risk_score"])
    return rows


# ---------------------------------------------------------------------------
# Description builder
# ---------------------------------------------------------------------------


def build_description(row, repo=""):
    kev = row["kev"]
    epss = row["epss"]
    pct = row["epss_pct"]
    cvss = row["cvss"]
    cwes = row["cwes"]
    related = row["related"]
    ref_url = row["data_source"]

    long_desc = ""
    if related and related[0].get("description"):
        long_desc = related[0]["description"]
    elif row["description"]:
        long_desc = row["description"]

    kev_html = ""
    if kev:
        kev_urls = " ".join(f'<a href="{esc(u)}">{esc(u)}</a>' for u in (kev.get("urls") or []))
        kev_html = (
            f"<p><strong>⚠️ CISA KEV — Confirmed Active Exploitation</strong></p><table>"
            f"<tr><td><strong>Date Added</strong></td><td>{esc(kev.get('dateAdded', ''))}</td></tr>"
            f"<tr><td><strong>Due Date</strong></td><td>{esc(kev.get('dueDate', ''))}</td></tr>"
            f"<tr><td><strong>Ransomware</strong></td><td>{esc(kev.get('knownRansomwareCampaignUse', 'unknown'))}</td></tr>"
            f"<tr><td><strong>Required Action</strong></td><td>{esc(kev.get('requiredAction', ''))}</td></tr>"
            f"<tr><td><strong>Notes</strong></td><td>{esc(kev.get('notes', ''))}</td></tr>"
            f"<tr><td><strong>URLs</strong></td><td>{kev_urls}</td></tr>"
            f"</table>"
        )

    fix_html = ""
    if row["fix_state"] == "not-fixed":
        fix_html = "<p><strong>Fix</strong>: No fix available.</p>"
    elif row["fix_version"]:
        fix_html = f"<p><strong>Fix</strong>: Upgrade to <code>{esc(row['fix_version'])}</code></p>"

    cwe_html = ""
    if cwes:
        links = " ".join(
            f'<a href="https://cwe.mitre.org/data/definitions/{esc(c.replace("CWE-", ""))}.html">{esc(c)}</a>'
            for c in cwes
        )
        cwe_html = f"<p><strong>CWE</strong>: {links}</p>"

    related_html = ""
    if related:
        rows_html = "".join(
            f'<tr><td><code>{esc(rv["id"])}</code></td><td><a href="{esc(rv["dataSource"])}">{esc(rv["dataSource"])}</a></td></tr>'
            for rv in related
            if rv.get("id")
        )
        if rows_html:
            related_html = f"<p><strong>Related Vulnerabilities</strong></p><table><tr><th>ID</th><th>Source</th></tr>{rows_html}</table>"

    ghsa_id = row["vuln_id"] if row["vuln_id"].startswith("GHSA-") else ""
    cve_ids = [rv["id"] for rv in related if rv.get("id", "").startswith("CVE-")]
    id_parts = []
    if ghsa_id:
        id_parts.append(f"<code>{esc(ghsa_id)}</code>")
    id_parts.extend(f"<code>{esc(c)}</code>" for c in cve_ids)
    id_html = f"<p><strong>IDs</strong>: {' · '.join(id_parts)}</p>" if id_parts else ""

    ref_html = (
        f'<p><strong>Reference</strong>: <a href="{esc(ref_url)}">{esc(ref_url)}</a></p>'
        if ref_url
        else ""
    )
    if epss is not None and pct is not None:
        epss_str = f"{epss:.4f} ({pct * 100:.0f}th percentile)"
    elif epss is not None:
        epss_str = f"{epss:.4f}"
    else:
        epss_str = "—"

    return (
        f"<p>{esc(long_desc)}</p><hr/>"
        f"{id_html}"
        f"<table>"
        f"<tr><td><strong>Repository</strong></td><td><code>{esc(repo)}</code></td></tr>"
        f"<tr><td><strong>Package</strong></td><td><code>{esc(row['package'])}@{esc(row['version'])}</code> ({esc(row['pkg_type'])})</td></tr>"
        f"<tr><td><strong>Location</strong></td><td><code>{esc(row['location'])}</code></td></tr>"
        f"<tr><td><strong>Severity</strong></td><td>{esc(row['severity'].upper())}</td></tr>"
        f"<tr><td><strong>CVSS</strong></td><td>{f'{cvss:.1f}' if cvss is not None else '—'}</td></tr>"
        f"<tr><td><strong>EPSS</strong></td><td>{esc(epss_str)}</td></tr>"
        f"<tr><td><strong>Risk Score</strong></td><td>{esc(str(row['risk_score']))}</td></tr>"
        f"<tr><td><strong>Priority</strong></td><td>{esc(row['risk_band'].upper())}</td></tr>"
        f"</table>"
        f"{kev_html}{fix_html}{cwe_html}{related_html}{ref_html}"
    )


# ---------------------------------------------------------------------------
# Plane API
# ---------------------------------------------------------------------------


class _TimeoutSession(requests.Session):
    """Session subclass that applies a default timeout to every request."""

    def request(self, *args, **kwargs):
        kwargs.setdefault("timeout", REQUEST_TIMEOUT)
        return super().request(*args, **kwargs)


def make_session(api_key):
    s = _TimeoutSession()
    s.headers.update({"X-API-Key": api_key, "Content-Type": "application/json"})
    return s


def bootstrap_labels(session, base_url, slug, project_id, rows, repo=""):
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

    needed = set()
    if repo:
        needed.add(f"repo:{repo}")
    for r in rows:
        needed.add(f"priority:{r['risk_band']}")
        needed.add(f"pkg:{r['package']}")
        needed.add(f"fix:{'available' if r['fix_state'] == 'fixed' else 'unavailable'}")
        if r["kev"]:
            needed.add("kev")

    def color(name):
        if name.startswith("priority:"):
            return LABEL_COLORS["priority"]
        if name.startswith("pkg:"):
            return LABEL_COLORS["pkg"]
        if name.startswith("fix:"):
            return LABEL_COLORS["fix"]
        if name.startswith("repo:"):
            return "#a78bfa"
        if name == "kev":
            return LABEL_COLORS["kev"]
        return "#95a7cf"

    new_labels = needed - set(cache)
    print(f"  Creating {len(new_labels)} new labels...")
    for name in sorted(new_labels):
        r = session.post(url, json={"name": name, "color": color(name)})
        if r.status_code == 409:
            all_lbls = session.get(url, params={"per_page": 500}).json()
            for lbl in all_lbls.get("results", []):
                cache[lbl["name"]] = lbl["id"]
        else:
            r.raise_for_status()
            cache[name] = r.json()["id"]
        time.sleep(0.3)
    return cache


def get_existing_ext_ids(session, base_url, slug, project_id):
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


def push_item(session, base_url, slug, project_id, state_id, row, label_cache, repo=""):
    short_desc = row["description"] or row["title"]
    if len(short_desc) > 160:
        short_desc = short_desc[:157] + "..."
    name = f"{row['package']}@{row['version']} — {short_desc}"
    if len(name) > 255:
        name = name[:252] + "..."

    label_names = [
        f"priority:{row['risk_band']}",
        f"pkg:{row['package']}",
        f"fix:{'available' if row['fix_state'] == 'fixed' else 'unavailable'}",
    ]
    if repo:
        label_names.insert(0, f"repo:{repo}")
    if row["kev"]:
        label_names.append("kev")
    label_ids = [label_cache[n] for n in label_names if n in label_cache]

    ext_id = (
        f"{repo}::{row['vuln_id']}::{row['package']}::{row['version']}"
        if repo
        else f"{row['vuln_id']}::{row['package']}::{row['version']}"
    )

    payload = {
        "name": name,
        "description_html": build_description(row, repo=repo),
        "priority": RISK_TO_PRIORITY[row["risk_band"]],
        "state": state_id,
        "labels": label_ids,
        "external_id": ext_id,
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
    parser = argparse.ArgumentParser(description="Push Grype findings to Plane")
    parser.add_argument("--input", required=True)
    parser.add_argument(
        "--repo",
        default=os.environ.get("PLANE_REPO", ""),
        help="Repository name — used in labels, description, and ext_id",
    )
    parser.add_argument("--base-url", default=os.environ.get("PLANE_BASE_URL", DEFAULT_BASE_URL))
    parser.add_argument("--slug", default=os.environ.get("PLANE_SLUG", DEFAULT_SLUG))
    parser.add_argument("--project", default=os.environ.get("PLANE_PROJECT", DEFAULT_PROJECT))
    parser.add_argument("--state", default=DEFAULT_STATE_TODO)
    parser.add_argument("--min-risk", default="low", choices=["low", "medium", "high", "urgent"])
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    api_key = os.environ.get("PLANE_API_KEY", "")
    if not api_key:
        sys.exit("Error: PLANE_API_KEY env var is required.")

    repo = args.repo
    doc = json.loads(Path(args.input).read_text(encoding="utf-8"))
    rows = flatten(doc)

    band_order: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "urgent": 3}
    rows = [r for r in rows if band_order[str(r["risk_band"])] >= band_order[args.min_risk]]
    print(f"Findings to push: {len(rows)} (min risk band: {args.min_risk})")

    if args.dry_run:
        for r in rows:
            labels = [f"priority:{r['risk_band']}", f"pkg:{r['package']}"]
            if r["kev"]:
                labels.append("kev")
            print(f"  [{r['risk_score']:6.1f}] {' '.join(labels)}")
            print(
                f"           {r['package']}@{r['version']} — {(r['description'] or r['title'])[:80]}"
            )
        return

    session = make_session(api_key)

    print("Bootstrapping labels...")
    label_cache = bootstrap_labels(session, args.base_url, args.slug, args.project, rows, repo=repo)
    print(f"  {len(label_cache)} labels ready.")

    print("Fetching existing work items to skip duplicates...")
    existing = get_existing_ext_ids(session, args.base_url, args.slug, args.project)
    print(f"  {len(existing)} existing item(s) found.")

    pushed = skipped = errors = 0
    for i, row in enumerate(rows, 1):
        ext_id = (
            f"{repo}::{row['vuln_id']}::{row['package']}::{row['version']}"
            if repo
            else f"{row['vuln_id']}::{row['package']}::{row['version']}"
        )
        if ext_id in existing:
            skipped += 1
            continue
        try:
            result = push_item(
                session,
                args.base_url,
                args.slug,
                args.project,
                args.state,
                row,
                label_cache,
                repo=repo,
            )
            print(
                f"  [{i}/{len(rows)}] OK    #{result.get('sequence_id', '?')} {ext_id}  (risk {row['risk_score']})"
            )
            pushed += 1
            existing.add(ext_id)
        except requests.HTTPError as e:
            status = e.response.status_code
            if status == 409:
                existing.add(ext_id)
                skipped += 1
            elif status in (401, 403):
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
                print(f"  [{i}/{len(rows)}] ERROR {ext_id}: {status} {e.response.text[:120]}")
                errors += 1
        time.sleep(REQUEST_DELAY_S)

    print(f"\nDone. Pushed: {pushed} | Skipped: {skipped} | Errors: {errors}")
    if errors > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
