#!/usr/bin/env python3
"""
grype-to-html.py — Convert Grype JSON output to an interactive HTML triage report.

Usage:
    python3 scripts/security/grype-to-html.py --input grype-results.json --html grype-report.html

The report has three tabs:
  - All Findings      — flat table sorted by risk score descending
  - Grouped by Vuln   — one section per CVE/GHSA, showing all affected packages
  - Grouped by Pkg    — one section per package@version, showing all vulnerabilities

Risk score formula (0–160):
    risk_score = KEV_bonus(100) + EPSS×50 + CVSS×1
    Bands: Urgent ≥ 110 | High ≥ 10 | Medium > 9 | Low ≤ 9
"""

import argparse
import html
import json
from collections import Counter, defaultdict
from pathlib import Path

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "negligible": 4, "unknown": 5}

SEVERITY_CVSS_FALLBACK = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "low": 2.0,
    "negligible": 0.5,
    "unknown": 0.0,
}

RISK_KEV_BONUS = 100
RISK_EPSS_WEIGHT = 50
RISK_CVSS_WEIGHT = 10


def esc(v):
    return html.escape(str(v)) if v is not None else ""


def sev_norm(v):
    return (v or "unknown").strip().lower()


def read_json(path):
    with path.open(encoding="utf-8") as f:
        return json.load(f)


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
    sev = sev_norm(vuln.get("severity"))
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


def risk_score(kev, epss, cvss):
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


def first_fix(match):
    fix = (match.get("vulnerability") or {}).get("fix") or {}
    versions = fix.get("versions") or []
    if versions:
        return ", ".join(str(v) for v in versions[:3])
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
# Data flattening
# ---------------------------------------------------------------------------


def flatten(doc):
    rows = []
    for m in doc.get("matches", []) or []:
        vuln = m.get("vulnerability") or {}
        art = m.get("artifact") or {}
        locs = art.get("locations") or []
        loc = (locs[0] or {}).get("path", "") if locs else ""

        cvss = get_cvss(vuln, m)
        epss, epss_pct = get_epss(vuln)
        kev = get_kev(vuln)
        score = risk_score(kev, epss, cvss)

        # related vuln IDs
        related = [
            {"id": rv.get("id", ""), "dataSource": rv.get("dataSource", "")}
            for rv in (m.get("relatedVulnerabilities") or [])
            if rv.get("id")
        ]

        rows.append(
            {
                "vuln_id": vuln.get("id", ""),
                "title": vuln_title(vuln),
                "description": (vuln.get("description") or "").strip(),
                "severity": sev_norm(vuln.get("severity")),
                "package": art.get("name", ""),
                "version": art.get("version", ""),
                "pkg_type": art.get("type", ""),
                "location": loc,
                "fix_version": first_fix(m),
                "fix_state": fix_state(m),
                "data_source": vuln.get("dataSource", ""),
                "cvss": cvss,
                "epss": epss,
                "epss_pct": epss_pct,
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
# Cell renderers
# ---------------------------------------------------------------------------

BAND_COLOR = {
    "urgent": "#ff4d6d",
    "high": "#ff8a5b",
    "medium": "#ffd166",
    "low": "#6ab4ff",
}


def render_risk_cell(r):
    score = r["risk_score"]
    color = BAND_COLOR.get(r["risk_band"], "#95a7cf")
    tip = (
        f"KEV:{RISK_KEV_BONUS if r['kev'] else 0} "
        f"+ EPSS×{RISK_EPSS_WEIGHT}({r['epss'] or 0:.3f}) "
        f"+ CVSS×1({r['cvss'] or 0:.1f}) = {score}"
    )
    bar = min(100, int((score / 160) * 100))
    return (
        f'<div title="{esc(tip)}" style="min-width:60px;">'
        f'<span style="font-weight:700;font-size:12px;color:{color};">{score:.1f}</span>'
        f'<div style="height:4px;background:rgba(255,255,255,.08);border-radius:999px;margin-top:3px;">'
        f'<div style="width:{bar}%;height:100%;background:{color};border-radius:999px;"></div></div>'
        f"</div>"
    )


def render_cvss_cell(r):
    score = r["cvss"]
    if score is None:
        return "—"
    color = (
        "#ff4d6d"
        if score >= 9
        else "#ff8a5b"
        if score >= 7
        else "#ffd166"
        if score >= 4
        else "#6ab4ff"
    )
    return f'<span style="color:{color};font-weight:700;">{score:.1f}</span>'


def render_epss_cell(r):
    e = r["epss"]
    if e is None:
        return "—"
    pct = r["epss_pct"]
    pct_s = f" ({pct * 100:.0f}th pct)" if pct is not None else ""
    color = (
        "#ff4d6d" if e >= 0.5 else "#ff8a5b" if e >= 0.1 else "#ffd166" if e >= 0.01 else "#6ab4ff"
    )
    bar = int(e * 100)
    return (
        f'<div title="{e:.4f}{pct_s}">'
        f'<span style="font-size:11px;font-weight:600;color:{color};">{e:.3f}</span>'
        f'<div style="height:3px;background:rgba(255,255,255,.08);border-radius:999px;margin-top:2px;">'
        f'<div style="width:{bar}%;height:100%;background:{color};border-radius:999px;"></div></div>'
        f"</div>"
    )


def render_kev_cell(r):
    kev = r["kev"]
    if not kev:
        return "—"
    tip = f"Added {kev.get('dateAdded', '')} | Due {kev.get('dueDate', '')} | Ransomware: {kev.get('knownRansomwareCampaignUse', 'unknown')}"
    return f'<span style="background:#ff4d6d;color:#fff;font-size:10px;font-weight:700;border-radius:4px;padding:2px 5px;" title="{esc(tip)}">KEV</span>'


def render_fix_cell(r):
    if r["fix_state"] == "not-fixed":
        return '<span style="background:rgba(255,77,109,.2);color:#ff4d6d;font-size:10px;font-weight:600;border-radius:4px;padding:2px 5px;border:1px solid #ff4d6d;">no fix</span>'
    return esc(r["fix_version"]) if r["fix_version"] else "—"


def render_cwe_cell(r):
    if not r["cwes"]:
        return "—"
    parts = []
    for cwe in r["cwes"][:3]:
        cid = cwe.replace("CWE-", "")
        parts.append(
            f'<a href="https://cwe.mitre.org/data/definitions/{esc(cid)}.html" target="_blank" style="color:#a7d0ff;">{esc(cwe)}</a>'
        )
    return " ".join(parts)


def render_ref_cell(r):
    url = r["data_source"]
    if not url:
        return "—"
    label = "GHSA" if "github.com/advisories" in url else "NVD"
    return f'<a href="{esc(url)}" target="_blank" style="color:#a7d0ff;">{label}</a>'


# ---------------------------------------------------------------------------
# Table rendering
# ---------------------------------------------------------------------------


def render_table(rows):
    head = (
        "<tr>"
        "<th style='width:5%;'>Risk ▼</th>"
        "<th style='width:3%;'>KEV</th>"
        "<th style='width:5%;'>EPSS</th>"
        "<th style='width:4%;'>CVSS</th>"
        "<th style='width:5%;'>Sev</th>"
        "<th style='width:8%;'>Vuln ID</th>"
        "<th style='width:6%;'>CWE</th>"
        "<th style='width:12%;'>Title</th>"
        "<th style='width:8%;'>Package</th>"
        "<th style='width:5%;'>Version</th>"
        "<th style='width:4%;'>Type</th>"
        "<th style='width:12%;'>Location</th>"
        "<th style='width:5%;'>Fix</th>"
        "<th style='width:3%;'>Ref</th>"
        "</tr>"
    )
    body = []
    for _i, r in enumerate(rows, 1):
        kev_cls = " kev-row" if r["kev"] else ""
        search = esc(
            f"{r['vuln_id']} {r['package']} {r['location']} {'KEV' if r['kev'] else ''}".lower()
        )
        body.append(
            f"<tr class='sev-{esc(r['severity'])}{kev_cls}' data-search='{search}' data-risk='{r['risk_score']}'>"
            f"<td>{render_risk_cell(r)}</td>"
            f"<td>{render_kev_cell(r)}</td>"
            f"<td>{render_epss_cell(r)}</td>"
            f"<td>{render_cvss_cell(r)}</td>"
            f"<td>{esc(r['severity'])}</td>"
            f"<td><code style='font-size:11px;'>{esc(r['vuln_id'])}</code></td>"
            f"<td>{render_cwe_cell(r)}</td>"
            f"<td>{esc(r['title']) or '—'}</td>"
            f"<td>{esc(r['package'])}</td>"
            f"<td>{esc(r['version']) or '—'}</td>"
            f"<td>{esc(r['pkg_type']) or '—'}</td>"
            f"<td style='word-break:break-all;font-size:11px;'>{esc(r['location']) or '—'}</td>"
            f"<td>{render_fix_cell(r)}</td>"
            f"<td>{render_ref_cell(r)}</td>"
            "</tr>"
        )
    return f"<table><thead>{head}</thead><tbody>{''.join(body)}</tbody></table>"


def render_grouped(groups, label):
    sections, idx = [], []
    for n, (key, rows) in enumerate(sorted(groups.items()), 1):
        rows = sorted(rows, key=lambda r: -r["risk_score"])
        sid = f"grp-{label.lower()}-{n}"
        idx.append(
            f"<li><span style='color:#95a7cf;margin-right:5px;'>{n}.</span>"
            f"<a href='#{esc(sid)}' style='color:#a7d0ff;'>{esc(key)}</a>"
            f" <span style='color:#95a7cf;'>({len(rows)})</span></li>"
        )
        sections.append(
            f"<div class='group' id='{esc(sid)}' data-label='{esc(key).lower()}' data-group-size='{len(rows)}'>"
            f"<h3>{esc(label)}: {esc(key)} ({len(rows)})</h3>"
            f"{render_table(rows)}</div>"
        )
    idx_html = (
        f"<div class='index'><strong>{esc(label)} index</strong><ol>{''.join(idx)}</ol></div>"
    )
    return idx_html + "".join(sections)


# ---------------------------------------------------------------------------
# Full report
# ---------------------------------------------------------------------------


def render_report(rows):
    by_vuln = defaultdict(list)
    by_pkg = defaultdict(list)
    for r in rows:
        by_vuln[r["vuln_id"] or "unknown"].append(r)
        by_pkg[f"{r['package']}@{r['version'] or '?'}"].append(r)

    sev_counts = Counter(r["severity"] for r in rows)
    kev_count = sum(1 for r in rows if r["kev"])
    high_epss = sum(1 for r in rows if (r["epss"] or 0) >= 0.5)
    total = max(1, len(rows))

    def pct(s):
        return sev_counts.get(s, 0) / total * 100

    Counter(r["risk_band"] for r in rows)

    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Grype Dependency Report</title>
  <style>
    :root {{
      --bg:#070b1a; --panel:#101935; --text:#eaf2ff; --muted:#95a7cf; --border:rgba(124,157,255,.28);
      --critical:#ff4d6d; --high:#ff8a5b; --medium:#ffd166; --low:#6ab4ff; --unknown:#95a7cf;
    }}
    *{{box-sizing:border-box;}} body{{margin:0;color:var(--text);font-family:Segoe UI,Arial,sans-serif;background:radial-gradient(circle at 20% 10%,#182650 0%,#0a1024 45%,#060a17 100%);}}
    .wrap{{max-width:1800px;margin:0 auto;padding:20px;}}
    .hero,.panel,.index,.group{{border:1px solid var(--border);background:rgba(16,25,53,.9);border-radius:14px;}}
    .hero{{padding:16px;margin-bottom:12px;}} .hero h1{{margin:0 0 4px;}}
    .meta{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:8px;margin-top:10px;}}
    .card{{padding:10px;border:1px solid var(--border);border-radius:10px;background:rgba(10,16,36,.8);}}
    .label{{font-size:12px;color:var(--muted);text-transform:uppercase;}} .value{{font-size:20px;font-weight:700;}}
    .bar{{margin-top:8px;height:10px;background:rgba(255,255,255,.1);border-radius:999px;overflow:hidden;display:flex;}}
    .seg{{height:100%;}} .critical{{background:var(--critical);}} .high{{background:var(--high);}} .medium{{background:var(--medium);}} .low{{background:var(--low);}}
    .tabs{{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;}}
    .tabs button{{border:1px solid var(--border);background:rgba(123,141,255,.16);color:var(--text);border-radius:999px;padding:8px 12px;cursor:pointer;}}
    .tabs button.active{{background:rgba(123,141,255,.38);}}
    .panel{{padding:10px;margin:10px 0 12px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;}}
    input,select{{border:1px solid var(--border);background:#0a1024;color:var(--text);border-radius:8px;padding:8px 10px;}}
    input{{min-width:280px;flex:1;}} .stats{{margin-left:auto;color:var(--muted);font-size:12px;}}
    .tab{{display:none;}} .tab.active{{display:block;}}
    .index{{padding:10px;margin-bottom:10px;}} .index ol{{margin:8px 0 0;padding:0;list-style:none;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:6px 14px;}}
    .group{{margin:0 0 12px;overflow:hidden;}} .group h3{{margin:0;padding:10px 12px;border-bottom:1px solid var(--border);background:rgba(123,141,255,.12);font-size:15px;}}
    table{{width:100%;border-collapse:collapse;table-layout:fixed;}} th,td{{border:1px solid rgba(124,157,255,.2);padding:7px;font-size:12px;vertical-align:top;word-wrap:break-word;}}
    th{{background:rgba(11,18,39,.95);position:sticky;top:0;z-index:2;}} .hidden{{display:none!important;}}
    .sev-critical{{background:rgba(255,77,109,.12);}} .sev-high{{background:rgba(255,138,91,.12);}} .sev-medium{{background:rgba(255,209,102,.11);}} .sev-low{{background:rgba(106,180,255,.12);}} .sev-unknown{{background:rgba(149,167,207,.11);}}
    .kev-row{{outline:1px solid var(--critical);outline-offset:-1px;}}
  </style>
</head>
<body>
<div class="wrap">
  <div class="hero">
    <h1>Grype Dependency Report</h1>
    <div class="meta">
      <div class="card"><div class="label">Total</div><div class="value">{len(rows)}</div></div>
      <div class="card"><div class="label">Critical</div><div class="value" style="color:var(--critical)">{sev_counts.get("critical", 0)}</div></div>
      <div class="card"><div class="label">High</div><div class="value" style="color:var(--high)">{sev_counts.get("high", 0)}</div></div>
      <div class="card"><div class="label">Medium</div><div class="value" style="color:var(--medium)">{sev_counts.get("medium", 0)}</div></div>
      <div class="card"><div class="label">Low</div><div class="value" style="color:var(--low)">{sev_counts.get("low", 0)}</div></div>
      <div class="card"><div class="label">KEV Active</div><div class="value" style="color:var(--critical)">{kev_count}</div></div>
      <div class="card"><div class="label">EPSS ≥50%</div><div class="value" style="color:var(--high)">{high_epss}</div></div>
      <div class="card" title="KEV×100 + EPSS×50 + CVSS×1 → 0–160 | Urgent≥110 High≥10 Medium>9 Low≤9">
        <div class="label">Risk Formula</div>
        <div class="value" style="font-size:11px;color:var(--muted);">KEV·100+EPSS·50+CVSS·1</div>
      </div>
    </div>
    <div class="bar" style="margin-top:10px;">
      <div class="seg critical" style="width:{pct("critical"):.2f}%"></div>
      <div class="seg high" style="width:{pct("high"):.2f}%"></div>
      <div class="seg medium" style="width:{pct("medium"):.2f}%"></div>
      <div class="seg low" style="width:{pct("low"):.2f}%"></div>
    </div>
    <div class="tabs" role="tablist">
      <button class="active" data-tab="all">All Findings</button>
      <button data-tab="by-vuln">By Vulnerability</button>
      <button data-tab="by-pkg">By Package</button>
    </div>
  </div>
  <div class="panel">
    <input id="q" type="text" placeholder="Filter by vuln/package/location/KEV..."/>
    <select id="sev">
      <option value="all">Severity: All</option>
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
      <option value="low">Low</option>
    </select>
    <select id="kev-filter">
      <option value="all">KEV: All</option>
      <option value="kev">KEV only</option>
      <option value="non-kev">Non-KEV only</option>
    </select>
    <div id="stats" class="stats">Findings: {len(rows)}/{len(rows)}</div>
  </div>
  <div class="tab active" data-tab="all">{render_table(rows)}</div>
  <div class="tab" data-tab="by-vuln">{render_grouped(by_vuln, "Vulnerability")}</div>
  <div class="tab" data-tab="by-pkg">{render_grouped(by_pkg, "Package")}</div>
</div>
<script>
(() => {{
  const tabs = [...document.querySelectorAll('[data-tab-target],[data-tab]:not(table [data-tab])')];
  const btns = [...document.querySelectorAll('.tabs button')];
  const panes = [...document.querySelectorAll('.wrap > .tab')];
  const q = document.getElementById('q');
  const sev = document.getElementById('sev');
  const kevF = document.getElementById('kev-filter');
  const stats = document.getElementById('stats');
  const rows = () => [...document.querySelectorAll('.tab.active tr[class^="sev-"]')];

  btns.forEach(b => b.addEventListener('click', () => {{
    btns.forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    panes.forEach(p => p.classList.toggle('active', p.dataset.tab === b.dataset.tab));
    apply();
  }}));

  function apply() {{
    const needle = (q.value || '').trim().toLowerCase();
    const level  = sev.value;
    const kv     = kevF.value;
    rows().forEach(r => {{
      const rs = [...r.classList].find(c => c.startsWith('sev-')).replace('sev-','');
      const isKev = r.classList.contains('kev-row');
      const ok = (level === 'all' || rs === level)
              && (kv === 'all' || (kv === 'kev' && isKev) || (kv === 'non-kev' && !isKev))
              && (!needle || (r.dataset.search || '').includes(needle));
      r.classList.toggle('hidden', !ok);
    }});
    const vis = rows().filter(r => !r.classList.contains('hidden')).length;
    const tot = rows().length;
    stats.textContent = `Findings: ${{vis}}/${{tot}}`;
    [...document.querySelectorAll('.tab.active .group')].forEach(g => {{
      const hasRows = g.querySelectorAll('tr[class^="sev-"]:not(.hidden)').length > 0;
      g.classList.toggle('hidden', !hasRows);
    }});
  }}

  q.addEventListener('input', apply);
  sev.addEventListener('change', apply);
  kevF.addEventListener('change', apply);
  apply();
}})();
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Convert Grype JSON to interactive HTML report")
    parser.add_argument("--input", required=True, help="Input Grype JSON file")
    parser.add_argument("--html", required=True, help="Output HTML file")
    args = parser.parse_args()

    doc = read_json(Path(args.input))
    rows = flatten(doc)
    out = render_report(rows)
    Path(args.html).write_text(out, encoding="utf-8")
    print(f"Wrote {args.html} with {len(rows)} findings")


if __name__ == "__main__":
    main()
