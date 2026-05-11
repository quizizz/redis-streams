#!/usr/bin/env python3
"""
sarif-to-html.py — Convert Semgrep SARIF output to an interactive HTML triage report.

Usage:
    python3 scripts/security/sarif-to-html.py \\
        --input semgrep.sarif \\
        --json-input semgrep-results.json \\
        --html semgrep-report.html

The report has four tabs:
  1. All Findings    — flat table
  2. By Rule         — grouped by rule ID
  3. By File         — grouped by file path
  4. Priority View   — grouped by Semgrep priority tier (urgent/high/medium/low/none)

Priority formula (mirrors Semgrep AppSec Platform):
  urgent = ERROR + HIGH confidence
  high   = ERROR + MEDIUM confidence
  medium = ERROR + LOW confidence
  low    = WARNING
  none   = NOTE / INFO
"""

import argparse
import html as html_lib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


def esc(v):
    return html_lib.escape(str(v)) if v is not None else ""


def slugify(v):
    return re.sub(r"[^a-z0-9]+", "-", str(v).strip().lower()).strip("-") or "g"


def read_json(path: Path):
    with path.open(encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Priority formula
# ---------------------------------------------------------------------------

PRIORITY_ORDER = {"urgent": 0, "high": 1, "medium": 2, "low": 3, "none": 4}


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


PRIORITY_COLOR = {
    "urgent": "var(--danger)",
    "high": "var(--warn)",
    "medium": "#ffd166",
    "low": "#6ab4ff",
    "none": "var(--muted)",
}

PRIORITY_LABEL = {
    "urgent": "🔴 Urgent",
    "high": "🟠 High",
    "medium": "🟡 Medium",
    "low": "🔵 Low",
    "none": "⚪ No Priority",
}

PRIORITY_DESC = {
    "urgent": "ERROR + confidence HIGH — fix immediately",
    "high": "ERROR + confidence MEDIUM — fix this sprint",
    "medium": "ERROR + confidence LOW — review before acting",
    "low": "WARNING — schedule when possible",
    "none": "NOTE/INFO — informational",
}


# ---------------------------------------------------------------------------
# CODEOWNERS
# ---------------------------------------------------------------------------


def load_codeowners(repo_root: Path):
    try:
        from codeowners import CodeOwners  # type: ignore

        for candidate in [
            repo_root / ".github" / "CODEOWNERS",
            repo_root / "CODEOWNERS",
        ]:
            if candidate.exists():
                return CodeOwners(candidate.read_text(encoding="utf-8"))
    except ImportError:
        pass
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
                "short": (rule.get("shortDescription") or {}).get("text", ""),
                "help_uri": rule.get("helpUri") or "",
                "level": (rule.get("defaultConfiguration") or {}).get("level", "warning"),
            }
    return rule_map


def load_json_metadata(json_path: Path) -> dict:
    if not json_path or not json_path.exists():
        return {}
    doc = read_json(json_path)
    lookup = {}
    for r in doc.get("results", []) or []:
        rid = r.get("check_id", "")
        fpath = r.get("path", "")
        ln = str(r.get("start", {}).get("line", ""))
        meta = r.get("extra", {}).get("metadata", {})
        lookup[(rid, fpath, ln)] = {
            "confidence": (meta.get("confidence") or "").upper(),
            "likelihood": (meta.get("likelihood") or "").upper(),
            "impact": (meta.get("impact") or "").upper(),
            "subcategory": meta.get("subcategory") or [],
        }
    return lookup


def parse_sarif(sarif_path: Path, co, json_meta: dict) -> list:
    sarif = read_json(sarif_path)
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
            owner = resolve_owner(file_uri, co)
            short_rule = rid.split(".")[-1] if rid else "unknown"

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
                }
            )
    return rows


# ---------------------------------------------------------------------------
# Shared CSS + JS
# ---------------------------------------------------------------------------

STYLES = """
<style>
  :root {
    --bg:#070b1a; --panel:rgba(18,24,44,.82); --text:#eaf2ff; --muted:#95a7cf;
    --border:rgba(124,157,255,.28); --danger:#ff5f87; --warn:#ffb35f; --info:#6ab4ff;
  }
  *{box-sizing:border-box;} html{scroll-behavior:smooth;}
  body{font-family:"Segoe UI",Arial,sans-serif;margin:0;color:var(--text);
       background:radial-gradient(circle at 15% 18%,#17254f 0%,#0a1024 35%,#060a17 70%,#05070f 100%);min-height:100vh;}
  .wrap{position:relative;z-index:1;padding:24px;max-width:1800px;margin:0 auto;}
  .hero{border:1px solid var(--border);border-radius:18px;background:linear-gradient(130deg,rgba(16,25,53,.94),rgba(10,16,36,.94));
        box-shadow:0 25px 60px rgba(0,0,0,.45);padding:20px 22px;margin-bottom:16px;}
  .hero h1{margin:0 0 6px;font-size:28px;}
  .meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin-top:12px;}
  .card{padding:10px 14px;border:1px solid var(--border);border-radius:12px;background:rgba(10,16,36,.8);}
  .clabel{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.6px;margin-bottom:4px;}
  .cval{font-size:22px;font-weight:700;}
  .bar{margin:8px 0;height:10px;background:rgba(255,255,255,.08);border-radius:999px;overflow:hidden;display:flex;}
  .seg{height:100%;}
  .seg.error{background:var(--danger);} .seg.warning{background:var(--warn);} .seg.note,.seg.info{background:var(--info);}
  .tab-nav{margin-top:14px;display:flex;gap:10px;flex-wrap:wrap;}
  .tab-btn{border:1px solid rgba(123,141,255,.45);border-radius:999px;background:rgba(123,141,255,.12);
           color:var(--text);padding:8px 13px;font-size:13px;cursor:pointer;}
  .tab-btn:hover{background:rgba(123,141,255,.3);}
  .tab-btn.active{background:linear-gradient(90deg,rgba(123,141,255,.4),rgba(79,241,204,.26));}
  .cmd{border:1px solid var(--border);border-radius:14px;background:var(--panel);padding:10px 12px;
       display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:14px;}
  .cmd input,.cmd select{border:1px solid rgba(123,141,255,.45);border-radius:10px;background:rgba(9,14,30,.95);
                          color:var(--text);padding:9px 11px;outline:none;}
  .cmd input{flex:1;min-width:250px;} .cmd .stats{margin-left:auto;font-size:12px;color:var(--muted);}
  .tab-content{display:none;margin-top:12px;} .tab-content.active{display:block;}
  .group{margin:0 0 14px;border:1px solid var(--border);border-radius:14px;background:var(--panel);overflow:hidden;}
  .group h2{margin:0;font-size:16px;padding:10px 14px;border-bottom:1px solid var(--border);
             background:rgba(123,141,255,.1);display:flex;align-items:center;gap:8px;}
  .index{padding:12px;border:1px solid var(--border);border-radius:14px;background:var(--panel);margin-bottom:12px;}
  .index ol{margin:8px 0 0;padding:0;list-style:none;display:grid;grid-template-columns:repeat(2,1fr);gap:5px 14px;}
  table{width:100%;border-collapse:collapse;table-layout:fixed;}
  th,td{border:1px solid rgba(124,157,255,.2);padding:7px;font-size:12px;vertical-align:top;word-wrap:break-word;}
  th{background:rgba(15,24,48,.96);position:sticky;top:0;z-index:1;}
  .sev-error{background:rgba(255,95,135,.13);} .sev-warning{background:rgba(255,179,95,.14);}
  .sev-note,.sev-info{background:rgba(106,180,255,.14);}
  .hidden{display:none!important;}
  .owner-index-list{margin:8px 0 0;padding:0;list-style:none;display:flex;flex-direction:column;gap:8px;}
  .owner-index-list li{padding:8px 10px;border:1px solid var(--border);border-radius:8px;background:rgba(10,16,36,.5);}
  .owner-name{font-size:12px;font-weight:600;color:#4ff1cc;word-break:break-all;}
  .owner-groups{font-size:12px;color:var(--muted);line-height:1.7;word-break:break-word;}
  .owner-groups a{color:#a7d0ff;text-decoration:none;margin-right:2px;} .owner-groups a:hover{text-decoration:underline;}
  a{color:#a7d0ff;text-decoration:none;} a:hover{text-decoration:underline;}
  code{font-size:11px;color:#8de1ff;}
</style>
"""

JS = """
<script>
(() => {
  const btns  = [...document.querySelectorAll('.tab-btn')];
  const panes = [...document.querySelectorAll('.tab-content')];
  const qEl   = document.getElementById('gFilter');
  const sevEl = document.getElementById('sevFilter');
  const stats = document.getElementById('gStats');

  function activate(key) {
    btns.forEach(b  => b.classList.toggle('active', b.dataset.tab === key));
    panes.forEach(p => p.classList.toggle('active', p.dataset.tab === key));
    apply();
  }
  btns.forEach(b => b.addEventListener('click', () => activate(b.dataset.tab)));
  activate(btns[0]?.dataset.tab || 'full');

  function apply() {
    const needle = (qEl?.value || '').trim().toLowerCase();
    const level  = sevEl?.value || 'all';
    const pane   = document.querySelector('.tab-content.active');
    if (!pane) return;
    const rows = [...pane.querySelectorAll("tr[class^='sev-']")];
    rows.forEach(r => {
      const rs   = [...r.classList].find(c => c.startsWith('sev-'))?.replace('sev-','') || '';
      const sevOk = level === 'all' || rs === level;
      const txtOk = !needle || (r.dataset.search || '').includes(needle);
      r.classList.toggle('hidden', !(sevOk && txtOk));
    });
    const groups = [...pane.querySelectorAll('.group')];
    groups.forEach(g => {
      const vis  = g.querySelectorAll("tr[class^='sev-']:not(.hidden)").length > 0;
      const lbl  = (g.dataset.label || '').toLowerCase();
      const lblOk = !needle || lbl.includes(needle);
      g.classList.toggle('hidden', !(vis && lblOk));
    });
    const visR = rows.filter(r => !r.classList.contains('hidden')).length;
    if (groups.length) {
      const visG = groups.filter(g => !g.classList.contains('hidden')).length;
      if (stats) stats.textContent = `Groups: ${visG}/${groups.length} | Findings: ${visR}/${rows.length}`;
    } else {
      if (stats) stats.textContent = `Findings: ${visR}/${rows.length}`;
    }
  }
  if (qEl)   qEl.addEventListener('input', apply);
  if (sevEl) sevEl.addEventListener('change', apply);
  apply();
})();
</script>
"""


# ---------------------------------------------------------------------------
# Table
# ---------------------------------------------------------------------------


def sort_key(r):
    return (r.get("file", ""), int(r.get("line") or 0), r.get("rule_id", ""))


def findings_table(rows, include_rule=True, include_file=True):
    head_cells = ["<th style='width:4%;'>#</th>", "<th style='width:7%;'>Sev</th>"]
    if include_rule:
        head_cells += ["<th style='width:18%;'>Rule</th>"]
    if include_file:
        head_cells += [
            "<th style='width:18%;'>File</th>",
            "<th style='width:6%;'>Line</th>",
        ]
    head_cells.append("<th>Message</th>")
    if include_rule:
        head_cells.append("<th style='width:8%;'>Docs</th>")

    body = []
    for i, r in enumerate(rows, 1):
        sev = esc(r["level"])
        cells = [f"<td>{i}</td>", f"<td>{sev}</td>"]
        if include_rule:
            cells.append(f"<td><code>{esc(r['rule_id'])}</code></td>")
        if include_file:
            cells.append(f"<td style='font-size:11px;word-break:break-all;'>{esc(r['file'])}</td>")
            cells.append(f"<td>{esc(r['line']) or '—'}</td>")
        cells.append(f"<td>{esc(r['message'])}</td>")
        if include_rule:
            uri = r.get("help_uri", "")
            link = f'<a href="{esc(uri)}" target="_blank">docs ↗</a>' if uri else "—"
            cells.append(f"<td>{link}</td>")

        search = esc(f"{r['rule_id']} {r['file']} {r.get('owner', '')}".lower())
        body.append(f"<tr class='sev-{sev}' data-search='{search}'>{''.join(cells)}</tr>")

    return f"<table><thead><tr>{''.join(head_cells)}</tr></thead><tbody>{''.join(body)}</tbody></table>"


# ---------------------------------------------------------------------------
# Tab renderers
# ---------------------------------------------------------------------------


def render_grouped_tab(groups: dict, label: str, _kind: str) -> str:
    sections, idx = [], []
    for n, key in enumerate(sorted(groups.keys()), 1):
        rows = sorted(groups[key], key=sort_key)
        sid = f"{slugify(key)}-{n}"
        idx.append(
            f"<li><span style='color:var(--muted);margin-right:5px;'>{n}.</span>"
            f"<a href='#{esc(sid)}'>{esc(key)}</a> <span style='color:var(--muted);'>({len(rows)})</span></li>"
        )
        sections.append(
            f"<div class='group' id='{esc(sid)}' data-label='{esc(key).lower()}' data-group-size='{len(rows)}'>"
            f"<h2>{esc(label)}: {esc(key)} ({len(rows)})</h2>"
            f"{findings_table(rows)}</div>"
        )
    idx_html = (
        f"<div class='index'><strong>{esc(label)} index</strong><ol>{''.join(idx)}</ol></div>"
    )
    return idx_html + "".join(sections)


def render_priority_tab(rows: list) -> str:
    tiers: dict = {"urgent": [], "high": [], "medium": [], "low": [], "none": []}
    for r in rows:
        tiers[r["priority"]].append(r)

    CONF_ORD = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "": 3}
    SEV_ORD = {"error": 0, "warning": 1, "note": 2, "info": 3}

    formula = (
        "<div style='margin:10px 0;padding:10px 14px;background:rgba(123,141,255,.08);"
        "border:1px solid var(--border);border-radius:10px;font-size:12px;color:var(--muted);'>"
        "<strong style='color:var(--text);'>Priority formula</strong>: "
        "<code style='color:var(--danger);'>Urgent</code> = ERROR + HIGH conf &nbsp;|&nbsp; "
        "<code style='color:var(--warn);'>High</code> = ERROR + MEDIUM conf &nbsp;|&nbsp; "
        "<code style='color:#ffd166;'>Medium</code> = ERROR + LOW conf &nbsp;|&nbsp; "
        "<code style='color:#6ab4ff;'>Low</code> = WARNING &nbsp;|&nbsp; "
        "<code style='color:var(--muted);'>None</code> = NOTE/INFO"
        "</div>"
    )

    counts_html = "".join(
        f'<span style="padding:6px 12px;border:1px solid {PRIORITY_COLOR[k]};border-radius:8px;'
        f'background:rgba(0,0,0,.2);font-size:13px;display:inline-flex;gap:5px;align-items:center;">'
        f'<span style="color:{PRIORITY_COLOR[k]};font-weight:700;">{PRIORITY_LABEL[k]}</span>'
        f'<span style="color:var(--muted);">({len(tiers[k])})</span></span>'
        for k in ("urgent", "high", "medium", "low", "none")
    )

    parts = [
        f"<div style='display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px;'>{counts_html}</div>",
        formula,
    ]

    for tier_key in ("urgent", "high", "medium", "low", "none"):
        tier_rows = tiers[tier_key]
        if not tier_rows:
            continue
        color = PRIORITY_COLOR[tier_key]
        label = PRIORITY_LABEL[tier_key]
        desc = PRIORITY_DESC[tier_key]
        sorted_rows = sorted(
            tier_rows,
            key=lambda r: (
                CONF_ORD.get(r.get("confidence", ""), 3),
                SEV_ORD.get(r.get("level", ""), 9),
                r.get("rule_id", ""),
                r.get("file", ""),
            ),
        )
        head = (
            "<th style='width:4%;'>#</th><th style='width:7%;'>Sev</th>"
            "<th style='width:8%;'>Conf</th><th style='width:7%;'>Like</th><th style='width:7%;'>Impact</th>"
            "<th style='width:16%;'>Rule</th><th style='width:16%;'>File:Line</th><th>Message</th>"
        )

        def badge(val, hc="var(--danger)", mc="var(--warn)"):
            c = {"HIGH": hc, "MEDIUM": mc, "LOW": "var(--muted)"}.get(val, "var(--muted)")
            return f"<span style='color:{c};font-weight:600;'>{val or '—'}</span>"

        body = []
        for j, r in enumerate(sorted_rows, 1):
            sev = esc(r["level"])
            uri = r.get("help_uri", "")
            rule_c = (
                f'<a href="{esc(uri)}" target="_blank"><code>{esc(r["rule_id"])}</code></a>'
                if uri
                else f"<code>{esc(r['rule_id'])}</code>"
            )
            fl = f"{esc(r['file'])}:{esc(r['line'])}"
            search = esc(f"{r['rule_id']} {r['file']} {r.get('owner', '')} {tier_key}".lower())
            body.append(
                f"<tr class='sev-{sev}' data-search='{search}'>"
                f"<td>{j}</td><td>{sev}</td>"
                f"<td>{badge(r.get('confidence', ''))}</td>"
                f"<td>{badge(r.get('likelihood', ''), hc='var(--danger)', mc='var(--warn)')}</td>"
                f"<td>{badge(r.get('impact', ''), hc='var(--danger)', mc='var(--warn)')}</td>"
                f"<td style='font-size:11px;'>{rule_c}</td>"
                f"<td style='font-size:11px;word-break:break-all;'>{fl}</td>"
                f"<td>{esc(r['message'])}</td></tr>"
            )
        table = f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"
        parts.append(
            f"<div class='group' id='pri-{tier_key}' data-label='{tier_key}' data-group-size='{len(tier_rows)}'>"
            f"<h2 style='border-left:4px solid {color};'>"
            f"<span style='color:{color};font-weight:700;margin-right:8px;'>{label}</span>"
            f"<span style='color:var(--muted);font-size:13px;font-weight:400;'>{desc}</span>"
            f"<span style='color:var(--muted);margin-left:8px;'>({len(tier_rows)})</span></h2>"
            f"{table}</div>"
        )
    return "".join(parts)


# ---------------------------------------------------------------------------
# Full report
# ---------------------------------------------------------------------------


def render_html(
    all_rows: list,
    by_rule: dict,
    by_file: dict,
    sev_counts: dict,
    _co,
    default_tab="full",
) -> str:
    pri_html = render_priority_tab(all_rows)
    full_html = findings_table(all_rows)
    grp_rule_html = render_grouped_tab(by_rule, "Rule", "rule")
    grp_file_html = render_grouped_tab(by_file, "File", "file")

    total = max(1, len(all_rows))
    sev_segs = "".join(
        f'<div class="seg {s}" style="width:{sev_counts.get(s, 0) / total * 100:.2f}%"></div>'
        for s in ("error", "warning", "note", "info")
        if sev_counts.get(s, 0)
    )
    sev_opts = "".join(
        f'<option value="{s}">Severity: {s.capitalize()}</option>'
        for s in ("error", "warning", "note", "info")
        if sev_counts.get(s)
    )
    sev_label = {
        "error": "error",
        "warning": "warning",
        "note": "info",
        "total": "info",
    }
    meta_cards = "".join(
        f'<div class="card"><span class="clabel">{esc(s)}</span>'
        f'<span class="cval" style="color:var(--{sev_label.get(s, "muted")});">{v}</span></div>'
        for s, v in [
            ("Total", len(all_rows)),
            ("error", sev_counts.get("error", 0)),
            ("warning", sev_counts.get("warning", 0)),
            ("note", sev_counts.get("note", 0)),
        ]
    )

    tabs = [
        ("full", "All Findings"),
        ("by-rule", "Grouped by Rule"),
        ("by-file", "Grouped by File"),
        ("priority", "Priority View"),
    ]
    tab_btns = "".join(
        f'<button class="tab-btn{" active" if k == default_tab else ""}" data-tab="{k}">{label}</button>'
        for k, label in tabs
    )
    tab_sections = {
        "full": full_html,
        "by-rule": grp_rule_html,
        "by-file": grp_file_html,
        "priority": pri_html,
    }
    content = "".join(
        f'<div class="tab-content{"  active" if k == default_tab else ""}" data-tab="{k}">{tab_sections[k]}</div>'
        for k, _ in tabs
    )

    return f"""<!doctype html>
<html>
<head><meta charset="utf-8"/><title>Semgrep SAST Report</title>{STYLES}</head>
<body>
<div class="wrap">
  <div class="hero">
    <h1>Semgrep SAST Report</h1>
    <div class="meta">{meta_cards}</div>
    <div class="bar">{sev_segs}</div>
    <div class="tab-nav" role="tablist">{tab_btns}</div>
  </div>
  <div class="cmd">
    <input id="gFilter" type="text" placeholder="Filter by rule/file/owner..."/>
    <select id="sevFilter">
      <option value="all">Severity: All</option>
      {sev_opts}
    </select>
    <div id="gStats" class="stats">Findings: {len(all_rows)}/{len(all_rows)}</div>
  </div>
  {content}
</div>
{JS}
</body>
</html>"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Convert Semgrep SARIF to interactive HTML report")
    parser.add_argument("--input", required=True, help="Input SARIF file")
    parser.add_argument(
        "--json-input",
        default=None,
        help="Semgrep JSON output (for confidence/likelihood/impact)",
    )
    parser.add_argument("--html", required=True, help="Output full HTML")
    args = parser.parse_args()

    sarif_path = Path(args.input)
    json_path = (
        Path(args.json_input)
        if args.json_input
        else sarif_path.parent / sarif_path.name.replace(".sarif", ".json")
    )
    co = load_codeowners(sarif_path.parent)
    json_meta = load_json_metadata(json_path)

    if json_meta:
        print(f"Enriched from {json_path}")
    else:
        print(f"Note: JSON metadata not found at {json_path}")

    all_rows = parse_sarif(sarif_path, co, json_meta)
    sev_counts = Counter(r["level"] for r in all_rows)

    by_rule: dict = defaultdict(list)
    by_file: dict = defaultdict(list)
    for r in all_rows:
        by_rule[r["rule_id"] or "unknown-rule"].append(r)
        by_file[r["file"] or "(no location)"].append(r)

    Path(args.html).write_text(
        render_html(all_rows, by_rule, by_file, sev_counts, co, "full"),
        encoding="utf-8",
    )

    print(f"Wrote {args.html}")
    print(f"Total findings: {len(all_rows)}")


if __name__ == "__main__":
    main()
