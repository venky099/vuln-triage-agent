"""Report rendering formats: Markdown, HTML, and JSON."""
from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from typing import Any

from .agent import TriageResult

BADGE: dict[str, str] = {
    "Critical": "#b21f2d",
    "High": "#c9600a",
    "Medium": "#9a7d09",
    "Low": "#0a63c9",
    "None": "#6b7280",
}


def _today() -> str:
    """Return the current UTC date formatted as YYYY-MM-DD."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _clean_target(target: str) -> str:
    """Sanitize target string to prevent line breaks or layout breaking characters."""
    cleaned = re.sub(r"[\r\n]+", " ", (target or "").strip())
    return cleaned[:200] if cleaned else "Unspecified target"


def to_markdown(result: TriageResult, target: str = "") -> str:
    """Render a TriageResult into a formatted Markdown report."""
    counts = result.counts()
    target_str = _clean_target(target)
    lines = [
        "# Vulnerability Assessment Report",
        "",
        f"**Target:** {target_str}  ",
        f"**Date:** {_today()}  ",
        f"**Findings:** {len(result.findings)} ({result.duplicates_removed} duplicate"
        f"{'' if result.duplicates_removed == 1 else 's'} merged)",
        "",
        "## Executive summary",
        "",
    ]

    top = result.findings[0] if result.findings else None
    if top and top.severity in ("Critical", "High"):
        lines.append(
            f"The assessment identified **{counts['Critical']} critical** and **{counts['High']} high** severity issues. "
            f"The most serious is *{top.title}*, scoring {top.cvss_score} ({top.severity}). Issues at this level should be "
            "remediated before the next release."
        )
    elif result.findings:
        lines.append(
            f"No critical or high severity issues were identified. {len(result.findings)} finding(s) of medium "
            "severity or below are listed below."
        )
    else:
        lines.append("No findings were reported by the scanner.")

    lines += ["", "| Severity | Count |", "|---|---|"]
    for sev in ("Critical", "High", "Medium", "Low", "None"):
        if counts.get(sev):
            lines.append(f"| {sev} | {counts[sev]} |")

    if result.flagged:
        lines += [
            "",
            f"> **{len(result.flagged)} finding(s) contain claims that could not be traced to the scan "
            "data.** They are marked below and must be reviewed before this report is sent.",
        ]

    lines += ["", "## Findings", ""]
    for i, f in enumerate(result.findings, 1):
        lines += [
            f"### {i}. {f.title}",
            "",
            f"**Severity:** {f.severity} ({f.cvss_score})  ",
            f"**CVSS v3.1:** `{f.cvss_vector}`  ",
        ]
        if f.cwe_id:
            lines.append(f"**Weakness:** {f.cwe_id} — {f.cwe_name}  ")
        lines.append(f"**Source:** {f.source_id}" +
                     (f" (also seen as {', '.join(f.duplicates)})" if f.duplicates else ""))
        lines += [
            "", f.summary, "",
            "**Reproduction**", "", f.reproduction, "",
            "**Remediation**", "", f.remediation, "",
        ]
        if f.flags:
            lines += ["**⚠ Needs review before sending:**", ""]
            lines += [f"- {flag}" for flag in f.flags]
            lines.append("")
        lines.append("---")
        lines.append("")

    lines += [
        "## About this report",
        "",
        "Findings were triaged with an LLM under a fixed output schema. CVSS scores "
        "are computed from the selected metrics by code, not stated by the model, and "
        "every claim is checked against the scanner output and a local CWE catalogue "
        "before inclusion. Claims that could not be traced are flagged above rather "
        "than silently removed.",
        "",
        f"Backend: `{result.backend}`. Schema retries: {result.schema_retries}.",
    ]
    return "\n".join(lines)


def to_html(result: TriageResult, target: str = "") -> str:
    """Render a TriageResult into a standalone, styled HTML report."""
    counts = result.counts()
    rows = []
    for i, f in enumerate(result.findings, 1):
        flags_html = ""
        if f.flags:
            flags_html = (
                "<div class='flags'><b>Needs review before sending</b><ul>"
                + "".join(f"<li>{html.escape(x)}</li>" for x in f.flags)
                + "</ul></div>"
            )

        badge_color = BADGE.get(f.severity, "#6b7280")
        cwe_part = (
            f" &middot; {html.escape(str(f.cwe_id))} {html.escape(f.cwe_name)}"
            if f.cwe_id else ""
        )

        rows.append(
            "<article class='finding'>"
            f"<div class='head'><span class='sev' style='background:{badge_color}'>"
            f"{html.escape(str(f.severity))} {html.escape(str(f.cvss_score))}</span>"
            f"<h3>{i}. {html.escape(f.title)}</h3></div>"
            f"<p class='meta'><code>{html.escape(f.cvss_vector)}</code>{cwe_part} &middot; source {html.escape(f.source_id)}</p>"
            f"<p>{html.escape(f.summary)}</p>"
            f"<h4>Reproduction</h4><p>{html.escape(f.reproduction)}</p>"
            f"<h4>Remediation</h4><p>{html.escape(f.remediation)}</p>{flags_html}</article>"
        )

    summary_cells = "".join(
        f"<div class='stat'><span style='color:{BADGE[s]}'>{counts[s]}</span><small>{s}</small></div>"
        for s in ("Critical", "High", "Medium", "Low") if counts.get(s)
    )

    clean_target_str = html.escape(_clean_target(target))

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Vulnerability Assessment Report</title><style>
:root{{--bg:#fff;--fg:#14161d;--muted:#5b6472;--line:#e4e7ee;--card:#fafbfd}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0d0f14;--fg:#e8eaf0;--muted:#98a1b0;--line:#252a34;--card:#141821}}}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--fg);font:15px/1.6 -apple-system,"Segoe UI",Roboto,sans-serif;padding:40px 20px}}
.wrap{{max-width:820px;margin:0 auto}}
h1{{font-size:1.7rem;margin-bottom:4px}}
.sub{{color:var(--muted);margin-bottom:24px}}
.stats{{display:flex;gap:10px;margin:20px 0 28px;flex-wrap:wrap}}
.stat{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 18px;text-align:center}}
.stat span{{display:block;font-size:1.5rem;font-weight:700}}
.stat small{{color:var(--muted)}}
.finding{{border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:16px;background:var(--card)}}
.head{{display:flex;align-items:center;gap:10px;margin-bottom:6px;flex-wrap:wrap}}
.sev{{color:#fff;font:700 .72rem/1 monospace;padding:5px 9px;border-radius:999px;white-space:nowrap}}
h3{{font-size:1.05rem}} h4{{font-size:.82rem;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);margin:14px 0 4px}}
.meta{{color:var(--muted);font-size:.84rem;margin-bottom:10px}}
code{{font-family:ui-monospace,Consolas,monospace;font-size:.82em}}
.flags{{margin-top:14px;padding:10px 14px;border-left:3px solid #c9600a;background:rgba(201,96,10,.08);border-radius:6px;font-size:.88rem}}
.flags ul{{margin:6px 0 0 18px}}
footer{{color:var(--muted);font-size:.84rem;margin-top:30px;border-top:1px solid var(--line);padding-top:16px}}
</style></head><body><div class="wrap">
<h1>Vulnerability Assessment Report</h1>
<p class="sub">{clean_target_str} &middot; {_today()} &middot; {len(result.findings)} findings, {result.duplicates_removed} duplicates merged</p>
<div class="stats">{summary_cells}</div>
{''.join(rows)}
<footer>Triaged with an LLM under a fixed output schema. CVSS scores are computed from the
selected metrics by code, never stated by the model. Every claim is checked against the scanner
output and a local CWE catalogue; untraceable claims are flagged, not silently dropped.
Backend: <code>{html.escape(result.backend)}</code>. Schema retries: {result.schema_retries}.</footer>
</div></body></html>"""


def to_json(result: TriageResult, target: str = "") -> str:
    """Serialize a TriageResult to JSON format."""
    return json.dumps({
        "target": _clean_target(target),
        "generated": _today(),
        "backend": result.backend,
        "counts": result.counts(),
        "duplicates_removed": result.duplicates_removed,
        "schema_retries": result.schema_retries,
        "ungrounded_findings": len(result.flagged),
        "findings": [f.to_dict() for f in result.findings],
    }, indent=2)
