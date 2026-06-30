"""Self-contained interactive HTML report.

Renders a single ``report.html`` from a run manifest with **no external
assets** (inline CSS + a few lines of vanilla JS), so it can be opened from
disk, emailed, or published as a CI artifact. Reviewers can filter findings by
severity, CWE and grounded/ungrounded. Secret material is redacted on the way
out, matching the Markdown/PDF/manifest emitters.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

_SEV_ORDER = ["critical", "high", "medium", "low", "informational"]
_SEV_COLOR = {
    "critical": "#7B0010",
    "high": "#C0291D",
    "medium": "#D88717",
    "low": "#3A6BC0",
    "informational": "#666666",
}


def _esc(text: Any) -> str:
    return html.escape(str(text))


def _findings_from_manifest(data: dict) -> tuple[list[dict], list[dict]]:
    final: list[dict] = []
    for stage in data.get("stages", []):
        if stage.get("stage_id") == "s9_emit":
            final = stage.get("findings", []) or []
    seen = {f.get("id") for f in final}
    dropped: list[dict] = []
    seen_d: set[str] = set()
    for stage in data.get("stages", []):
        for f in stage.get("findings", []) or []:
            fid = f.get("id")
            if fid and fid not in seen and fid not in seen_d:
                if any(t.startswith(("dropped:", "hallucinated:")) for t in f.get("tags") or []):
                    dropped.append(f)
                    seen_d.add(fid)
    return final, dropped


_CSS = """
:root { --purple:#7B189F; --pale:#f4f4f6; --dark:#1a1a1a; }
* { box-sizing: border-box; }
body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
       margin: 0; color: var(--dark); background: #fbfbfd; }
header { background: var(--purple); color: #fff; padding: 20px 28px; }
header h1 { margin: 0 0 4px; font-size: 22px; }
header .meta { font-size: 13px; opacity: .9; }
main { padding: 20px 28px; max-width: 1100px; margin: 0 auto; }
.controls { position: sticky; top: 0; background: #fbfbfd; padding: 12px 0;
            border-bottom: 1px solid #e3e3e8; display: flex; gap: 12px; flex-wrap: wrap; align-items:center; }
.controls input, .controls select { padding: 6px 8px; border: 1px solid #ccc; border-radius: 6px; font-size: 13px; }
.badge { display:inline-block; padding:2px 8px; border-radius: 10px; color:#fff; font-size:11px; font-weight:600; }
.finding { border:1px solid #e3e3e8; border-radius: 10px; padding: 14px 16px; margin: 12px 0; background:#fff; }
.finding h3 { margin: 0 0 8px; font-size: 15px; }
.kv { font-size: 13px; color:#444; margin: 2px 0; }
.kv b { color:#222; }
.desc { font-size: 13px; margin: 8px 0; white-space: pre-wrap; }
.rem { font-size: 12px; color:#0E7C3F; }
.counts { display:flex; gap:8px; flex-wrap:wrap; margin: 8px 0 4px; }
.count-pill { font-size:12px; padding:3px 10px; border-radius: 10px; background: var(--pale); }
.hidden { display:none; }
footer { padding: 16px 28px; font-size: 12px; color:#777; }
"""

_JS = """
function applyFilters() {
  const sev = document.getElementById('sev').value;
  const cwe = document.getElementById('cwe').value.trim().toLowerCase();
  const grounded = document.getElementById('grounded').value;
  const q = document.getElementById('q').value.trim().toLowerCase();
  let shown = 0;
  document.querySelectorAll('.finding').forEach(el => {
    const okSev = !sev || el.dataset.severity === sev;
    const okCwe = !cwe || (el.dataset.cwe||'').toLowerCase().includes(cwe);
    const okG = !grounded || el.dataset.grounded === grounded;
    const okQ = !q || el.textContent.toLowerCase().includes(q);
    const show = okSev && okCwe && okG && okQ;
    el.classList.toggle('hidden', !show);
    if (show) shown++;
  });
  document.getElementById('shown').textContent = shown;
}
document.addEventListener('DOMContentLoaded', () => {
  ['sev','cwe','grounded','q'].forEach(id =>
    document.getElementById(id).addEventListener('input', applyFilters));
  applyFilters();
});
"""


def _render_finding(f: dict) -> str:
    sev = (f.get("severity") or "informational").lower()
    locs = f.get("locations") or [{}]
    loc = locs[0]
    grounded = "true" if f.get("grounded") else "false"
    tags = ", ".join(f.get("tags") or [])
    color = _SEV_COLOR.get(sev, "#666")
    return f"""
    <div class="finding" data-severity="{_esc(sev)}" data-cwe="{_esc(f.get("cwe") or "")}"
         data-grounded="{grounded}">
      <h3><span class="badge" style="background:{color}">{_esc(sev.upper())}</span>
        {_esc(f.get("title", ""))} <span style="color:#999">{_esc(f.get("id", ""))}</span></h3>
      <div class="kv"><b>CWE:</b> {_esc(f.get("cwe") or "unknown")} &nbsp;
        <b>Location:</b> {_esc(loc.get("path", "?"))}:{_esc(loc.get("start_line", "?"))} &nbsp;
        <b>Confidence:</b> {_esc(f"{f.get('confidence', 0):.2f}")} &nbsp;
        <b>Grounded:</b> {_esc(grounded)}</div>
      <div class="kv"><b>Lens/stage:</b> {_esc(f.get("skill", "-"))} / {_esc(f.get("stage", "-"))}
        &nbsp; <b>Tags:</b> {_esc(tags or "-")}</div>
      <div class="desc">{_esc(f.get("description", "") or "(no description)")}</div>
      <div class="rem"><b>Remediation:</b> {_esc(f.get("remediation", "") or "(none)")}</div>
    </div>"""


def render_manifest_html(
    manifest_path: Path, output: Path, *, target_name: str | None = None
) -> Path:
    """Render ``manifest_path`` into a single self-contained ``output`` HTML file."""
    data = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    findings, _dropped = _findings_from_manifest(data)
    target_name = target_name or Path(data.get("target_repo", "target")).name

    counts: dict[str, int] = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        counts[(f.get("severity") or "informational").lower()] = (
            counts.get((f.get("severity") or "informational").lower(), 0) + 1
        )
    order = {s: i for i, s in enumerate(reversed(_SEV_ORDER))}
    findings_sorted = sorted(
        findings, key=lambda f: -order.get((f.get("severity") or "").lower(), 0)
    )

    pills = "".join(
        f'<span class="count-pill" style="border-left:4px solid {_SEV_COLOR[s]}">'
        f"{s}: <b>{counts[s]}</b></span>"
        for s in _SEV_ORDER
    )
    findings_html = "".join(_render_finding(f) for f in findings_sorted) or (
        "<p><i>No findings survived the quality pipeline.</i></p>"
    )

    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RedEye report -- {_esc(target_name)}</title>
<style>{_CSS}</style></head>
<body>
<header>
  <h1>RedEye Security Scan Report</h1>
  <div class="meta">{_esc(target_name)} &middot; profile {_esc(data.get("profile", "-"))}
    &middot; {_esc(data.get("finding_count", len(findings)))} findings
    &middot; cost ${_esc(f"{data.get('total_cost_usd', 0):.3f}")}</div>
</header>
<main>
  <div class="counts">{pills}</div>
  <div class="controls">
    <label>Severity
      <select id="sev"><option value="">all</option>
        {"".join(f'<option value="{s}">{s}</option>' for s in _SEV_ORDER)}
      </select></label>
    <label>Grounded
      <select id="grounded"><option value="">all</option>
        <option value="true">grounded</option><option value="false">ungrounded</option>
      </select></label>
    <input id="cwe" placeholder="CWE filter, e.g. 89">
    <input id="q" placeholder="search text...">
    <span style="font-size:12px;color:#666">showing <b id="shown">0</b> finding(s)</span>
  </div>
  {findings_html}
</main>
<footer>LLM-generated triage candidates -- treat as starting points for human review.
  Generated by redeye {_esc(data.get("version", ""))}.</footer>
<script>{_JS}</script>
</body></html>"""

    from redeye.redaction import redact_secrets

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(redact_secrets(doc), encoding="utf-8")
    return output
