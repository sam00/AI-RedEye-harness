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
:root { --purple:#7B189F; --pale:#f4f4f6; --dark:#1a1a1a; --ok:#0E7C3F; --no:#B0392C; }
* { box-sizing: border-box; }
body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
       margin: 0; color: var(--dark); background: #fbfbfd; }
header { background: var(--purple); color: #fff; padding: 20px 28px; }
header h1 { margin: 0 0 4px; font-size: 22px; }
header .meta { font-size: 13px; opacity: .9; }
main { padding: 20px 28px; max-width: 1100px; margin: 0 auto; }
.controls { position: sticky; top: 0; background: #fbfbfd; padding: 12px 0; z-index: 5;
            border-bottom: 1px solid #e3e3e8; display: flex; gap: 12px; flex-wrap: wrap; align-items:center; }
.controls input, .controls select { padding: 6px 8px; border: 1px solid #ccc; border-radius: 6px; font-size: 13px; }
.badge { display:inline-block; padding:2px 8px; border-radius: 10px; color:#fff; font-size:11px; font-weight:600; }
.finding { border:1px solid #e3e3e8; border-radius: 10px; padding: 14px 16px; margin: 12px 0; background:#fff; }
.finding h3 { margin: 0 0 8px; font-size: 15px; }
.kv { font-size: 13px; color:#444; margin: 2px 0; }
.kv b { color:#222; }
.desc { font-size: 13px; margin: 8px 0; white-space: pre-wrap; }
.rem { font-size: 12px; color:var(--ok); }
.counts { display:flex; gap:8px; flex-wrap:wrap; margin: 8px 0 4px; }
.count-pill { font-size:12px; padding:3px 10px; border-radius: 10px; background: var(--pale); }
.hidden { display:none; }
footer { padding: 16px 28px; font-size: 12px; color:#777; }
.verdict { display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:700; }
.verdict.yes { background:#e5f4ec; color:var(--ok); border:1px solid #bfe3cd; }
.verdict.no  { background:#fbe9e7; color:var(--no); border:1px solid #f2c6bf; }
.chips { display:flex; gap:6px; flex-wrap:wrap; margin:6px 0; }
.chip { font-size:11px; padding:2px 8px; border-radius:10px; border:1px solid #ddd; }
.chip.ok { background:#e5f4ec; color:var(--ok); border-color:#bfe3cd; }
.chip.no { background:#f4f4f6; color:#999; }
details.sec { margin:8px 0; border:1px solid #eee; border-radius:8px; padding:6px 10px; background:#fcfcff; }
details.sec > summary { cursor:pointer; font-size:12px; font-weight:600; color:#444; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:12px; }
pre.code { background:#f6f6fa; border:1px solid #eee; border-radius:6px; padding:8px; overflow:auto;
           font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:12px; white-space:pre-wrap; }
table.tbl { border-collapse: collapse; font-size:12px; margin:8px 0; width:100%; }
table.tbl th, table.tbl td { border:1px solid #e6e6ea; padding:4px 8px; text-align:left; }
table.tbl th { background: var(--pale); }
.evi-pass { color:var(--ok); font-weight:600; }
.evi-fail { color:var(--no); font-weight:600; }
"""

_JS = """
function applyFilters() {
  const sev = document.getElementById('sev').value;
  const cwe = document.getElementById('cwe').value.trim().toLowerCase();
  const grounded = document.getElementById('grounded').value;
  const verified = document.getElementById('verified').value;
  const corrob = document.getElementById('corrob').value;
  const q = document.getElementById('q').value.trim().toLowerCase();
  let shown = 0;
  document.querySelectorAll('.finding').forEach(el => {
    const okSev = !sev || el.dataset.severity === sev;
    const okCwe = !cwe || (el.dataset.cwe||'').toLowerCase().includes(cwe);
    const okG = !grounded || el.dataset.grounded === grounded;
    const okV = !verified || el.dataset.verified === verified;
    const okC = !corrob || el.dataset.corroborated === corrob;
    const okQ = !q || el.textContent.toLowerCase().includes(q);
    const show = okSev && okCwe && okG && okV && okC && okQ;
    el.classList.toggle('hidden', !show);
    if (show) shown++;
  });
  document.getElementById('shown').textContent = shown;
}
document.addEventListener('DOMContentLoaded', () => {
  ['sev','cwe','grounded','verified','corrob','q'].forEach(id =>
    document.getElementById(id).addEventListener('input', applyFilters));
  applyFilters();
});
"""


_SIGNAL_LABELS = {
    "grounded": "grounded",
    "taint_complete": "taint",
    "concrete_poc": "PoC",
    "reachable": "reachable",
    "vote_confirmed": "voted",
    "externally_corroborated": "corroborated",
}


def _is_verified(f: dict) -> bool:
    v = f.get("verification") or {}
    return bool(v.get("verified"))


def _is_corroborated(f: dict) -> bool:
    if f.get("externally_corroborated"):
        return True
    return any(
        (e.get("check") == "pass" and e.get("kind") == "external_corroboration")
        for e in (f.get("evidence") or [])
    )


def _render_verification(f: dict) -> str:
    v = f.get("verification") or {}
    if not v:
        return (
            '<details class="sec"><summary>Verification (S8c)</summary>'
            "<div class='kv'><i>no outcome verification ran</i></div></details>"
        )
    signals = v.get("signals") or {}
    passed = sum(1 for ok in signals.values() if ok)
    considered = len(signals)
    verdict_cls = "yes" if v.get("verified") else "no"
    verdict_txt = "VERIFIED" if v.get("verified") else "UNVERIFIED"
    chips = "".join(
        f'<span class="chip {"ok" if signals.get(k) else "no"}">'
        f"{'&#10003;' if signals.get(k) else '&#8211;'} {_esc(label)}</span>"
        for k, label in _SIGNAL_LABELS.items()
        if k in signals
    )
    extra = ""
    tools = f.get("corroborating_tools") or []
    if tools:
        extra += f'<div class="kv"><b>Corroborated by:</b> {_esc(", ".join(tools))}</div>'
    if f.get("calibrated_confidence") is not None:
        calib = _esc(f"{f.get('calibrated_confidence', 0):.2f}")
        extra += f'<div class="kv"><b>Calibrated confidence:</b> {calib}</div>'
    if f.get("abstained"):
        extra += '<div class="kv"><b>Abstained:</b> routed to human review</div>'
    score_str = _esc(f"{v.get('score', 0):.2f}")
    threshold = _esc(v.get("threshold", 3))
    rationale = _esc(v.get("rationale", ""))
    return (
        '<details class="sec" open><summary>Verification (S8c)</summary>'
        f'<div class="kv"><span class="verdict {verdict_cls}">{verdict_txt}</span> &nbsp;'
        f"score {score_str} &nbsp; "
        f"{passed}/{considered} signals (need {threshold})</div>"
        f'<div class="chips">{chips}</div>'
        f'<div class="kv">{rationale}</div>'
        f"{extra}</details>"
    )


def _render_taint(f: dict) -> str:
    t = f.get("taint") or {}
    if not (t.get("source") or t.get("sink")):
        return ""
    path = t.get("taint_path") or []
    steps = " &rarr; ".join(
        f"{_esc(s.get('path', '?'))}:{_esc(s.get('start_line', '?'))}" for s in path
    )
    rows = [
        f'<div class="kv"><b>Source:</b> <span class="mono">{_esc(t.get("source") or "?")}</span></div>',
        f'<div class="kv"><b>Sink:</b> <span class="mono">{_esc(t.get("sink") or "?")}</span></div>',
    ]
    if steps:
        rows.append(f'<div class="kv"><b>Path:</b> <span class="mono">{steps}</span></div>')
    return '<details class="sec"><summary>Taint flow</summary>' + "".join(rows) + "</details>"


def _render_poc(f: dict) -> str:
    poc = f.get("poc") or {}
    if not poc:
        return ""
    if not poc.get("is_concrete"):
        eff = poc.get("expected_effect") or "(no rationale)"
        return (
            '<details class="sec"><summary>Proof of concept</summary>'
            f'<div class="kv"><i>no concrete PoC</i> &ndash; {_esc(eff)}</div></details>'
        )
    body = ""
    if poc.get("payload"):
        body += f'<div class="kv"><b>Payload:</b></div><pre class="code">{_esc(poc["payload"][:1500])}</pre>'
    if poc.get("invocation"):
        body += (
            f'<div class="kv"><b>Invocation:</b></div>'
            f'<pre class="code">{_esc(poc["invocation"][:1500])}</pre>'
        )
    if poc.get("expected_effect"):
        body += (
            f'<div class="kv"><b>Expected effect:</b> {_esc(poc["expected_effect"][:600])}</div>'
        )
    return '<details class="sec"><summary>Proof of concept</summary>' + body + "</details>"


def _render_evidence(f: dict) -> str:
    evi = f.get("evidence") or []
    if not evi:
        return ""
    rows = ""
    for e in evi[:12]:
        cls = {"pass": "evi-pass", "fail": "evi-fail"}.get(e.get("check", ""), "")
        rows += (
            f"<tr><td class='{cls}'>{_esc(e.get('check', '?'))}</td>"
            f"<td>{_esc(e.get('kind', ''))}</td>"
            f"<td>{_esc((e.get('detail', '') or '')[:240])}</td></tr>"
        )
    return (
        '<details class="sec"><summary>Evidence trail</summary>'
        '<table class="tbl"><tr><th>Check</th><th>Kind</th><th>Detail</th></tr>'
        f"{rows}</table></details>"
    )


def _render_votes(f: dict) -> str:
    votes = f.get("votes") or []
    if not votes:
        return ""
    rows = ""
    for v in votes:
        rows += (
            f"<tr><td>{_esc(v.get('role', '-'))}</td><td>{_esc(v.get('model', '-'))}</td>"
            f"<td>{_esc(v.get('verdict', '-'))}</td>"
            f"<td>{_esc((v.get('rationale', '') or '')[:200])}</td></tr>"
        )
    return (
        '<details class="sec"><summary>Votes</summary>'
        '<table class="tbl"><tr><th>Role</th><th>Model</th><th>Verdict</th><th>Rationale</th></tr>'
        f"{rows}</table></details>"
    )


def _render_finding(f: dict) -> str:
    sev = (f.get("severity") or "informational").lower()
    locs = f.get("locations") or [{}]
    loc = locs[0]
    grounded = "true" if f.get("grounded") else "false"
    verified = "true" if _is_verified(f) else "false"
    corroborated = "true" if _is_corroborated(f) else "false"
    tags = ", ".join(f.get("tags") or [])
    color = _SEV_COLOR.get(sev, "#666")

    cvss = ""
    if f.get("cvss_vector"):
        score = f.get("cvss_score")
        cvss = (
            f'<div class="kv"><b>CVSS:</b> <span class="mono">{_esc(f["cvss_vector"])}</span>'
            + (f" (score {_esc(f'{score:.1f}')})" if isinstance(score, (int, float)) else "")
            + "</div>"
        )
    vbadge = (
        '<span class="verdict yes">VERIFIED</span>'
        if verified == "true"
        else '<span class="verdict no">unverified</span>'
    )
    cbadge = ' <span class="chip ok">corroborated</span>' if corroborated == "true" else ""
    attack = f.get("attack_chain") or []
    chain_html = ""
    if attack:
        items = "".join(f"<li>{_esc(step)}</li>" for step in attack)
        chain_html = (
            f'<details class="sec"><summary>Attack chain</summary><ol>{items}</ol></details>'
        )

    return f"""
    <div class="finding" data-severity="{_esc(sev)}" data-cwe="{_esc(f.get("cwe") or "")}"
         data-grounded="{grounded}" data-verified="{verified}" data-corroborated="{corroborated}">
      <h3><span class="badge" style="background:{color}">{_esc(sev.upper())}</span>
        {_esc(f.get("title", ""))} <span style="color:#999">{_esc(f.get("id", ""))}</span>
        &nbsp;{vbadge}{cbadge}</h3>
      <div class="kv"><b>CWE:</b> {_esc(f.get("cwe") or "unknown")} &nbsp;
        <b>Location:</b> {_esc(loc.get("path", "?"))}:{_esc(loc.get("start_line", "?"))} &nbsp;
        <b>Confidence:</b> {_esc(f"{f.get('confidence', 0):.2f}")} &nbsp;
        <b>Grounded:</b> {_esc(grounded)}</div>
      <div class="kv"><b>Lens/stage:</b> {_esc(f.get("skill", "-"))} / {_esc(f.get("stage", "-"))}
        &nbsp; <b>Tags:</b> {_esc(tags or "-")}</div>
      {cvss}
      <div class="desc">{_esc(f.get("description", "") or "(no description)")}</div>
      {_render_verification(f)}
      {_render_taint(f)}
      {_render_poc(f)}
      {chain_html}
      {_render_evidence(f)}
      {_render_votes(f)}
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

    def _triage_key(f: dict) -> tuple:
        # Triage-first: verified, then corroborated, then severity, then confidence.
        return (
            1 if _is_verified(f) else 0,
            1 if _is_corroborated(f) else 0,
            order.get((f.get("severity") or "").lower(), 0),
            float(f.get("confidence") or 0.0),
        )

    findings_sorted = sorted(findings, key=_triage_key, reverse=True)

    verified_n = sum(1 for f in findings if _is_verified(f))
    corroborated_n = sum(1 for f in findings if _is_corroborated(f))
    abstained_n = sum(1 for f in findings if f.get("abstained"))

    pills = "".join(
        f'<span class="count-pill" style="border-left:4px solid {_SEV_COLOR[s]}">'
        f"{s}: <b>{counts[s]}</b></span>"
        for s in _SEV_ORDER
    )
    pills += (
        f'<span class="count-pill" style="border-left:4px solid #0E7C3F">'
        f"verified: <b>{verified_n}</b></span>"
        f'<span class="count-pill" style="border-left:4px solid #3A6BC0">'
        f"corroborated: <b>{corroborated_n}</b></span>"
        f'<span class="count-pill" style="border-left:4px solid #D88717">'
        f"abstained: <b>{abstained_n}</b></span>"
    )
    findings_html = "".join(_render_finding(f) for f in findings_sorted) or (
        "<p><i>No findings survived the quality pipeline.</i></p>"
    )

    # Per-stage cost / timing table so operators can see where budget went.
    stage_rows = ""
    for s in data.get("stages", []) or []:
        cost = s.get("cost_usd", 0) or 0
        dur = s.get("duration_seconds", 0) or 0
        nf = len(s.get("findings", []) or [])
        err = s.get("error") or ""
        stage_rows += (
            f"<tr><td class='mono'>{_esc(s.get('stage_id', '?'))}</td>"
            f"<td>{_esc(s.get('skill', '-'))}</td>"
            f"<td>${_esc(f'{cost:.3f}')}</td>"
            f"<td>{_esc(f'{dur:.1f}')}s</td>"
            f"<td>{nf}</td>"
            f"<td>{_esc(err[:80])}</td></tr>"
        )
    stage_table = (
        '<details class="sec"><summary>Pipeline stages (cost &amp; timing)</summary>'
        '<table class="tbl"><tr><th>Stage</th><th>Skill</th><th>Cost</th>'
        "<th>Time</th><th>Findings</th><th>Error</th></tr>"
        f"{stage_rows}</table></details>"
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
    &middot; {verified_n} verified &middot; {corroborated_n} corroborated
    &middot; cost ${_esc(f"{data.get('total_cost_usd', 0):.3f}")}</div>
</header>
<main>
  <div class="counts">{pills}</div>
  {stage_table}
  <div class="controls">
    <label>Severity
      <select id="sev"><option value="">all</option>
        {"".join(f'<option value="{s}">{s}</option>' for s in _SEV_ORDER)}
      </select></label>
    <label>Verified
      <select id="verified"><option value="">all</option>
        <option value="true">verified</option><option value="false">unverified</option>
      </select></label>
    <label>Corroborated
      <select id="corrob"><option value="">all</option>
        <option value="true">yes</option><option value="false">no</option>
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
  Verified/corroborated badges reflect deterministic cross-checks, not confirmed exploitation.
  Generated by redeye {_esc(data.get("version", ""))}.</footer>
<script>{_JS}</script>
</body></html>"""

    from redeye.redaction import redact_secrets

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(redact_secrets(doc), encoding="utf-8")
    return output
