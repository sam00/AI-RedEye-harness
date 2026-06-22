"""`redeye collect-feedback` -- ingest reviewer marks from a PR comment.

The GitHub Actions workflow calls this on the ``issue_comment.edited``
event with the comment body piped on stdin (or pointed at a file). We
parse the ``<!-- vuln-id: ... scan-id: ... -->`` markers and the TP/FP
checkbox state immediately below each marker, and write the verdict back
to the SQLite store.
"""

from __future__ import annotations

import logging
import re
import sys
from pathlib import Path

from rich.console import Console

from redeye.feedback.store import FindingsStore

log = logging.getLogger(__name__)

_MARKER_RE = re.compile(
    r"<!--\s*vuln-id:\s*(?P<vuln>\S+)\s+scan-id:\s*(?P<scan>\S+?)\s*-->",
    re.IGNORECASE,
)


def _parse(comment: str) -> list[tuple[str, str, str]]:
    """Yield (scan_id, vuln_id, verdict) tuples.

    Verdict is "TP", "FP", or "UNK" depending on which checkbox is ticked
    immediately below the marker.
    """
    out: list[tuple[str, str, str]] = []
    for match in _MARKER_RE.finditer(comment):
        vuln = match.group("vuln")
        scan = match.group("scan")
        # Look at the ~6 lines after the marker for `[x]` or `[X]` checkboxes.
        tail = comment[match.end() : match.end() + 800]
        lines = tail.splitlines()[:8]
        verdict = "UNK"
        for line in lines:
            line_l = line.strip().lower()
            if line_l.startswith("- [x]") or line_l.startswith("- [X]"):
                if "true positive" in line_l:
                    verdict = "TP"
                    break
                if "false positive" in line_l:
                    verdict = "FP"
                    break
        out.append((scan, vuln, verdict))
    return out


def run(*, console: Console, comment_file: Path | None) -> int:
    if comment_file is not None:
        try:
            comment = comment_file.read_text(encoding="utf-8")
        except OSError as exc:
            console.print(f"[red]could not read {comment_file}:[/red] {exc}")
            return 2
    else:
        comment = sys.stdin.read()

    marks = _parse(comment)
    if not marks:
        console.print(
            "[yellow]no vuln-id markers found in input.[/yellow] "
            "Did you point this at a RedEye PR comment?"
        )
        return 1

    store = FindingsStore.default()
    written = 0
    for scan_id, vuln_id, verdict in marks:
        if verdict == "UNK":
            continue
        try:
            store.record_reviewer_verdict(scan_id=scan_id, finding_id=vuln_id, verdict=verdict)
            written += 1
            console.print(f"  recorded: scan={scan_id} vuln={vuln_id} verdict={verdict}")
        except Exception as exc:  # noqa: BLE001
            console.print(f"  [red]failed[/red] {vuln_id}: {exc}")

    console.print(f"\nIngested {written} reviewer mark(s) into {store.db_path}")
    return 0
