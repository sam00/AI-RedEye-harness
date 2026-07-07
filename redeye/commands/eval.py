"""`redeye eval` -- score a scan against a labeled benchmark (improvement #3).

The hallucination counters RedEye emits per run say what was *pruned*; they
can't say whether the reported findings are *correct*. This command runs the
pipeline over a benchmark whose true vulnerabilities are known, then reports
precision, recall, F1 and a hallucination rate -- turning "we reduced
hallucination" from an assertion into a measurement, and giving CI a gate.

Usage::

    redeye eval                         # bundled benchmark, mock profile
    redeye eval --profile fable         # measure a real backend
    redeye eval --min-precision 0.8 --min-recall 0.5   # CI gate (nonzero exit)

The bundled benchmark lives in ``redeye/eval/benchmark`` with a ``labels.json``
ground truth. Point ``--benchmark`` / ``--labels`` at your own set to track a
private corpus.
"""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path

from rich.console import Console
from rich.table import Table

from redeye.config import load_profile
from redeye.eval_harness import LabeledVuln, Prediction, evaluate
from redeye.pipeline.orchestrator import Orchestrator
from redeye.scope import Scope

log = logging.getLogger(__name__)

_BUNDLED = Path(__file__).resolve().parent.parent / "eval" / "benchmark"


def _load_labels(labels_path: Path) -> tuple[list[LabeledVuln], int]:
    data = json.loads(labels_path.read_text(encoding="utf-8"))
    tol = int(data.get("line_tolerance", 3))
    vulns = [
        LabeledVuln(path=v["path"], line=int(v["line"]), cwe=v.get("cwe"))
        for v in data.get("vulns", [])
    ]
    return vulns, tol


def _source_line_counts(root: Path) -> dict[str, int]:
    """Map <relative posix path> -> line count for every source file, so the
    eval harness can flag predictions citing missing files / out-of-range lines."""
    counts: dict[str, int] = {}
    for p in root.rglob("*"):
        if not p.is_file() or p.name == "labels.json":
            continue
        try:
            n = sum(1 for _ in p.open(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        counts[p.relative_to(root).as_posix().lower()] = n
    return counts


def _predictions_from_manifest(manifest) -> list[Prediction]:  # type: ignore[no-untyped-def]
    """Extract (path, line, cwe) predictions from the last stage's findings."""
    findings = []
    for stage in manifest.stages:
        if stage.findings:
            findings = stage.findings
    preds: list[Prediction] = []
    for f in findings:
        for loc in f.locations:
            preds.append(Prediction(path=loc.path, line=loc.start_line, cwe=f.cwe))
    return preds


def run(
    *,
    console: Console,
    profile: str | None = None,
    benchmark: str | None = None,
    labels: str | None = None,
    min_precision: float = 0.0,
    min_recall: float = 0.0,
    max_hallucination: float = 1.0,
    output_json: str | None = None,
) -> int:
    """Run the benchmark and print metrics. Returns nonzero if a gate fails."""
    bench_dir = Path(benchmark) if benchmark else _BUNDLED
    labels_path = Path(labels) if labels else bench_dir / "labels.json"
    if not bench_dir.is_dir():
        console.print(f"[red]benchmark directory not found:[/red] {bench_dir}")
        return 2
    if not labels_path.is_file():
        console.print(f"[red]labels file not found:[/red] {labels_path}")
        return 2

    cfg = load_profile(profile or "mock")
    truth, tol = _load_labels(labels_path)
    console.print(
        f"[bold]redeye eval[/bold] profile=[cyan]{cfg.name}[/cyan] "
        f"benchmark=[cyan]{bench_dir}[/cyan] labels={len(truth)}"
    )

    with tempfile.TemporaryDirectory(prefix="redeye-eval-") as tmp:
        scope = Scope.build(target=bench_dir)
        orchestrator = Orchestrator(
            config=cfg,
            console=console,
            target=bench_dir,
            output_dir=Path(tmp),
            scope=scope,
        )
        manifest = orchestrator.run()

    preds = _predictions_from_manifest(manifest)
    result = evaluate(preds, truth, line_tol=tol, source_lines=_source_line_counts(bench_dir))

    table = Table(title="Evaluation metrics")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    m = result.to_dict()
    for key in (
        "total_predicted",
        "total_labeled",
        "tp",
        "fp",
        "fn",
        "hallucinated",
        "precision",
        "recall",
        "f1",
        "hallucination_rate",
    ):
        table.add_row(key, str(m[key]))
    console.print(table)

    if output_json:
        Path(output_json).write_text(json.dumps(m, indent=2), encoding="utf-8")
        console.print(f"[dim]wrote {output_json}[/dim]")

    # CI gate.
    failures = []
    if result.precision < min_precision:
        failures.append(f"precision {result.precision} < {min_precision}")
    if result.recall < min_recall:
        failures.append(f"recall {result.recall} < {min_recall}")
    if result.hallucination_rate > max_hallucination:
        failures.append(f"hallucination_rate {result.hallucination_rate} > {max_hallucination}")
    if failures:
        console.print("[red]eval gate FAILED:[/red] " + "; ".join(failures))
        return 1
    console.print("[green]eval gate passed[/green]")
    return 0
