"""Deterministic, AST-based analyses used to upgrade lens findings from
co-occurrence evidence (regex match near sink) to proven dataflow.

Modules here have zero LLM cost. They run inside the deterministic
layers of the pipeline (S1b structural pre-index, S4b grounding pass).
"""

from redeye.analysis.cvss import compute_cvss
from redeye.analysis.sql_templates import find_sql_template_injections
from redeye.analysis.taint import (
    SANITIZERS,
    SINK_FUNCTIONS,
    SOURCE_PATTERNS,
    TaintPath,
    TaintTracer,
)

__all__ = [
    "TaintTracer",
    "TaintPath",
    "SOURCE_PATTERNS",
    "SINK_FUNCTIONS",
    "SANITIZERS",
    "compute_cvss",
    "find_sql_template_injections",
]
