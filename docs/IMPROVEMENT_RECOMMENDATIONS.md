# Improvement recommendations — verified outputs & lower hallucination

Scope: concrete, additive improvements *beyond* the existing 0.3 controls
(structural pre-index S1b, taint schema, grounding S4b, validator S6.5, PoC
gate S8b, cross-model voting S6, K-of-N outcome verifier S8c, feedback loop).
These target the gaps that remain after those layers, ordered by
impact-to-effort. Each item names the file(s) it touches so it can be picked
up as a work item.

## Where the current design still leaks

The existing stack is strong but three assumptions are soft:

1. **Grounding is lexical, not semantic.** `redeye/grounding.py` accepts a
   finding when *any* CWE-family token appears within ±5 lines of the cited
   line (`_CWE_TOKENS`). A finding can pass because the word `query` happens
   to be nearby, and can fail on aliased imports or wrapper functions. It
   checks that suggestive text exists — not that the claimed source→sink path
   exists.
2. **The PoC gate is syntactic, not behavioral.** S8b accepts a payload that
   *looks* concrete (quotes, `../`, a SQL keyword). Nothing confirms the
   payload actually reaches the sink or breaks anything.
3. **Quality is measured relative to itself, not to ground truth.** The
   hallucination counters (`ungrounded_dropped`, `voted_out`, …) show what the
   harness pruned, but there is no labeled benchmark proving a change actually
   raised precision or lowered the hallucination rate.

## Priority 1 — highest leverage

### 1. Graph-backed grounding (upgrade S4b from tokens to dataflow)

The repo already computes a call graph and a `reachability` score
(`test_callgraph`, `finding.reachability`). Wire that into grounding: instead
of "a token appears near the cited line," verify that (a) the cited sink is a
real call node of the claimed sink family in the AST, and (b) each `taint_path`
step corresponds to an actual call/assignment edge between the cited source and
sink. Keep the token check as a cheap fallback for languages without a parser.
This converts grounding from a sanity check into near-proof and kills the
largest remaining class of "plausible but wrong" findings.
Touches: `redeye/grounding.py`, `redeye/structural.py`, callgraph module.

### 2. Deterministic-SAST corroboration as a verification signal

`redeye/external.py` already ingests Semgrep / CodeQL / Bandit / Trivy / SARIF
— but only into the S1b discovery inventory. Promote it: add an
`externally_corroborated` signal to the S8c `_SIGNALS` set so a finding an
independent scanner also flagged counts toward the K-of-N verdict. Independent
tool agreement is one of the strongest true-positive predictors available and
it costs zero extra tokens.
Touches: `redeye/pipeline/verification.py` (`_SIGNALS`,
`deterministic_signals`), `redeye/external.py`.

### 3. A labeled evaluation harness in CI

Add a golden benchmark (OWASP Benchmark, NIST Juliet, or a curated internal set
with known TP/FP/known-clean) and a `redeye eval` command that runs the
pipeline against it and reports precision, recall, and a true hallucination
rate (findings citing code with no real vuln). Gate merges on no regression.
This is what lets you *claim* "validated and verified" instead of asserting it —
every other item on this list should be measured against it.
Touches: new `redeye/commands/eval.py`, `tests/`, `.github/workflows/ci.yml`.

## Priority 2 — strong FP/hallucination reduction

### 4. Closed-set (citation-constrained) lens output

Make it structurally impossible to invent a sink. The lens may only cite
sources/sinks that exist in the S1b inventory (a closed set passed in-context),
and must quote the actual source line rather than recall it. Reject at parse
time any finding whose `sink_location` is not in the inventory. This moves
"invented sink/route" from *caught after the fact* to *cannot be emitted*.
Touches: S4 lens prompts (`redeye/skills/`), S4 parse contract, `schema.py`.

### 5. Self-consistency sampling inside a lens

Voting (S6) is cross-model on the already-refined finding. Add cheap
within-lens self-consistency first: sample k=3–5 at temperature and keep only
findings that recur across samples. Stochastic one-off hallucinations die
before they consume grounding/adversarial budget. For temperature-rejecting
models (Opus 4.x, the `cli` backend) where voting collapses to a no-op, use
**prompt-perturbation** ensembling (vary phrasing/ordering) to recover
diversity.
Touches: `redeye/pipeline/stages/s4_research.py`, lens runner.

### 6. Behavioral PoC validation (opt-in)

For a safe subset (SQLi, command injection, path traversal, SSRF), go past
syntactic checks: run the payload through an oracle — e.g. `sqlparse` to confirm
the injection breaks out of the intended statement, a shell lexer to confirm a
metacharacter reaches `argv`, URL parsing to confirm an SSRF target resolves
off-host — or execute against an ephemeral sandbox where one exists. Promote
findings with a *demonstrated* trigger; demote the rest. Sandbox execution must
be off by default and network-gated (`REDEYE_NO_NETWORK`).
Touches: `redeye/pipeline/stages/s8b_poc.py`, new oracle helpers.

### 7. Evidence-quoting verdicts for the judge stages

Require the validator (S6.5) and adversarial reviewer (S6) to quote the exact
code line (sanitizer, authz check, or the sink) that justifies
confirm/reject/uncertain, and reject any verdict whose quote does not match
real source. This applies the grounding principle to the *judge*, so it can't
rationalize away — or hallucinate — its own decision.
Touches: `redeye/pipeline/stages/s6b_validator.py`, `s6_adversarial.py`.

## Priority 3 — calibration, governance, auditability

### 8. Calibrated confidence + explicit abstention

Confidence today is heuristic (capped ≤0.5 on weak evidence). Fit a calibrator
(Platt/isotonic) on the TP/FP history already stored in `~/.redeye/scans.db`
so a reported 0.8 empirically means ~80% precision, and add an abstention band
that routes borderline findings to human review instead of asserting a verdict.
Touches: `redeye/feedback` store, `schema.py`, report emitters.

### 9. Two-key promotion for HIGH/CRITICAL (enterprise policy)

Codify in the policy gate that a finding may only be reported at
HIGH/CRITICAL if it passes a strong-model validator **and** at least one of
{external corroboration, demonstrated PoC}. Everything else is capped at MEDIUM
pending human confirmation. Prevents a single model's confident mistake from
paging on-call.
Touches: `redeye/pipeline/stages/s5` policy gate, profile config.

### 10. Per-finding provenance for reproducibility

Record the model id, prompt hash, sampling params/seed, and structural-index
hash for each finding in `run_manifest.json`. Combined with the mock backend
this makes any finding reproducible and any run auditable — the backbone of
"verified" output for regulated environments.
Touches: `redeye/output/manifest.py`, orchestrator.

## Suggested sequencing

Do #3 (eval harness) first so everything after it is measurable, then #2 and #1
(cheap, deterministic, high-impact), then #4–#7 (model-side precision), then
#8–#10 (calibration and governance). Track precision / recall / hallucination
rate per release against the #3 benchmark and treat any regression as a release
blocker.
