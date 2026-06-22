# Architecture

`redeye` is a 13-stage pipeline grouped into three phases. Five
of the stages (S1b, S4b, S5, S7, plus the voting half of S6) are *fully
deterministic* -- they do not call an LLM. This is deliberate: every
deterministic layer is one that the model cannot lie its way past.

```text
+------------------------------------------------------------+
|  Phase A -- Discovery & Modeling                           |
|                                                            |
|   S1   attack_surface_mapper      (LLM, surveyor)          |
|   S1b  structural_index           (DET, regex/AST)         |
|   S2   threat_modeler             (LLM, surveyor)          |
|   S3   research_strategist        (LLM, researcher)        |
+------------------------------------------------------------+
                              |
                              v
+------------------------------------------------------------+
|  Phase B -- Deep Dive & Verification                       |
|                                                            |
|   S4   research_lenses            (LLM, researcher)        |
|        |- language                                         |
|        |- crypto                                           |
|        |- logic                                            |
|        |- access_control                                   |
|        '- iac                                              |
|                                                            |
|   S4b  grounding_pass             (DET, file I/O)          |
|        verifies cited file:line + CWE-family tokens.       |
|   S5   policy_gate                (DET, no LLM)            |
|   S6   adversarial_reviewer       (LLM, adversary)         |
|        + multi-agent voting (configurable quorum)          |
|   S6.5 validator                  (LLM, cheap)             |
|        single-pass TP/FP gate; auto-rejects S4b failures.  |
+------------------------------------------------------------+
                              |
                              v
+------------------------------------------------------------+
|  Phase C -- Synthesis, Chaining & Reporting                |
|                                                            |
|   S7   dedupe                     (DET)                    |
|   S8   exploit_strategist         (LLM, reporter)          |
|   S8b  poc_gate                   (LLM, cheap)             |
|        demands a concrete exploit; demotes findings with   |
|        no payload (drops with --require-poc).              |
|   S9   emit                       (writes MD + SARIF)      |
+------------------------------------------------------------+
```

For a deeper write-up of *why* each filter exists, see
[`REDUCING_HALLUCINATIONS.md`](REDUCING_HALLUCINATIONS.md).

## Stage contracts

Every stage is a function `run(ctx) -> StageResult`. The orchestrator
owns the running list of `Finding` records and the running `artifacts`
dict; stages read from `ctx` and return what they want stored, but do
not mutate the orchestrator state directly.

| Stage | Reads from `ctx.artifacts` | Writes to `result.artifacts` | Modifies findings? |
|---|---|---|---|
| S1 | -- | `attack_surface` | no |
| S1b | -- | `structural_index`, `structural_summary` | no |
| S2 | `attack_surface` | `threat_model` | no |
| S3 | `threat_model` | `research_plan` | no |
| S4 | `attack_surface`, `research_plan`, `structural_index` | `per_lens_count` | adds new |
| S4b | -- | `grounding_report`, `grounding_dropped_ids`, `strict` | tags + drops |
| S5 | -- | `input_count`, `kept_count` | drops some |
| S6 | -- | `voting_kept`, `voting_dropped` | refines + votes |
| S6.5 | -- | `validator_kept`, `validator_rejected`, `rejected_ids` | drops some |
| S7 | -- | `input_count`, `output_count` | merges duplicates |
| S8 | -- | -- | enriches |
| S8b | -- | `poc_metrics`, `strict` | demotes / drops |
| S9 | `attack_surface`, `threat_model`, `_hallucination_metrics`, `structural_summary` | `report_md`, `report_sarif`, counts | -- |

## Multi-agent voting (S6)

Voting is the single biggest lever on false-positive rate among the
LLM-based filters. It runs *after* the adversarial reviewer rewrites
the attack chain, so voters score the refined finding rather than the
raw lens output.

```yaml
voting:
  enabled: true
  quorum: 2                                # finding survives if >= 2 confirms
  voters: [adversary_a, adversary_b, researcher]
```

Voters whose backend rejects `temperature` (e.g. `cli`, some Opus
models) are skipped silently because there's no sampling diversity to
gain. When voting is disabled (the default for `cli`-only profiles),
every finding from S6 passes through to S6.5 untouched.

## Failure modes

| Failure | Behavior |
|---|---|
| A single stage crashes | Its `StageResult.error` is set, the orchestrator continues, downstream stages see the running state as it was *before* the crash. |
| A backend errors mid-call | Backend implementations fall back to the deterministic mock so the run still completes. The error is recorded on the stage. |
| Out of budget | The stage stops calling the backend but keeps the partial result it has. |
| YAML profile invalid | Hard fail in `load_profile`, exit code 2, before any stage runs. |
| All findings hallucinated | Strict-grounding drops them all; report is empty but quality metrics show what was filtered. |

## Determinism

The pipeline aims for repeatable runs at the level of "the same code +
config + target SHA produces a manifest with the same stage list and
artifact shapes". It does **not** guarantee identical findings between
runs unless every backend is `mock` -- temperature-capable backends
sample.

The deterministic layers (S1b structural index, S4b grounding, S5
policy gate, S7 dedupe, voting tally) sit between the
non-deterministic layers so that *most* of the noise is squeezed out
before findings reach the report.

## Extending

- **A new research lens** -- add `redeye/skills/lens_<name>.py`,
  register in `s4_research._LENSES`, add to profile `lenses` lists,
  document in [`SKILLS.md`](SKILLS.md).
- **A new backend** -- subclass `BackendBase`, register in
  `redeye.backends.BACKENDS`, add credential vars to `.env.example`.
- **A new structural pattern** -- append to
  `redeye.structural._SINK_PATTERNS` (or `_SOURCE_PATTERNS`,
  `_ROUTE_PATTERNS`, `_SECRET_PATTERNS`). The lens prompts read the
  inventory verbatim, so new patterns immediately become visible to the
  model.
- **A new CWE token catalog** -- add an entry to
  `redeye.grounding._CWE_TOKENS` so S4b can ground findings
  for that CWE family.
- **A new emitter** -- add a module under `redeye/output/`,
  call it from `s9_emit.run`, document the new artifact under
  [`USER_GUIDE.md`](USER_GUIDE.md).
