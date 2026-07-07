# RedEye Harness — Improvements & Capabilities

A detailed, implementation-grounded write-up of what `redeye` (the AI-RedEye
harness) is, the concrete improvements it makes over a naive
"ask-an-LLM-to-find-bugs" SAST loop, how it goes beyond its ancestor **VVAH**,
and why it is pleasant to actually operate. The emphasis throughout is the
four things that make or break AI-driven SAST in production:

1. **Validated & verified output** — every reported finding has survived
   independent, cross-checking evidence, and quality is *measured* against
   ground truth rather than asserted.
2. **Less hallucination** — no invented files, lines, sinks, or CWEs.
3. **Fewer false positives.**
4. **Bounded, predictable cost.**

> RedEye is a derivative of Visa's **Vulnerability Agentic Harness (VVAH)**
> (Apache-2.0), substantially reworked and extended. See `NOTICE` and the
> README attribution. §10 details what changed relative to VVAH.

---

## 1. The problem RedEye is built to solve

LLM-driven SAST is *noisy by default*. A frontier model asked "find vulns in
this repo" will happily cite files and line numbers that do not exist,
hallucinate sinks the code never calls, assert a CWE the code does not exhibit,
and write confident "remediations" for bugs that were never there.

RedEye's core design principle: **put cheap, deterministic, cross-checking
evidence in front of every finding** so that what reaches a human cites real
code and has survived every inexpensive check the harness can run. The model is
allowed to be *aggressive about discovery* precisely because deterministic
layers carry the precision burden.

---

## 2. Architecture at a glance

A 14-stage pipeline grouped into three phases. Critically, **the majority of
stages are fully deterministic and never call an LLM** (`S1b` structural
pre-index, `S4b` grounding pass, `S5` policy gate, `S7` dedupe, the `S6` voting
tally, and the `S8c` outcome verifier).

| Phase | Stages | Purpose |
|---|---|---|
| A — Discovery & Modeling | S1, **S1b (DET)**, S2, S3 | Attack-surface mapping, structural pre-index, STRIDE threat model, hunting plan |
| B — Deep Dive & Verification | S4, **S4b (DET)**, **S5 (DET)**, S6 (+vote tally DET), S6.5 | Multi-lens research, grounding, policy gate, adversarial review + voting, validator |
| C — Synthesis, Chaining & Reporting | **S7 (DET)**, S8, S8b, **S8c (DET)**, S9 | Dedupe, exploit chaining, PoC gate, outcome verification, SARIF/MD emit |

Reference: `docs/architecture.md`, `docs/REDUCING_HALLUCINATIONS.md`.

---

## 3. Supported frontier models & backends

RedEye is backend-pluggable through a single registry
(`redeye/backends/__init__.py`); no provider is a hard dependency, and every
real backend falls back to the deterministic `mock` on error so a run always
completes.

| Backend (`via`) | Provider | Models with first-class pricing/wiring |
|---|---|---|
| `sdk` | Anthropic API | **`claude-opus-4-8`**, `claude-opus-4-7`, `claude-fable-5`, `claude-sonnet-4-6`, `claude-haiku-4` |
| `cli` | Claude Code CLI | `claude-sonnet-4-6` |
| `bedrock` | AWS Bedrock | `anthropic.claude-opus-4-5`, `claude-3-5-sonnet`, `claude-3-haiku` |
| `vertex` | Google Vertex AI | `gemini-2.5-pro`, `gemini-2.5-flash`, `gemini-1.5-pro` |
| `openai` | OpenAI / OpenAI-compatible | `gpt-4o`, `gpt-4o-mini` |
| `ollama` | Local Ollama | `qwen2.5-coder`, any local model |
| `mock` | none (deterministic) | `mock-deep`, `mock-fast` |

Bundled profiles: `default` (cli), `cli`, `full` (cross-vendor voting),
**`fable`** (Fable 5 heavy + Haiku cheap), `mock`, `ollama_local`. Any model on
a backend runs even without a priced entry (a default price is applied), so the
lists above are the *priced* set, not an allowlist.

---

## 4. Validated & verified output (the v0.4 verification layer)

This is the headline of the v0.4 work: moving from "we filtered the noise" to
"every finding is independently corroborated, and we can *prove* it." Six
improvements, all deterministic where possible.

### 4.1 External-scanner corroboration — a new verification signal (#2)

RedEye already ingests Semgrep / CodeQL / Bandit / Trivy / SARIF into the S1b
inventory as candidate hotspots. v0.4 promotes that same signal into
*verification*: when a RedEye finding lands on the same file / line
neighbourhood / CWE that an independent tool also flagged, it earns a distinct
`externally_corroborated` signal in the S8c K-of-N verdict. Independent-tool
agreement is one of the strongest true-positive predictors available and costs
zero tokens. Matching is basename-tolerant and CWE-aware (a different bug class
at the same line does *not* corroborate). `redeye/corroboration.py`,
`redeye/pipeline/verification.py`.

### 4.2 Graph/AST-backed grounding (#1)

The original grounding pass (S4b) accepts a finding when a CWE-family *token*
appears within ±5 lines of the cited line. v0.4 upgrades this for Python
targets: the file is parsed to an AST and the pass confirms the cited line
actually contains a **call** to a sink-family function (`execute`, `os.system`,
`eval`, …), not merely a suggestive word. This both hardens grounding against
"plausible but wrong" citations and *rescues* real findings the coarse token
catalog missed. Non-Python / unparseable sources fall back to the token check.
`redeye/ast_grounding.py`, `redeye/grounding.py`.

### 4.3 Behavioral PoC oracle (#6)

The PoC gate (S8b) historically accepted any payload that *looked* concrete.
v0.4 adds a deterministic **oracle** that reasons about whether the payload
would actually subvert the sink: SQLi break-out + tautology/UNION/stacked
query; command-injection metacharacter chaining a real command; ≥2 traversal
hops or a sensitive target; SSRF against an internal/metadata host; active XSS
vectors; code-exec tokens. A `demonstrated` verdict sets `poc_demonstrated` and
becomes a strong TP signal for S8c and the two-key policy. No code is executed
and no network is touched. `redeye/poc_oracle.py`.

### 4.4 Two-key promotion for HIGH/CRITICAL (#9)

Optional enterprise policy (`two_key_high_severity`): a finding may only
*report* at HIGH or CRITICAL when it has two independent keys — a model
confirmation (validator/adversary) **AND** a corroborating key (external
corroboration or a demonstrated/concrete PoC). Otherwise its severity is capped
at MEDIUM (never dropped) and it is tagged `capped:two-key`. This stops a single
model's confident mistake from paging on-call. `redeye/pipeline/stages/s5_policy_gate.py`.

### 4.5 Labeled-benchmark evaluation — `redeye eval` (#3)

The per-run hallucination counters say what was *pruned*; they can't say
whether reported findings are *correct*. `redeye eval` runs the pipeline over a
benchmark with known vulnerabilities and reports **precision, recall, F1, and a
true hallucination rate** (findings citing code that doesn't exist). It ships
with a small bundled benchmark (`redeye/eval/benchmark` + `labels.json`) and
supports CI gates:

```bash
redeye eval                                   # bundled benchmark, mock profile
redeye eval --profile fable                   # measure a real backend
redeye eval --min-precision 0.8 --min-recall 0.5 --max-hallucination 0.05
```

This is what turns "we reduced hallucination" from a claim into a tracked,
regression-gated metric. `redeye/eval_harness.py`, `redeye/commands/eval.py`.

### 4.6 Closed-set citation, self-consistency, evidence-quoting verdicts (#4/#5/#7)

Deterministic cores in `redeye/precision.py`:

- **Closed-set citation (#4):** a lens finding may only cite a sink/source
  location present in the S1b inventory; off-inventory findings are tagged
  `off-inventory` (or dropped under `closed_set_strict`), making "invented
  sink" structurally impossible rather than caught later.
- **Self-consistency (#5):** keep only findings that recur across *k* sampled
  lens passes (aggregator provided; enable via `self_consistency_samples`).
  Kills stochastic one-off hallucinations; for temperature-rejecting models
  (Opus / `cli`) prompt-perturbation provides the diversity.
- **Evidence-quoting verdicts (#7):** a validator "confirm" must quote source
  that actually exists in the cited file; a verdict whose quote isn't found is
  tagged `unquoted-verdict` (enable via `require_quoted_verdict`).

### 4.7 Calibrated confidence + abstention (#8)

`redeye/abstention.py` fits **Platt scaling** (a dependency-free logistic fit)
over the reviewer TP/FP history already in `~/.redeye/scans.db`, turning a raw
score into an empirically-calibrated probability, then bands it into
confirm / **uncertain** / reject. The middle *abstention* band routes borderline
findings to a human instead of asserting or silently dropping. Complements the
existing per-CWE/per-skill reliability prior in `redeye/calibration.py`.

### 4.8 Per-finding provenance (#10)

Every finding is stamped (`redeye/provenance.py`) with the producing model, a
SHA-256 of the prompt context (so secrets never hit disk), sampling params, and
the structural-index hash. Combined with the `mock` backend this makes any
finding reproducible and any run auditable — the backbone of "verified" output
in regulated environments. The stamp lands in `Finding.provenance` and flows
into `run_manifest.json` for free.

---

## 5. The pre-existing hallucination-reduction stack (v0.3)

The v0.4 layer sits on top of the 0.3 controls, which remain the foundation:

| Layer | Stage | What it kills | LLM cost |
|---|---|---|---|
| Structural pre-index | S1b | Invented routes/sources/sinks/secrets | **Zero** (regex/AST) |
| Taint-flow schema | S4 contract | Findings with no source→sink theory | Zero (parse-time) |
| Grounding pass | S4b | Cited file/line that doesn't exist; no CWE evidence | **Zero** (file I/O + AST) |
| Validator auto-reject | S6.5 | Findings already tagged hallucinated by S4b | Zero (skips the call) |
| PoC gate | S8b | Findings with no concrete/demonstrable payload | Cheap LLM + oracle |
| Multi-agent voting | S6 | Findings only one voter agrees with | LLM × N |
| Outcome verifier | S8c | Findings failing the K-of-N deterministic verdict | **Zero** |

`docs/REDUCING_HALLUCINATIONS.md` has the long-form rationale for each. Note the
S8c verdict now spans **six** independent signals: grounded, taint-complete,
concrete-PoC, reachable, vote-confirmed, and (new) externally-corroborated.

---

## 6. Fewer false positives

Defense-in-depth, cheap deterministic filters first: multi-agent **voting**
(cross-vendor voters recommended, default quorum ≥2), a distinct single-pass
**validator** (S6.5), the deterministic **policy gate** (S5) + two-key
promotion, **dedupe** (S7), **outcome verification** (S8c K-of-N), operator
**baseline acceptance** (stable `sha256(cwe+path+line+skill)` fingerprint), and
the SQLite **feedback loop** that injects prior TP/FP marks into the next scan's
prompts and confidence calibration.

---

## 7. Reduced, predictable cost

Cheap-first ordering (zero-LLM layers run before any paid stage), per-stage
`max_budget_usd` caps with a global guardrail, a no-spend `redeye estimate` dry
run, scope/DoS limits (`--diff-only`, `--max-files`, `--exclude-path`, default
ignore dirs), an incremental structural cache keyed by `(path, size, mtime_ns)`,
cheap models for cheap stages (validator/PoC on Haiku-class), and a zero-cost
`mock` backend for CI smoke tests. The new corroboration, AST grounding, PoC
oracle, two-key, closed-set, and provenance layers are all **zero-token**.

---

## 8. Auditability, CI/CD & integration

`run_manifest.json` per run (tool version, profile, config hash, target SHA,
per-stage cost + quality metrics, and now per-finding provenance). **SARIF
2.1.0** output with `security-severity` and taint `codeFlows` for GitHub Code
Scanning; PR comments with TP/FP checkboxes that drive the feedback loop;
webhooks (Slack/Teams/Discord) with optional HMAC signing; a drop-in GitHub
Actions workflow and reusable `action.yml`; CVSS vectors/scores carried into
SARIF. `redeye doctor` reports per-backend reachability before a run.

---

## 9. User-friendliness

RedEye is designed so a first run is easy and a hundredth run is predictable.

- **Zero-setup first run.** `redeye scan --repo . --profile mock` runs the full
  14-stage pipeline with **no API key and no network** and produces a
  deterministic report — ideal for trying the tool, demos, and CI smoke tests.
- **Guided setup.** `redeye init` (a.k.a. `make init`) detects which
  credentials you have, recommends a profile (now including `fable`), explains
  *why*, and writes a tailored `.env`. No global state, no telemetry, no
  network calls.
- **Auto backend detection.** With no `--profile`, RedEye picks the best
  available backend on the machine; `REDEYE_PREFER_QUALITY=1` upgrades the SDK
  path to Fable 5.
- **Preset-driven dual mode.** One tool is both a researcher's deep-dive and a
  PR gate. `--preset quick|pr|ci|deep` sets sensible scope/grounding defaults;
  any explicit flag still wins.

  | Preset | Backend | Scope | Grounding | Use when |
  |---|---|---|---|---|
  | `quick` | mock (no cost) | small | lenient | trying it / CI smoke |
  | `pr` | active profile | changed files | strict | every PR |
  | `ci` | active profile | whole repo, DoS-capped | strict | nightly |
  | `deep` | active profile | unlimited | lenient | research |

- **Spend before you commit.** `redeye estimate` previews files, language mix,
  and per-stage USD budget with no LLM calls.
- **Measurable quality on demand.** `redeye eval` gives a one-command
  precision/recall/hallucination read-out — and a CI gate.
- **Readable, self-contained reports.** Markdown with an evidence trail and
  hallucination metrics up top, plus optional self-contained HTML and styled
  PDF built straight from the manifest — no external service.
- **Honest failure modes.** Backends fall back to `mock` on error rather than
  crashing a run; malformed external feeds are recorded, never fatal;
  `REDEYE_NO_NETWORK=1` hard-refuses network backends.
- **Truthful `--help` and agent recipe.** `AGENTS.md`/`CLAUDE.md` document the
  five-step recipe (`--version → doctor → estimate → scan → summarize`) so both
  humans and AI agents drive the tool the same, safe way.

---

## 10. How RedEye improves on VVAH

VVAH (Visa's Vulnerability Agentic Harness) pioneered the agentic-SAST loop
RedEye descends from. RedEye keeps that lineage and hardens it for production
operation, precision, and auditability.

| Dimension | VVAH (baseline agentic loop) | RedEye |
|---|---|---|
| Grounding | Prompt-level discipline | Deterministic S4b: path/line resolution **+ AST sink-call confirmation** (#1), evidence rows per finding |
| Invented sinks/routes | Possible | Constrained by S1b ground truth **and closed-set citation** (#4) |
| Verification | Model self-assessment | Deterministic **K-of-N over six independent signals** (S8c), temperature-free — works even where voting is a no-op |
| Independent corroboration | Not a first-class signal | Semgrep/CodeQL/Bandit/Trivy agreement is a **verification signal** (#2) |
| Proof of concept | "Describe an exploit" | Syntactic gate **+ behavioral oracle** that proves the payload subverts the sink (#6) |
| Severity integrity | Model-assigned | **Two-key** rule caps HIGH/CRITICAL without independent corroboration (#9) |
| Measuring quality | Anecdotal | `redeye eval`: precision/recall/**hallucination rate** vs. labeled benchmark, CI-gated (#3) |
| Confidence | Raw model score | **Platt-calibrated** probability + explicit **abstention** band (#8) |
| Reproducibility | Limited | Per-finding **provenance** (model, prompt hash, seed, index hash) + deterministic `mock` (#10) |
| Backends | Provider-coupled | Six pluggable backends + mock, auto-detected, graceful fallback |
| Cost control | Largely unbounded | Per-stage budgets, global guardrail, diff scope, incremental cache, cheap-first ordering |
| Output & CI | Free text | SARIF 2.1.0 + Markdown + HTML/PDF + manifest; GitHub-native PR/feedback loop |
| Repeat false positives | Re-reported | Baseline fingerprints + SQLite feedback loop suppress them |
| Operability | Research-oriented | `init` wizard, presets, `doctor`, `estimate`, offline mock, truthful agent recipe |

The throughline: VVAH proved the agentic loop; RedEye makes its output
**validated, verified, measurable, reproducible, cheaper, and pleasant to
run.**

---

## 11. Limitations (honest framing)

- **LLM-generated, non-deterministic** on real backends — findings are triage
  candidates, not confirmed vulns; two runs can differ unless every backend is
  `mock`. Provenance + `eval` make the variation *visible and measurable*.
- **AST grounding and the PoC oracle are strongest on Python** and the modeled
  CWE families; other languages fall back to the token/heuristic checks.
- **Self-consistency (#5) sampling loop** is wired as config + a tested
  aggregator; enabling k>1 uses the lens sampling path.
- **Token-hungry** on real backends — use `estimate`, presets, and DoS limits.
- **Feedback/calibration are local-first** (SQLite at `~/.redeye/scans.db`).

---

## 12. References (in-repo)

- `README.md` — overview, quickstart, presets, capabilities
- `docs/architecture.md` — stage-by-stage pipeline + contracts
- `docs/REDUCING_HALLUCINATIONS.md` — long-form rationale for each filter
- `docs/IMPROVEMENT_RECOMMENDATIONS.md` — the roadmap these v0.4 features implement
- `docs/configuration.md` — profiles, budgets, voter selection
- `docs/CI_AND_FEEDBACK.md` — CI/CD wiring + feedback loop
- `CHANGELOG.md` — release notes
- New source: `redeye/corroboration.py`, `redeye/ast_grounding.py`,
  `redeye/poc_oracle.py`, `redeye/eval_harness.py`, `redeye/precision.py`,
  `redeye/abstention.py`, `redeye/provenance.py`, `redeye/commands/eval.py`
