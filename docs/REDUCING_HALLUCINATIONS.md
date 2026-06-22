# Reducing hallucinations

The single hardest part of LLM-driven SAST is **the model is happy to invent
findings**. It will cite a file that doesn't exist, claim a CWE the code
doesn't exhibit, and write a "remediation" for a bug that was never there.
Every layer in the 0.3 redesign is built around this constraint.

This document explains *why* each layer is here. If you're tightening a
profile or designing a new lens, read it first.

## The five layers

```
                                        DROP / DOWNGRADE
                                              ^
                                              |
   raw lens output -+------+------+------+------+------+--->  reported
                    |      |      |      |      |      |      finding
                    v      v      v      v      v      v
                  [S4b]  [S5]  [S6]   [S6.5]  [S7]  [S8b]
                  ground  policy adver  vali-  dedupe  PoC
                  -ing    gate   sarial dator         gate
                  pass    +vote
                  (det.) (det.)  (LLM)  (LLM) (det.)  (LLM)
```

| Layer | What it kills | Cost |
|---|---|---|
| **S4b grounding** | Findings whose cited file doesn't exist, line doesn't resolve, or snippet has no CWE-family tokens | Zero LLM, file I/O only |
| **S5 policy gate** | Findings in test/vendor paths, findings without remediation, findings below severity floor | Zero LLM |
| **S6 adversarial review** | Findings whose reachability is implausible | LLM |
| **S6 voting** | Findings only one of N voters agrees with | LLM x N |
| **S6.5 validator** | Final 1-of-1 TP/FP gate. Auto-rejects findings tagged hallucinated by S4b | LLM (cheap) |
| **S7 dedupe** | Same root cause described by multiple lenses | Zero LLM |
| **S8b PoC gate** | Findings the model can't write a concrete payload for | LLM (cheap) |

The order matters. **Cheap deterministic layers come first** so we don't
spend tokens adversarially-reviewing a finding that cites a path which
doesn't exist.

## Layer 1: structural pre-index (S1b)

Before any lens runs, regex + AST patterns extract a deterministic
inventory of:

- **Routes** -- HTTP / RPC entrypoints (FastAPI, Flask, Express, Spring,
  Django).
- **Sources** -- request body, query string, env vars, stdin, argv,
  Kafka consumers.
- **Sinks** -- SQL execute, subprocess, eval/exec, deserialization
  (pickle, yaml.load, ObjectInputStream), os.system, weak crypto, JWT
  misverification, SSRF helpers, path traversal candidates.
- **Secrets** -- AWS / Anthropic / OpenAI / Google / GitHub / Slack tokens,
  PEM private keys, generic high-entropy assignments.

This inventory becomes ground truth for every later prompt. The lens
reasons "given these *real* sinks, which combinations are dangerous?"
instead of "imagine where bugs might be". A large class of hallucinations
disappears immediately because the model can no longer invent routes or
sinks the codebase doesn't have.

**Cost:** zero LLM tokens. Tens of milliseconds for a 50k-LoC repo.

## Layer 2: explicit taint shape

Every lens response must include a ``taint`` block with:

- ``source`` -- where attacker-controlled data enters,
- ``source_location`` -- file:line,
- ``sink`` -- the dangerous operation,
- ``sink_location`` -- file:line,
- ``sanitizer_missing`` -- explicit boolean,
- ``sanitizers_observed`` -- list of sanitizers the lens DID see,
- ``taint_path`` -- ordered list of file:line steps from source to sink.

A response without source + sink is rejected. This forces the model to
have a *theory* of the bug rather than a vibe. Crucially, the
``sanitizers_observed`` field is how the model can disprove its own
suspicion -- if it saw an authz check that defeats the IDOR, it should
say so and not emit the finding. The 0.3 prompts are explicit about this.

## Layer 3: grounding pass (S4b)

For each candidate finding, the grounding pass:

1. Resolves the cited path against the target. Reject if the path
   escapes the target via ``..`` or doesn't exist.
2. Checks that ``start_line`` is within the file's actual line count.
3. Reads a +/-5 line window around the cited line and checks for tokens
   from the claimed CWE family. (E.g. CWE-89 looks for ``execute``,
   ``query``, ``cursor``, etc. CWE-78 looks for ``subprocess``,
   ``shell``, ``os.system``.)

| Outcome | Tag | Default behavior | ``--strict-grounding`` |
|---|---|---|---|
| All three pass | ``grounded: true`` | keep | keep |
| File or line missing | ``hallucinated:bad-path`` / ``hallucinated:bad-line`` | keep, tag, validator auto-rejects | drop |
| Tokens missing | ``weak-evidence`` | keep, cap confidence at 0.5 | keep, cap confidence at 0.5 |

The grounding pass produces an ``Evidence`` row for every finding
recording exactly which check passed or failed. These rows surface in
the Markdown report's "Evidence collected" section so reviewers can see
why the harness believes the finding.

**Cost:** zero LLM tokens. Bounded by file I/O.

## Layer 4: validator auto-reject

The single-pass validator (S6.5) consults ``finding.tags`` *before*
spending an LLM call. Findings with ``hallucinated:bad-path`` or
``hallucinated:bad-line`` are auto-rejected -- there's no point asking a
model to confirm a bug that cites fictional code.

For everything else, the validator gets a compact dossier including the
deterministic grounding evidence and the taint shape, and decides
``confirm`` / ``reject`` / ``uncertain``. The dossier shape ensures the
validator can't paper over a hallucination it would otherwise rationalise.

## Layer 5: PoC gate (S8b)

The PoC gate asks the model to write a *concrete* exploit string. We
parse the result and decide whether it counts as concrete using
syntactic checks: it must contain at least one of {a quoted payload, a
URL, an HTTP verb, an injection metacharacter, ``../``, ``${``,
``<script``, a SQL keyword}. Placeholder PoCs (``<exploit_here>``,
``malicious_input``) are rejected.

Findings without a concrete PoC get demoted by one severity notch
(HIGH -> MEDIUM, MEDIUM -> LOW). With ``--require-poc`` they are dropped
outright. The rationale: a real bug usually has an obvious payload; if
the model can't write one, the model probably doesn't actually
understand the bug.

**Cost:** small LLM call per finding (Haiku-class is fine).

## Layer 6: hallucination metrics

Every scan emits hallucination metrics in ``run_manifest.json`` and at
the top of the Markdown report:

```json
{
  "raw_lens": 24,
  "ungrounded_dropped": 6,
  "ungrounded_downgraded": 4,
  "validator_rejected": 3,
  "voted_out": 2,
  "missing_poc": 1
}
```

A high ``ungrounded_dropped`` count means the lens is hallucinating
paths -- consider tightening the lens prompt, switching to a stronger
model, or adding files the model can read directly. A high ``voted_out``
count means voters disagree -- voting is doing its job, but you might
have a noisy lens.

These metrics also flow into ``feedback`` rows when ``--store-findings``
is on, so the feedback loop trains the next run away from the
hallucinations the previous run produced.

## When to enable strict mode

- ``--strict-grounding`` -- default OFF. Turn it ON in CI / PR scans
  where you want zero noise reaching reviewers; leave it OFF during
  research where the appendix of dropped findings is itself useful.
- ``--require-poc`` -- default OFF. Turn it ON when you want to publish
  a public-facing report where every finding has a runnable demo.

Combining both gives the strictest possible filter: every reported
finding has a real file, a real line, CWE-family tokens at that line,
voter agreement, and a concrete exploit payload.

## Tuning

| Symptom | Likely cause | Fix |
|---|---|---|
| Reports are full of confidently-wrong findings | Lens model is too small, or you're not running S4b | Use Sonnet+, ensure ``s4b_grounding`` is in the profile |
| Scans miss obvious bugs | Structural inventory missed the sink | Add a regex to ``redeye.structural._SINK_PATTERNS`` |
| Voting drops everything | Voters use the same model family | Use cross-vendor voters in the ``full`` profile |
| Validator confirms hallucinations | Validator is too small | Move it from Haiku to Sonnet for the validator role |
| Low recall on PR scans | DoS limits cap files too aggressively | Bump ``--max-files`` / ``--max-total-bytes`` |
