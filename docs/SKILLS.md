# Skills

A *skill* is the part of `redeye` that does the actual
LLM-prompting work for one stage. Stages are thin: they read context,
hand it to a skill, and store the result. This split lets you tune,
version, or swap a skill without touching the orchestrator.

## Catalog

| Skill | Used by | What it does |
|---|---|---|
| `attack_surface_mapper` | S1 | Walks the repo, asks the surveyor LLM to summarise entrypoints, auth boundaries, sensitive sinks. |
| `threat_modeler` | S2 | STRIDE/OWASP threat model against the surface. |
| `research_strategist` | S3 | Picks <=5 high-yield questions for S4 to answer. |
| `lens_language` | S4 | Language-level bugs: injection, deserialization, XXE, etc. |
| `lens_crypto` | S4 | Weak ciphers, hardcoded keys, IV reuse, JWT misconfig. |
| `lens_logic` | S4 | TOCTOU, races, IDOR, workflow-step skipping. |
| `lens_access_control` | S4 | Authn/authz boundaries, role checks, tenant bypass. |
| `lens_iac` | S4 | Terraform, K8s, Dockerfile, GitHub Actions misconfig. |
| `policy_gate` | S5 | Deterministic noise filter (no LLM). |
| `adversarial_reviewer` | S6 | Per-finding reachability trace + confirm/reject. |
| `dedupe` | S7 | Heuristic merge of overlapping findings (no LLM). |
| `exploit_strategist` | S8 | Polishes attack chain & remediation copy; tags chained-exploit pairs. |
| `emit` | S9 | Writes Markdown + SARIF to disk. |

## Adding a research lens

1. **Implement the lens.** Create `redeye/skills/lens_<name>.py`
   following the pattern in `lens_language.py` -- a system prompt and a
   `run(**kwargs)` that delegates to `_lens_common.run_lens`:

   ```python
   from redeye.skills._lens_common import run_lens

   _SYSTEM = """\
   You are inspecting code for <X>. Return JSON:
   {findings: [{title, severity, cwe, path, start_line, end_line,
                description, remediation, confidence}]}.
   """

   def run(**kwargs):
       return run_lens(lens_name="<name>", system_prompt=_SYSTEM, **kwargs)
   ```

2. **Register it.** Add to the `_LENSES` map in
   `redeye/pipeline/stages/s4_research.py`.

3. **Profile it.** Add the lens name to the `lenses:` list under
   `s4_research.params` in every profile that should run it.

4. **Document it.** Add a row to the catalog above and an entry under
   "Lens conventions" below.

5. **Test it.** A two-line smoke test in `tests/test_pipeline.py` that
   exercises the mock backend is enough.

## Lens conventions

- **One JSON object reply** -- the helper looks for `{findings: [...]}`
  inside a fenced ```json block. Anything else is ignored.
- **Be conservative on severity** -- prefer MEDIUM over HIGH unless the
  reachability is obvious; voters are stricter on HIGH/CRITICAL.
- **Always set `cwe`** -- SARIF consumers and downstream rule packs key
  off CWE. If you genuinely don't know, use `CWE-1000` (Research
  Concepts root).
- **Concrete file paths only** -- `path` should be a repo-relative POSIX
  path. Glob patterns or descriptions like "various login files" will be
  rejected by the SARIF emitter.
- **Remediation must be code-level** -- "use parameterised queries via
  `text(...).bindparams(...)`" beats "sanitize input".

## Replacing a skill

Skills are imported by name from `redeye/skills/` -- there is no
plug-in system. To replace one:

1. Fork the package.
2. Replace the module under `redeye/skills/<name>.py`.
3. Reinstall (`pip install -e .`).

This is intentional. A plug-in system makes it too easy to load a
malicious skill from a malicious repo, and the harness already runs with
elevated privilege.

## Skill performance budget

The orchestrator passes `max_budget_usd` into every skill (split across
lenses for S4). Skills are responsible for not blowing the budget;
multi-call skills should track usage and stop early if they're trending
over. The mock backend reports cost as 0.0, so budgets effectively don't
apply during CI tests.
