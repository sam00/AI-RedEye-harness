# Contributing

Thank you for your interest in `redeye`.

## External contributions

This repository is a **reference implementation**. The maintainers may not
accept unsolicited pull requests against `main` — please open a discussion
or issue first to scope the change. Forks are welcome and encouraged for
internal customization.

If your fork adds value to the broader community, consider publishing it as
a separate skill pack — see [`docs/SKILLS.md`](docs/SKILLS.md).

## Local development

```bash
git clone <fork-url> redeye
cd redeye
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Run the test suite

```bash
pytest
```

### Lint and type-check

```bash
ruff check .
ruff format --check .
mypy redeye
```

### Smoke-test the pipeline (no LLM credential needed)

```bash
redeye scan --repo . --profile mock --output-dir ./out
```

This runs all 9 stages against the mock backend and emits a
deterministic Markdown / SARIF report to `./out/`.

## Reporting bugs

For non-security bugs, open a GitHub issue with:

- The `redeye --version` output.
- The exact command you ran.
- Relevant lines from `errors.jsonl` and the full stderr.
- The git SHA of the target repo (if shareable).

For security issues, see [`SECURITY.md`](SECURITY.md).

## DCO sign-off

All commits must be signed off (Developer Certificate of Origin):

```bash
git commit -s -m "your message"
```
