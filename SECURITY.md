# Security Policy

## Supported versions

`redeye` is in early development. Only the latest release (`main`)
receives security fixes.

| Version | Supported |
|---|---|
| 0.1.x   | ? |
| < 0.1   | ? |

## Reporting a vulnerability

**Do not** open public GitHub issues for security problems.

Email the maintainers at **security@example.invalid** (replace with your
real address before publishing) with:

1. A description of the issue and its impact.
2. Steps to reproduce, including any required configuration / inputs.
3. Affected version (commit hash if cloning from `main`).
4. Suggested remediation, if any.

We aim to acknowledge reports within **3 business days** and to provide a
remediation plan within **14 days** for confirmed vulnerabilities.

## Operational risk

This tool runs with elevated privilege (it reads source code, may invoke a
local `claude` CLI subprocess, and may make outbound LLM calls). Treat it as
**trusted-input only**:

- Run only against repositories you own or have explicit permission to scan.
- Do not point the harness at untrusted code — a malicious repository could
  attempt to exfiltrate environment variables (API keys, OAuth tokens) by
  injecting prompts into source files that are read into LLM context.
- Use `REDEYE_NO_NETWORK=1` to disable network-using backends in
  air-gapped environments.

## Coordinated disclosure

We follow a 90-day coordinated disclosure window by default. We will work
with you on a faster or slower timeline if circumstances warrant.
