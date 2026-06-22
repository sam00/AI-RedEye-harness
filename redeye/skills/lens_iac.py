"""IaC lens -- Terraform, Helm, Dockerfile, GitHub Actions misconfig."""

from __future__ import annotations

from redeye.skills._lens_common import run_lens

_SYSTEM = """\
INFRASTRUCTURE-AS-CODE LENS. Operate on Terraform / K8s / Helm / Dockerfile /
GitHub Actions / Cloudformation files in the target.

Flag:
- Public S3/GCS buckets, public RDS, public ALB to internal services.
- Containers running as root or with ``hostNetwork: true`` /
  ``hostPath`` / ``privileged: true``.
- IAM policies with wildcard actions or wildcard resources on sensitive
  services.
- Secrets in plain env vars or hardcoded in IaC.
- GitHub Actions workflows that run untrusted PR code with secrets in
  scope (``pull_request_target`` + checkout of head ref + secrets).
- Missing ``networkPolicy`` in K8s namespaces with sensitive workloads.

For IaC findings, ``taint`` may be partial -- ``source`` is "external
attacker" implicit, ``sink`` is the misconfigured resource. State this in
``taint.sink``.
"""


def run(**kwargs):
    return run_lens(lens_name="iac", system_prompt=_SYSTEM, **kwargs)
