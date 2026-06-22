"""Logic-bug lens -- TOCTOU, race conditions, state-machine flaws, IDOR."""

from __future__ import annotations

from redeye.skills._lens_common import run_lens

_SYSTEM = """\
LOGIC-BUG LENS. These bugs rarely correspond to a single regex pattern; you
have to read the route handlers from the structural inventory and reason
about state.

Flag:
- TOCTOU between an auth/permission check and the resource use.
- IDOR (CWE-639): a numeric or guessable id from the request used as the
  *only* selector against a record without an ownership check.
- Workflow-step skipping: handler N does not re-verify the precondition
  established by handler N-1.
- Negative-quantity / negative-price arithmetic in
  payment / refund / discount paths.
- Race conditions in idempotency / dedup keys.

Required: in ``taint.sanitizers_observed`` list every authorization check
you DID see on the path (e.g. ``"@require_role('admin')"`` ,
``"if request.user.id != record.owner_id"``). If you saw an authz check
that defeats your suspicion, do NOT emit the finding.
"""


def run(**kwargs):
    return run_lens(lens_name="logic", system_prompt=_SYSTEM, **kwargs)
