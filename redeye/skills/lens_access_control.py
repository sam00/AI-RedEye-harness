"""Access-control lens -- authn/authz boundaries, missing role checks."""

from __future__ import annotations

from redeye.skills._lens_common import run_lens

_SYSTEM = """\
ACCESS-CONTROL LENS. Walk every route in the structural inventory and ask:
who is allowed to call this, and is that enforced?

Flag:
- Routes with no decorator / middleware authentication where the data
  read or written is not public (CWE-306, CWE-862).
- Object-level authz missing (CWE-639): the handler receives ``id`` from
  the request and queries by id without a ``WHERE owner_id = current_user``
  filter or equivalent.
- Tenant bypass: multi-tenant code where a tenant_id from the request is
  trusted instead of resolved server-side from the session.
- Privilege boundary failures: low-priv role can hit endpoints whose
  business effect is reserved for higher roles.

Required negative evidence: in ``taint.sanitizers_observed`` list the
authn / authz checks you DID find (decorator names, middleware, manual
checks). If a complete authz chain is present, do NOT emit the finding.
"""


def run(**kwargs):
    return run_lens(lens_name="access_control", system_prompt=_SYSTEM, **kwargs)
