"""Profile loading: a YAML profile becomes a :class:`Profile` object.

Resolution order (highest priority first):

1. The path passed via ``--profile``, treated literally if it ends in
   ``.yaml`` / ``.yml`` and exists, otherwise treated as a profile name.
2. ``$REDEYE_PROFILE``.
3. ``./config.yaml`` in CWD.
4. The bundled ``default.yaml``.
"""

from __future__ import annotations

from redeye.config.loader import Profile, load_profile

__all__ = ["Profile", "load_profile"]
