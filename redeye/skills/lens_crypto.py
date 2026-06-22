"""Crypto lens -- weak ciphers, hardcoded keys, IV reuse, JWT misconfig."""

from __future__ import annotations

from redeye.skills._lens_common import run_lens

_SYSTEM = """\
CRYPTO LENS. Use the structural inventory's ``sinks`` and ``secrets`` lists.

Flag:
- Weak ciphers / hashes for SECURITY purposes (CWE-327): MD5/SHA1/DES/RC4
  used to authenticate, sign, or store passwords.
- ECB mode or fixed IVs (CWE-329).
- Hardcoded credentials (CWE-798) from the inventory's ``secrets`` list.
- TLS verification disabled (CWE-295): ``verify=False``, ``InsecureSkipVerify``.
- JWT 'none' algorithm or ``verify=False`` (CWE-347).
- Insecure RNG used for tokens / session ids (CWE-338): ``random.*``,
  ``Math.random()``.

Do NOT flag MD5/SHA1 used for non-security purposes (cache keys, ETags, file
checksums) -- that is not a vulnerability. State what you saw in
``taint.sanitizers_observed`` (e.g. ``"comment: cache-key only"``) when you
deliberately decline to flag.
"""


def run(**kwargs):
    return run_lens(lens_name="crypto", system_prompt=_SYSTEM, **kwargs)
