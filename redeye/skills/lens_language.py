"""Language lens -- common language-specific weaknesses (injection, deser, etc.)."""

from __future__ import annotations

from redeye.skills._lens_common import run_lens

_SYSTEM = """\
LANGUAGE LENS. Look for language-level vulnerabilities at the sinks listed
in the structural inventory:
- SQL / NoSQL injection (CWE-89): tainted input flowing into ``execute``,
  ``raw_query``, f-string SQL.
- Command injection (CWE-78): tainted input flowing into ``subprocess.*``
  with ``shell=True``, ``os.system``, ``exec``, backticks.
- Code injection (CWE-95): ``eval`` / ``exec`` / ``Function`` on tainted input.
- Unsafe deserialization (CWE-502): ``pickle.loads``, ``yaml.load`` (1-arg),
  Java ``ObjectInputStream``.
- Path traversal (CWE-22): ``open`` / ``read`` on a path built from
  attacker-controlled segments.
- XXE: lxml/Python parsers with external entities enabled.

Do not flag: prepared-statement code, code that uses ``shell=False``, code
that calls ``yaml.safe_load``, paths constructed only from constants.
"""


def run(**kwargs):
    return run_lens(lens_name="language", system_prompt=_SYSTEM, **kwargs)
