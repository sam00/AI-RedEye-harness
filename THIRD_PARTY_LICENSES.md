# Third-party licenses

`redeye` depends on the following third-party Python packages,
installed from PyPI at install time. None are bundled in this repository.

| Package | License | Use |
|---|---|---|
| [click](https://pypi.org/project/click/) | BSD-3-Clause | CLI argument parsing |
| [pyyaml](https://pypi.org/project/PyYAML/) | MIT | Config profile loading |
| [rich](https://pypi.org/project/rich/) | MIT | Terminal output |
| [python-dotenv](https://pypi.org/project/python-dotenv/) | BSD-3-Clause | `.env` discovery |
| [pydantic](https://pypi.org/project/pydantic/) | MIT | Schema validation |
| [httpx](https://pypi.org/project/httpx/) | BSD-3-Clause | HTTP client (OpenAI backend) |
| [tenacity](https://pypi.org/project/tenacity/) | Apache-2.0 | Retry helpers |
| [anthropic](https://pypi.org/project/anthropic/) (extra `[sdk]`) | MIT | Anthropic SDK backend |
| [openai](https://pypi.org/project/openai/) (extra `[openai]`) | Apache-2.0 | OpenAI backend |

Dev-only:

| Package | License |
|---|---|
| pytest | MIT |
| pytest-cov | MIT |
| ruff | MIT |
| mypy | MIT |

To regenerate this inventory after adding/removing dependencies:

```bash
pip install pip-licenses
pip-licenses --format=markdown --with-urls --order=license
```
