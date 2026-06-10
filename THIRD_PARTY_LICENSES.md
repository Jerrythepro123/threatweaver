# Third-Party License Inventory

vvaharness is licensed under Apache-2.0 (see `LICENSE`). It depends on the
third-party packages listed below. These dependencies are installed from PyPI
at install time (`pipx install .` / `pip install .`) and are **not** vendored
or redistributed as part of this repository. This inventory is provided for
transparency and compliance review.

**Source:** Sonatype Nexus IQ scan — June 4, 2026

| License | Packages |
|---|---|
| MIT | anthropic, anyio, annotated-types, charset-normalizer, docstring-parser, exceptiongroup, h11, jiter, pydantic, pydantic-core, pyyaml, sniffio, urllib3 |
| Apache-2.0 | distro, requests, sniffio *(dual MIT / Apache-2.0)* |
| BSD-3-Clause | httpcore, httpx, idna |
| MPL-2.0 | certifi |
| PSF (Python Software Foundation) | typing-extensions |

All dependency licenses above are permissive (MIT, Apache-2.0, BSD-3-Clause,
PSF) or weak-copyleft at file level (MPL-2.0); none impose copyleft
obligations on first-party source.