# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Load known CVEs from a JSON file. Format is intentionally simple — adapt
to your tracker (NVD export, internal DB dump, etc.)."""
from __future__ import annotations
import json
from pathlib import Path
from pydantic import ValidationError
from vvaharness.models import CVE
from vvaharness.util import errlog as _errlog


def load_cves(path: str | Path) -> list[CVE]:
    p = Path(path)
    if not p.exists():
        return []
    # A present-but-malformed / hand-edited feed must DEGRADE (empty list)
    # rather than abort the whole scan with a raw traceback. Parse, key
    # extraction and per-item validation are all guarded; the failure is
    # recorded to the structured error log next to the report.
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        # Accept either a bare list or {"cves": [...]}. Only treat a dict as a
        # wrapper when it actually carries a "cves" key — otherwise iterating
        # the dict yields its string keys, which then fail validation. A dict
        # without "cves" is malformed input, not a single CVE.
        if isinstance(data, dict):
            items = data.get("cves")
            if items is None:
                raise ValueError(
                    "CVE feed is a JSON object without a 'cves' key — expected "
                    "a list or {\"cves\": [...]}")
        else:
            items = data
        return [CVE.model_validate(item) for item in items]
    except (OSError, ValueError, TypeError, ValidationError) as e:
        print(f"  [inject] WARN: could not load CVE feed {p} ({type(e).__name__}: "
              f"{e}); continuing with no injected CVEs.", file=__import__("sys").stderr)
        _errlog.log("inject.cves", str(p), e)
        return []
