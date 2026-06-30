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

"""Argument parser and tunable-override helpers for ``vvaharness validate``."""

from __future__ import annotations

import argparse
from pathlib import Path

from vvaharness.validation.constants.artifacts import VALIDATABLE_STATUSES

# Human-readable list of validatable statuses, derived from the constant so the help text
# can never drift from the actual selection set.
_VALIDATABLE_HELP = " / ".join(VALIDATABLE_STATUSES)


def _build_parser() -> argparse.ArgumentParser:
    """Return a configured ArgumentParser for ``vvaharness validate``."""
    parser = argparse.ArgumentParser(
        prog="vvaharness validate",
        description="s11 — agentic validation agent (invoke as `validate` or `s11`).",
    )
    parser.add_argument("--repo", type=Path, required=True, help="Target repository root")
    parser.add_argument("--config", default=None, help="Config profile path (else default)")
    parser.add_argument(
        "--finding",
        dest="findings",
        action="append",
        help="Finding id to validate (repeatable)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help=(
            f"Validate ALL validatable findings ({_VALIDATABLE_HELP}); "
            "bypasses the max_findings cap"
        ),
    )
    parser.add_argument(
        "--max-findings",
        dest="max_findings",
        type=int,
        default=None,
        help=(
            f"Cap to the top-N validatable findings ({_VALIDATABLE_HELP}) "
            "by CVSS; overrides step_validate.max_findings"
        ),
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help=(
            "Workspace root for staged copies. Treated as ephemeral and removed on "
            "completion — pass a new or empty path (a non-empty directory is refused)"
        ),
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip findings already validated in a prior run (cached verdict reprinted)",
    )
    parser.add_argument(
        "--scan-report",
        type=Path,
        default=None,
        dest="scan_report",
        help="Combined report (.md) to enrich; else the newest in security-remediation/",
    )
    return parser


# step_validate scalar knobs forwarded as typed overrides into the validation config layer.
_TUNABLE_ATTRS: tuple[str, ...] = ("effort", "max_turns", "max_budget_usd", "max_findings")


def _tunable_overrides(cfg: object) -> dict[str, object]:
    """Collect present ``step_validate`` knobs as typed config overrides.

    Covers effort, turns, budget, and the findings cap; an absent block or unset value is
    omitted so the env/default layer still wins.
    """
    block = getattr(cfg, "step_validate", None)
    if block is None:
        return {}
    overrides: dict[str, object] = {}
    for attr in _TUNABLE_ATTRS:
        value = getattr(block, attr, None)
        if value is not None:
            overrides[attr] = value
    return overrides
