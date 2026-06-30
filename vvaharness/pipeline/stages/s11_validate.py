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
"""s11_validate — thin wrapper that hooks the validation package into the pipeline.

The validation package (`vvaharness/validation/`) is the engine; this module is
only the pipeline-stage entry point that calls it with the right argv.
"""
from __future__ import annotations
from pathlib import Path


def run(
    repo: Path | str,
    *,
    cfg,
    config_path: str,
    finding_ids: list[str] | None = None,
    resume: bool = False,
    report_md: Path | str | None = None,
) -> int:
    """Run the s11 agentic validator against awaiting remediate_report.json files.

    ``config_path`` is forwarded as ``--config`` so the validator reads the same
    profile the scan ran with (model/backend/budget). If it is empty, the validator
    resolves its packaged default profile instead (logged downstream, not silent).
    ``report_md`` is the canonical combined report this run produced, forwarded as
    ``--scan-report`` so validation enriches exactly that file.
    """
    from vvaharness.validation.cli import main as validate_main
    argv = ["--repo", str(repo)]
    if config_path:
        argv += ["--config", str(config_path)]
    if finding_ids:
        for fid in finding_ids:
            argv += ["--finding", fid]
    else:
        argv += ["--all"]
    if resume:
        argv += ["--resume"]
    if report_md:
        argv += ["--scan-report", str(report_md)]
    return validate_main(argv)
