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


from __future__ import annotations

"""
Agentic SAST — 9-stage LLM security pipeline.

Usage (via the `vvaharness` console script):
  vvaharness scan --repo /path/to/target [--config config.yaml]
                   [--resume] [--repo-name acme/payments] [--application-id ID]

The default profile runs every role through the Claude CLI (`via: cli`) on
claude-sonnet-4-6, reusing your Claude Code login (run `claude` then `/login`,
or set CLAUDE_CODE_OAUTH_TOKEN) — no ANTHROPIC_SDK_API_KEY required. Roles can
be re-pointed at the Anthropic SDK (`via: sdk`; auth: ANTHROPIC_SDK_API_KEY) or
an OpenAI-compatible endpoint (`via: openai`; auth: OPENAI_API_KEY) in
config.yaml.

Steps:
  1. Pre-process (agentic exploration)      → ContextPackage
  2. Threat-model (consumes ctx)            → ThreatModel
  3. Decompose (1 run)                      → TaskManifest
  4. Deep-dive (×N + majority vote)         → Finding[]
  5. Pre-filter (deterministic + pre-dedup) → Finding[]
  6. Adversarial verify                     → (verified[], dropped[])
  7. Dedup + VulContextSeverity/Offensive   → (canonical[], dup_dropped[])
  8. Chain                                  → FinalReport (+ ScanMetrics)
  9. MD → SARIF                             → *_report.sarif

Each step checkpoints to {repo}/checkpoints/. --resume skips completed steps.
Final report is written to {repo}/security-scan/{module}_{timestamp}_report.{md,sarif}.
"""
import shutil  # noqa: F401 — patched by tests via orchestrator.shutil
from vvaharness.orchestrator.config_paths import (  # noqa: F401
    _app_root, _default_config, _resolve_against, _iter_model_roles, _MODEL_ROLES)
from vvaharness.orchestrator.checkpoints import (  # noqa: F401
    _ckpt_path, save_ckpt, load_ckpt, run_id_for)
from vvaharness.orchestrator.cleanup import (  # noqa: F401
    _rmtree_rw, _preserve_set, _purge_clone)
from vvaharness.orchestrator.cmdb import (  # noqa: F401
    _cmdb_path, _set_cmdb_path, _load_app_profile)
from vvaharness.orchestrator.enrich_findings import _enrich_findings  # noqa: F401
from vvaharness.orchestrator.preflight import (  # noqa: F401
    _mask, _reachable_despite_token_cap, configure_backends,
    check_backends, probe_backends)
from vvaharness.orchestrator.scan import scan_repo  # noqa: F401
from vvaharness.orchestrator.batch import run_batch  # noqa: F401
from vvaharness.orchestrator.entry import main  # noqa: F401

