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

"""orchestrator.config_paths — see package docstring."""
from pathlib import Path





def _app_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _default_config() -> Path:
    cwd_cfg = Path.cwd() / "config.yaml"
    if cwd_cfg.exists():
        return cwd_cfg
    return _packaged_default()


def _packaged_default() -> Path:
    """The bundled default profile — the trusted fallback used when a config
    sourced from inside the scan target is refused."""
    return _app_root() / "config" / "profiles" / "default.yaml"


def _path_within(candidate, root) -> bool:
    """True if `candidate` resolves at or under `root` (both fully resolved).
    Used to refuse a config/.env that lives INSIDE the scanned (untrusted)
    repository, which an attacker who controls the checkout could plant."""
    try:
        Path(candidate).resolve().relative_to(Path(root).resolve())
        return True
    except (ValueError, OSError):
        return False


def _resolve_against(base: Path, p: str) -> str:
    pp = Path(p)
    return str(pp if pp.is_absolute() else (base / pp))


_MODEL_ROLES = ("autoexclude", "preprocess", "threatmodel", "decompose",
                "deepdive", "verify", "dedup", "chain")


def _iter_model_roles(cfg):
    for r in _MODEL_ROLES:
        m = getattr(cfg.models, r, None)
        if m is not None:
            yield r, m
