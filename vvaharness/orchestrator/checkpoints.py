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

"""orchestrator.checkpoints — see package docstring."""
import builtins
import os
import pickle
import sys
from pathlib import Path


# ── Hardened checkpoint loading ──────────────────────────────────────────────
# Checkpoints only ever hold this pipeline's own pydantic models plus the plain
# containers and scalars they nest. A checkpoint file can live in a location the
# scanned project influences, so loading one with stock pickle would let a
# crafted file execute an arbitrary __reduce__ gadget at resume time. The
# restricted unpickler below allow-lists exactly the classes a legitimate
# checkpoint needs and refuses everything else, so a tampered/hostile checkpoint
# is rejected (the stage simply re-runs) instead of being deserialised.
_SAFE_BUILTINS = {
    "dict", "list", "set", "frozenset", "tuple", "str", "bytes",
    "bytearray", "int", "float", "bool", "complex", "NoneType",
}
_SAFE_IMPORTS = {
    "copyreg": {"_reconstructor", "__newobj__", "__newobj_ex__"},
    "collections": {"OrderedDict", "defaultdict", "Counter", "deque"},
    "datetime": {"datetime", "date", "time", "timezone", "timedelta"},
    "decimal": {"Decimal"},
    "uuid": {"UUID"},
    "enum": {"Enum", "IntEnum", "StrEnum", "Flag", "IntFlag"},
}


class _RestrictedUnpickler(pickle.Unpickler):
    """Unpickler that only reconstructs the pipeline's own model classes and a
    small allow-list of safe stdlib primitives — never os/subprocess/builtins
    callables that a malicious checkpoint would use for code execution."""

    def find_class(self, module: str, name: str):
        if module == "vvaharness" or module.startswith("vvaharness."):
            return super().find_class(module, name)
        if module == "builtins" and name in _SAFE_BUILTINS:
            return getattr(builtins, name)
        allowed = _SAFE_IMPORTS.get(module)
        if allowed and name in allowed:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(
            f"refusing to load disallowed checkpoint object {module}.{name}")



def _ckpt_path(ckpt_dir: Path, run_id: str, step: str) -> Path:
    return ckpt_dir / f"{run_id}_{step}.pkl"


def save_ckpt(ckpt_dir: Path, run_id: str, step: str, obj) -> None:
    ckpt_dir.mkdir(parents=True, exist_ok=True)
    final = _ckpt_path(ckpt_dir, run_id, step)
    tmp = final.with_suffix(final.suffix + ".tmp")
    with open(tmp, "wb") as f:
        pickle.dump(obj, f)
    # Atomic on POSIX and Windows: a kill mid-dump leaves only the .tmp,
    # so --resume never sees a truncated .pkl and dies on UnpicklingError.
    os.replace(tmp, final)
    print(f"  [ckpt] saved {step}", file=sys.stderr)


def load_ckpt(ckpt_dir: Path, run_id: str, step: str):
    p = _ckpt_path(ckpt_dir, run_id, step)
    if not p.exists():
        return None
    try:
        with open(p, "rb") as f:
            obj = _RestrictedUnpickler(f).load()
    except (pickle.UnpicklingError, EOFError, ValueError,
            ModuleNotFoundError, ImportError, AttributeError) as e:
        # Three cases degrade the same safe way — re-run the step instead of
        # crashing or executing untrusted bytes:
        #   * corrupt / truncated file (EOFError, UnpicklingError);
        #   * checkpoint written by a different tool version whose model
        #     classes have moved/renamed (ModuleNotFoundError/ImportError/
        #     AttributeError);
        #   * a tampered checkpoint referencing a disallowed class, which the
        #     restricted unpickler rejects with UnpicklingError BEFORE the
        #     object is reconstructed (so no __reduce__ gadget can fire).
        print(f"  [ckpt] WARN: {p.name} is unreadable, version-mismatched, or "
              f"untrusted ({e}); ignoring and re-running {step}", file=sys.stderr)
        return None
    print(f"  [ckpt] resumed {step} from disk", file=sys.stderr)
    return obj


def run_id_for(repo: Path) -> str:
    """Stable run id per repo path so --resume picks up the right checkpoints."""
    safe = "".join(c if c.isalnum() else "_" for c in str(repo.resolve()))
    return safe[-60:]
