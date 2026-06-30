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

"""Resolution of AI auto-exclude (--auto-step1 flag OR step1.auto_exclude config).

Mirrors the OR-precedence --remediate uses with step_remediate.enabled: the
flag only turns it ON, config can default it on, and a profile sets
auto_exclude:false to opt out.
"""
from vvaharness.config import Config
from vvaharness.orchestrator.config_paths import _packaged_default
from vvaharness.orchestrator.entry import _resolve_auto_step1
import vvaharness.config as config_mod


def _cfg(step1: dict | None) -> Config:
    return Config({} if step1 is None else {"step1": step1})


# --------------------------------------------------------------------------
# _resolve_auto_step1 — flag vs config OR-precedence
# --------------------------------------------------------------------------

def test_flag_set_wins_regardless_of_config():
    # Explicit flag turns it on; source is the flag even if config also true.
    assert _resolve_auto_step1(True, _cfg({"auto_exclude": True})) == (True, "--auto-step1")
    assert _resolve_auto_step1(True, _cfg({"auto_exclude": False})) == (True, "--auto-step1")


def test_config_true_enables_when_flag_absent():
    assert _resolve_auto_step1(False, _cfg({"auto_exclude": True})) == (True, "step1.auto_exclude")


def test_disable_wins_over_config_default():
    # --no-auto-step1 hard-disables irrespective of a config default-on.
    assert _resolve_auto_step1(False, _cfg({"auto_exclude": True}),
                               disable=True) == (False, "--no-auto-step1")


def test_disable_wins_over_flag():
    # Defensive: even if both somehow arrive, disable wins (argparse also makes
    # --auto-step1 / --no-auto-step1 mutually exclusive at parse time).
    assert _resolve_auto_step1(True, _cfg({"auto_exclude": True}),
                               disable=True) == (False, "--no-auto-step1")


def test_config_false_keeps_off_when_flag_absent():
    # A profile can opt a run out by setting auto_exclude:false.
    assert _resolve_auto_step1(False, _cfg({"auto_exclude": False})) == (False, None)


def test_key_absent_defaults_off():
    # No auto_exclude key anywhere -> off (preserves pre-feature behaviour).
    assert _resolve_auto_step1(False, _cfg({"max_file_kb": 1024})) == (False, None)


def test_step1_block_absent_defaults_off():
    # A config with no step1 block at all must not crash.
    assert _resolve_auto_step1(False, _cfg(None)) == (False, None)


def test_non_bool_truthy_config_value_enables():
    # YAML could yield a non-bool truthy/falsey; bool() coercion governs.
    assert _resolve_auto_step1(False, _cfg({"auto_exclude": 1}))[0] is True
    assert _resolve_auto_step1(False, _cfg({"auto_exclude": 0}))[0] is False
    assert _resolve_auto_step1(False, _cfg({"auto_exclude": None}))[0] is False


# --------------------------------------------------------------------------
# Shipped default profile actually ships the new default ON
# --------------------------------------------------------------------------

def test_packaged_default_profile_enables_auto_exclude():
    cfg = config_mod.load(_packaged_default())
    enabled, src = _resolve_auto_step1(False, cfg)
    assert enabled is True
    assert src == "step1.auto_exclude"
