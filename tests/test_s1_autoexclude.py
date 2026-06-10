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

"""Unit tests for s1_autoexclude pure helpers: _extract_yaml and _norm_list."""
from vvaharness.pipeline.stages.s1_autoexclude import _extract_yaml, _norm_list


# --------------------------------------------------------------------------
# _extract_yaml
# --------------------------------------------------------------------------

def test_extract_yaml_fenced_block():
    text = (
        "Here is my answer:\n"
        "```yaml\n"
        "exclude_dirs:\n"
        "  - generated\n"
        "  - samples\n"
        "```\n"
        "trailing chatter that must be ignored"
    )
    assert _extract_yaml(text) == {"exclude_dirs": ["generated", "samples"]}


def test_extract_yaml_yml_fence_label():
    text = "```yml\nexclude_exts:\n  - .min.js\n```"
    assert _extract_yaml(text) == {"exclude_exts": [".min.js"]}


def test_extract_yaml_unlabeled_fence():
    # Fence with no language label still matches the (?:yaml|yml)? optional group.
    text = "```\nmax_file_kb: 2048\n```"
    assert _extract_yaml(text) == {"max_file_kb": 2048}


def test_extract_yaml_no_fence_parses_whole_text():
    # No fence at all -> parse the entire text as YAML.
    text = "exclude_dirs:\n  - vendored\n"
    assert _extract_yaml(text) == {"exclude_dirs": ["vendored"]}


def test_extract_yaml_step1_wrapper_unwrapped():
    text = (
        "```yaml\n"
        "step1:\n"
        "  exclude_dirs:\n"
        "    - docs\n"
        "  max_file_kb: 512\n"
        "```"
    )
    # The sole top-level key "step1" should be unwrapped.
    assert _extract_yaml(text) == {"exclude_dirs": ["docs"], "max_file_kb": 512}


def test_extract_yaml_step1_wrapper_only_unwrapped_when_sole_key():
    # step1 present but NOT the only key -> left as-is (no unwrap).
    text = (
        "```yaml\n"
        "step1:\n"
        "  exclude_dirs:\n"
        "    - docs\n"
        "other: 1\n"
        "```"
    )
    result = _extract_yaml(text)
    assert set(result) == {"step1", "other"}
    assert result["step1"] == {"exclude_dirs": ["docs"]}


def test_extract_yaml_step1_wrapper_not_unwrapped_when_value_not_dict():
    text = "```yaml\nstep1: just-a-string\n```"
    # set(data) == {"step1"} but value is not a dict, so no unwrap.
    assert _extract_yaml(text) == {"step1": "just-a-string"}


def test_extract_yaml_malformed_returns_empty(capsys):
    # Unbalanced bracket / bad indentation -> YAMLError -> empty overlay.
    text = "```yaml\nexclude_dirs: [unclosed, list\n  - bad: : indent\n```"
    assert _extract_yaml(text) == {}
    err = capsys.readouterr().err
    assert "auto-step1" in err
    assert "empty overlay" in err


def test_extract_yaml_empty_block_returns_empty_dict():
    # safe_load(None/"") -> falls back to {}.
    assert _extract_yaml("```yaml\n\n```") == {}


def test_extract_yaml_non_dict_scalar_returns_empty_dict():
    # A bare scalar parses fine but is not a dict -> coerced to {}.
    assert _extract_yaml("just a plain sentence with no mapping") == {}


def test_extract_yaml_list_top_level_returns_empty_dict():
    text = "```yaml\n- a\n- b\n```"
    # A top-level list is valid YAML but not a dict.
    assert _extract_yaml(text) == {}


def test_extract_yaml_case_insensitive_fence_label():
    text = "```YAML\nmax_file_kb: 64\n```"
    assert _extract_yaml(text) == {"max_file_kb": 64}


# --------------------------------------------------------------------------
# _norm_list
# --------------------------------------------------------------------------

def test_norm_list_none_and_empty():
    assert _norm_list(None) == []
    assert _norm_list([]) == []
    assert _norm_list("") == []


def test_norm_list_string_coerced_to_single_element():
    assert _norm_list("Generated") == ["Generated"]


def test_norm_list_dedup_preserves_first_order():
    assert _norm_list(["a", "b", "a", "c", "b"]) == ["a", "b", "c"]


def test_norm_list_lowercasing():
    assert _norm_list(["Foo", "BAR"], lower=True) == ["foo", "bar"]


def test_norm_list_no_lowercasing_by_default():
    assert _norm_list(["Foo", "BAR"]) == ["Foo", "BAR"]


def test_norm_list_strips_surrounding_whitespace():
    assert _norm_list(["  spaced  ", "\tx\t"]) == ["spaced", "x"]


def test_norm_list_strips_leading_and_trailing_slashes():
    # .strip("/\\") removes both forward and backslashes from both ends.
    assert _norm_list(["/foo/", "\\bar\\", "//baz//"]) == ["foo", "bar", "baz"]


def test_norm_list_does_not_strip_interior_slashes():
    assert _norm_list(["tools/codegen"]) == ["tools/codegen"]


def test_norm_list_skips_non_string_elements():
    assert _norm_list(["keep", 123, None, {"x": 1}, "also"]) == ["keep", "also"]


def test_norm_list_drops_elements_that_become_empty_after_strip():
    # "/" strips down to "" and is dropped; whitespace-only too.
    assert _norm_list(["/", "  ", "\\\\", "real"]) == ["real"]


def test_norm_list_dedup_after_lowercasing_collapses_case_variants():
    # Foo and FOO both lower to "foo" -> deduped to one.
    assert _norm_list(["Foo", "FOO", "foo"], lower=True) == ["foo"]


def test_norm_list_strip_then_dedup():
    # "/x/" and "x" both normalize to "x".
    assert _norm_list(["/x/", "x"]) == ["x"]
