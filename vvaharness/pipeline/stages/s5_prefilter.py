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

"""
Step 5 — Deterministic pre-filter.

Runs between s4 deep-dive and s6 verify. Pure Python, no model calls.
Cuts obvious false-positives and trivial duplicates so the expensive
adversarial verifier isn't burned on findings that can be rejected
mechanically:

  - findings outside C/C++ source and header files
  - findings outside the low-level memory-safety classes eligible for ASAN
  - test/mock/example/fixture paths (model ignores the prompt rule ~10%)
  - hallucinated file paths not present in the repo inventory
  - s4 confidence below step5_prefilter.min_pre_confidence (legacy: step6_verify.min_pre_confidence)
  - missing source_ref/sink_ref when step5_prefilter.require_evidence is on (legacy: step6_verify.require_evidence)
  - trivial dups: same file + vuln_class within step7_dedup.line_tolerance
  - SEMANTIC dups (one LLM call) when ≥ step7_dedup.pre_verify_threshold
    findings survive the gates above — collapsing root-cause duplicates here
    avoids paying for N independent verifiers on the same bug in s6

Not checkpointed — the deterministic gates are ~0ms and the optional semantic
call is one cheap dedup-model invocation, both re-run against the loaded s4
checkpoint on --resume.
"""
from __future__ import annotations
import re
import sys
from pathlib import PurePosixPath

from vvaharness.lang.hints import EXT_TO_LANG
from vvaharness.models import ContextPackage, Finding, DroppedFinding, VulnClass
from . import s7_dedup


_EXCLUDE_PATH_RE = re.compile(
    r"(^|/)(tests?|__tests__|mocks?|examples?|fixtures?|samples?|testdata)(/|$)"
    r"|_test\.|\.test\.|\.spec\.|Test\.java$|Tests\.cs$",
    re.IGNORECASE,
)

# Credential-class evidence in the finding text. A committed AWS key, JWT,
# or BEGIN PRIVATE KEY block in tests/fixtures/*.pem is a real production
# risk regardless of where it lives — the file is in source control and
# was likely real once. Findings matching this stay even when the path
# matches _EXCLUDE_PATH_RE.
_SECRET_TEXT_RX = re.compile(
    r"(?i)\b(?:"
    r"hard[\s-]?coded|"
    r"password|passwd|"
    r"api[_-]?key|access[_-]?key|secret[_-]?key|"
    r"auth[_-]?token|bearer\s+token|jwt|"
    r"private[_-]?key|client[_-]?secret|credential"
    r")\b"
    r"|-----BEGIN\s+[A-Z ]*PRIVATE\s+KEY-----"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\bgh[pousr]_[0-9A-Za-z]{36,}\b"
    r"|\bxox[baprs]-[0-9A-Za-z-]{10,}\b"
)

# Stage 5 is intentionally scoped to C/C++ memory-safety findings for now.
# Keep this aligned with the default classes eligible for ASAN verification.
_LOW_LEVEL_MEMORY_CLASSES = frozenset({
    VulnClass.UAF,
    VulnClass.HEAP_OVERFLOW,
    VulnClass.STACK_OVERFLOW,
    VulnClass.FMT_STRING,
    VulnClass.INT_OVERFLOW,
    VulnClass.TYPE_CONFUSION,
})


def _is_c_cpp_file(file: str) -> bool:
    """Return whether *file* has a C/C++ source or header extension."""
    normalized = file.replace("\\", "/")
    suffix = PurePosixPath(normalized).suffix.lower()
    return EXT_TO_LANG.get(suffix) == "c-cpp"


def _is_secret_class(f: Finding) -> bool:
    """True for findings that report committed credentials / hardcoded
    secrets — kept even in test paths because the file is in source control."""
    if f.vuln_class == VulnClass.INFO_LEAK:
        return True
    haystack = " ".join(s for s in (f.title, f.description, f.code_snippet) if s)
    return bool(_SECRET_TEXT_RX.search(haystack))


def _gate(cfg, key: str, default):
    """Read a prefilter gate. Prefers the new `step5_prefilter` section;
    falls back to legacy `step6_verify` for older configs that haven't been
    migrated yet."""
    s5p = getattr(cfg, "step5_prefilter", None)
    if s5p is not None:
        v = getattr(s5p, key, None)
        if v is not None:
            return v
    s6v = getattr(cfg, "step6_verify", None)
    if s6v is not None:
        v = getattr(s6v, key, None)
        if v is not None:
            return v
    return default


def run(findings: list[Finding], ctx: ContextPackage, cfg
        ) -> tuple[list[Finding], list[DroppedFinding]]:
    min_conf = _gate(cfg, "min_pre_confidence", 0.0) or 0.0
    require_evidence = _gate(cfg, "require_evidence", False)

    valid_files = set(ctx.all_files) if ctx.all_files else None
    keep: list[Finding] = []
    dropped: list[DroppedFinding] = []

    def _drop(f: Finding, reason: str, detail: str) -> None:
        dropped.append(DroppedFinding(
            file=f.file, line=f.line_start, vuln_class=f.vuln_class,
            title=f.title, chunk_id=f.chunk_id, reason=reason, detail=detail))

    kept_in_test: list[Finding] = []
    for f in findings:
        in_test_path = bool(_EXCLUDE_PATH_RE.search(f.file))
        secret_class = in_test_path and _is_secret_class(f)
        if not _is_c_cpp_file(f.file):
            _drop(f, "EXCLUDED", "not a C/C++ source or header file")
        elif f.vuln_class not in _LOW_LEVEL_MEMORY_CLASSES:
            _drop(f, "EXCLUDED", "not a low-level memory-safety finding")
        elif in_test_path and not secret_class:
            _drop(f, "EXCLUDED", "test/mock/example path")
        elif valid_files is not None and f.file not in valid_files:
            _drop(f, "EXCLUDED", "file not in repo inventory")
        elif f.confidence < min_conf:
            _drop(f, "UNCONFIRMED",
                  f"s4 confidence {f.confidence:.2f} < gate {min_conf:.2f}")
        elif require_evidence and not ((f.source_ref or "").strip()
                                       and (f.sink_ref or "").strip()):
            _drop(f, "UNCONFIRMED",
                  "missing source_ref/sink_ref — data flow unproven")
        else:
            keep.append(f)
            if secret_class:
                kept_in_test.append(f)

    if kept_in_test:
        shown = ", ".join(f"{f.file}:{f.line_start}" for f in kept_in_test[:5])
        more = (f" (+{len(kept_in_test) - 5} more)"
                if len(kept_in_test) > 5 else "")
        print(f"  [s5-prefilter] kept {len(kept_in_test)} secret-class "
              f"finding(s) in test paths: {shown}{more}", file=sys.stderr)

    s7d = getattr(cfg, "step7_dedup", None)
    line_tol = getattr(s7d, "line_tolerance", 10)
    keep, dup_dropped = s7_dedup.prefilter(keep, line_tol)
    dropped.extend(dup_dropped)

    # ── Semantic dedup BEFORE verify (triage §2b) ────────────────────────
    # One cheap dedup-model call here can save dozens of expensive s6 verifier
    # calls on chatty repos where parallel s4 chunks report the same root cause
    # under different titles/categories. Only fires above the threshold.
    pre_thresh = getattr(s7d, "pre_verify_threshold", 25)
    if (pre_thresh and len(keep) >= pre_thresh
            and getattr(s7d, "semantic", True)):
        print(f"  [s5-prefilter] {len(keep)} survivors ≥ pre_verify_threshold "
              f"{pre_thresh} → running semantic dedup ahead of s6",
              file=sys.stderr)
        keep, sem_dropped = s7_dedup.run(keep, cfg, label="s5-prefilter")
        for d in sem_dropped:
            # canonical_idx points into the *pre-verify* list and would be
            # stale once s6 drops FPs and re-dedups; report reasoning only.
            d.canonical_idx = None
            d.detail = f"pre-verify semantic: {d.detail}"
        dropped.extend(sem_dropped)

    if dropped:
        by: dict[str, int] = {}
        for d in dropped:
            by[d.reason] = by.get(d.reason, 0) + 1
        breakdown = ", ".join(f"{n} {k.lower()}" for k, n in sorted(by.items()))
        print(f"  [s5-prefilter] {len(findings)} → {len(keep)} ({breakdown})",
              file=sys.stderr)
    else:
        print(f"  [s5-prefilter] {len(findings)} → {len(keep)} (nothing dropped)",
              file=sys.stderr)
    return keep, dropped
