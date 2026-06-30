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
Data contracts passed between pipeline steps.

Rule: every step receives and emits one of these. No raw dicts cross step
boundaries — that's how you keep the pipeline debuggable when a $50 run dies
at step 3.
"""
from __future__ import annotations
import re
from enum import Enum
from typing import Literal
from pydantic import BaseModel, Field, field_validator

_ATX_HEADING_RX = re.compile(r"^(\s{0,3})#{1,6}[ \t]+(.*)$")
_FENCE_RX = re.compile(r"^\s{0,3}(```|~~~)")


def _demote_md_headings(text):
    if not text:
        return text
    out, in_fence = [], False
    for ln in str(text).splitlines():
        if _FENCE_RX.match(ln):
            in_fence = not in_fence
            out.append(ln)
            continue
        if not in_fence:
            ln = _ATX_HEADING_RX.sub(
                lambda m: f"{m.group(1)}**{m.group(2).rstrip()}**", ln)
        out.append(ln)
    return "\n".join(out)


def _md_cell(text) -> str:
    if text is None:
        return ""
    return (str(text).replace("\r", " ").replace("\n", " ")
            .replace("|", "\\|").strip())


# ─────────────────────────────────────────────────────────────────────────────
# LLM-output coercion helpers
#
# Several fields below are strict Literal[...] / Enum / int types that get
# populated straight from model_validate(LLM-emitted JSON). A single
# off-schema value (e.g. kind="rpc", size="tiny", risk_rank="high") used to
# kill the whole run. Every such field now carries a `field_validator(
# mode="before")` that maps common synonyms to a valid member and falls back
# to a safe default — so the pipeline degrades instead of crashing,
# regardless of which backend (cli/sdk/openai) produced the JSON.
# ─────────────────────────────────────────────────────────────────────────────

def _norm(v) -> str:
    return str(v or "").strip().lower().replace("-", "_").replace(" ", "_")


def _coerce_enum(v, valid: set[str], alias: dict[str, str], default: str) -> str:
    raw = str(v or "").strip()
    if raw in valid:                       # exact (case-preserving) hit
        return raw
    k = _norm(v)
    if k in valid:
        return k
    return alias.get(k, default)


def _coerce_int(v, default: int = 0) -> int:
    if isinstance(v, bool):                # bool ⊂ int in Python; reject
        return default
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        # NaN / ±Infinity are not convertible to int — int(float('nan'))
        # raises ValueError and int(float('inf')) raises OverflowError,
        # which would violate this helper's "never crash" contract.
        if v != v or v in (float("inf"), float("-inf")):
            return default
        return int(v)
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def _coerce_confidence(v, default: float = 0.5) -> float:
    """
    Crash-proof float coercion for the strict Finding.confidence field
    (Field(ge=0.0, le=1.0)). An off-schema LLM value (e.g. "high", 95,
    NaN, null) used to fail validation and silently drop the whole
    finding at s4. Map common shapes to [0.0, 1.0] and clamp; fall back
    to `default` for anything uninterpretable — so the finding survives
    with a neutral confidence instead of vanishing.
    """
    if isinstance(v, bool):                # bool ⊂ int; treat as no signal
        return default
    if isinstance(v, (int, float)):
        f = float(v)
    else:
        s = str(v if v is not None else "").strip().rstrip("%").strip()
        try:
            f = float(s)
        except (TypeError, ValueError):
            return default
    if f != f or f in (float("inf"), float("-inf")):   # NaN / ±Inf
        return default
    if 2.0 <= f <= 10.0 and f == int(f):
        f = f / 10.0
    elif 2.0 <= f <= 100.0:
        f = f / 100.0
    return min(1.0, max(0.0, f))


# ─────────────────────────────────────────────────────────────────────────────
# Injected context (loaded once, threaded through every step)
# ─────────────────────────────────────────────────────────────────────────────

class CVE(BaseModel):
    id: str                          # CVE-2024-1234
    summary: str
    affected_files: list[str] = []   # if known
    cvss: float | None = None
    patched: bool = False


_CONTROL_KINDS = {"auth", "sandbox", "input-validation", "aslr", "cfi", "other"}
_CONTROL_KIND_ALIAS = {
    "authn": "auth", "authentication": "auth", "authz": "auth",
    "authorization": "auth", "rbac": "auth", "iam": "auth", "sso": "auth",
    "waf": "input-validation", "validation": "input-validation",
    "input_validation": "input-validation", "sanitization": "input-validation",
    "sanitisation": "input-validation", "encoding": "input-validation",
    "seccomp": "sandbox", "container": "sandbox", "isolation": "sandbox",
    "chroot": "sandbox", "jail": "sandbox",
}


class Control(BaseModel):
    """Design-level mitigation. The strategist/chain LLM uses these to downrank exploitability."""
    name: str                        # "auth-gateway", "wasm-sandbox"
    kind: Literal["auth", "sandbox", "input-validation", "aslr", "cfi", "other"]
    protects: list[str] = []         # file globs or module names behind this control
    notes: str = ""

    @field_validator("kind", mode="before")
    @classmethod
    def _v_kind(cls, v):
        return _coerce_enum(v, _CONTROL_KINDS, _CONTROL_KIND_ALIAS, "other")


class AppProfile(BaseModel):
    """CMDB-derived deployment context for the application under scan.
    Built once from report.enrich.lookup_app() and threaded into s1/s2/s6 so
    threat-model actor selection and CVSS environmental scoring agree."""
    application_id: str
    name: str = ""
    externally_facing: bool = False
    pci_scoped: bool = False
    processes_pan: bool = False
    pii: bool = False
    source: str = ""                 # "application" | "component->parent NNN" | …

    def to_prompt_block(self) -> str:
        sens = []
        if self.pci_scoped:   sens.append("PCI-scoped")
        if self.processes_pan: sens.append("processes PAN")
        if self.pii:          sens.append("handles PII")
        return (
            "CMDB APPLICATION PROFILE:\n"
            f"  - Application ID: {self.application_id}\n"
            f"  - Name: {self.name or '(unnamed)'}\n"
            f"  - Externally facing: {'YES' if self.externally_facing else 'NO'}\n"
            f"  - Data sensitivity: {', '.join(sens) or 'standard'}\n"
            f"  - Source: {self.source}\n"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Step 2 output: ThreatModel  (application-level, code-independent)
# ─────────────────────────────────────────────────────────────────────────────

_SENSITIVITY = {"low", "medium", "high", "critical"}
_SENSITIVITY_ALIAS = {
    "none": "low", "info": "low", "informational": "low", "minor": "low",
    "moderate": "medium", "med": "medium", "normal": "medium",
    "major": "high", "severe": "high", "important": "high",
    "crit": "critical", "blocker": "critical", "extreme": "critical",
}


class Asset(BaseModel):
    name: str
    description: str = ""
    sensitivity: Literal["low", "medium", "high", "critical"] = "medium"

    @field_validator("sensitivity", mode="before")
    @classmethod
    def _v_sensitivity(cls, v):
        return _coerce_enum(v, _SENSITIVITY, _SENSITIVITY_ALIAS, "medium")


class TrustBoundary(BaseModel):
    entry_point: str
    crossing: str                    # "unauth network → application logic"
    reachable_assets: list[str] = []


_ACTORS = {"remote_unauth", "remote_auth", "adjacent_network",
           "local_user", "local_admin", "supply_chain", "insider"}
_ACTOR_ALIAS = {
    "external": "remote_unauth", "anonymous": "remote_unauth",
    "unauthenticated": "remote_unauth", "internet": "remote_unauth",
    "public": "remote_unauth", "attacker": "remote_unauth",
    "authenticated": "remote_auth", "user": "remote_auth",
    "tenant": "remote_auth", "customer": "remote_auth",
    "internal": "adjacent_network", "network": "adjacent_network",
    "lan": "adjacent_network", "adjacent": "adjacent_network",
    "local": "local_user", "physical": "local_user",
    "admin": "local_admin", "root": "local_admin",
    "operator": "local_admin", "privileged": "local_admin",
    "supply": "supply_chain", "dependency": "supply_chain",
    "third_party": "supply_chain", "vendor": "supply_chain",
    "employee": "insider", "developer": "insider", "malicious_insider": "insider",
}
_IMPACTS = {"low", "medium", "high", "critical", "existential"}
_IMPACT_ALIAS = {**_SENSITIVITY_ALIAS,
                 "catastrophic": "existential", "fatal": "existential"}
_LIKELIHOODS = {"very_rare", "rare", "possible", "likely", "almost_certain"}
_LIKELIHOOD_ALIAS = {
    "very_unlikely": "very_rare", "negligible": "very_rare",
    "remote": "very_rare", "improbable": "very_rare",
    "unlikely": "rare", "low": "rare",
    "moderate": "possible", "medium": "possible", "occasional": "possible",
    "probable": "likely", "high": "likely", "frequent": "likely",
    "very_likely": "almost_certain", "certain": "almost_certain",
    "definite": "almost_certain", "inevitable": "almost_certain",
}


class Threat(BaseModel):
    id: str                          # T1, T2, …
    threat: str
    actor: Literal["remote_unauth", "remote_auth", "adjacent_network",
                   "local_user", "local_admin", "supply_chain", "insider"]
    surface: str                     # entry_point name from trust_boundaries
    asset: str
    impact: Literal["low", "medium", "high", "critical", "existential"]
    likelihood: Literal["very_rare", "rare", "possible", "likely", "almost_certain"]
    controls: str = ""
    evidence: str = ""

    @field_validator("actor", mode="before")
    @classmethod
    def _v_actor(cls, v):
        return _coerce_enum(v, _ACTORS, _ACTOR_ALIAS, "remote_auth")

    @field_validator("impact", mode="before")
    @classmethod
    def _v_impact(cls, v):
        return _coerce_enum(v, _IMPACTS, _IMPACT_ALIAS, "medium")

    @field_validator("likelihood", mode="before")
    @classmethod
    def _v_likelihood(cls, v):
        return _coerce_enum(v, _LIKELIHOODS, _LIKELIHOOD_ALIAS, "possible")


class ThreatModel(BaseModel):
    system_context: str = ""
    assets: list[Asset] = []
    trust_boundaries: list[TrustBoundary] = []
    threats: list[Threat] = []
    open_questions: list[str] = []

    def to_prompt_block(self) -> str:
        lines = ["THREAT MODEL:", "", "System context:", self.system_context, ""]
        if self.assets:
            lines.append(f"Assets ({len(self.assets)}):")
            for a in self.assets:
                lines.append(f"  - [{a.sensitivity}] {a.name} — {a.description}")
            lines.append("")
        if self.trust_boundaries:
            lines.append(f"Trust boundaries ({len(self.trust_boundaries)}):")
            for b in self.trust_boundaries:
                ra = ", ".join(b.reachable_assets) or "-"
                lines.append(f"  - {b.entry_point}: {b.crossing} → assets: {ra}")
            lines.append("")
        if self.threats:
            lines.append(f"Ranked threats ({len(self.threats)}):")
            for t in self.threats:
                lines.append(
                    f"  - {t.id} [{t.impact}/{t.likelihood}] {t.threat} "
                    f"(actor={t.actor}, surface={t.surface}, asset={t.asset}"
                    + (f", controls: {t.controls}" if t.controls and t.controls != "none" else "")
                    + ")"
                )
            lines.append("")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Step 1 output: ContextPackage  (preprocess → strategist, NO raw source code)
# ─────────────────────────────────────────────────────────────────────────────

_EP_KINDS = {"network", "ipc", "file", "cli", "deserialization", "other"}
_EP_KIND_ALIAS = {
    "rpc": "network", "grpc": "network", "http": "network",
    "https": "network", "rest": "network", "api": "network",
    "graphql": "network", "websocket": "network", "ws": "network",
    "soap": "network", "tcp": "network", "udp": "network",
    "socket": "network", "webhook": "network", "endpoint": "network",
    "queue": "ipc", "message": "ipc", "mq": "ipc", "kafka": "ipc",
    "amqp": "ipc", "jms": "ipc", "pubsub": "ipc", "event": "ipc",
    "signal": "ipc", "pipe": "ipc", "bus": "ipc",
    "stdin": "cli", "argv": "cli", "command": "cli", "arg": "cli",
    "config": "file", "env": "file", "filesystem": "file", "fs": "file",
    "deserialize": "deserialization", "serde": "deserialization",
    "unmarshal": "deserialization", "parse": "deserialization",
    "pickle": "deserialization", "json": "deserialization",
}


class EntryPoint(BaseModel):
    file: str
    function: str
    kind: Literal["network", "ipc", "file", "cli", "deserialization", "other"]
    reachable_from_unauth: bool = False

    @field_validator("kind", mode="before")
    @classmethod
    def _v_kind(cls, v):
        return _coerce_enum(v, _EP_KINDS, _EP_KIND_ALIAS, "other")


class Sink(BaseModel):
    """Unsafe function call site flagged by static grep."""
    file: str
    line: int = 0
    function: str                    # strcat, memcpy, sprintf, system, ...
    snippet: str = ""                # the offending line, ~120 chars max

    @field_validator("line", mode="before")
    @classmethod
    def _v_line(cls, v):
        return _coerce_int(v, 0)


class ModuleInfo(BaseModel):
    name: str
    files: list[str] = []
    loc: int = 0                     # rough lines of code
    purpose: str = ""                # one-line summary from the mapper

    @field_validator("loc", mode="before")
    @classmethod
    def _v_loc(cls, v):
        return _coerce_int(v, 0)


class ContextPackage(BaseModel):
    repo_root: str
    language: str                    # primary language detected
    call_graph: dict[str, list[str]] = {}     # caller_fqn -> [callee_fqn]
    call_graph_files: dict[str, list[str]] = {}   # fn -> ["file:line", …] (deterministic def-sites from s1 supplement)
    entry_points: list[EntryPoint] = []
    unsafe_sinks: list[Sink] = []
    modules: list[ModuleInfo] = []
    all_files: list[str] = []                 # injected: deterministic repo walk (rel paths)
    excluded: dict = {}                       # injected: {dirs:{path:n}, exts:{ext:n}, globs:{pat:n}, oversize:n}
    known_cves: list[CVE] = []                # injected
    design_controls: list[Control] = []       # injected
    app_profile: AppProfile | None = None     # injected (CMDB)
    threat_model: ThreatModel | None = None   # s2 output, attached to ctx after s2
    notes: str = ""                           # free-form Opus observations

    def to_prompt_block(self) -> str:
        """Compact text representation for the strategist LLM. Never include raw code."""
        lines = [
            f"REPO: {self.repo_root}  LANG: {self.language}",
            "",
            f"MODULES ({len(self.modules)}):",
        ]
        for m in self.modules:
            lines.append(f"  - {m.name} ({m.loc} loc): {m.purpose}")
            for fp in m.files:
                lines.append(f"      • {fp}")
        lines.append("")
        lines.append(f"ALL FILES ({len(self.all_files)}) — every chunk.files entry MUST come from this list:")
        for fp in self.all_files:
            lines.append(f"  - {fp}")
        lines.append("")
        lines.append(f"ENTRY POINTS ({len(self.entry_points)}):")
        for e in self.entry_points:
            unauth = " [UNAUTH-REACHABLE]" if e.reachable_from_unauth else ""
            lines.append(f"  - {e.kind}: {e.function} @ {e.file}{unauth}")
        lines.append("")
        lines.append(f"UNSAFE SINKS ({len(self.unsafe_sinks)}):")
        for s in self.unsafe_sinks:
            lines.append(f"  - {s.function} @ {s.file}:{s.line}")
        lines.append("")
        sigs = self._signatures_block()
        if sigs:
            lines += sigs
            lines.append("")
        if self.call_graph:
            lines += self._call_graph_block()
            lines.append("")
        if self.known_cves:
            lines.append(f"KNOWN CVEs ({len(self.known_cves)}) — DO NOT REDISCOVER:")
            for c in self.known_cves:
                lines.append(f"  - {c.id}: {c.summary}")
            lines.append("")
        if self.design_controls:
            lines.append(f"DESIGN CONTROLS ({len(self.design_controls)}):")
            for c in self.design_controls:
                prot = ", ".join(c.protects) if c.protects else "global"
                lines.append(f"  - [{c.kind}] {c.name} → protects: {prot}")
            lines.append("")
        if self.app_profile:
            lines.append(self.app_profile.to_prompt_block())
            lines.append("")
        if self.threat_model:
            lines.append(self.threat_model.to_prompt_block())
        if self.notes:
            lines.append(f"OPUS NOTES:\n{self.notes}")
        return "\n".join(lines)

    def _call_graph_block(self, max_edges: int = 400) -> list[str]:
        """
        Render call_graph for the s3 strategist. Edges that touch an entry
        point or an unsafe sink are listed first (those are the data-flow
        paths the strategist is told to keep in one chunk); the rest are
        appended up to `max_edges`.
        """
        ep_funcs = {e.function for e in self.entry_points}
        sink_funcs = {s.function for s in self.unsafe_sinks}
        bare = lambda qn: qn.rpartition("::")[2]
        hot, cold = [], []
        for caller, callees in self.call_graph.items():
            uniq = list(dict.fromkeys(c for c in callees if c))
            if not uniq:
                continue
            line = f"  - {caller} -> {', '.join(uniq)}"
            if bare(caller) in ep_funcs or bare(caller) in sink_funcs \
                    or any(bare(c) in sink_funcs or bare(c) in ep_funcs
                           for c in uniq):
                hot.append(line)
            else:
                cold.append(line)
        ordered = hot + cold
        n_total = len(ordered)
        out = [f"CALL GRAPH ({n_total} edges — group caller+callee files in the SAME chunk):"]
        out += ordered[:max_edges]
        if n_total > max_edges:
            out.append(f"  … ({n_total - max_edges} more edges truncated)")
        return out

    def _signatures_block(self, body_lines: int = 3, cap: int = 60) -> list[str]:
        """
        Real code excerpts for entry points and sinks so the s3 strategist can
        see parameter types / annotations / taint shape when deciding which
        files belong together — instead of grouping on filenames alone.
        """
        from pathlib import Path
        root = Path(self.repo_root)
        out = ["SIGNATURES (entry points + sinks — use param types to group "
               "related files into one chunk):"]
        seen: set[tuple[str, int]] = set()

        def _emit(tag: str, file: str, fn: str, hint_line: int) -> None:
            if len(seen) >= cap:
                return
            p = root / file
            try:
                src = p.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                return
            anchor = hint_line - 1 if 0 < hint_line <= len(src) else None
            if anchor is None:
                for i, ln in enumerate(src):
                    if fn and fn in ln and "(" in ln:
                        anchor = i
                        break
            if anchor is None or (file, anchor) in seen:
                return
            seen.add((file, anchor))
            hi = min(len(src), anchor + 1 + body_lines)
            out.append(f"  [{tag}] {file}:{anchor + 1} {fn}()")
            for ln in src[anchor:hi]:
                out.append(f"      {ln.rstrip()[:160]}")

        for e in self.entry_points:
            _emit("ENTRY", e.file, e.function, 0)
        for s in self.unsafe_sinks:
            _emit("SINK", s.file, s.function, s.line)
        if len(seen) >= cap:
            out.append(f"  … (capped at {cap})")
        return out if len(out) > 1 else []


# ─────────────────────────────────────────────────────────────────────────────
# Step 3 output: TaskManifest  (the strategist's prioritized hunt list)
# ─────────────────────────────────────────────────────────────────────────────

class ChunkSize(str, Enum):
    SMALL = "small"      # fits in one context, exhaustive
    MEDIUM = "medium"    # fits, but tight
    LARGE = "large"      # needs sliding window anchored to entry points


_CHUNK_SIZES = {"small", "medium", "large"}
_CHUNK_SIZE_ALIAS = {
    "xs": "small", "tiny": "small", "s": "small",
    "m": "medium", "med": "medium", "moderate": "medium",
    "normal": "medium", "default": "medium",
    "l": "large", "xl": "large", "xxl": "large",
    "big": "large", "huge": "large", "x_large": "large",
}


class Chunk(BaseModel):
    id: str                          # "chunk-01"
    size: ChunkSize = ChunkSize.MEDIUM
    risk_rank: int = 999             # 1 = highest risk, descending
    files: list[str] = []            # files the researcher should load for this chunk
    focus_entry_points: list[str] = []  # function names to anchor sliding window on
    hypothesis: str = ""             # strategist's reasoning: "likely heap overflow via..."
    related_cves: list[str] = []     # variant-hunt seeds
    threat_id: str | None = None     # ThreatModel.threats[].id this chunk tests (coverage metric)
    languages: list[str] = []        # detected from file extensions (s3)
    specialist: str | None = None    # "crypto" | "logic-bug" → repo-wide pass

    @field_validator("size", mode="before")
    @classmethod
    def _v_size(cls, v):
        return _coerce_enum(v, _CHUNK_SIZES, _CHUNK_SIZE_ALIAS, "medium")

    @field_validator("risk_rank", mode="before")
    @classmethod
    def _v_rank(cls, v):
        return _coerce_int(v, 999)


class TaskManifest(BaseModel):
    chunks: list[Chunk]
    rationale: str                   # strategist explains its ranking

    def sorted_chunks(self) -> list[Chunk]:
        return sorted(self.chunks, key=lambda c: c.risk_rank)


# ─────────────────────────────────────────────────────────────────────────────
# Step 4 output: Finding  (Opus deep-dive results, post-intersection)
# ─────────────────────────────────────────────────────────────────────────────

class VulnClass(str, Enum):
    UAF = "use-after-free"
    HEAP_OVERFLOW = "heap-overflow"
    STACK_OVERFLOW = "stack-overflow"
    FMT_STRING = "format-string"
    INT_OVERFLOW = "integer-overflow"
    TYPE_CONFUSION = "type-confusion"
    RACE = "race-condition"
    INJECTION = "injection"
    DESERIALIZATION = "unsafe-deserialization"
    LOGIC = "logic-flaw"
    INFO_LEAK = "info-leak"
    OTHER = "other"


class DupLocation(BaseModel):
    """A finding that was collapsed into a canonical finding during dedup.
    Preserved on `Finding.duplicates` so per-call-site / per-endpoint detail
    isn't lost — the markdown report and SARIF `relatedLocations` surface
    every site that needs remediation, not just the canonical one."""
    file: str
    line_start: int
    line_end: int = 0
    vuln_class: VulnClass
    title: str = ""
    chunk_id: str = ""
    source_ref: str | None = None
    sink_ref: str | None = None
    reasoning: str = ""              # why dedup merged this into the canonical


class Finding(BaseModel):
    chunk_id: str
    file: str
    line_start: int
    line_end: int
    vuln_class: VulnClass
    cwe: str | None = None           # canonical "CWE-79"; set by s4, carried to MD + SARIF taxa
    title: str
    impact: str = ""                 # 2-3 sentences, plain language, business-facing
    description: str
    exploit_scenario: str = ""       # ≤5 sentences: concrete input → impact
    preconditions: list[str] = []    # what must be true for exploitation
    recommendation: str = ""         # security property + specific code change
    code_snippet: str
    source_ref: str | None = None    # "file:line" where untrusted input enters (s4 evidence gate)
    sink_ref: str | None = None      # "file:line" where it is used unsafely
    confidence: float = Field(ge=0.0, le=1.0)
    votes: int = 1                   # set by intersection logic (1..N runs)
    duplicates: list[DupLocation] = []  # call sites collapsed into this canonical by s7_dedup

    @field_validator("confidence", mode="before")
    @classmethod
    def _v_confidence(cls, v):
        return _coerce_confidence(v, 0.5)

    # ── Step 6 adversarial verification (set by s6_verify) ──────────────
    verdict: Literal["TRUE_POSITIVE", "FALSE_POSITIVE"] | None = None
    verdict_confidence: int | None = None     # 0..10
    verdict_reason: str = ""
    cvss_vector: str | None = None            # CVSS:3.1/AV:_/AC:_/...
    cvss_score: float | None = None           # 0.0–10.0, computed from vector
    cvss_rating: str | None = None            # None/Low/Medium/High/Critical (cvss.rating(), CVSS 3.1 bands)
    verifier_reasoning: str = ""              # full verifier output, verbatim

    # ── Post-s7 environmental enrichment (set by pipeline._enrich_findings) ──
    vsvs_vector: str | None = None            # CVSS env vector w/ CR/IR/AR/MAV
    vsvs_score: float | None = None           # 0.0–10.0
    vsvs_rating: str | None = None            # None/Low/Medium/High
    offensive_priority: str | None = None       # P1..P4
    offensive_reason: str = ""

    def canonical_key(self, line_bucket: int = 10) -> tuple:
        """
        Identity for intersection. T=1 jitter means Opus might say line 142
        on run A and line 145 on run B — same bug. Bucket the line number.
        """
        return (self.file, self.line_start // line_bucket, self.vuln_class)


# ─────────────────────────────────────────────────────────────────────────────
# Step 8 output: Final report
# ─────────────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


OFFENSIVE_LABELS: dict[str, str] = {
    "P1": "Externally Exploitable, No Auth",
    "P2": "Externally Exploitable, Obtainable Auth",
    "P3": "Internal Network / Privileged Position",
    "P4": "Code-Knowledge / Insider Dependent",
}


class Chain(BaseModel):
    """Multi-step exploit path that combines several findings."""
    title: str                       # "UAF → arb write → code exec"
    steps: list[int]                 # indices into FinalReport.findings
    severity: Severity
    blocked_by_controls: list[str] = []   # control names that genuinely stop this
    narrative: str


class RankedFinding(BaseModel):
    finding: Finding
    severity: Severity
    exploitability_notes: str        # chain-pass LLM commentary incl. mitigations


class DroppedFinding(BaseModel):
    """Audit-trail entry for a finding removed before the final report."""
    file: str
    line: int
    vuln_class: VulnClass
    title: str
    chunk_id: str
    reason: Literal["FALSE_POSITIVE", "VERIFY_ERROR", "DUPLICATE",
                    "UNCONFIRMED", "EXCLUDED", "GUARDRAIL_BLOCKED"]
    detail: str = ""                 # verdict_reason / error text / dedup reasoning
    canonical_idx: int | None = None # for DUPLICATE: index into FinalReport.findings


class ScopeEntry(BaseModel):
    """One analysis unit (chunk) in the scope appendix."""
    name: str
    kind: Literal["risk", "catchall", "specialist"]
    files: list[str]


class ScanMetrics(BaseModel):
    """Coverage + verification stats rendered at the top of the report."""
    scan_id: str = ""
    module_name: str = ""
    start_ts: str = ""               # ISO 8601
    end_ts: str = ""
    duration_sec: float = 0.0
    total_files_in_scope: int = 0
    analyzed_files_unique: int = 0
    chunks_total: int = 0
    chunks_risk: int = 0
    chunks_catchall: int = 0
    chunks_specialist: int = 0
    # Per-chunk deep-dive outcome tally (default 0 keeps older reports valid).
    chunks_attempted: int = 0
    chunks_failed: int = 0           # failed / timed-out / guardrail-blocked
    errors_by_stage: dict[str, int] = {}   # coarse per-stage error-record counts
    errors_log_path: str = ""              # path to the per-run errors.jsonl
    loc_in_scope_by_language: dict[str, int] = {}
    loc_scanned_by_language: dict[str, int] = {}
    raw_findings_count: int = 0
    true_positive_count: int = 0
    false_positive_count: int = 0
    duplicate_count: int = 0
    # Token accounting (None → render "unavailable")
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    tokens_by_phase: dict[str, dict] | None = None
    # Scope appendix
    folders_scanned: list[str] = []
    scope: list[ScopeEntry] = []
    excluded: dict = {}

    @property
    def coverage_pct(self) -> float:
        if not self.total_files_in_scope:
            return 0.0
        return self.analyzed_files_unique / self.total_files_in_scope * 100

    @property
    def verification_precision_pct(self) -> float:
        if not self.raw_findings_count:
            return 0.0
        return self.true_positive_count / self.raw_findings_count * 100


class FinalReport(BaseModel):
    repo_root: str
    repo_name: str | None = None     # repository_name from repos.txt/csv — used for the report title
    git_sha: str | None = None       # B9: HEAD at scan time; step 10 refuses on mismatch
    findings: list[RankedFinding]
    chains: list[Chain]
    dropped: list[DroppedFinding] = []
    raw_findings_count: int = 0      # pre-verification count
    metrics: ScanMetrics | None = None
    threat_model: ThreatModel | None = None
    app_profile: AppProfile | None = None
    summary: str
    degraded: bool = False
    degraded_reason: str = ""

    def to_markdown(self) -> str:
        tp = len(self.findings)
        fp = sum(1 for d in self.dropped if d.reason == "FALSE_POSITIVE")
        dup = sum(1 for d in self.dropped if d.reason == "DUPLICATE")
        # Undetermined verifications (unparseable reply / guardrail) are NOT
        # confirmed false positives — surface them so a degraded verification
        # pass is visible rather than silently folded into the FP count.
        verr = sum(1 for d in self.dropped
                   if d.reason in ("VERIFY_ERROR", "GUARDRAIL_BLOCKED"))
        precision = (tp / self.raw_findings_count * 100) if self.raw_findings_count else 0.0
        safe_title = re.sub(r"[<>`|\[\]]", "", str(self.repo_name or self.repo_root or ""))
        out = [
            f"# Agentic SAST — {safe_title}",
            "",
            "## Summary",
            _demote_md_headings(self.summary),
            "",
        ]
        if self.metrics:
            out.extend(self._render_metrics())
        out.extend(self._render_scan_health())
        if self.threat_model:
            out.extend(self._render_threat_model())
        out.extend([
            "## Verification",
            f"- Raw findings (pre-verification): {self.raw_findings_count}",
            f"- True positives (verified): {tp}",
            f"- False positives (dropped): {fp}",
            f"- Verifier errors (excluded — undetermined, not confirmed clean): {verr}",
            f"- Duplicates collapsed (all passes): {dup}",
            f"- Verification precision: {precision:.1f}%",
            "",
            f"## Findings ({len(self.findings)})",
            "",
        ])
        for i, rf in enumerate(self.findings, 1):
            f = rf.finding
            if f.cvss_score is not None:
                cvss = f"**{f.cvss_score:.1f}** ({f.cvss_rating}) — `{f.cvss_vector}`"
            elif f.cvss_vector:
                cvss = f"`{f.cvss_vector}`"
            else:
                cvss = "_not computed_"
            from vvaharness.report.cwe import cwe_name, cwe_for
            # Resolve a deterministic CWE: the finding's own token if present,
            # else the VulnClass→CWE fallback (None for unclassified "other").
            _cwe = cwe_for(f.cwe, f.vuln_class)
            _nm = cwe_name(_cwe) if _cwe else ""
            _cwe_label = (f"{_cwe}: {_nm}" if _nm else _cwe) if _cwe else ""
            out.extend([
                f"### {i}. [{rf.severity.value.upper()}] {_md_cell(f.title)}",
                f"**Class:** {_cwe_label or f.vuln_class.value}",
            ])
            if _cwe:
                _n = _cwe.split('-')[-1]
                out.append(
                    f"**CWE:** {_cwe_label} - "
                    f"https://cwe.mitre.org/data/definitions/{_n}.html")
            out.extend([
                f"**File:** `{f.file}:{f.line_start}-{f.line_end}`",
                f"**CVSS 3.1:** {cvss}",
            ])
            if f.vsvs_score is not None:
                out.append(f"**VulContextSeverity:** `{f.vsvs_vector}` - "
                           f"**{f.vsvs_score:.1f} ({f.vsvs_rating})**")
            if f.offensive_priority:
                out.append(f"**OffensivePriority:** **{f.offensive_priority}** - "
                           f"{OFFENSIVE_LABELS.get(f.offensive_priority, '')} | "
                           f"*{f.offensive_reason}*")
            _vote_word = "run" if f.votes == 1 else "runs"
            out.append(f"**Confidence:** {f.confidence:.2f} "
                       f"({f.votes} {_vote_word} agreed)")
            if f.duplicates:
                refs = ", ".join(
                    f"`{d.file}:{d.line_start}"
                    + (f"-{d.line_end}`" if d.line_end and d.line_end != d.line_start
                       else "`")
                    for d in f.duplicates
                )
                out.append(f"**Also at:** {refs}")
            out.append("")
            if f.duplicates:
                out.extend([
                    f"*{len(f.duplicates)} additional call site(s) collapsed "
                    f"during dedup — same root cause; each location needs the "
                    f"same fix applied.*",
                    "",
                ])
            out.extend(["#### Description", _demote_md_headings(f.description), ""])
            if f.impact:
                out.extend(["#### Impact", _demote_md_headings(f.impact), ""])
            if f.exploit_scenario:
                out.extend(["#### Exploit scenario",
                            _demote_md_headings(f.exploit_scenario), ""])
            if f.preconditions:
                out.append("#### Preconditions")
                out.extend(f"- {_md_cell(p)}" for p in f.preconditions)
                out.append("")
            out.extend([
                "```",
                f.code_snippet,
                "```",
                "",
            ])
            if f.recommendation:
                out.extend(["#### How to fix",
                            _demote_md_headings(f.recommendation), ""])
            out.extend([f"**Exploitability:** "
                        f"{_demote_md_headings(rf.exploitability_notes)}", ""])
            if f.verdict:
                out.extend([
                    "#### Adversarial verification",
                    f"**Verdict:** {f.verdict} (confidence: "
                    f"{f.verdict_confidence}/10) — "
                    f"{_demote_md_headings(f.verdict_reason)}",
                    "",
                    _demote_md_headings(f.verifier_reasoning),
                    "",
                ])
        if self.chains:
            out.extend(["## Exploit Chains", ""])
            for c in self.chains:
                steps_str = " → ".join(
                    f"#{idx+1} {_md_cell(self.findings[idx].finding.title)}"
                    for idx in c.steps
                )
                blocked = (
                    f"  \n**Blocked by:** "
                    f"{', '.join(_md_cell(x) for x in c.blocked_by_controls)}"
                    if c.blocked_by_controls else ""
                )
                out.extend([
                    f"### [{c.severity.value.upper()}] {c.title}",
                    f"**Path:** {steps_str}{blocked}",
                    "",
                    _demote_md_headings(c.narrative),
                    "",
                ])
        elif not self.degraded:
            out.extend([
                "## Exploit Chains",
                "",
                "No exploit chains were identified — the findings above are "
                "independent and do not combine into a multi-step path.",
                "",
            ])
        out.extend(["", "## Dropped Findings", ""])
        if self.dropped:
            _tag = {
                "FALSE_POSITIVE":    "FP",
                "UNCONFIRMED":       "UNCONFIRMED",
                "VERIFY_ERROR":      "VERIFY-ERR",
                "EXCLUDED":          "EXCLUDED",
                "GUARDRAIL_BLOCKED": "GUARDRAIL",
            }
            for d in self.dropped:
                if d.reason == "DUPLICATE":
                    tag = (f"DUP of #{d.canonical_idx + 1}"
                           if d.canonical_idx is not None
                           else "DUP (pre-verify)")
                else:
                    tag = _tag.get(d.reason, d.reason)
                out.append(f"- **[{tag}]** `{d.file}:{d.line}` "
                           f"{d.vuln_class.value} ({_md_cell(d.chunk_id)}) — "
                           f"{_md_cell(d.detail)}")
        else:
            out.append("_None._")
        out.append("")
        if self.metrics:
            out.extend(self._render_scope_appendix())
        return "\n".join(out)

    def _render_threat_model(self) -> list[str]:
        tm = self.threat_model
        out = ["## Threat Model", ""]
        if self.app_profile:
            ap = self.app_profile
            sens = ", ".join(s for s, ok in (
                ("PCI-scoped", ap.pci_scoped),
                ("processes PAN", ap.processes_pan),
                ("PII", ap.pii)) if ok) or "standard"
            out.extend([
                "### Application profile (CMDB)",
                # application_id (--application-id) / name / source are operator/CMDB
                # supplied, not tool-derived; escape them so a value with a newline or
                # `|` can't terminate this list/heading and inject Markdown into the
                # report (same neutralisation the rest of this renderer already uses).
                f"- ID: `{_md_cell(ap.application_id)}`  ({_md_cell(ap.name) or '-'})",
                f"- Externally facing: **{'YES' if ap.externally_facing else 'NO'}**",
                f"- Data sensitivity: {sens}",
                f"- Source: {_md_cell(ap.source)}",
                "",
            ])
        if tm.system_context:
            out.extend(["### System context", "",
                        _demote_md_headings(tm.system_context), ""])
        if tm.assets:
            out.extend(["### Assets", "",
                        "| Asset | Sensitivity | Description |",
                        "|---|---|---|"])
            for a in tm.assets:
                out.append(f"| {_md_cell(a.name)} | {_md_cell(a.sensitivity)} "
                           f"| {_md_cell(a.description)} |")
            out.append("")
        if tm.trust_boundaries:
            out.extend(["### Trust boundaries", ""])
            for b in tm.trust_boundaries:
                ra = ", ".join(_md_cell(x) for x in b.reachable_assets) or "-"
                out.append(f"- **{_md_cell(b.entry_point)}** — "
                           f"{_md_cell(b.crossing)} → {ra}")
            out.append("")
        if tm.threats:
            out.extend(["### Ranked threats", "",
                        "| ID | Threat | Actor | Surface | Asset | Impact | Likelihood | Controls |",
                        "|---|---|---|---|---|---|---|---|"])
            for t in tm.threats:
                out.append(f"| {_md_cell(t.id)} | {_md_cell(t.threat)} | "
                           f"{_md_cell(t.actor)} | {_md_cell(t.surface)} | "
                           f"{_md_cell(t.asset)} | {_md_cell(t.impact)} | "
                           f"{_md_cell(t.likelihood)} | "
                           f"{_md_cell(t.controls) or '-'} |")
            out.append("")
        if tm.open_questions:
            out.extend(["### Open questions", ""])
            out.extend(f"- {_md_cell(q)}" for q in tm.open_questions)
            out.append("")
        return out

    def _render_metrics(self) -> list[str]:
        m = self.metrics
        lines = [
            "## Scan Metrics",
            "",
            f"- Scan ID: {m.scan_id}",
            f"- Module: {m.module_name}",
            f"- Start: {m.start_ts}",
            f"- End: {m.end_ts}",
            f"- Duration (sec): {m.duration_sec:.0f}",
            f"- Files in scope: {m.total_files_in_scope}",
            f"- Files analyzed (unique): {m.analyzed_files_unique}",
            f"- Coverage: {m.coverage_pct:.1f}%",
            f"- Chunks: {m.chunks_total} "
            f"(risk={m.chunks_risk}, catch-all={m.chunks_catchall}, "
            f"specialist={m.chunks_specialist})",
            f"- Tokens (prompt): {m.prompt_tokens if m.prompt_tokens is not None else 'unavailable'}",
            f"- Tokens (completion): {m.completion_tokens if m.completion_tokens is not None else 'unavailable'}",
            f"- Tokens (total): {m.total_tokens if m.total_tokens is not None else 'unavailable'}",
            "",
        ]
        if m.folders_scanned:
            lines.append(f"- Folders scanned: {len(m.folders_scanned)}")
        if m.tokens_by_phase:
            lines.extend([
                "### Tokens by Phase",
                "",
                "_Prompt = fresh + cache-write (billable). Cache-read shown "
                "separately, NOT included in totals._",
                "",
                "| Phase | Calls | Prompt | Completion | Total | % | Cache-read (excl.) |",
                "|---|---:|---:|---:|---:|---:|---:|",
            ])
            grand = sum(b["prompt"] + b["completion"]
                        for b in m.tokens_by_phase.values()) or 1
            for ph, b in sorted(m.tokens_by_phase.items(),
                                key=lambda kv: -(kv[1]["prompt"] + kv[1]["completion"])):
                tot = b["prompt"] + b["completion"]
                lines.append(
                    f"| {ph} | {b['calls']} | {b['prompt']:,} | {b['completion']:,} "
                    f"| {tot:,} | {tot / grand * 100:.1f} | {b['cache_read']:,} |"
                )
            lines.append("")
        if m.loc_in_scope_by_language:
            lines.extend([
                "### Language LOC Coverage",
                "",
                "| Language | LOC in scope | LOC scanned | Coverage % |",
                "|---|---:|---:|---:|",
            ])
            for lang, loc_in in sorted(m.loc_in_scope_by_language.items()):
                loc_sc = m.loc_scanned_by_language.get(lang, 0)
                pct = (loc_sc / loc_in * 100) if loc_in else 0.0
                lines.append(f"| {lang} | {loc_in} | {loc_sc} | {pct:.1f} |")
            lines.append("")
        return lines

    def _render_scan_health(self) -> list[str]:
        """Surface deep-dive coverage loss and per-stage errors so a degraded
        run is not silently indistinguishable from a clean one. Renders nothing
        when the scan was healthy (no failed chunks, no logged errors) and the
        chain pass completed — so a clean report carries no noise.

        The chain-degraded banner (set when s8 falls back to the unranked
        report) is rendered here too via `self.degraded`."""
        from pathlib import Path
        m = self.metrics
        lines: list[str] = []
        degraded = getattr(self, "degraded", False)
        failed = m.chunks_failed if m else 0
        errs = (m.errors_by_stage if m else {}) or {}
        if not (degraded or failed or errs):
            return lines
        lines.extend(["## Scan Health", ""])
        if degraded:
            reason = getattr(self, "degraded_reason", "") or \
                "the exploit-chain pass could not be computed; findings are unranked"
            lines.append(f"- ⚠️ **DEGRADED** — {reason}")
        if failed:
            attempted = (m.chunks_attempted or m.chunks_total) if m else 0
            lines.append(f"- ⚠️ Degraded coverage: {failed}/{attempted} deep-dive "
                         "chunk(s) failed or timed out — their findings are "
                         "absent from this report.")
        if errs:
            brk = ", ".join(f"{s}={n}" for s, n in sorted(errs.items()))
            lines.append(f"- Recoverable errors logged by stage: {brk}")
        if m and m.errors_log_path:
            lines.append(f"- Full error log: `{Path(m.errors_log_path).name}`")
        lines.append("")
        return lines

    def _render_scope_appendix(self) -> list[str]:
        m = self.metrics
        out = ["", "---", "", "## Appendix: Scan Scope", ""]

        if m.folders_scanned:
            out.append(f"### Folders scanned ({len(m.folders_scanned)})")
            out.append("")
            for d in m.folders_scanned:
                out.append(f"- `{d}/`")
            out.append("")

        ex = m.excluded or {}
        dd_dropped = (ex.get("config_dedup") or {}).get("dropped") or 0
        if dd_dropped or any(ex.get(k) for k in ("dirs", "exts", "globs",
                                                 "oversize", "symlinks")):
            n_total = (sum((ex.get("dirs") or {}).values())
                       + sum((ex.get("exts") or {}).values())
                       + sum((ex.get("globs") or {}).values())
                       + (ex.get("oversize") or 0)
                       + sum((ex.get("symlinks") or {}).values())
                       + dd_dropped)
            out.append(f"### Excluded from scan ({n_total} files)")
            out.append("")
            if ex.get("dirs"):
                out.append("**Folders** (matched `exclude_dirs`):")
                out.append("")
                for d, n in sorted(ex["dirs"].items(), key=lambda kv: -kv[1]):
                    out.append(f"- `{d}/` — {n} files")
                out.append("")
            if ex.get("exts"):
                out.append("**File types** (matched `exclude_exts`):")
                out.append("")
                for e, n in sorted(ex["exts"].items(), key=lambda kv: -kv[1]):
                    out.append(f"- `*{e}` — {n} files")
                out.append("")
            if ex.get("globs"):
                out.append("**Patterns** (matched `exclude_globs`):")
                out.append("")
                for g, n in sorted(ex["globs"].items(), key=lambda kv: -kv[1]):
                    out.append(f"- `{g}` — {n} files")
                out.append("")
            if ex.get("oversize"):
                out.append(f"**Oversize** (> `max_file_kb`): {ex['oversize']} files")
                out.append("")
                for path, sz in ex.get("oversize_files") or []:
                    out.append(f"- `{path}` — {sz / 1024:.0f} KB")
                if ex.get("oversize_files"):
                    out.append("")
            if ex.get("symlinks"):
                out.append("**Symlinks** (target resolves outside the repo — "
                           "not followed):")
                out.append("")
                for path, n in sorted(ex["symlinks"].items(),
                                      key=lambda kv: -kv[1]):
                    out.append(f"- `{_md_cell(path)}`"
                               + (f" — {n} files" if n != 1 else ""))
                out.append("")
            dd = ex.get("config_dedup") or {}
            if dd.get("dropped"):
                out.append(
                    f"**Config dedup**: {dd['candidates']} config files -> "
                    f"{dd['clusters']} shape-clusters; kept {dd['kept_reps']} "
                    f"representatives + {dd['promoted']} promoted "
                    f"(suspicious value), dropped {dd['dropped']} "
                    f"near-duplicates.")
                out.append("")
                for c in dd.get("top_clusters") or []:
                    out.append(f"- `{c['sample']}` x{c['size']} "
                               f"(kept {len(c['reps'])}, dropped {c['dropped']})")
                if dd.get("promoted_files"):
                    out.append("")
                    out.append("Promoted (suspicious value not present in "
                               "cluster representative):")
                    out.append("")
                    for p, why in dd["promoted_files"]:
                        out.append(f"- `{p}` — `{why}`")
                out.append("")

        return out
