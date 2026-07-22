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

"""Experimental streaming coordinator for stages 4, 5, and stage 6.

The released batch path remains in :mod:`vvaharness.orchestrator.scan`.  This
module is entered only through ``--experimental-streaming-verification``.
"""
from __future__ import annotations

import sys
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass
from queue import SimpleQueue
from threading import BoundedSemaphore, Event, Lock, Thread

from vvaharness.backends import claude_cli as cli
from vvaharness.backends.claude_cli import GuardrailBlocked
from vvaharness.models import ContextPackage, DroppedFinding, Finding
from vvaharness.pipeline.stages import (
    asan_verify, s4_deepdive, s5_prefilter, s6_verify,
)
from vvaharness.report.redact import redact
from vvaharness.util import errlog as _errlog


@dataclass
class StreamResult:
    findings: list[Finding]
    chunk_outcomes: dict[str, str]
    pre_dropped: list[DroppedFinding]
    static_verified: list[Finding]
    static_dropped: list[DroppedFinding]
    verified: list[Finding]
    asan_dropped: list[DroppedFinding]
    submitted: int
    speculative: int


def _finding_label(finding: Finding) -> str:
    title = redact((finding.title or "untitled").replace("\n", " ")).strip()
    if len(title) > 100:
        title = title[:97] + "..."
    return (f"title={title!r} location={finding.file}:{finding.line_start} "
            f"class={finding.vuln_class.value}")


def _audit_state(active: Event) -> str:
    return "running" if active.is_set() else "complete"


def _format_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    minutes, secs = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h{minutes:02d}m{secs:02d}s"
    if minutes:
        return f"{minutes}m{secs:02d}s"
    return f"{secs}s"


def _elapsed(started: float) -> str:
    return _format_duration(time.monotonic() - started)


@contextmanager
def _heartbeat(label: str, audit_active: Event, *, interval: int = 30):
    """Emit progress while a long Codex/build operation is otherwise silent."""
    stopped = Event()
    started = time.monotonic()

    def _run() -> None:
        while not stopped.wait(interval):
            print(f"    [{label}] RUNNING elapsed={_elapsed(started)} "
                  f"audit={_audit_state(audit_active)}",
                  file=sys.stderr, flush=True)

    thread = Thread(target=_run, name=f"{label}-heartbeat", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stopped.set()
        thread.join(timeout=1)


def run(chunks, ctx: ContextPackage, cfg) -> StreamResult:
    """Stream locally admissible s4 candidates into static s6 verification.

    The complete, collapsed s4 result still goes through the normal
    ``s5_prefilter.run`` afterward.  Only futures belonging to that
    authoritative survivor set are accepted; earlier work for cross-chunk or
    semantic duplicates is deliberately speculative.
    """
    parallel = max(1, int(getattr(cfg.step6_verify, "parallel", 4)))
    max_in_flight = max(parallel, parallel * 2)
    slots = BoundedSemaphore(max_in_flight)
    audit_active = Event()
    audit_active.set()
    dispatcher_abort = Event()
    executor = ThreadPoolExecutor(max_workers=parallel,
                                  thread_name_prefix="streaming-verify")
    asan_session = _StreamingAsanSession(ctx, cfg, audit_active)
    asan_executor = (ThreadPoolExecutor(max_workers=1,
                                        thread_name_prefix="streaming-asan")
                     if asan_verify.enabled(cfg) else None)
    submitted: dict[int, tuple[Future, int, Finding]] = {}
    next_index = 0
    candidate_queue: SimpleQueue[object] = SimpleQueue()
    queue_end = object()
    dispatcher_errors: list[BaseException] = []

    def _release(_future: Future) -> None:
        slots.release()

    def _submit(finding: Finding) -> int:
        nonlocal next_index
        identity = id(finding)
        if identity in submitted:
            return submitted[identity][1]
        # Only the dispatcher (and, after it joins, the reconciliation thread)
        # waits for verifier capacity.  s4 workers never call this function.
        while not slots.acquire(timeout=0.2):
            if dispatcher_abort.is_set():
                raise RuntimeError("streaming verifier dispatcher aborted")
        idx = next_index
        next_index += 1
        try:
            future = executor.submit(
                _verify_and_schedule_asan, idx, finding, ctx, cfg,
                asan_executor, asan_session, audit_active)
        except BaseException:
            slots.release()
            raise
        future.add_done_callback(_release)
        submitted[identity] = (future, idx, finding)
        return idx

    def _on_findings(chunk_findings: list[Finding]) -> None:
        # SimpleQueue.put() is nonblocking.  This is the entire s4 callback so
        # verifier latency/capacity can never pause an audit worker.
        candidate_queue.put(chunk_findings)
        for finding in chunk_findings:
            print(f"  [streaming-verification] DISCOVERED "
                  f"{_finding_label(finding)} "
                  f"audit={_audit_state(audit_active)}",
                  file=sys.stderr, flush=True)

    def _dispatch() -> None:
        """Apply local s5 policy and feed s6 independently of s4 workers."""
        try:
            while not dispatcher_abort.is_set():
                batch = candidate_queue.get()
                if batch is queue_end:
                    return
                # Candidate-local gates are safe before the complete s4
                # population is known.  Global dedup remains authoritative.
                eligible, _ = s5_prefilter.policy_filter(
                    batch, ctx, cfg, announce=False)
                for finding in eligible:
                    idx = _submit(finding)
                    print(f"  [streaming-verification] STATIC SUBMITTED "
                          f"bug#{idx + 1} {_finding_label(finding)} "
                          f"audit={_audit_state(audit_active)}",
                          file=sys.stderr, flush=True)
        except BaseException as exc:  # surfaced after the audit producer exits
            dispatcher_errors.append(exc)
            dispatcher_abort.set()

    dispatcher = Thread(target=_dispatch, name="streaming-dispatcher",
                        daemon=True)
    dispatcher.start()

    try:
        try:
            findings, outcomes = s4_deepdive.run(
                chunks, ctx, cfg, on_findings=_on_findings)
        except BaseException:
            dispatcher_abort.set()
            raise
        finally:
            audit_active.clear()
            print("  [streaming-verification] AUDIT COMPLETE; draining static "
                  "and ASAN verification", file=sys.stderr, flush=True)
            candidate_queue.put(queue_end)
            dispatcher.join(timeout=1 if dispatcher_abort.is_set() else None)

        if dispatcher_errors:
            raise dispatcher_errors[0]

        # This is the same full-population s5 operation used by the legacy
        # path.  It can overlap with verifier futures already in flight.
        authoritative, pre_dropped = s5_prefilter.run(findings, ctx, cfg)
        for finding in authoritative:
            _submit(finding)  # belt-and-braces if a future callback changes s4

        selected = {
            future: (idx, finding)
            for finding in authoritative
            for future, idx, _original in [submitted[id(finding)]]
        }
        static_verified, static_dropped, verified, asan_dropped = _collect(
            selected, cfg)
        speculative = len(submitted) - len(selected)
        print(f"  [streaming-verification] static verification complete: "
              f"{len(selected)} authoritative, {speculative} speculative",
              file=sys.stderr)
        return StreamResult(
            findings=findings,
            chunk_outcomes=outcomes,
            pre_dropped=pre_dropped,
            static_verified=static_verified,
            static_dropped=static_dropped,
            verified=verified,
            asan_dropped=asan_dropped,
            submitted=len(submitted),
            speculative=speculative,
        )
    except KeyboardInterrupt:
        cli.abort()
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    except BaseException:
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    finally:
        executor.shutdown(wait=True)
        if asan_executor is not None:
            asan_executor.shutdown(wait=True)


def _verify_and_schedule_asan(idx: int, finding: Finding,
                              ctx: ContextPackage, cfg,
                              asan_executor: ThreadPoolExecutor | None,
                              asan_session: "_StreamingAsanSession",
                              audit_active: Event):
    """Run static verification and immediately continue a TP into ASAN."""
    started = time.monotonic()
    print(f"    [streaming-static] START bug#{idx + 1} "
          f"{_finding_label(finding)} audit={_audit_state(audit_active)}",
          file=sys.stderr, flush=True)
    try:
        result = s6_verify._verify_one(idx, finding, ctx, cfg)
    except BaseException:
        print(f"    [streaming-static] DONE bug#{idx + 1} result=error "
              f"elapsed={_elapsed(started)} audit={_audit_state(audit_active)}",
              file=sys.stderr, flush=True)
        raise
    print(f"    [streaming-static] DONE bug#{idx + 1} "
          f"result={result.verdict} confidence={result.verdict_confidence}/10 "
          f"elapsed={_elapsed(started)} audit={_audit_state(audit_active)}",
          file=sys.stderr, flush=True)
    min_conf = getattr(cfg.step6_verify, "min_confidence", 7)
    asan_future = None
    if (asan_executor is not None
            and result.verdict == "TRUE_POSITIVE"
            and (result.verdict_confidence or 0) >= min_conf):
        if not asan_verify.should_try(result, cfg):
            print(f"    [streaming-verification] ASAN SKIP bug#{idx + 1} "
                  f"reason=class-not-enabled class={result.vuln_class.value} "
                  f"audit={_audit_state(audit_active)}",
                  file=sys.stderr, flush=True)
        else:
            position, build_state, active = asan_session.reserve(idx)
            print(f"    [streaming-verification] ASAN QUEUED bug#{idx + 1} "
                  f"position={position} build={build_state} active={active} "
                  f"{_finding_label(result)} audit={_audit_state(audit_active)}",
                  file=sys.stderr, flush=True)
            asan_future = asan_executor.submit(asan_session.verify, result, idx)
    return result, asan_future


class _StreamingAsanSession:
    """One serialized ASAN build/repro session shared by streamed findings."""

    def __init__(self, ctx: ContextPackage, cfg, audit_active: Event) -> None:
        self.ctx = ctx
        self.cfg = cfg
        self.audit_active = audit_active
        self.build = None
        self.build_state = "pending"
        self.attempted = 0
        self._state_lock = Lock()
        self._waiting = 0
        self._active: int | None = None
        block = getattr(cfg.step6_verify, "asan", None)
        self.require_crash = bool(getattr(block, "require_crash", True))
        raw_limit = getattr(block, "max_findings", "all")
        self.limit = s6_verify._asan_limit(raw_limit, 1_000_000_000)

    def reserve(self, idx: int) -> tuple[int, str, str]:
        with self._state_lock:
            self._waiting += 1
            active = (f"bug#{self._active + 1}"
                      if self._active is not None else "none")
            return self._waiting, self.build_state, active

    def verify(self, finding: Finding, idx: int
               ) -> tuple[Finding | None, DroppedFinding | None]:
        with self._state_lock:
            self._waiting = max(0, self._waiting - 1)
            self._active = idx
        try:
            return self._verify(finding, idx)
        finally:
            with self._state_lock:
                self._active = None

    def _verify(self, finding: Finding, idx: int
                ) -> tuple[Finding | None, DroppedFinding | None]:
        if not asan_verify.should_try(finding, self.cfg):
            print(f"    [streaming-asan] SKIP bug#{idx + 1} "
                  f"reason=class-not-enabled class={finding.vuln_class.value}",
                  file=sys.stderr, flush=True)
            return finding, None
        if self.attempted >= self.limit:
            print(f"    [streaming-asan] SKIP bug#{idx + 1} "
                  "reason=max-findings-budget-exhausted",
                  file=sys.stderr, flush=True)
            if self.require_crash:
                return None, s6_verify._drop(
                    finding, "UNCONFIRMED",
                    "ASAN verification required but per-run ASAN attempt "
                    "budget was exhausted", stage="asan")
            return finding, None

        self.attempted += 1
        bug_idx = self.attempted
        if self.build is None:
            started = time.monotonic()
            with self._state_lock:
                self.build_state = "building"
            print("    [streaming-asan] BUILD START trigger=first-static-tp "
                  f"audit={_audit_state(self.audit_active)}",
                  file=sys.stderr, flush=True)
            with _heartbeat("streaming-asan-build", self.audit_active):
                self.build = asan_verify.build_repo(
                    self.ctx, self.cfg, findings=[finding])
            status = "success" if self.build.succeeded else "failed"
            with self._state_lock:
                self.build_state = status
            print(f"    [streaming-asan] BUILD DONE result={status} "
                  f"elapsed={_elapsed(started)} "
                  f"audit={_audit_state(self.audit_active)}",
                  file=sys.stderr, flush=True)

        if not self.build.succeeded:
            artifacts = ([str(self.build.artifact_dir)]
                         if self.build.artifact_dir is not None else [])
            updated = finding.model_copy(update={
                "asan_status": "no_crash",
                "asan_evidence": self.build.summary,
                "asan_repro_command": "",
                "asan_artifacts": artifacts,
            })
            if self.require_crash:
                return None, s6_verify._drop(
                    updated, "UNCONFIRMED",
                    s6_verify._asan_drop_detail(
                        "ASAN repo build failed; dynamic repro was skipped",
                        self.build.summary), stage="asan")
            return updated, None

        started = time.monotonic()
        print(f"    [streaming-asan] START bug#{idx + 1} attempt={bug_idx} "
              f"{_finding_label(finding)} audit={_audit_state(self.audit_active)}",
              file=sys.stderr, flush=True)
        with _heartbeat(f"streaming-asan-bug#{idx + 1}", self.audit_active):
            result = asan_verify.run(
                finding, self.ctx, self.cfg, idx=bug_idx, build=self.build)
        status = "crash_confirmed" if result.crashed else "no_crash"
        artifacts = ([str(result.artifact_dir)]
                     if result.artifact_dir is not None else [])
        updated = finding.model_copy(update={
            "asan_status": status,
            "asan_evidence": result.summary,
            "asan_repro_command": result.repro_command,
            "asan_artifacts": artifacts,
        })
        print(f"    [streaming-asan] DONE bug#{idx + 1} result={status} "
              f"elapsed={_elapsed(started)} audit={_audit_state(self.audit_active)}",
              file=sys.stderr, flush=True)
        if self.require_crash and not result.crashed:
            return None, s6_verify._drop(
                updated, "UNCONFIRMED",
                s6_verify._asan_drop_detail(
                    "ASAN did not confirm a crash/repro within the per-bug budget",
                    result.summary), stage="asan")
        return updated, None


def _collect(futures: dict[Future, tuple[int, Finding]], cfg
             ) -> tuple[list[Finding], list[DroppedFinding],
                        list[Finding], list[DroppedFinding]]:
    """Apply the legacy static-verifier verdict gates to streamed futures."""
    min_conf = getattr(cfg.step6_verify, "min_confidence", 7)
    parallel = max(1, int(getattr(cfg.step6_verify, "parallel", 4)))
    guardrail_gate = max(3, parallel)
    guardrail_hits = 0
    successes = 0
    static_verified: list[tuple[int, Finding]] = []
    static_dropped: list[tuple[int, DroppedFinding]] = []
    verified: list[tuple[int, Finding]] = []
    asan_dropped: list[tuple[int, DroppedFinding]] = []

    for future in as_completed(futures):
        idx, finding = futures[future]
        try:
            result, asan_future = future.result()
        except GuardrailBlocked as exc:
            guardrail_hits += 1
            _errlog.log("s6-static", f"guardrail#{idx}", exc,
                        file=finding.file, line=finding.line_start)
            static_dropped.append((idx, s6_verify._drop(
                finding, "GUARDRAIL_BLOCKED", str(exc)[:200])))
            if guardrail_hits >= guardrail_gate and successes == 0:
                cli.abort()
                raise RuntimeError(
                    f"s6-static: {guardrail_hits} cumulative guardrail blocks "
                    "with zero successes — aborting run") from exc
            continue
        except Exception as exc:  # noqa: BLE001 - one candidate must not kill scan
            _errlog.log("s6-static", f"#{idx}", exc, file=finding.file,
                        line=finding.line_start,
                        vuln_class=str(finding.vuln_class))
            print(f"    [s6-static] #{idx} verify ERROR: {redact(str(exc))}",
                  file=sys.stderr)
            static_dropped.append((idx, s6_verify._drop(
                finding, "VERIFY_ERROR", str(exc)[:200])))
            continue

        successes += 1
        if (result.verdict == "TRUE_POSITIVE"
                and (result.verdict_confidence or 0) >= min_conf):
            static_verified.append((idx, result))
            if asan_future is None:
                verified.append((idx, result))
            else:
                try:
                    retained, dynamic_drop = asan_future.result()
                except Exception as exc:  # noqa: BLE001
                    asan_dropped.append((idx, s6_verify._drop(
                        result, "VERIFY_ERROR", f"ASAN streaming error: {exc}",
                        stage="asan")))
                else:
                    if retained is not None:
                        verified.append((idx, retained))
                    if dynamic_drop is not None:
                        asan_dropped.append((idx, dynamic_drop))
        elif result.verdict == "TRUE_POSITIVE":
            static_dropped.append((idx, s6_verify._drop(
                result, "UNCONFIRMED",
                f"verifier confidence {result.verdict_confidence}/10 "
                f"below gate {min_conf}")))
        elif (result.verdict_reason == "verifier output unparseable"
              and (result.verdict_confidence or 0) == 0):
            static_dropped.append((idx, s6_verify._drop(
                result, "VERIFY_ERROR", result.verdict_reason)))
        else:
            static_dropped.append((idx, s6_verify._drop(
                result, "FALSE_POSITIVE", result.verdict_reason)))

    # Thread completion order must not leak into s7/report ordering.
    verified.sort(key=lambda item: item[0])
    static_verified.sort(key=lambda item: item[0])
    static_dropped.sort(key=lambda item: item[0])
    asan_dropped.sort(key=lambda item: item[0])
    return (
        [finding for _, finding in static_verified],
        [finding for _, finding in static_dropped],
        [finding for _, finding in verified],
        [finding for _, finding in asan_dropped],
    )
