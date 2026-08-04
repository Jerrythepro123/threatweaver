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


class _StreamProgress:
    """Atomic aggregate progress lines for the overlapping s4/s5/s6 pipeline."""

    def __init__(self, audit_active: Event) -> None:
        self.audit_active = audit_active
        self.started = time.monotonic()
        self.lock = Lock()
        self.static_queued = 0
        self.static_running = 0
        self.static_completed = 0
        self.asan_queued = 0
        self.asan_running = 0
        self.asan_completed = 0

    def static_submit(self) -> None:
        with self.lock:
            self.static_queued += 1
            self._static("submitted")

    def static_cancel(self) -> None:
        with self.lock:
            self.static_queued = max(0, self.static_queued - 1)
            self._static("submit_failed")

    def static_start(self) -> None:
        with self.lock:
            self.static_queued = max(0, self.static_queued - 1)
            self.static_running += 1
            self._static("started")

    def static_done(self) -> None:
        with self.lock:
            self.static_running = max(0, self.static_running - 1)
            self.static_completed += 1
            self._static("completed")

    def _static(self, event: str) -> None:
        print(f"  [s6-progress] STATIC event={event} "
              f"queued={self.static_queued} running={self.static_running} "
              f"completed={self.static_completed} elapsed={_elapsed(self.started)} "
              f"audit={_audit_state(self.audit_active)}",
              file=sys.stderr, flush=True)

    def asan_queue(self) -> None:
        with self.lock:
            self.asan_queued += 1
            self._asan("queued")

    def asan_start(self) -> None:
        with self.lock:
            self.asan_queued = max(0, self.asan_queued - 1)
            self.asan_running += 1
            self._asan("started")

    def asan_done(self) -> None:
        with self.lock:
            self.asan_running = max(0, self.asan_running - 1)
            self.asan_completed += 1
            self._asan("completed")

    def _asan(self, event: str) -> None:
        print(f"  [s6-progress] ASAN event={event} queued={self.asan_queued} "
              f"running={self.asan_running} completed={self.asan_completed} "
              f"elapsed={_elapsed(self.started)} "
              f"audit={_audit_state(self.audit_active)}",
              file=sys.stderr, flush=True)

    def finish(self, *, findings: int, static_confirmed: int,
               static_dropped: int, dynamic_confirmed: int,
               asan_dropped: int, asan_enabled: bool) -> None:
        with self.lock:
            static_completed = static_confirmed + static_dropped
            asan_completed = dynamic_confirmed + asan_dropped
            print("  [s6-progress] DONE scope=authoritative "
                  f"static_completed={static_completed} "
                  f"static_tp={static_confirmed} "
                  f"static_dropped={static_dropped} "
                  f"asan_completed={asan_completed} "
                  f"asan={'enabled' if asan_enabled else 'disabled'} "
                  f"elapsed={_elapsed(self.started)}",
                  file=sys.stderr, flush=True)
            print(f"  [stage456-progress] DONE scope=authoritative "
                  f"findings={findings} "
                  f"static_confirmed={static_confirmed} "
                  f"dynamic_confirmed={dynamic_confirmed} "
                  f"asan={'enabled' if asan_enabled else 'disabled'} "
                  f"elapsed={_elapsed(self.started)}",
                  file=sys.stderr, flush=True)


def run(chunks, ctx: ContextPackage, cfg) -> StreamResult:
    """Stream each completed s4 batch through s5 policy and into s6.

    The callback from s4 only enqueues work, so verifier backpressure cannot
    occupy an audit worker.  The full-population s5 pass at the end performs
    cross-chunk deduplication and selects the results retained for reporting;
    it does not delay static or ASAN verification startup.
    """
    parallel = max(1, int(getattr(cfg.step6_verify, "parallel", 4)))
    max_in_flight = max(parallel, parallel * 2)
    slots = BoundedSemaphore(max_in_flight)
    audit_active = Event()
    audit_active.set()
    progress = _StreamProgress(audit_active)
    dispatcher_abort = Event()
    executor = ThreadPoolExecutor(max_workers=parallel,
                                  thread_name_prefix="streaming-verify")
    asan_session = _StreamingAsanSession(ctx, cfg, audit_active, progress)
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
        while not slots.acquire(timeout=0.2):
            if dispatcher_abort.is_set():
                raise RuntimeError("streaming verifier dispatcher aborted")
        idx = next_index
        next_index += 1
        progress.static_submit()
        try:
            future = executor.submit(
                _verify_and_schedule_asan, idx, finding, ctx, cfg,
                asan_executor, asan_session, audit_active, progress)
        except BaseException:
            progress.static_cancel()
            slots.release()
            raise
        future.add_done_callback(_release)
        submitted[identity] = (future, idx, finding)
        return idx

    def _on_findings(chunk_findings: list[Finding]) -> None:
        candidate_queue.put(chunk_findings)

    def _dispatch() -> None:
        """Make s4+s5 one streaming producer for the s6 consumers."""
        try:
            while not dispatcher_abort.is_set():
                batch = candidate_queue.get()
                if batch is queue_end:
                    return
                eligible, _ = s5_prefilter.policy_filter(
                    batch, ctx, cfg, announce=False)
                for finding in eligible:
                    _submit(finding)
        except BaseException as exc:
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

        # Global s5 dedup reconciles already-running work but never gates the
        # start of s6.  Candidate-local policy has already run before submit.
        authoritative, pre_dropped = s5_prefilter.run(findings, ctx, cfg)
        for finding in authoritative:
            _submit(finding)

        selected = {
            future: (idx, finding)
            for finding in authoritative
            for future, idx, _original in [submitted[id(finding)]]
        }
        static_verified, static_dropped, verified, asan_dropped = _collect(
            selected, cfg)
        for finding in static_verified:
            print("  [streaming-verification] AUTHORITATIVE STATIC "
                  f"{_finding_label(finding)} "
                  f"confidence={finding.verdict_confidence}/10",
                  file=sys.stderr, flush=True)
        progress.finish(
            findings=len(findings),
            static_confirmed=len(static_verified),
            static_dropped=len(static_dropped),
            dynamic_confirmed=sum(
                finding.asan_status == "crash_confirmed"
                for finding in verified),
            asan_dropped=len(asan_dropped),
            asan_enabled=asan_executor is not None,
        )
        reconciled = len(submitted) - len(selected)
        print(f"  [streaming-verification] static verification complete: "
              f"{len(selected)} authoritative, {reconciled} reconciled by "
              "global s5 dedup",
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
            speculative=reconciled,
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
                              audit_active: Event,
                              progress: _StreamProgress):
    """Run static verification and immediately continue a TP into ASAN."""
    progress.static_start()
    try:
        result = s6_verify._verify_one(idx, finding, ctx, cfg)
    except BaseException:
        progress.static_done()
        raise
    min_conf = getattr(cfg.step6_verify, "min_confidence", 7)
    progress.static_done()
    asan_future = None
    if (asan_executor is not None
            and result.verdict == "TRUE_POSITIVE"
            and (result.verdict_confidence or 0) >= min_conf):
        if asan_verify.should_try(result, cfg):
            asan_session.reserve(idx)
            progress.asan_queue()
            asan_future = asan_executor.submit(asan_session.verify, result, idx)
    return result, asan_future


class _StreamingAsanSession:
    """One serialized ASAN build/repro session shared by streamed findings."""

    def __init__(self, ctx: ContextPackage, cfg, audit_active: Event,
                 progress: _StreamProgress) -> None:
        self.ctx = ctx
        self.cfg = cfg
        self.audit_active = audit_active
        self.progress = progress
        self.build = None
        self.build_state = "pending"
        self.attempted = 0
        self._state_lock = Lock()
        self._waiting = 0
        self._active: int | None = None
        block = getattr(cfg.step6_verify, "asan", None)
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
        self.progress.asan_start()
        try:
            kept, dropped = self._verify(finding, idx)
            return kept, dropped
        finally:
            self.progress.asan_done()
            with self._state_lock:
                self._active = None

    def _verify(self, finding: Finding, idx: int
                ) -> tuple[Finding | None, DroppedFinding | None]:
        if not asan_verify.should_try(finding, self.cfg):
            return None, s6_verify._drop(
                finding, "UNCONFIRMED",
                "ASAN crash required, but the finding is not eligible under "
                "the active ASAN class policy",
                stage="asan")
        if self.attempted >= self.limit:
            return None, s6_verify._drop(
                finding, "UNCONFIRMED",
                "ASAN verification required but per-run ASAN attempt "
                "budget was exhausted", stage="asan")

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
            return None, s6_verify._drop(
                updated, "UNCONFIRMED",
                s6_verify._asan_drop_detail(
                    "ASAN repo build failed; dynamic repro was skipped",
                    self.build.summary), stage="asan")

        with _heartbeat("streaming-asan-verification", self.audit_active):
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
        if not result.crashed:
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
                if asan_verify.enabled(cfg):
                    asan_dropped.append((idx, s6_verify._drop(
                        result, "UNCONFIRMED",
                        "ASAN crash required, but runtime verification was "
                        "not scheduled for this finding",
                        stage="asan")))
                else:
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
