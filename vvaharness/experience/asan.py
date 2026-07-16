# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

"""Human-editable, persistent archive of ASAN-confirmed findings."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from vvaharness.experience.fingerprint import finding_fingerprint, repository_fingerprint
from vvaharness.report.redact import redact


_README = """vvaharness ASAN experience archive

Each subdirectory contains one ASAN-confirmed bug:
  active/<fingerprint>/experience.yaml   trusted experience used across scans
  rejected/<fingerprint>/experience.yaml human-rejected experience

The YAML files are deliberately human-editable. Set `active: false` or run
`vvaharness experience remove <fingerprint-prefix>` to reject an entry. Rejected
entries are not recreated by later scans. Run `vvaharness experience restore`
to undo a rejection, and `vvaharness experience validate` after manual edits.

Override this location with VVAHARNESS_EXPERIENCE_DIR.
"""


def _now() -> datetime:
    return datetime.now(timezone.utc)


class AsanObservation(BaseModel):
    model_config = ConfigDict(extra="allow")

    observed_at: datetime = Field(default_factory=_now)
    scan_id: str = ""
    commit_sha: str | None = None
    source_artifact_dir: str = ""
    repro_command: str = ""


class AsanExperience(BaseModel):
    """On-disk contract for one stable ASAN-confirmed bug."""

    model_config = ConfigDict(extra="allow")

    schema_version: int = 1
    id: str
    active: bool = True
    human_notes: str = ""
    rejection_reason: str = ""
    repository: str
    repository_fingerprint: str
    language: str = "unknown"
    vulnerability_class: str
    cwe: str | None = None
    title: str
    file: str
    line_start: int
    line_end: int
    source_ref: str | None = None
    sink_ref: str | None = None
    description: str = ""
    exploit_scenario: str = ""
    asan_summary: str = ""
    repro_command: str = ""
    artifact_path: str = "artifacts"
    first_seen: datetime = Field(default_factory=_now)
    last_seen: datetime = Field(default_factory=_now)
    seen_count: int = 1
    observations: list[AsanObservation] = Field(default_factory=list)


def experience_root() -> Path:
    configured = os.environ.get("VVAHARNESS_EXPERIENCE_DIR")
    return (Path(configured).expanduser() if configured
            else Path.home() / ".vvaharness" / "experience")


def asan_root() -> Path:
    return experience_root() / "asan"


def _initialize() -> Path:
    root = asan_root()
    (root / "active").mkdir(parents=True, exist_ok=True)
    (root / "rejected").mkdir(parents=True, exist_ok=True)
    readme = root / "README.txt"
    if not readme.exists():
        readme.write_text(_README, encoding="utf-8")
    return root


def _yaml_path(directory: Path) -> Path:
    return directory / "experience.yaml"


def _load(directory: Path) -> AsanExperience:
    data = yaml.safe_load(_yaml_path(directory).read_text(encoding="utf-8"))
    return AsanExperience.model_validate(data)


def _write(directory: Path, record: AsanExperience) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    target = _yaml_path(directory)
    tmp = target.with_suffix(".yaml.tmp")
    payload: dict[str, Any] = record.model_dump(mode="json")
    tmp.write_text(yaml.safe_dump(payload, sort_keys=False, allow_unicode=True),
                   encoding="utf-8")
    tmp.replace(target)


def _git_head(repo: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=20,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception:  # noqa: BLE001
        return None


def _repository_identity(repo: Path) -> str:
    """Prefer a stable remote identity, without persisting embedded credentials."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=20,
        )
        remote = result.stdout.strip() if result.returncode == 0 else ""
        if remote:
            return re.sub(r"(?<=://)[^/@]+@", "", remote)
    except Exception:  # noqa: BLE001
        pass
    return str(repo)


def _copy_artifacts(source: Path | None, destination: Path) -> None:
    if source is None or not source.is_dir():
        return
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination, symlinks=True)


def save_verified_bug(finding, ctx, *, scan_id: str) -> Path | None:
    """Persist one finalized ASAN finding. Returns None when human-rejected."""
    repo = Path(ctx.repo_root).resolve()
    repo_identity = _repository_identity(repo)
    repo_fp = repository_fingerprint(repo_identity)
    fp = finding_fingerprint(
        repository=repo_fp,
        vulnerability_class=finding.vuln_class.value,
        cwe=finding.cwe,
        file=finding.file,
        source_ref=finding.source_ref,
        sink_ref=finding.sink_ref,
        excerpt=finding.code_snippet,
    )
    root = _initialize()
    active_dir = root / "active" / fp
    rejected_dir = root / "rejected" / fp
    if rejected_dir.exists():
        return None

    now = _now()
    observation = AsanObservation(
        observed_at=now,
        scan_id=scan_id,
        commit_sha=_git_head(repo),
        source_artifact_dir=(finding.asan_artifacts[0]
                             if finding.asan_artifacts else ""),
        repro_command=redact(finding.asan_repro_command or ""),
    )
    if active_dir.exists():
        record = _load(active_dir)
        if not record.active:  # supports direct human editing of the YAML
            return None
        if any(item.scan_id == scan_id for item in record.observations):
            return active_dir
        record.last_seen = now
        record.seen_count += 1
        record.asan_summary = redact(finding.asan_evidence or "")
        record.repro_command = redact(finding.asan_repro_command or "")
        record.observations = (record.observations + [observation])[-50:]
    else:
        record = AsanExperience(
            id=fp,
            repository=repo_identity,
            repository_fingerprint=repo_fp,
            language=getattr(ctx, "language", "unknown") or "unknown",
            vulnerability_class=finding.vuln_class.value,
            cwe=finding.cwe,
            title=finding.title,
            file=finding.file,
            line_start=finding.line_start,
            line_end=finding.line_end,
            source_ref=finding.source_ref,
            sink_ref=finding.sink_ref,
            description=finding.description,
            exploit_scenario=finding.exploit_scenario,
            asan_summary=redact(finding.asan_evidence or ""),
            repro_command=redact(finding.asan_repro_command or ""),
            first_seen=now,
            last_seen=now,
            observations=[observation],
        )
    artifact_dir = (Path(finding.asan_artifacts[0])
                    if finding.asan_artifacts else None)
    _copy_artifacts(artifact_dir, active_dir / "artifacts")
    _write(active_dir, record)
    return active_dir


def save_completed_scan(report, ctx, *, scan_id: str) -> tuple[list[Path], int]:
    """Commit ASAN experience only from a successfully completed s9 report."""
    saved: list[Path] = []
    rejected = 0
    for ranked in report.findings:
        finding = getattr(ranked, "finding", ranked)
        if getattr(finding, "asan_status", "") != "crash_confirmed":
            continue
        path = save_verified_bug(finding, ctx, scan_id=scan_id)
        if path is None:
            rejected += 1
        else:
            saved.append(path)
    return saved, rejected


def iter_experiences(*, include_rejected: bool = False) -> list[tuple[Path, AsanExperience]]:
    root = _initialize()
    states = ["active", "rejected"] if include_rejected else ["active"]
    records: list[tuple[Path, AsanExperience]] = []
    for state in states:
        for directory in sorted((root / state).iterdir()):
            if directory.is_dir() and _yaml_path(directory).is_file():
                records.append((directory, _load(directory)))
    return records


def resolve_experience(identifier: str, *, include_rejected: bool = True
                       ) -> tuple[Path, AsanExperience]:
    matches = [item for item in iter_experiences(include_rejected=include_rejected)
               if item[1].id.startswith(identifier)]
    if not matches:
        raise KeyError(f"no ASAN experience matches {identifier!r}")
    if len(matches) > 1:
        raise KeyError(f"ASAN experience prefix {identifier!r} is ambiguous")
    return matches[0]


def reject_experience(identifier: str, reason: str = "rejected by human") -> Path:
    path, record = resolve_experience(identifier, include_rejected=False)
    record.active = False
    record.rejection_reason = reason
    destination = _initialize() / "rejected" / record.id
    if destination.exists():
        raise FileExistsError(destination)
    _write(path, record)
    path.replace(destination)
    return destination


def restore_experience(identifier: str) -> Path:
    path, record = resolve_experience(identifier, include_rejected=True)
    if path.parent.name != "rejected":
        return path
    record.active = True
    record.rejection_reason = ""
    destination = _initialize() / "active" / record.id
    if destination.exists():
        raise FileExistsError(destination)
    _write(path, record)
    path.replace(destination)
    return destination


def validate_archive() -> list[str]:
    errors: list[str] = []
    root = _initialize()
    for state in ("active", "rejected"):
        for directory in sorted((root / state).iterdir()):
            if not directory.is_dir():
                continue
            try:
                record = _load(directory)
                if record.id != directory.name:
                    errors.append(f"{directory}: id does not match directory name")
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{directory}: {exc}")
    return errors
