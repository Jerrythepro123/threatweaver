# Copyright 2026 Visa, Inc.
# Licensed under the Apache License, Version 2.0

"""CLI for inspecting and curating persistent ASAN experience."""
from __future__ import annotations

import argparse
import sys

import yaml

from vvaharness.experience.asan import (
    asan_root, iter_experiences, reject_experience, resolve_experience,
    restore_experience, validate_archive,
)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vvaharness experience")
    sub = ap.add_subparsers(dest="action", required=True)
    sub.add_parser("path", help="print the persistent ASAN experience folder")
    ls = sub.add_parser("list", help="list ASAN-confirmed experiences")
    ls.add_argument("--all", action="store_true", help="include rejected entries")
    show = sub.add_parser("show", help="print one experience YAML file")
    show.add_argument("id", help="full id or unique prefix")
    remove = sub.add_parser("remove", help="reject a wrong experience persistently")
    remove.add_argument("id", help="full id or unique prefix")
    remove.add_argument("--reason", default="rejected by human")
    restore = sub.add_parser("restore", help="restore a rejected experience")
    restore.add_argument("id", help="full id or unique prefix")
    sub.add_parser("validate", help="validate manually edited YAML files")
    args = ap.parse_args(argv)

    try:
        if args.action == "path":
            print(asan_root())
        elif args.action == "list":
            records = iter_experiences(include_rejected=args.all)
            if not records:
                print("No ASAN experiences recorded.")
            for path, record in records:
                state = ("active" if record.active and path.parent.name == "active"
                         else "rejected")
                print(f"{record.id[:16]}  {state:<8}  {record.vulnerability_class:<20} "
                      f"{record.file}:{record.line_start}  {record.title}")
        elif args.action == "show":
            path, _ = resolve_experience(args.id)
            print((path / "experience.yaml").read_text(encoding="utf-8"), end="")
        elif args.action == "remove":
            print(reject_experience(args.id, args.reason))
        elif args.action == "restore":
            print(restore_experience(args.id))
        elif args.action == "validate":
            errors = validate_archive()
            if errors:
                for error in errors:
                    print(f"ERROR: {error}", file=sys.stderr)
                return 1
            print(f"Experience archive valid: {asan_root()}")
        return 0
    except (KeyError, FileExistsError, OSError, ValueError, yaml.YAMLError) as exc:
        print(f"experience: {exc}", file=sys.stderr)
        return 2
