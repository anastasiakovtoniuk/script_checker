from __future__ import annotations

import argparse
import os
import sys

from .analyzer import analyze_project
from .reporting import to_json, to_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Audit SwiftPM dependencies from Package.resolved against OSV, "
            "then map vulnerable packages back to dependency paths."
        )
    )
    parser.add_argument(
        "--project-dir",
        default=".",
        help="Directory with Package.swift (default: current dir).",
    )
    parser.add_argument(
        "--resolved",
        default="Package.resolved",
        help="Path to Package.resolved (default: Package.resolved).",
    )
    parser.add_argument(
        "--graph-json",
        help="Optional path to JSON from `swift package show-dependencies --format json`.",
    )
    parser.add_argument(
        "--lookup",
        choices=["auto", "commit", "version"],
        default="auto",
        help="OSV lookup mode. 'auto' prefers commit and falls back to version.",
    )
    parser.add_argument(
        "--api-base",
        default="https://api.osv.dev/v1",
        help="OSV API base URL.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format.",
    )
    parser.add_argument(
        "--ignore-advisory",
        action="append",
        default=[],
        help="Advisory ID to ignore. Repeatable.",
    )
    parser.add_argument(
        "--no-details",
        action="store_true",
        help="Skip GET /v1/vulns/<id> calls and print only advisory ids from querybatch.",
    )
    parser.add_argument(
        "--fail-on-any-vuln",
        action="store_true",
        help="Exit with code 1 when any vulnerability is found.",
    )
    parser.add_argument(
        "--fail-on-severity",
        choices=["low", "medium", "high", "critical"],
        help="Exit with code 1 if a finding of this severity or above is found.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    project_dir = os.path.abspath(args.project_dir)
    resolved_path = os.path.abspath(os.path.join(project_dir, args.resolved))

    try:
        result = analyze_project(
            project_dir=project_dir,
            resolved_path=resolved_path,
            graph_json_path=args.graph_json,
            lookup=args.lookup,
            api_base=args.api_base,
            ignore_ids=set(args.ignore_advisory),
            fetch_details=not args.no_details,
        )
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"UNEXPECTED ERROR: {exc}", file=sys.stderr)
        return 3

    output = to_json(result) if args.format == "json" else to_text(result)
    print(output)

    if args.fail_on_any_vuln and result.has_findings():
        return 1

    if args.fail_on_severity and result.violates_policy(args.fail_on_severity):
        return 1

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
