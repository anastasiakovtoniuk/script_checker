from __future__ import annotations

import argparse
import os
import sys

from .analyzer import analyze_project
from .autofix import apply_fix_in_temp_copy, build_fix_candidate
from .autoverify import verify_fix
from .reporting import to_json, to_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SwiftPM dependency vulnerability audit via OSV")
    parser.add_argument("--project-dir", default=".", help="Шлях до кореня SwiftPM-проєкту")
    parser.add_argument("--resolved", default="Package.resolved", help="Шлях до Package.resolved відносно project-dir")
    parser.add_argument("--graph-json", default=None, help="Готовий JSON з swift package show-dependencies")
    parser.add_argument("--lookup", default="auto", choices=["auto", "version", "commit"])
    parser.add_argument("--api-base", default="https://api.osv.dev/v1")
    parser.add_argument("--format", default="text", choices=["text", "json"])
    parser.add_argument("--fail-on-any-vuln", action="store_true")
    parser.add_argument("--fail-on-severity", default=None)
    parser.add_argument("--ignore-advisory", action="append", default=[])
    parser.add_argument("--no-details", action="store_true")

    parser.add_argument("--auto-fix", action="store_true", help="Спробувати автофікс для прямих залежностей")
    parser.add_argument("--keep-temp-copy", action="store_true", help="Не видаляти тимчасову копію після auto-verify")

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

        if args.auto_fix:
            for finding in result.findings:
                candidate = build_fix_candidate(finding)
                finding.fix_candidate = candidate

                application = apply_fix_in_temp_copy(project_dir, candidate)
                verification = verify_fix(
                    application=application,
                    original_finding=finding,
                    lookup=args.lookup,
                    api_base=args.api_base,
                    ignore_ids=set(args.ignore_advisory),
                    fetch_details=not args.no_details,
                    keep_temp_copy=args.keep_temp_copy,
                )
                finding.verification = verification

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
