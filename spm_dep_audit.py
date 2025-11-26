from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional


def run_swift_show_dependencies(cwd: str) -> Dict[str, Any]:
    cmd = ["swift", "package", "show-dependencies", "--format", "json"]

    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False
        )
    except FileNotFoundError:
        print(
            "ERROR: 'swift' command not found in PATH.\n"
            "Make sure Swift toolchain is installed and available in terminal.",
            file=sys.stderr
        )
        sys.exit(127)

    if proc.returncode != 0:
        print("ERROR: Failed to run `swift package show-dependencies`", file=sys.stderr)
        if proc.stderr.strip():
            print(proc.stderr, file=sys.stderr)
        sys.exit(proc.returncode)

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        print("ERROR: Could not parse JSON from swift output.", file=sys.stderr)
        print(str(e), file=sys.stderr)
        sys.exit(2)


def load_graph(json_path: Optional[str], cwd: str) -> Dict[str, Any]:
    if json_path:
        with open(json_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return run_swift_show_dependencies(cwd)


def get_deps(node: Dict[str, Any]) -> List[Dict[str, Any]]:
    for key in ("dependencies", "deps", "children"):
        val = node.get(key)
        if isinstance(val, list):
            return [d for d in val if isinstance(d, dict)]
    return []


def get_name(node: Dict[str, Any]) -> str:
    for key in ("name", "identity", "package"):
        val = node.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()

    url = node.get("url")
    if isinstance(url, str) and url:
        return url.rstrip("/").split("/")[-1].replace(".git", "")
    return "<unknown>"


def get_version(node: Dict[str, Any]) -> str:
    for key in ("version", "revision", "branch"):
        v = node.get(key)
        if isinstance(v, str) and v:
            return v

    state = node.get("state")
    if isinstance(state, dict):
        for key in ("version", "revision", "branch"):
            v = state.get(key)
            if isinstance(v, str) and v:
                return v

    return "?"


def format_pkg(node: Dict[str, Any]) -> str:
    name = get_name(node)
    version = get_version(node)
    url = node.get("url")
    if isinstance(url, str) and url:
        return f"{name}@{version} ({url})"
    return f"{name}@{version}"


# треба додати ще

def is_problem(node: Dict[str, Any], problem_names: set[str]) -> bool:
    """
    перевірки залежностей (треба подумати)
    """
    return get_name(node) in problem_names


def dfs_paths(
    root: Dict[str, Any],
    problem_names: set[str],
    matches: List[List[Dict[str, Any]]],
    stack: Optional[List[Dict[str, Any]]] = None,
):
    if stack is None:
        stack = []

    stack.append(root)
    stack_ids = {id(n) for n in stack}

    for child in get_deps(root):
        if id(child) in stack_ids:
            continue

        if is_problem(child, problem_names):
            matches.append(stack + [child])

        dfs_paths(child, problem_names, matches, stack)

    stack.pop()


def print_issue(path: List[Dict[str, Any]]):
    problem = path[-1]
    print("\n" + "=" * 80)
    print("PROBLEM DETECTED in dependency:")
    print(f"  {format_pkg(problem)}")
    print("\nDependency chain from your project to the problematic package:")
    for depth, node in enumerate(path):
        indent = "  " * depth
        print(f"{indent}- {format_pkg(node)}")
    print("=" * 80 + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Traverse SwiftPM dependency graph and print full root→...→problem paths."
    )
    ap.add_argument("--json", help="Path to JSON from `swift package show-dependencies --format json`.")
    ap.add_argument("--project-dir", default=".", help="Directory with Package.swift (default: current dir).")
    ap.add_argument("--problem-packages", default="", help="Comma-separated package names to treat as problematic.")
    ap.add_argument("--fail-on-issue", action="store_true", help="Exit non-zero if any issue is found (CI).")

    args = ap.parse_args()
    cwd = os.path.abspath(args.project_dir)
    problem_names = {p.strip() for p in args.problem_packages.split(",") if p.strip()}

    graph = load_graph(args.json, cwd)

    matches: List[List[Dict[str, Any]]] = []
    if is_problem(graph, problem_names):
        matches.append([graph])

    dfs_paths(graph, problem_names, matches)

    if not matches:
        print("No problematic dependencies found.")
        return 0

    for p in matches:
        print_issue(p)

    return 1 if args.fail_on_issue else 0


if __name__ == "__main__":
    raise SystemExit(main())
