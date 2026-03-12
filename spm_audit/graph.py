from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from .identifiers import aliases_for_package, normalize_identity


def run_swift_show_dependencies(project_dir: str) -> dict[str, Any]:
    cmd = ["swift", "package", "show-dependencies", "--format", "json"]
    try:
        proc = subprocess.run(
            cmd,
            cwd=project_dir,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        print(
            "ERROR: 'swift' command not found in PATH. Install Swift toolchain first.",
            file=sys.stderr,
        )
        raise SystemExit(127)

    if proc.returncode != 0:
        print("ERROR: Failed to run `swift package show-dependencies`.", file=sys.stderr)
        if proc.stderr.strip():
            print(proc.stderr, file=sys.stderr)
        raise SystemExit(proc.returncode)

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        print("ERROR: Could not parse JSON from `swift package show-dependencies`.", file=sys.stderr)
        print(str(exc), file=sys.stderr)
        raise SystemExit(2)


def load_graph(project_dir: str, json_path: str | None = None) -> dict[str, Any]:
    if json_path:
        graph_path = Path(json_path)
        if not graph_path.exists():
            raise RuntimeError(f"Dependency graph JSON not found: {graph_path}")
        if not graph_path.is_file():
            raise RuntimeError(f"Dependency graph path is not a file: {graph_path}")

        try:
            return json.loads(graph_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Invalid JSON in dependency graph: {graph_path}\n{exc}") from exc

    return run_swift_show_dependencies(project_dir)

def get_children(node: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("dependencies", "deps", "children"):
        value = node.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def node_display(node: dict[str, Any]) -> str:
    name = (
        node.get("name")
        or node.get("identity")
        or node.get("package")
        or "unknown"
    )
    if not isinstance(name, str):
        name = "unknown"

    version = (
        node.get("version")
        or node.get("revision")
        or (node.get("state") or {}).get("version")
        or (node.get("state") or {}).get("revision")
    )
    if isinstance(version, str) and version:
        return f"{normalize_identity(name)}@{version}"

    return normalize_identity(name)


def node_aliases(node: dict[str, Any]) -> set[str]:
    name = node.get("name") if isinstance(node.get("name"), str) else None
    identity = node.get("identity") if isinstance(node.get("identity"), str) else None
    package = node.get("package") if isinstance(node.get("package"), str) else None
    url = node.get("url") if isinstance(node.get("url"), str) else None

    aliases = aliases_for_package(
        identity=identity or package or name,
        url=url,
        name=name,
    )

    if not aliases and name:
        aliases.add(normalize_identity(name))

    return aliases


def index_paths(root: dict[str, Any]) -> dict[str, list[list[str]]]:
    indexed: dict[str, list[list[str]]] = {}

    def visit(node: dict[str, Any], stack: list[str], seen: set[int]) -> None:
        current_display = node_display(node)
        current_path = stack + [current_display]

        for alias in node_aliases(node):
            indexed.setdefault(alias, [])
            if current_path not in indexed[alias]:
                indexed[alias].append(current_path)

        next_seen = set(seen)
        next_seen.add(id(node))

        for child in get_children(node):
            if id(child) in next_seen:
                continue
            visit(child, current_path, next_seen)

    visit(root, [], set())
    return indexed
