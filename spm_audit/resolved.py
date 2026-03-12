from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .identifiers import aliases_for_package, normalize_identity, normalize_git_url
from .models import PackagePin


def _extract_pins(document: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(document.get("pins"), list):
        return [p for p in document["pins"] if isinstance(p, dict)]

    object_section = document.get("object")
    if isinstance(object_section, dict) and isinstance(object_section.get("pins"), list):
        return [p for p in object_section["pins"] if isinstance(p, dict)]

    raise ValueError("Unsupported Package.resolved format: missing pins array.")


def _extract_state(pin: dict[str, Any]) -> dict[str, Any]:
    state = pin.get("state")
    if isinstance(state, dict):
        return state

    version = pin.get("version")
    revision = pin.get("revision")
    branch = pin.get("branch")
    fallback = {}
    if version:
        fallback["version"] = version
    if revision:
        fallback["revision"] = revision
    if branch:
        fallback["branch"] = branch
    return fallback


def parse_package_resolved(path: str | Path) -> list[PackagePin]:
    resolved_path = Path(path)

    if not resolved_path.exists():
        raise RuntimeError(f"Package.resolved not found: {resolved_path}")

    if not resolved_path.is_file():
        raise RuntimeError(f"Package.resolved path is not a file: {resolved_path}")

    try:
        payload = json.loads(resolved_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON in Package.resolved: {resolved_path}\n{exc}") from exc

    pins: list[PackagePin] = []

    for pin in _extract_pins(payload):
        state = _extract_state(pin)

        identity = normalize_identity(
            pin.get("identity")
            or pin.get("package")
            or pin.get("location", "").rstrip("/").split("/")[-1].replace(".git", "")
        )
        url = normalize_git_url(pin.get("location") or pin.get("repositoryURL") or pin.get("url"))
        version = state.get("version")
        revision = state.get("revision")
        kind = pin.get("kind") or pin.get("sourceControlURL")

        aliases = aliases_for_package(identity=identity, url=url)
        pins.append(
            PackagePin(
                identity=identity,
                url=url,
                version=version if isinstance(version, str) else None,
                revision=revision if isinstance(revision, str) else None,
                kind=kind if isinstance(kind, str) else None,
                aliases=frozenset(aliases),
            )
        )

    return pins
