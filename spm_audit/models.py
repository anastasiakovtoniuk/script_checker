from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PackagePin:
    identity: str
    url: str
    version: str | None
    revision: str | None
    kind: str | None = None
    aliases: frozenset[str] = frozenset()

    @property
    def display_name(self) -> str:
        version = self.version or self.revision or "unknown"
        return f"{self.identity}@{version}"


@dataclass(frozen=True)
class AdvisoryRef:
    id: str
    modified: str | None = None


@dataclass
class AdvisoryDetail:
    id: str
    summary: str | None = None
    severity: str | None = None
    published: str | None = None
    modified: str | None = None
    aliases: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    package: PackagePin
    advisory: AdvisoryDetail
    dependency_paths: list[list[str]]
    introduced_by: list[str] = field(default_factory=list)
    is_direct_dependency: bool = False
    remediation_direction: str | None = None
