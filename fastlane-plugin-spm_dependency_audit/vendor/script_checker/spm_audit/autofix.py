from __future__ import annotations

import re
import shutil
import tempfile
from pathlib import Path

from .models import FixApplicationResult, FixCandidate, Finding


def _strip_version_suffix(value: str) -> str:
    return value.split("@", 1)[0].strip()


def build_fix_candidate(finding: Finding) -> FixCandidate:
    if not finding.is_direct_dependency:
        target = _strip_version_suffix(finding.introduced_by[0]) if finding.introduced_by else finding.package.identity
        return FixCandidate(
            target_dependency=target,
            suggested_version=None,
            strategy="direct-only",
            supported=False,
            note="MVP-режим автофіксу підтримує лише прямі залежності.",
        )

    if not finding.advisory.fixed_versions:
        return FixCandidate(
            target_dependency=finding.package.identity,
            suggested_version=None,
            strategy="direct-only",
            supported=False,
            note="Для advisory не знайдено безпечної версії, тому автофікс пропущено.",
        )

    return FixCandidate(
        target_dependency=finding.package.identity,
        suggested_version=finding.advisory.fixed_versions[0],
        strategy="replace-version-in-package-swift",
        supported=True,
        note="Залежність є прямою, тому можна автоматично спробувати оновити її у тимчасовій копії проєкту.",
    )


def _make_temp_copy(project_dir: str) -> Path:
    tmp_root = Path(tempfile.mkdtemp(prefix="spm-autofix-"))
    workdir = tmp_root / "project"
    shutil.copytree(
        project_dir,
        workdir,
        ignore=shutil.ignore_patterns(
            ".git",
            ".build",
            ".swiftpm",
            "__pycache__",
            "*.pyc",
            "deps.json",
            "report.json",
            "bad.json",
        ),
    )
    return workdir


def _patch_package_swift(package_swift_path: Path, dependency_name: str, new_version: str) -> bool:
    text = package_swift_path.read_text(encoding="utf-8")
    pattern = re.compile(
        rf'(\.package\(\s*url:\s*"[^"]*{re.escape(dependency_name)}(?:\.git)?",\s*(?:exact|from)\s*:\s*")([^"]+)("\s*\))'
    )

    new_text, count = pattern.subn(rf"\g<1>{new_version}\g<3>", text, count=1)
    if count == 0:
        return False

    package_swift_path.write_text(new_text, encoding="utf-8")
    return True


def apply_fix_in_temp_copy(project_dir: str, candidate: FixCandidate) -> FixApplicationResult:
    if not candidate.supported or not candidate.suggested_version:
        return FixApplicationResult(
            candidate=candidate,
            applied=False,
            temp_project_dir=None,
            note=candidate.note,
        )

    workdir = _make_temp_copy(project_dir)
    package_swift_path = workdir / "Package.swift"

    if not package_swift_path.exists():
        return FixApplicationResult(
            candidate=candidate,
            applied=False,
            temp_project_dir=str(workdir),
            note="У тимчасовій копії не знайдено Package.swift.",
        )

    patched = _patch_package_swift(
        package_swift_path=package_swift_path,
        dependency_name=candidate.target_dependency,
        new_version=candidate.suggested_version,
    )

    if not patched:
        return FixApplicationResult(
            candidate=candidate,
            applied=False,
            temp_project_dir=str(workdir),
            note=(
                f"Не вдалося автоматично змінити залежність {candidate.target_dependency} у Package.swift. "
                f"MVP підтримує лише записи з url + exact/from."
            ),
        )

    return FixApplicationResult(
        candidate=candidate,
        applied=True,
        temp_project_dir=str(workdir),
        note=(
            f"У тимчасовій копії проєкту залежність {candidate.target_dependency} "
            f"змінено на {candidate.suggested_version}."
        ),
    )
