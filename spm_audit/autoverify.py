from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .analyzer import analyze_project
from .models import FixApplicationResult, Finding, VerificationResult


def _run_command(args: list[str], cwd: Path) -> tuple[bool, str]:
    result = subprocess.run(
        args,
        cwd=cwd,
        text=True,
        capture_output=True,
    )
    output = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
    return result.returncode == 0, output


def verify_fix(
    application: FixApplicationResult,
    original_finding: Finding,
    lookup: str,
    api_base: str,
    ignore_ids: set[str] | None = None,
    fetch_details: bool = True,
    keep_temp_copy: bool = False,
) -> VerificationResult:
    ignore_ids = ignore_ids or set()

    if not application.applied or not application.temp_project_dir:
        return VerificationResult(
            attempted=False,
            resolve_success=False,
            vulnerability_removed=False,
            verified_safe=False,
            temp_project_dir=None,
            output="",
            note=application.note or "Auto-fix не було застосовано.",
        )

    workdir = Path(application.temp_project_dir)

    resolve_ok, resolve_output = _run_command(["swift", "package", "resolve"], cwd=workdir)
    if not resolve_ok:
        if not keep_temp_copy:
            shutil.rmtree(workdir.parent, ignore_errors=True)

        return VerificationResult(
            attempted=True,
            resolve_success=False,
            vulnerability_removed=False,
            verified_safe=False,
            temp_project_dir=str(workdir) if keep_temp_copy else None,
            output=resolve_output,
            note="swift package resolve завершився з помилкою. Запропонований автофікс несумісний.",
        )

    graph_ok, graph_output = _run_command(
        ["swift", "package", "show-dependencies", "--format", "json"],
        cwd=workdir,
    )
    if not graph_ok:
        if not keep_temp_copy:
            shutil.rmtree(workdir.parent, ignore_errors=True)

        return VerificationResult(
            attempted=True,
            resolve_success=True,
            vulnerability_removed=False,
            verified_safe=False,
            temp_project_dir=str(workdir) if keep_temp_copy else None,
            output=graph_output,
            note="Не вдалося побудувати dependency graph після автофіксу.",
        )

    deps_path = workdir / "deps.autoverify.json"
    deps_path.write_text(graph_output, encoding="utf-8")

    rerun = analyze_project(
        project_dir=str(workdir),
        resolved_path=str(workdir / "Package.resolved"),
        graph_json_path=str(deps_path),
        lookup=lookup,
        api_base=api_base,
        ignore_ids=ignore_ids,
        fetch_details=fetch_details,
    )

    still_present = any(
        item.package.identity == original_finding.package.identity
        and item.advisory.id.upper() == original_finding.advisory.id.upper()
        for item in rerun.findings
    )

    note = (
        "Після автофіксу вразливість більше не відтворюється."
        if not still_present
        else "Після автофіксу вразливість все ще присутня."
    )

    result = VerificationResult(
        attempted=True,
        resolve_success=True,
        vulnerability_removed=not still_present,
        verified_safe=not still_present,
        temp_project_dir=str(workdir) if keep_temp_copy else None,
        output=resolve_output,
        note=note,
    )

    if not keep_temp_copy:
        shutil.rmtree(workdir.parent, ignore_errors=True)

    return result
