from __future__ import annotations

import json

from .analyzer import AuditResult


def to_text(result: AuditResult) -> str:
    if not result.findings:
        return "No known vulnerabilities found in Package.resolved."

    blocks: list[str] = []

    for finding in result.findings:
        blocks.append("=" * 88)
        blocks.append(f"Package:   {finding.package.display_name}")
        blocks.append(f"Source:    {finding.package.url or 'unknown'}")
        blocks.append(f"Advisory:  {finding.advisory.id}")

        if finding.advisory.severity:
            blocks.append(f"Severity:  {finding.advisory.severity}")
        if finding.advisory.summary:
            blocks.append(f"Summary:   {finding.advisory.summary}")
        if finding.advisory.fixed_versions:
            blocks.append("Fixed in:  " + ", ".join(finding.advisory.fixed_versions))

        if finding.is_direct_dependency:
            blocks.append("Cause:     Пакет є прямою залежністю проєкту.")
        elif finding.introduced_by:
            blocks.append("Cause:     Пакет є транзитивною залежністю.")
            blocks.append("Introduced by: " + ", ".join(finding.introduced_by))
        else:
            blocks.append("Cause:     Не вдалося точно визначити пряму залежність-джерело.")

        if finding.remediation_direction:
            blocks.append(f"Fix:       {finding.remediation_direction}")

        if finding.fix_candidate:
            blocks.append(
                f"Auto-fix candidate: target={finding.fix_candidate.target_dependency}, "
                f"version={finding.fix_candidate.suggested_version}, "
                f"supported={finding.fix_candidate.supported}"
            )
            blocks.append(f"Auto-fix note: {finding.fix_candidate.note}")

        if finding.verification:
            blocks.append(
                f"Auto-verify: attempted={finding.verification.attempted}, "
                f"resolve_success={finding.verification.resolve_success}, "
                f"verified_safe={finding.verification.verified_safe}"
            )
            blocks.append(f"Auto-verify note: {finding.verification.note}")
            if finding.verification.temp_project_dir:
                blocks.append(f"Temp copy:  {finding.verification.temp_project_dir}")

        blocks.append("Paths:")
        for path in finding.dependency_paths:
            blocks.append("  - " + " -> ".join(path))

    blocks.append("=" * 88)
    blocks.append(f"Total findings: {len(result.findings)}")
    return "\n".join(blocks)


def to_json(result: AuditResult) -> str:
    payload = {
        "project_root": result.project_root,
        "findings": [
            {
                "package": {
                    "identity": finding.package.identity,
                    "url": finding.package.url,
                    "version": finding.package.version,
                    "revision": finding.package.revision,
                },
                "advisory": {
                    "id": finding.advisory.id,
                    "summary": finding.advisory.summary,
                    "severity": finding.advisory.severity,
                    "published": finding.advisory.published,
                    "modified": finding.advisory.modified,
                    "aliases": finding.advisory.aliases,
                    "fixed_versions": finding.advisory.fixed_versions,
                    "references": finding.advisory.references,
                },
                "dependency_paths": finding.dependency_paths,
                "introduced_by": finding.introduced_by,
                "is_direct_dependency": finding.is_direct_dependency,
                "remediation_direction": finding.remediation_direction,
                "fix_candidate": (
                    {
                        "target_dependency": finding.fix_candidate.target_dependency,
                        "suggested_version": finding.fix_candidate.suggested_version,
                        "strategy": finding.fix_candidate.strategy,
                        "supported": finding.fix_candidate.supported,
                        "note": finding.fix_candidate.note,
                    }
                    if finding.fix_candidate
                    else None
                ),
                "verification": (
                    {
                        "attempted": finding.verification.attempted,
                        "resolve_success": finding.verification.resolve_success,
                        "vulnerability_removed": finding.verification.vulnerability_removed,
                        "verified_safe": finding.verification.verified_safe,
                        "temp_project_dir": finding.verification.temp_project_dir,
                        "output": finding.verification.output,
                        "note": finding.verification.note,
                    }
                    if finding.verification
                    else None
                ),
            }
            for finding in result.findings
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
