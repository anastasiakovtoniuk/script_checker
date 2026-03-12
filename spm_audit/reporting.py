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
        if finding.advisory.references:
            blocks.append("Refs:      " + ", ".join(finding.advisory.references[:3]))

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
            }
            for finding in result.findings
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
