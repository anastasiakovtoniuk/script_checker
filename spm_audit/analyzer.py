from __future__ import annotations

from .graph import index_paths, load_graph
from .models import Finding, PackagePin
from .osv_client import OSVClient
from .resolved import parse_package_resolved


SEVERITY_RANK = {
    None: 0,
    "UNKNOWN": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


class AuditResult:
    def __init__(self, findings: list[Finding], project_root: str):
        self.findings = findings
        self.project_root = project_root

    def has_findings(self) -> bool:
        return bool(self.findings)

    def violates_policy(self, min_severity: str | None = None) -> bool:
        if not self.findings:
            return False

        if min_severity is None:
            return True

        target = SEVERITY_RANK.get(min_severity.upper(), 0)
        for finding in self.findings:
            current = SEVERITY_RANK.get((finding.advisory.severity or "UNKNOWN").upper(), 0)
            if current >= target:
                return True

        return False


def analyze_project(
    project_dir: str,
    resolved_path: str,
    graph_json_path: str | None,
    lookup: str,
    api_base: str,
    ignore_ids: set[str] | None = None,
    fetch_details: bool = True,
) -> AuditResult:
    ignore_ids = {item.upper() for item in (ignore_ids or set())}

    packages = parse_package_resolved(resolved_path)
    graph = load_graph(project_dir=project_dir, json_path=graph_json_path)
    path_index = index_paths(graph)

    client = OSVClient(api_base=api_base)
    references_by_package = client.query_batch(packages, lookup=lookup)

    findings: list[Finding] = []

    for package in packages:
        advisory_refs = references_by_package.get(package.identity, [])
        if not advisory_refs:
            continue

        matching_paths = []
        seen_paths = set()
        for alias in package.aliases:
            for path in path_index.get(alias, []):
                path_tuple = tuple(path)
                if path_tuple in seen_paths:
                    continue
                seen_paths.add(path_tuple)
                matching_paths.append(path)

        if not matching_paths:
            matching_paths = [[package.identity]]

        for advisory_ref in advisory_refs:
            if advisory_ref.id.upper() in ignore_ids:
                continue

            if fetch_details:
                detail = client.get_vulnerability(advisory_ref.id)
            else:
                from .models import AdvisoryDetail

                detail = AdvisoryDetail(id=advisory_ref.id, modified=advisory_ref.modified)

            findings.append(
                Finding(
                    package=package,
                    advisory=detail,
                    dependency_paths=matching_paths,
                )
            )

    findings.sort(key=lambda item: (item.package.identity, item.advisory.id))
    return AuditResult(findings=findings, project_root=project_dir)
