from __future__ import annotations

from .graph import index_paths, load_graph
from .identifiers import normalize_identity
from .models import Finding
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


def _display_identity(display_name: str) -> str:
    base = display_name.split("@", 1)[0]
    return normalize_identity(base)


def _extract_direct_introducers(package_identity: str, dependency_paths: list[list[str]]) -> tuple[list[str], bool]:
    """
    - список прямих залежностей, через які пакет потрапив у проєкт
    - чи є сам пакет прямою залежністю
    """
    direct_introducers: list[str] = []

    for path in dependency_paths:
        if len(path) >= 2:
            direct_dep = path[1]
        elif len(path) == 1:
            direct_dep = path[0]
        else:
            continue

        if direct_dep not in direct_introducers:
            direct_introducers.append(direct_dep)

    is_direct = any(_display_identity(item) == package_identity for item in direct_introducers)
    return direct_introducers, is_direct


def _build_remediation_direction(
    package_identity: str,
    introduced_by: list[str],
    is_direct_dependency: bool,
    fixed_versions: list[str],
) -> str:
    fixed_hint = ""
    if fixed_versions:
        fixed_hint = f" Безпечні версії/виправлення: {', '.join(fixed_versions)}."

    if is_direct_dependency:
        return (
            f"Пакет є прямою залежністю. "
            f"Рекомендовано оновити, замінити або видалити саме {package_identity}."
            f"{fixed_hint}"
        )

    if not introduced_by:
        return (
            "Не вдалося визначити, яка саме пряма залежність притягнула пакет. "
            "Потрібно додатково перевірити dependency graph."
        )

    if len(introduced_by) == 1:
        return (
            f"Пакет є транзитивною залежністю. "
            f"Він потрапив у проєкт через пряму залежність {introduced_by[0]}. "
            f"Рекомендовано оновити, замінити або прибрати саме цю пряму залежність."
            f"{fixed_hint}"
        )

    return (
        f"Пакет є транзитивною залежністю і потрапляє через кілька прямих залежностей: "
        f"{', '.join(introduced_by)}. "
        f"Рекомендовано перевірити оновлення або заміну саме цих прямих залежностей."
        f"{fixed_hint}"
    )


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

        direct_introducers, is_direct = _extract_direct_introducers(
            package_identity=package.identity,
            dependency_paths=matching_paths,
        )

        for advisory_ref in advisory_refs:
            if advisory_ref.id.upper() in ignore_ids:
                continue

            if fetch_details:
                detail = client.get_vulnerability(advisory_ref.id)
            else:
                from .models import AdvisoryDetail
                detail = AdvisoryDetail(id=advisory_ref.id, modified=advisory_ref.modified)

            remediation_direction = _build_remediation_direction(
                package_identity=package.identity,
                introduced_by=direct_introducers,
                is_direct_dependency=is_direct,
                fixed_versions=detail.fixed_versions,
            )

            findings.append(
                Finding(
                    package=package,
                    advisory=detail,
                    dependency_paths=matching_paths,
                    introduced_by=direct_introducers,
                    is_direct_dependency=is_direct,
                    remediation_direction=remediation_direction,
                )
            )

    findings.sort(key=lambda item: (item.package.identity, item.advisory.id))
    return AuditResult(findings=findings, project_root=project_dir)
