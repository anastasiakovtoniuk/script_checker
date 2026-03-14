from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from .identifiers import normalize_swifturl_name
from .models import AdvisoryDetail, AdvisoryRef, PackagePin


class OSVClient:
    def __init__(self, api_base: str = "https://api.osv.dev/v1", timeout: int = 20):
        self.api_base = api_base.rstrip("/")
        self.timeout = timeout

    def build_query(self, package: PackagePin, lookup: str = "auto") -> dict[str, Any]:
        lookup_mode = lookup.lower()

        if lookup_mode not in {"auto", "commit", "version"}:
            raise ValueError(f"Unsupported lookup mode: {lookup}")

        if lookup_mode in {"auto", "version"} and package.version and package.url:
            return {
                "package": {
                    "ecosystem": "SwiftURL",
                    "name": normalize_swifturl_name(package.url),
                },
                "version": package.version,
            }

        if lookup_mode in {"auto", "commit"} and package.revision:
            return {"commit": package.revision}

        raise ValueError(
            f"Package {package.identity} does not have enough data for OSV lookup."
        )

    def query_batch(
        self,
        packages: list[PackagePin],
        lookup: str = "auto",
    ) -> dict[str, list[AdvisoryRef]]:
        queries: list[dict[str, Any]] = []
        indexed_packages: list[PackagePin] = []

        for package in packages:
            try:
                query = self.build_query(package, lookup=lookup)
            except ValueError:
                continue
            queries.append(query)
            indexed_packages.append(package)

        if not queries:
            return {}

        payload = json.dumps({"queries": queries}).encode("utf-8")
        request = urllib.request.Request(
            f"{self.api_base}/querybatch",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Failed to reach OSV API: {exc}") from exc

        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Invalid JSON from OSV API:\n{raw}") from exc

        results = decoded.get("results", [])
        findings: dict[str, list[AdvisoryRef]] = {}

        for package, result in zip(indexed_packages, results):
            vulns = result.get("vulns", []) if isinstance(result, dict) else []
            refs: list[AdvisoryRef] = []

            for vuln in vulns:
                vuln_id = vuln.get("id")
                if not vuln_id:
                    continue
                refs.append(
                    AdvisoryRef(
                        id=vuln_id,
                        modified=vuln.get("modified"),
                    )
                )

            findings[package.identity] = refs

        return findings

    def get_vulnerability(self, vuln_id: str) -> AdvisoryDetail:
        request = urllib.request.Request(
            f"{self.api_base}/vulns/{vuln_id}",
            headers={"Content-Type": "application/json"},
            method="GET",
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Failed to fetch vulnerability {vuln_id}: {exc}") from exc

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Invalid JSON for vulnerability {vuln_id}:\n{raw}") from exc

        return self._parse_vulnerability(payload)

    def _parse_vulnerability(self, payload: dict[str, Any]) -> AdvisoryDetail:
        severity = self._extract_severity(payload)
        fixed_versions = self._extract_fixed_versions(payload)
        references = self._extract_references(payload)

        return AdvisoryDetail(
            id=payload.get("id", "UNKNOWN"),
            summary=payload.get("summary"),
            severity=severity,
            published=payload.get("published"),
            modified=payload.get("modified"),
            aliases=payload.get("aliases", []) or [],
            fixed_versions=fixed_versions,
            references=references,
            raw=payload,
        )

    def _extract_severity(self, payload: dict[str, Any]) -> str | None:
        database_specific = payload.get("database_specific", {})
        if isinstance(database_specific, dict):
            sev = database_specific.get("severity")
            if isinstance(sev, str) and sev.strip():
                return sev.upper()

        severities = payload.get("severity", [])
        if isinstance(severities, list) and severities:
            first = severities[0]
            if isinstance(first, dict):
                score = first.get("score")
                if isinstance(score, str) and score.strip():
                    return score

        return None

    def _extract_fixed_versions(self, payload: dict[str, Any]) -> list[str]:
        fixed: list[str] = []

        for affected in payload.get("affected", []) or []:
            if not isinstance(affected, dict):
                continue

            ranges = affected.get("ranges", []) or []
            for item in ranges:
                if not isinstance(item, dict):
                    continue
                for event in item.get("events", []) or []:
                    if not isinstance(event, dict):
                        continue
                    fixed_version = event.get("fixed")
                    if isinstance(fixed_version, str) and fixed_version not in fixed:
                        fixed.append(fixed_version)

        return fixed

    def _extract_references(self, payload: dict[str, Any]) -> list[str]:
        refs: list[str] = []

        for ref in payload.get("references", []) or []:
            if not isinstance(ref, dict):
                continue
            url = ref.get("url")
            if isinstance(url, str) and url not in refs:
                refs.append(url)

        return refs
