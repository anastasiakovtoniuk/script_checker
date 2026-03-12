from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .models import AdvisoryDetail, AdvisoryRef, PackagePin

DEFAULT_API_BASE = "https://api.osv.dev/v1"


class OSVClient:
    def __init__(self, api_base: str = DEFAULT_API_BASE, timeout: int = 20):
        self.api_base = api_base.rstrip("/")
        self.timeout = timeout

    def build_query(self, package: PackagePin, lookup: str = "auto") -> dict[str, Any]:
        lookup_mode = lookup.lower()

        if lookup_mode not in {"auto", "commit", "version"}:
            raise ValueError(f"Unsupported lookup mode: {lookup}")

        if lookup_mode in {"auto", "commit"} and package.revision:
            return {"commit": package.revision}

        if not package.version:
            if package.revision:
                return {"commit": package.revision}
            raise ValueError(f"Package {package.identity} has neither version nor revision.")

        if not package.url:
            raise ValueError(
                f"Package {package.identity} does not have a canonical git URL required by SwiftURL ecosystem."
            )

        return {
            "package": {
                "ecosystem": "SwiftURL",
                "name": package.url,
            },
            "version": package.version,
        }

    def query_batch(self, packages: list[PackagePin], lookup: str = "auto") -> dict[str, list[AdvisoryRef]]:
        payload = {"queries": [self.build_query(package, lookup=lookup) for package in packages]}
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{self.api_base}/querybatch",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                response_data = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"OSV querybatch failed with HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Failed to reach OSV API: {exc}") from exc

        results: dict[str, list[AdvisoryRef]] = {}

        for package, result in zip(packages, response_data.get("results", []), strict=False):
            vulns = result.get("vulns", []) if isinstance(result, dict) else []
            refs: list[AdvisoryRef] = []

            for vuln in vulns:
                if not isinstance(vuln, dict):
                    continue
                vuln_id = vuln.get("id")
                if not isinstance(vuln_id, str):
                    continue
                refs.append(AdvisoryRef(id=vuln_id, modified=vuln.get("modified")))

            results[package.identity] = refs

        return results

    def get_vulnerability(self, vuln_id: str) -> AdvisoryDetail:
        safe_id = urllib.parse.quote(vuln_id, safe="")
        request = urllib.request.Request(
            f"{self.api_base}/vulns/{safe_id}",
            method="GET",
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"OSV vulnerability lookup failed for {vuln_id}: HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Failed to reach OSV API for {vuln_id}: {exc}") from exc

        return AdvisoryDetail(
            id=payload.get("id", vuln_id),
            summary=payload.get("summary"),
            severity=_extract_severity(payload),
            published=payload.get("published"),
            modified=payload.get("modified"),
            aliases=[a for a in payload.get("aliases", []) if isinstance(a, str)],
            fixed_versions=_extract_fixed_versions(payload),
            references=_extract_reference_urls(payload),
            raw=payload,
        )


def _extract_reference_urls(payload: dict[str, Any]) -> list[str]:
    references = payload.get("references", [])
    result: list[str] = []

    for item in references:
        if isinstance(item, dict):
            url = item.get("url")
            if isinstance(url, str):
                result.append(url)

    return result


def _extract_fixed_versions(payload: dict[str, Any]) -> list[str]:
    fixed_versions: set[str] = set()
    affected = payload.get("affected", [])

    for item in affected:
        if not isinstance(item, dict):
            continue
        for range_item in item.get("ranges", []):
            if not isinstance(range_item, dict):
                continue
            for event in range_item.get("events", []):
                if not isinstance(event, dict):
                    continue
                fixed = event.get("fixed")
                if isinstance(fixed, str) and fixed:
                    fixed_versions.add(fixed)

    return sorted(fixed_versions)


def _extract_severity(payload: dict[str, Any]) -> str | None:
    severity_items = payload.get("severity", [])
    for entry in severity_items:
        if not isinstance(entry, dict):
            continue
        score = entry.get("score")
        if isinstance(score, str):
            level = _severity_from_score_string(score)
            if level:
                return level

    database_specific = payload.get("database_specific")
    if isinstance(database_specific, dict):
        level = database_specific.get("severity")
        if isinstance(level, str) and level:
            return level.upper()

    return None


def _severity_from_score_string(score: str) -> str | None:
    text = score.strip().upper()

    for literal in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if literal in text:
            return literal

    try:
        numeric = float(text)
    except ValueError:
        return None

    if numeric >= 9.0:
        return "CRITICAL"
    if numeric >= 7.0:
        return "HIGH"
    if numeric >= 4.0:
        return "MEDIUM"
    return "LOW"
