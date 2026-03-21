from __future__ import annotations

from urllib.parse import urlparse


def normalize_identity(value: str | None) -> str:
    if not value:
        return ""
    return value.strip().lower()


def normalize_git_url(value: str | None) -> str:
    if not value:
        return ""
    return value.strip()


def normalize_swifturl_name(value: str | None) -> str:
    if not value:
        return ""

    raw = value.strip().lower()

    if "://" in raw:
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        path = parsed.path or ""
        normalized = f"{host}{path}"
    else:
        normalized = raw

    if normalized.endswith(".git"):
        normalized = normalized[:-4]

    normalized = normalized.rstrip("/")

    return normalized


def aliases_for_package(
    identity: str | None = None,
    url: str | None = None,
    name: str | None = None,
) -> set[str]:
    """
    Підтримує і новий виклик:
        aliases_for_package(identity=..., url=...)
    і старий:
        aliases_for_package(name=..., url=...)
    """
    base_name = identity or name or ""
    aliases = {normalize_identity(base_name)}

    if url:
        aliases.add(normalize_identity(url))
        aliases.add(normalize_identity(url.rstrip("/").split("/")[-1].replace(".git", "")))
        aliases.add(normalize_swifturl_name(url))

    return {item for item in aliases if item}
