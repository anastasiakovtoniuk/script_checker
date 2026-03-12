from __future__ import annotations

import re
from urllib.parse import urlparse


def normalize_identity(value: str | None) -> str:
    if not value:
        return ""
    return re.sub(r"\s+", "-", value.strip().lower())


def normalize_git_url(value: str | None) -> str:
    if not value:
        return ""

    raw = value.strip()
    if not raw:
        return ""

    # git@github.com:owner/repo.git -> https://github.com/owner/repo
    if raw.startswith("git@") and ":" in raw:
        user_host, path = raw.split(":", 1)
        host = user_host.split("@", 1)[1]
        raw = f"https://{host}/{path}"

    parsed = urlparse(raw)
    if not parsed.scheme:
        raw = "https://" + raw.lstrip("/")
        parsed = urlparse(raw)

    scheme = parsed.scheme.lower() or "https"
    host = parsed.netloc.lower()
    path = parsed.path.rstrip("/")
    if path.endswith(".git"):
        path = path[:-4]

    return f"{scheme}://{host}{path}"


def url_repo_slug(url: str | None) -> str:
    normalized = normalize_git_url(url)
    if not normalized:
        return ""
    parsed = urlparse(normalized)
    return parsed.path.lstrip("/").lower()


def url_repo_name(url: str | None) -> str:
    slug = url_repo_slug(url)
    if not slug:
        return ""
    return slug.rsplit("/", 1)[-1]


def aliases_for_package(identity: str | None = None, url: str | None = None, name: str | None = None) -> set[str]:
    aliases: set[str] = set()

    for candidate in (identity, name):
        normalized = normalize_identity(candidate)
        if normalized:
            aliases.add(normalized)

    normalized_url = normalize_git_url(url)
    if normalized_url:
        aliases.add(normalized_url)

    slug = url_repo_slug(url)
    if slug:
        aliases.add(slug)

    repo_name = url_repo_name(url)
    if repo_name:
        aliases.add(repo_name)

    return aliases
