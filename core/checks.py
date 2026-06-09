from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import quote_plus


@dataclass(frozen=True)
class PlatformCheck:
    name: str
    url: str
    kind: str = "status"
    found_statuses: tuple[int, ...] = (200,)
    not_found_statuses: tuple[int, ...] = (404,)
    headers: dict[str, str] = field(default_factory=dict)
    category: str = "Account"
    notes: str = ""


PLATFORM_CHECKS = [
    PlatformCheck(
        name="Gravatar",
        url="https://www.gravatar.com/{md5}.json",
        kind="gravatar_profile",
        category="Profile",
        notes="Public Gravatar profile, if enabled by the account owner.",
    ),
    PlatformCheck(
        name="Gravatar Avatar",
        url="https://www.gravatar.com/avatar/{md5}?d=404",
        category="Profile Picture",
        notes="Public avatar signal for the email hash.",
    ),
    PlatformCheck(
        name="Libravatar",
        url="https://seccdn.libravatar.org/avatar/{md5}?d=404",
        category="Profile Picture",
        notes="Public Libravatar avatar signal.",
    ),
    PlatformCheck(
        name="GitHub Public Commits",
        url="https://api.github.com/search/commits?q=author-email:{email_url}",
        kind="github_commit_search",
        headers={"Accept": "application/vnd.github.cloak-preview+json"},
        category="Developer",
        notes="Public commits authored with this email.",
    ),
]


def build_context(email: str, local: str, domain: str, md5_hash: str) -> dict[str, str]:
    return {
        "email": email,
        "email_url": quote_plus(email),
        "local": local,
        "domain": domain,
        "md5": md5_hash,
    }
