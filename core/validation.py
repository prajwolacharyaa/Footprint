from __future__ import annotations

import re


EMAIL_RE = re.compile(r"^(?=.{3,254}$)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}$", re.I)


def normalize_email(email: str) -> str:
    return email.strip().lower()


def is_valid_email(email: str) -> bool:
    if not EMAIL_RE.fullmatch(email):
        return False
    local, domain = email.rsplit("@", 1)
    return not (
        local.startswith(".")
        or local.endswith(".")
        or ".." in local
        or domain.startswith("-")
        or domain.endswith("-")
        or ".." in domain
    )
