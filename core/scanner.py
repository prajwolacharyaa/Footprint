from __future__ import annotations

import hashlib
import random
import socket
import time
from datetime import datetime, timezone
from typing import Any

import requests

from core.checks import PLATFORM_CHECKS, PlatformCheck, build_context
from core.integrations import run_holehe, run_sherlock
from core.validation import normalize_email


USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15",
]


class FootprintScanner:
    def __init__(self, timeout: int = 10, delay: tuple[float, float] = (0.2, 0.8)) -> None:
        self.timeout = timeout
        self.delay = delay
        self.session = requests.Session()

    def scan(self, email: str) -> dict[str, Any]:
        email = normalize_email(email)
        local, domain = email.rsplit("@", 1)
        md5_hash = hashlib.md5(email.encode()).hexdigest()
        context = build_context(email, local, domain, md5_hash)

        platforms: list[dict[str, Any]] = []
        names: list[dict[str, str]] = []
        usernames = self._username_candidates(local)
        links: list[dict[str, str]] = []
        profile_pictures: list[dict[str, str]] = []
        dates: list[dict[str, str]] = []

        for check in PLATFORM_CHECKS:
            result = self._check_platform(check, context)
            platforms.append(result)
            names.extend(result.pop("_names", []))
            usernames.extend(result.pop("_usernames", []))
            links.extend(result.pop("_links", []))
            profile_pictures.extend(result.pop("_pictures", []))
            dates.extend(result.pop("_dates", []))

        domain_intel = self._domain_intelligence(domain)
        external_tools = [run_holehe(email).__dict__, run_sherlock(local).__dict__]
        self._merge_external_findings(external_tools, platforms, links)

        return {
            "email": email,
            "scan_time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "profile": {
                "display": email,
                "username": local,
                "domain": domain,
                "email_hash_md5": md5_hash,
                "risk_note": self._risk_note(platforms, domain_intel),
            },
            "summary": {
                "accounts": sum(1 for p in platforms if p["status"] == "found"),
                "usernames": len(self._dedupe(usernames, "value")),
                "links": len(self._dedupe(links, "url")),
                "pictures": len(self._dedupe(profile_pictures, "url")),
                "domain_signals": len(domain_intel),
            },
            "names": self._dedupe(names, "value"),
            "usernames": self._dedupe(usernames, "value"),
            "locations": self._locations_from_domain(domain),
            "dates": dates,
            "links": self._dedupe(links, "url"),
            "profile_pictures": self._dedupe(profile_pictures, "url"),
            "platforms": platforms,
            "domain_intel": domain_intel,
            "external_tools": external_tools,
        }

    def _check_platform(self, check: PlatformCheck, context: dict[str, str]) -> dict[str, Any]:
        url = check.url.format(**context)
        headers = {"User-Agent": random.choice(USER_AGENTS), **check.headers}
        try:
            response = self.session.get(url, headers=headers, timeout=self.timeout, allow_redirects=True)
            time.sleep(random.uniform(*self.delay))
        except requests.RequestException as exc:
            return {
                "name": check.name,
                "category": check.category,
                "status": "error",
                "detail": f"Request failed: {exc.__class__.__name__}",
                "url": url,
                "notes": check.notes,
            }

        result: dict[str, Any] = {
            "name": check.name,
            "category": check.category,
            "status": self._status(response.status_code, check),
            "detail": f"HTTP {response.status_code}",
            "url": url,
            "notes": check.notes,
        }

        if check.kind == "github_commit_search":
            self._parse_github(response, result)
        elif check.kind == "gravatar_profile":
            self._parse_gravatar(response, result, context["md5"])

        return result

    @staticmethod
    def _status(status_code: int, check: PlatformCheck) -> str:
        if status_code in check.found_statuses:
            return "found"
        if status_code in check.not_found_statuses:
            return "not_found"
        return "unknown"

    @staticmethod
    def _parse_github(response: requests.Response, result: dict[str, Any]) -> None:
        try:
            payload = response.json()
        except requests.JSONDecodeError:
            result["status"] = "unknown"
            result["detail"] = "Invalid JSON response"
            return
        count = int(payload.get("total_count", 0))
        result["status"] = "found" if count else "not_found"
        result["detail"] = f"{count} public commit signal(s)"
        result["_dates"] = []
        result["_links"] = []
        for item in payload.get("items", [])[:5]:
            html_url = item.get("html_url")
            date = item.get("commit", {}).get("author", {}).get("date")
            if html_url:
                result["_links"].append({"label": "GitHub commit", "url": html_url, "source": "GitHub"})
            if date:
                result["_dates"].append({"label": "GitHub commit date", "value": date, "source": "GitHub"})

    @staticmethod
    def _parse_gravatar(response: requests.Response, result: dict[str, Any], md5_hash: str) -> None:
        if response.status_code != 200:
            result["status"] = "not_found" if response.status_code == 404 else "unknown"
            result["detail"] = f"HTTP {response.status_code}"
            return
        try:
            entry = response.json().get("entry", [{}])[0]
        except (requests.JSONDecodeError, IndexError, AttributeError):
            result["status"] = "unknown"
            result["detail"] = "Could not parse Gravatar profile"
            return
        result["status"] = "found"
        result["detail"] = "Public Gravatar profile found"
        result["_names"] = []
        result["_usernames"] = []
        result["_links"] = []
        result["_pictures"] = []
        if entry.get("displayName"):
            result["_names"].append({"value": entry["displayName"], "source": "Gravatar"})
        if entry.get("preferredUsername"):
            result["_usernames"].append({"value": entry["preferredUsername"], "source": "Gravatar"})
        if entry.get("thumbnailUrl"):
            result["_pictures"].append({"url": entry["thumbnailUrl"], "source": "Gravatar"})
        for account in entry.get("accounts", []):
            url = account.get("url")
            username = account.get("shortname") or account.get("username")
            if url:
                result["_links"].append({"label": account.get("name", "Gravatar account"), "url": url, "source": "Gravatar"})
            if username:
                result["_usernames"].append({"value": username, "source": "Gravatar"})
        result["_links"].append({"label": "Gravatar profile", "url": f"https://gravatar.com/{md5_hash}", "source": "Gravatar"})

    @staticmethod
    def _username_candidates(local: str) -> list[dict[str, str]]:
        candidates = {local, local.replace(".", ""), local.replace("_", ""), local.split(".")[0], local.split("_")[0]}
        return [{"value": item, "source": "Email local-part"} for item in sorted(item for item in candidates if item)]

    @staticmethod
    def _domain_intelligence(domain: str) -> list[dict[str, str]]:
        rows = []
        try:
            addresses = sorted({item[4][0] for item in socket.getaddrinfo(domain, None)})
        except socket.gaierror:
            addresses = []
        rows.append({
            "label": "Domain",
            "value": domain,
            "detail": "Email domain extracted from target.",
        })
        rows.append({
            "label": "DNS Address Records",
            "value": ", ".join(addresses[:5]) if addresses else "Not resolved",
            "detail": "Public DNS A/AAAA resolution from local resolver.",
        })
        return rows

    @staticmethod
    def _locations_from_domain(domain: str) -> list[dict[str, str]]:
        tld = domain.rsplit(".", 1)[-1]
        if len(tld) == 2:
            return [{"value": f"Country-code TLD: .{tld}", "source": "Domain"}]
        return []

    @staticmethod
    def _merge_external_findings(external_tools: list[dict[str, Any]], platforms: list[dict[str, Any]], links: list[dict[str, str]]) -> None:
        for tool in external_tools:
            for item in tool.get("parsed") or []:
                if item["type"] == "profile_link":
                    links.append({"label": "Profile", "url": item["value"], "source": item["source"]})
                elif item["type"] == "registered_account":
                    platforms.append({
                        "name": item["value"],
                        "category": item["source"],
                        "status": "found",
                        "detail": "External tool account signal",
                        "url": "",
                        "notes": "Parsed from external tool output.",
                    })

    @staticmethod
    def _risk_note(platforms: list[dict[str, Any]], domain_intel: list[dict[str, str]]) -> str:
        found = sum(1 for item in platforms if item["status"] == "found")
        if found >= 3:
            return "Multiple public signals found. Review exposure and account reuse."
        if found:
            return "Some public signals found. Verify whether they belong to the target."
        if any(item["value"] == "Not resolved" for item in domain_intel):
            return "Domain did not resolve. Check whether the email address is mistyped."
        return "Limited public signals found from passive checks."

    @staticmethod
    def _dedupe(rows: list[dict[str, str]], key: str) -> list[dict[str, str]]:
        seen = set()
        output = []
        for row in rows:
            value = row.get(key, "")
            if value and value not in seen:
                seen.add(value)
                output.append(row)
        return output
