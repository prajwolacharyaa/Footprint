from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class ToolResult:
    name: str
    status: str
    detail: str
    output: str = ""
    parsed: list[dict[str, str]] | None = None


def run_holehe(email: str, timeout: int = 120) -> ToolResult:
    exe = shutil.which("holehe")
    if not exe:
        return ToolResult("Holehe", "skipped", "holehe was not found in PATH.", parsed=[])
    return _run("Holehe", [exe, "--no-color", email], timeout, parse_holehe)


def run_sherlock(username: str, timeout: int = 180) -> ToolResult:
    exe = shutil.which("sherlock")
    if not exe:
        return ToolResult("Sherlock", "skipped", "sherlock was not found in PATH.", parsed=[])
    return _run("Sherlock", [exe, "--no-color", "--timeout", "8", username], timeout, parse_sherlock)


def _run(name: str, command: list[str], timeout: int, parser) -> ToolResult:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return ToolResult(name, "error", f"{name} timed out.", parsed=[])
    except OSError as exc:
        return ToolResult(name, "error", f"{name} failed: {exc}", parsed=[])

    output = "\n".join(part for part in [result.stdout, result.stderr] if part).strip()
    status = "completed" if result.returncode == 0 else "error"
    detail = f"{name} completed." if status == "completed" else f"{name} exited with code {result.returncode}."
    return ToolResult(name, status, detail, output, parser(output))


def parse_holehe(output: str) -> list[dict[str, str]]:
    rows = []
    for line in output.splitlines():
        clean = line.strip()
        if not clean or clean.startswith("[*]"):
            continue
        if "[+]" in clean or "used" in clean.lower():
            rows.append({"type": "registered_account", "source": "Holehe", "value": clean})
        elif "[-]" in clean or "not used" in clean.lower():
            rows.append({"type": "not_registered", "source": "Holehe", "value": clean})
        elif "[x]" in clean or "rate limit" in clean.lower():
            rows.append({"type": "blocked_or_unknown", "source": "Holehe", "value": clean})
    return rows


def parse_sherlock(output: str) -> list[dict[str, str]]:
    rows = []
    url_re = re.compile(r"https?://\S+")
    for line in output.splitlines():
        clean = line.strip()
        match = url_re.search(clean)
        if match:
            rows.append({"type": "profile_link", "source": "Sherlock", "value": match.group(0)})
    return rows
