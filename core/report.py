from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape


def generate_report(data: dict[str, Any], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    env = Environment(
        loader=FileSystemLoader(Path(__file__).resolve().parent.parent / "templates"),
        autoescape=select_autoescape(["html"]),
    )
    report = output_dir / f"{data['email']}.html"
    report.write_text(env.get_template("report.html").render(**data), encoding="utf-8")
    return report
