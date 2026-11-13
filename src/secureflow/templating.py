"""Shared standalone report templates, independent of Flask request contexts."""

import json

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .config import PACKAGE_ROOT

environment = Environment(
    loader=FileSystemLoader(PACKAGE_ROOT / "templates"),
    autoescape=select_autoescape(["html"]),
)
environment.filters["pretty"] = lambda value: json.dumps(value, ensure_ascii=False, indent=2)


def render_template(name: str, **context) -> str:
    return environment.get_template(name).render(**context)
