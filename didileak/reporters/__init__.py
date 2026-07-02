"""Reporters: render a ScanResult to Markdown, JSON, or a self-contained HTML dashboard."""
from didileak.reporters.html import render_html
from didileak.reporters.json_report import render_json
from didileak.reporters.markdown import render_markdown

__all__ = ["render_markdown", "render_json", "render_html"]
