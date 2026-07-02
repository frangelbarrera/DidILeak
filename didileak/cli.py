"""didileak CLI - `didileak scan`, `didileak report`, `didileak tui`."""
from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable
from pathlib import Path

from didileak import __version__
from didileak.detectors import DetectorEngine
from didileak.models import Message, ScanResult, Severity
from didileak.parsers import detect_provider, get_parser
from didileak.reporters import render_html, render_json, render_markdown
from didileak.rotation import GUIDE

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    _HAS_RICH = True
except ImportError:  # pragma: no cover
    _HAS_RICH = False


def _console() -> Console | None:
    return Console() if _HAS_RICH else None


# --------------------------------------------------------------------------- #
# Core scan pipeline (reused by CLI, tests, and dashboard backend)
# --------------------------------------------------------------------------- #

def scan_path(path: Path, provider: str | None = None) -> ScanResult:
    """Run the full pipeline against a single export file."""
    if not path.exists():
        raise FileNotFoundError(f"export file not found: {path}")

    # Sniff provider if not specified
    if not provider:
        head = path.read_bytes()[:8192] if path.is_file() else None
        provider = detect_provider(str(path), head)

    parser_cls = get_parser(provider)
    parser = parser_cls(path)
    messages: list[Message] = list(parser.parse())

    engine = DetectorEngine()
    findings = engine.scan(messages)

    return ScanResult(
        source=str(path),
        provider=provider,
        messages_scanned=len(messages),
        conversations_scanned=getattr(parser, "conversation_count", 0),
        findings=findings,
        parser_warnings=parser.warnings,
    )


def scan_many(paths: Iterable[Path], provider: str | None = None) -> list[ScanResult]:
    return [scan_path(p, provider) for p in paths]


# --------------------------------------------------------------------------- #
# CLI commands
# --------------------------------------------------------------------------- #

def _print_summary(result: ScanResult) -> None:
    con = _console()
    if con is None:
        print(f"[didileak] {result.source}: {result.total_findings} findings "
              f"({result.by_severity()})")
        return
    by_sev = result.by_severity()
    con.print()
    con.print(Panel.fit(
        f"[bold]{result.total_findings}[/bold] findings in [bold]{result.messages_scanned}[/bold] messages "
        f"({result.conversations_scanned} conversations) from [bold]{result.provider}[/bold] export",
        title=f"didileak :: {Path(result.source).name}",
        border_style="red",
    ))
    t = Table(show_header=True, header_style="bold", show_lines=False)
    t.add_column("Severity")
    t.add_column("Count", justify="right")
    sev_styles = {
        "critical": "bold red",
        "high": "bold yellow",
        "medium": "yellow",
        "low": "cyan",
        "info": "dim",
    }
    for sev in Severity:
        n = by_sev.get(sev.value, 0)
        if n:
            t.add_row(f"[{sev_styles[sev.value]}]{sev.value}[/]", str(n))
    con.print(t)

    # Top 5 findings preview
    if result.findings:
        top = result.sorted_findings()[:5]
        ft = Table(show_header=True, header_style="bold", title="Top findings (preview)")
        ft.add_column("Sev")
        ft.add_column("Detector")
        ft.add_column("Value", overflow="fold")
        ft.add_column("Conversation", overflow="fold")
        for f in top:
            ft.add_row(
                f"[{sev_styles[f.severity.value]}]{f.severity.value}[/]",
                f.rule_name,
                f.masked_value,
                (f.conversation_title or "")[:60],
            )
        con.print(ft)
        if result.total_findings > 5:
            con.print(f"[dim]...and {result.total_findings - 5} more. "
                      f"Open the HTML dashboard for the full triage.[/]")
    con.print()


def cmd_scan(args: argparse.Namespace) -> int:
    paths = _resolve_paths(args.paths)
    if not paths:
        print("no input files found", file=sys.stderr)
        return 2

    results: list[ScanResult] = []
    for p in paths:
        try:
            r = scan_path(p, args.provider)
        except Exception as e:  # noqa: BLE001
            print(f"[!] failed to scan {p}: {e}", file=sys.stderr)
            continue
        results.append(r)
        _print_summary(r)

        if args.json:
            out = Path(args.json)
            out.write_text(render_json(r), encoding="utf-8")
            print(f"  -> wrote JSON report: {out}")
        if args.markdown:
            out = Path(args.markdown)
            out.write_text(render_markdown(r), encoding="utf-8")
            print(f"  -> wrote Markdown report: {out}")
        if args.html:
            out = Path(args.html)
            out.write_text(render_html(r), encoding="utf-8")
            print(f"  -> wrote HTML dashboard: {out}")

    return 0 if results else 1


def cmd_report(args: argparse.Namespace) -> int:
    """Convenience: scan + render all formats in one shot."""
    paths = _resolve_paths(args.paths)
    if not paths:
        print("no input files found", file=sys.stderr)
        return 2

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    combined_findings = []
    total_msgs = 0
    total_convs = 0
    warnings: list[str] = []
    first_provider: str | None = None
    for p in paths:
        try:
            r = scan_path(p, args.provider)
        except Exception as e:  # noqa: BLE001
            warnings.append(f"failed to scan {p}: {e}")
            continue
        if first_provider is None:
            first_provider = r.provider
        combined_findings.extend(r.findings)
        total_msgs += r.messages_scanned
        total_convs += r.conversations_scanned
        warnings.extend(r.parser_warnings)

    combined = ScanResult(
        source=str(paths[0]) if len(paths) == 1 else f"{len(paths)} files",
        provider="multi" if len(paths) > 1 else (first_provider or "unknown"),
        messages_scanned=total_msgs,
        conversations_scanned=total_convs,
        findings=combined_findings,
        parser_warnings=warnings,
    )

    (outdir / "didileak_report.md").write_text(render_markdown(combined), encoding="utf-8")
    (outdir / "didileak_report.json").write_text(render_json(combined), encoding="utf-8")
    (outdir / "didileak_report.html").write_text(render_html(combined), encoding="utf-8")
    _print_summary(combined)
    print(f"reports written to {outdir}/")
    return 0


def cmd_rotation(args: argparse.Namespace) -> int:
    con = _console()
    if args.rule_id:
        guide = GUIDE.get(args.rule_id)
        if not guide:
            print(f"unknown rule: {args.rule_id}", file=sys.stderr)
            print(f"available rules: {', '.join(sorted(GUIDE.keys()))}", file=sys.stderr)
            return 2
        if con:
            con.print(Panel(guide, title=f"rotation :: {args.rule_id}", border_style="yellow"))
        else:
            print(f"== {args.rule_id} ==\n{guide}")
        return 0

    # List all
    if con:
        t = Table(show_header=True, header_style="bold", title="Rotation guides")
        t.add_column("Rule ID")
        t.add_column("What to do")
        for rid, guide in sorted(GUIDE.items()):
            t.add_row(rid, guide[:120] + ("..." if len(guide) > 120 else ""))
        con.print(t)
    else:
        for rid, guide in sorted(GUIDE.items()):
            print(f"== {rid} ==\n{guide}\n")
    return 0


def cmd_tui(args: argparse.Namespace) -> int:
    try:
        from textual.app import App
        from textual.widgets import DataTable, Footer, Header, Label
    except ImportError:
        print("TUI requires the `tui` extra. Install with: pip install 'didileak[tui]'",
              file=sys.stderr)
        return 2

    paths = _resolve_paths(args.paths)
    if not paths:
        print("no input files found", file=sys.stderr)
        return 2

    results = scan_many(paths, args.provider)
    all_findings = [f for r in results for f in r.findings]

    class SpillageApp(App):  # type: ignore[type-arg]
        TITLE = "didileak"
        BINDINGS = [("q", "quit", "Quit")]

        def compose(self):
            yield Header()
            yield Label(f"{len(all_findings)} findings across {len(results)} file(s)", id="status")
            yield DataTable()
            yield Footer()

        def on_mount(self):
            table = self.query_one(DataTable)
            table.add_columns("Sev", "Rule", "Value", "Conversation", "When")
            sev_w = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
            for f in sorted(all_findings, key=lambda f: -sev_w.get(f.severity.value, 0)):
                table.add_row(
                    f.severity.value,
                    f.rule_name,
                    f.masked_value,
                    (f.conversation_title or "")[:40],
                    str(f.timestamp or ""),
                )

    SpillageApp().run()
    return 0


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _resolve_paths(paths: list[str]) -> list[Path]:
    """Expand directories and globs into a flat list of files."""
    out: list[Path] = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            # Common export file names
            for name in ("conversations.json", "chat.html", "conversations.html",
                         "messages.json", "cursor-export.json"):
                f = path / name
                if f.exists():
                    out.append(f)
            # Also accept any *.json / *.html in the directory
            for f in sorted(path.glob("*.json")) + sorted(path.glob("*.html")):
                if f not in out:
                    out.append(f)
        elif path.exists():
            out.append(path)
        else:
            # Treat as glob
            import glob
            for g in glob.glob(p):
                out.append(Path(g))
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="didileak",
        description="Scan your LLM chat history for leaked secrets, credentials, and PII.",
        epilog=(
            "Examples:\n"
            "  didileak scan ~/Downloads/chatgpt-export/conversations.json --html report.html\n"
            "  didileak report ~/Downloads/claude-export/ --outdir ./reports\n"
            "  didileak rotation aws-access-token\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"didileak {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    # scan
    sp = sub.add_parser("scan", help="Scan one or more export files and print a summary")
    sp.add_argument("paths", nargs="+", help="Export file(s) or directories")
    sp.add_argument("--provider", choices=["chatgpt", "claude", "cursor", "generic"],
                    help="Force a parser (auto-detected by default)")
    sp.add_argument("--json", metavar="PATH", help="Write JSON report to PATH")
    sp.add_argument("--markdown", metavar="PATH", help="Write Markdown report to PATH")
    sp.add_argument("--html", metavar="PATH", help="Write HTML dashboard to PATH")
    sp.set_defaults(func=cmd_scan)

    # report
    rp = sub.add_parser("report", help="Scan and write MD + JSON + HTML reports to a directory")
    rp.add_argument("paths", nargs="+", help="Export file(s) or directories")
    rp.add_argument("--provider", choices=["chatgpt", "claude", "cursor", "generic"])
    rp.add_argument("--outdir", default=".", help="Output directory (default: cwd)")
    rp.set_defaults(func=cmd_report)

    # rotation
    rtp = sub.add_parser("rotation", help="Print rotation guides")
    rtp.add_argument("rule_id", nargs="?", help="Specific rule (omit to list all)")
    rtp.set_defaults(func=cmd_rotation)

    # tui
    tp = sub.add_parser("tui", help="Interactive terminal UI (requires `didileak[tui]`)")
    tp.add_argument("paths", nargs="+", help="Export file(s) or directories")
    tp.add_argument("--provider", choices=["chatgpt", "claude", "cursor", "generic"])
    tp.set_defaults(func=cmd_tui)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
