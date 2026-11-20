"""Command line: launch the TUI, or export a report without it."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from spinneret import __version__
from spinneret.app import SpinneretApp
from spinneret.errors import SpinneretError
from spinneret.report import export_engagement
from spinneret.storage import Store, default_root


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="spinneret",
        description="Terminal notes and reporting for penetration tests.",
    )
    parser.add_argument(
        "--root",
        type=Path,
        help="Data directory (default: ~/spinneret, or $SPINNERET_ROOT)",
    )
    parser.add_argument("--version", action="version", version=f"spinneret {__version__}")
    sub = parser.add_subparsers(dest="command")
    export = sub.add_parser("export", help="Write an engagement report and exit")
    export.add_argument("engagement", help="Engagement slug, for example htb-cpts")
    export.add_argument("--markdown", type=Path, help="Markdown output path")
    export.add_argument("--pdf", type=Path, help="PDF output path")
    export.add_argument("--no-markdown", action="store_true", help="Skip the Markdown file")
    export.add_argument("--no-pdf", action="store_true", help="Skip the PDF file")
    args = parser.parse_args(argv)
    root = args.root or default_root()
    if args.command == "export":
        return _export(root, args)
    SpinneretApp(root=root).run()
    return 0


def _export(root: Path, args: argparse.Namespace) -> int:
    store = Store(root)
    try:
        store.get_engagement(args.engagement)
    except SpinneretError as exc:
        print(exc, file=sys.stderr)
        return 1
    directory = store.engagement_dir(args.engagement)
    markdown = None if args.no_markdown else (args.markdown or directory / "report.md")
    pdf = None if args.no_pdf else (args.pdf or directory / "report.pdf")
    if markdown is None and pdf is None:
        print("Choose Markdown, PDF, or both.", file=sys.stderr)
        return 1
    try:
        written = export_engagement(
            store,
            args.engagement,
            markdown_path=markdown,
            pdf_path=pdf,
        )
    except SpinneretError as exc:
        print(exc, file=sys.stderr)
        return 1
    for path in written:
        print(path)
    return 0
