"""Markdown and PDF export."""

from io import BytesIO

import pytest
from PIL import Image
from pypdf import PdfReader

from spinneret.models import Finding
from spinneret.report import (
    SUMMARY_PLACEHOLDER,
    ReportError,
    build_report,
    export_engagement,
    render_markdown,
)
from spinneret.storage import Store


def _png(path) -> None:
    buffer = BytesIO()
    Image.new("RGB", (8, 8), (18, 140, 90)).save(buffer, format="PNG")
    path.write_bytes(buffer.getvalue())


def _seed(tmp_path) -> tuple[Store, str]:
    store = Store(tmp_path)
    engagement = store.create_engagement("HTB CPTS", client="Hack The Box")
    lame = store.create_box(
        engagement.slug,
        "Lame",
        ip="10.10.10.3",
        hostnames=["lame.htb"],
        os="Linux",
    )
    blue = store.create_box(engagement.slug, "Blue", ip="10.10.10.40", os="Windows")
    shot = store.screenshots_dir(engagement.slug, lame.slug) / "ftp.png"
    _png(shot)
    store.write_note(
        engagement.slug,
        lame.slug,
        "recon",
        "# Recon\n\nPort 21 open\n\n![ftp](../screenshots/ftp.png)\n",
    )
    store.save_finding(
        engagement.slug,
        blue.slug,
        Finding(
            id="",
            title="Low note",
            vector="CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
            score=0,
            severity="",
            affected_host="10.10.10.40",
            description="Local low impact.",
            remediation="Patch it.",
        ),
    )
    store.save_finding(
        engagement.slug,
        lame.slug,
        Finding(
            id="",
            title="Anonymous FTP",
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            score=0,
            severity="",
            affected_host="10.10.10.3",
            description="Anonymous login writes files.",
            evidence=["screenshots/ftp.png"],
            remediation="Disable anonymous write.",
        ),
    )
    return store, engagement.slug


def test_markdown_sorts_findings_and_embeds_notes(tmp_path) -> None:
    store, slug = _seed(tmp_path)
    report = build_report(store, slug)
    output = tmp_path / slug / "report.md"
    text = render_markdown(report, output=output)
    assert text.index("Anonymous FTP") < text.index("Low note")
    assert "9.8" in text
    assert "Critical" in text
    assert SUMMARY_PLACEHOLDER in text
    assert "Port 21 open" in text
    assert "lame/screenshots/ftp.png" in text
    assert "## Executive Summary" in text
    assert "### Lame" in text
    assert "10.10.10.3" in text

    store.write_summary(slug, "The forest is the priority.\n")
    written = export_engagement(
        store,
        slug,
        markdown_path=output,
        pdf_path=tmp_path / slug / "report.pdf",
    )
    markdown = output.read_text(encoding="utf-8")
    assert "The forest is the priority." in markdown
    assert "Placeholder" not in markdown
    pdf_path = written[1]
    assert pdf_path.read_bytes().startswith(b"%PDF")
    reader = PdfReader(pdf_path)
    extracted = "\n".join(page.extract_text() or "" for page in reader.pages)
    assert "Anonymous FTP" in extracted
    assert "The forest is the priority." in extracted
    assert any(page.images for page in reader.pages)


def test_export_requires_a_format(tmp_path) -> None:
    store, slug = _seed(tmp_path)
    with pytest.raises(ReportError):
        export_engagement(store, slug)
