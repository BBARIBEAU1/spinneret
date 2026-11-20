"""Engagement report as Markdown and PDF.

PDF rendering uses fpdf2, which is pure Python, so a Kali install does not
need Cairo or Pandoc. Unicode text uses DejaVu when the font is installed
(``fonts-dejavu-core``); otherwise the PDF uses the built-in Helvetica font
and replaces characters outside Latin-1.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from fpdf import FPDF
from fpdf.enums import WrapMode

from spinneret.errors import SpinneretError
from spinneret.models import PHASES, Engagement, Finding, note_is_empty
from spinneret.storage import Store

SUMMARY_PLACEHOLDER = (
    "_Placeholder. Replace this section with a concise overview of risk, "
    "scope, and the actions to take first. Edit the engagement summary "
    "(Summary on the engagement screen, saved as `summary.md`) and export again._"
)

_IMAGE = re.compile(r"!\[([^\]]*)\]\(([^)]+)\)")
_FONT_CANDIDATES = (
    Path("/usr/share/fonts/truetype/dejavu"),
    Path("/usr/share/fonts/TTF"),
    Path("/usr/share/fonts/dejavu"),
    Path("/usr/share/fonts/truetype/DejaVu"),
)


class ReportError(SpinneretError):
    """The report could not be rendered."""


@dataclass
class HostSection:
    box_name: str
    box_slug: str
    ip: str
    hostnames: list[str]
    os: str
    directory: Path
    notes: dict[str, str]
    findings: list[Finding] = field(default_factory=list)


@dataclass
class Report:
    engagement: Engagement
    summary: str
    engagement_dir: Path
    hosts: list[HostSection]
    findings: list[Finding]
    generated: str


def build_report(store: Store, engagement_slug: str, generated: datetime | None = None) -> Report:
    engagement = store.get_engagement(engagement_slug)
    moment = generated or datetime.now(UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    stamp = moment.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
    hosts: list[HostSection] = []
    findings: list[Finding] = []
    for box in store.list_boxes(engagement_slug):
        notes = {
            phase: store.read_note(engagement_slug, box.slug, phase) for phase, _label in PHASES
        }
        box_findings = store.list_findings(engagement_slug, box.slug)
        findings.extend(box_findings)
        hosts.append(
            HostSection(
                box_name=box.name,
                box_slug=box.slug,
                ip=box.ip,
                hostnames=list(box.hostnames),
                os=box.os,
                directory=store.box_dir(engagement_slug, box.slug),
                notes=notes,
                findings=list(box_findings),
            )
        )
    findings.sort(key=lambda item: item.sort_key())
    return Report(
        engagement=engagement,
        summary=store.read_summary(engagement_slug).strip(),
        engagement_dir=store.engagement_dir(engagement_slug),
        hosts=hosts,
        findings=findings,
        generated=stamp,
    )


def render_markdown(report: Report, output: Path | None = None) -> str:
    """Render the report. Image links are relative to ``output`` when set."""
    engagement = report.engagement
    lines: list[str] = [
        f"# {engagement.name}",
        "",
        "| | |",
        "| --- | --- |",
        f"| Client | {_cell(engagement.client or '—')} |",
        f"| Generated | {report.generated} |",
        f"| Targets | {len(report.hosts)} |",
        "",
        "## Executive Summary",
        "",
        report.summary if report.summary else SUMMARY_PLACEHOLDER,
        "",
        "## Scope",
        "",
        "| Box | IP | Hostnames | OS |",
        "| --- | --- | --- | --- |",
    ]
    if report.hosts:
        for host in report.hosts:
            hosts = ", ".join(host.hostnames) if host.hostnames else "—"
            lines.append(
                f"| {_cell(host.box_name)} | {_cell(host.ip or '—')} | "
                f"{_cell(hosts)} | {_cell(host.os or '—')} |"
            )
    else:
        lines.append("| — | — | — | — |")
    lines.extend(["", "## Findings", ""])
    if not report.findings:
        lines.append("No findings recorded.")
        lines.append("")
    else:
        lines.append("Ordered by severity, then by CVSS 3.1 base score.")
        lines.append("")
        for finding in report.findings:
            lines.extend(_finding_markdown(report, finding, output))
    lines.extend(["## Hosts", ""])
    if not report.hosts:
        lines.append("No targets recorded.")
        lines.append("")
    for host in report.hosts:
        lines.extend(_host_markdown(report, host, output))
    return "\n".join(lines).rstrip() + "\n"


def write_pdf(report: Report, path: Path) -> None:
    """Write a light, printable PDF with screenshots embedded."""
    path.parent.mkdir(parents=True, exist_ok=True)
    pdf = _ReportPDF(report.engagement.name)
    pdf.add_page()
    pdf.h1(report.engagement.name)
    pdf.meta_line(f"Client: {report.engagement.client or '—'}")
    pdf.meta_line(f"Generated: {report.generated}")
    pdf.gap()
    pdf.h2("Executive Summary")
    pdf.body(report.summary if report.summary else _plain_placeholder())
    pdf.h2("Scope")
    if not report.hosts:
        pdf.body("No targets recorded.")
    for host in report.hosts:
        hosts = ", ".join(host.hostnames) if host.hostnames else "—"
        pdf.body(f"{host.box_name}    {host.ip or '—'}    {hosts}    {host.os or '—'}")
    pdf.h2("Findings")
    if not report.findings:
        pdf.body("No findings recorded.")
    else:
        pdf.body("Ordered by severity, then by CVSS 3.1 base score.")
        for finding in report.findings:
            _finding_pdf(pdf, report, finding)
    pdf.h2("Hosts")
    for host in report.hosts:
        _host_pdf(pdf, host)
    pdf.output(path)


def export_engagement(
    store: Store,
    engagement_slug: str,
    *,
    markdown_path: Path | None = None,
    pdf_path: Path | None = None,
) -> list[Path]:
    """Write the selected formats and return the paths that were written."""
    if markdown_path is None and pdf_path is None:
        raise ReportError("Choose Markdown, PDF, or both.")
    report = build_report(store, engagement_slug)
    written: list[Path] = []
    if markdown_path is not None:
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        markdown_path.write_text(
            render_markdown(report, output=markdown_path),
            encoding="utf-8",
        )
        written.append(markdown_path)
    if pdf_path is not None:
        write_pdf(report, pdf_path)
        written.append(pdf_path)
    return written


def _finding_markdown(report: Report, finding: Finding, output: Path | None) -> list[str]:
    host = _host_for(report, finding.box)
    lines = [
        f"### {finding.id} · {finding.severity.title()} · {finding.score:.1f} — {finding.title}",
        "",
        "| | |",
        "| --- | --- |",
        f"| Affected host | {_cell(finding.affected_host or '—')} |",
        f"| Box | {_cell(host.box_name if host else finding.box)} |",
        f"| CVSS 3.1 | `{finding.vector}` |",
        "",
    ]
    if finding.description:
        lines.extend(["#### Description", "", finding.description.strip(), ""])
    if finding.evidence:
        lines.extend(["#### Evidence", ""])
        for item in finding.evidence:
            lines.extend(_evidence_markdown(item, host, output))
        lines.append("")
    if finding.remediation:
        lines.extend(["#### Remediation", "", finding.remediation.strip(), ""])
    return lines


def _host_markdown(report: Report, host: HostSection, output: Path | None) -> list[str]:
    names = ", ".join(host.hostnames) if host.hostnames else "—"
    lines = [
        f"### {host.box_name}",
        "",
        "| | |",
        "| --- | --- |",
        f"| IP | {_cell(host.ip or '—')} |",
        f"| Hostnames | {_cell(names)} |",
        f"| OS | {_cell(host.os or '—')} |",
        "",
    ]
    if host.findings:
        lines.append("#### Findings on this host")
        lines.append("")
        ordered = sorted(host.findings, key=lambda item: item.sort_key())
        for finding in ordered:
            lines.append(
                f"- **{finding.id}** {finding.severity.title()} "
                f"({finding.score:.1f}) {finding.title}"
            )
        lines.append("")
    for phase, label in PHASES:
        body = _note_body(host.notes.get(phase, ""), label)
        if note_is_empty(body):
            continue
        lines.extend([f"#### {label}", "", _rewrite_images(body, host, output), ""])
    return lines


def _evidence_markdown(item: str, host: HostSection | None, output: Path | None) -> list[str]:
    image = _resolve_image(host, item) if host else None
    if image is not None:
        link = _relative_link(image, host, output) if host else image.name
        return [f"![{image.name}]({link})", ""]
    return [item, ""]


def _rewrite_images(text: str, host: HostSection, output: Path | None) -> str:
    def replace(match: re.Match[str]) -> str:
        alt, raw = match.group(1), match.group(2)
        if raw.startswith(("http://", "https://")):
            return match.group(0)
        image = _resolve_image(host, raw)
        if image is None:
            return match.group(0)
        return f"![{alt}]({_relative_link(image, host, output)})"

    return _IMAGE.sub(replace, text)


def _relative_link(image: Path, host: HostSection, output: Path | None) -> str:
    if output is None:
        try:
            return image.resolve().relative_to(host.directory.parent.resolve()).as_posix()
        except ValueError:
            return image.as_posix()
    return Path(os.path.relpath(image.resolve(), output.parent.resolve())).as_posix()


def _resolve_image(host: HostSection, reference: str) -> Path | None:
    raw = reference.strip()
    matched = _IMAGE.fullmatch(raw)
    if matched:
        raw = matched.group(2).strip()
    if raw.startswith(("http://", "https://")):
        return None
    path = Path(raw)
    candidates = [
        host.directory / path,
        host.directory / "screenshots" / path.name,
        host.directory / "notes" / path,
    ]
    for candidate in candidates:
        suffix = candidate.suffix.lower()
        if candidate.is_file() and suffix in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
            return candidate
    return None


def _note_body(text: str, label: str) -> str:
    lines = text.splitlines()
    if lines and lines[0].strip().lower() == f"# {label}".lower():
        lines = lines[1:]
    return "\n".join(lines).strip()


def _cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _plain_placeholder() -> str:
    return (
        "Placeholder. Replace this section with a concise overview of risk, "
        "scope, and the actions to take first. Edit summary.md and export again."
    )


def _host_for(report: Report, slug: str) -> HostSection | None:
    for host in report.hosts:
        if host.box_slug == slug:
            return host
    return None


class _ReportPDF(FPDF):
    def __init__(self, engagement_name: str) -> None:
        super().__init__(format="A4", unit="mm")
        regular = _find_font("DejaVuSans.ttf")
        bold = _find_font("DejaVuSans-Bold.ttf")
        if regular is not None:
            self.add_font("DejaVu", "", str(regular))
            self.add_font("DejaVu", "B", str(bold or regular))
            self.font_name = "DejaVu"
            self.unicode_ok = True
        else:
            self.font_name = "Helvetica"
            self.unicode_ok = False
        self.engagement_name = engagement_name
        self.set_margins(15, 20, 15)
        self.set_auto_page_break(auto=True, margin=16)
        self.set_title(f"{engagement_name} report")
        self.set_author("spinneret")
        self.set_creator("spinneret")

    def header(self) -> None:
        self.set_fill_color(12, 28, 22)
        self.rect(0, 0, 210, 12, "F")
        self.set_xy(self.l_margin, 2.5)
        self.set_text_color(125, 255, 179)
        self.set_font(self.font_name, "B", 10)
        self.cell(40, 7, self._safe("spinneret"))
        self.set_font(self.font_name, "", 9)
        self.set_text_color(190, 214, 200)
        self.set_xy(self.l_margin, 2.5)
        self.cell(self.epw, 7, self._safe(self.engagement_name), align="R")
        self.set_text_color(20, 24, 22)
        self.set_xy(self.l_margin, 16)

    def footer(self) -> None:
        self.set_auto_page_break(auto=False)
        self.set_y(-12)
        self.set_x(self.l_margin)
        self.set_font(self.font_name, "", 8)
        self.set_text_color(90, 110, 100)
        label = f"{self.engagement_name}  |  {self.page_no()}"
        self.cell(self.epw, 8, self._safe(label), align="C")
        self.set_auto_page_break(auto=True, margin=16)

    def h1(self, text: str) -> None:
        self._block(text, 18, 9, bold=True, color=(14, 48, 34))
        self.ln(1)

    def h2(self, text: str) -> None:
        self.ln(2)
        self._block(text, 14, 8, bold=True, color=(14, 48, 34))
        self.set_draw_color(30, 90, 60)
        y = self.get_y()
        self.line(self.l_margin, y, self.w - self.r_margin, y)
        self.ln(3)

    def h3(self, text: str) -> None:
        self.ln(1)
        self._block(text, 12, 7, bold=True, color=(20, 32, 28))
        self.ln(1)

    def meta_line(self, text: str) -> None:
        self._block(text, 10, 5, color=(60, 72, 66))

    def body(self, text: str) -> None:
        self._block(text, 11, 6, color=(20, 24, 22))
        self.ln(1)

    def _block(
        self,
        text: str,
        size: int,
        height: float,
        *,
        bold: bool = False,
        color: tuple[int, int, int] = (20, 24, 22),
    ) -> None:
        self.set_x(self.l_margin)
        self.set_text_color(*color)
        self.set_font(self.font_name, "B" if bold else "", size)
        self.multi_cell(self.epw, height, self._safe(text), wrapmode=WrapMode.CHAR)

    def gap(self) -> None:
        self.ln(2)

    def embed(self, image: Path) -> None:
        if self.get_y() > 230:
            self.add_page()
        try:
            self.image(str(image), w=min(160, self.epw))
        except Exception as exc:
            self.body(f"[image unreadable: {image.name}: {exc}]")
            return
        self.ln(2)

    def _safe(self, text: str) -> str:
        if self.unicode_ok:
            return text
        return text.encode("latin-1", errors="replace").decode("latin-1")


def _finding_pdf(pdf: _ReportPDF, report: Report, finding: Finding) -> None:
    host = _host_for(report, finding.box)
    pdf.h3(f"{finding.id}  {finding.severity.title()}  {finding.score:.1f}  {finding.title}")
    pdf.body(f"Affected host: {finding.affected_host or '—'}")
    pdf.body(f"Box: {host.box_name if host else finding.box}")
    pdf.body(f"CVSS 3.1: {finding.vector}")
    if finding.description:
        pdf.body(finding.description.strip())
    for item in finding.evidence:
        image = _resolve_image(host, item) if host else None
        if image is not None:
            pdf.embed(image)
        else:
            pdf.body(item)
    if finding.remediation:
        pdf.body(f"Remediation: {finding.remediation.strip()}")


def _host_pdf(pdf: _ReportPDF, host: HostSection) -> None:
    names = ", ".join(host.hostnames) if host.hostnames else "—"
    pdf.h3(host.box_name)
    pdf.body(f"IP: {host.ip or '—'}    Hostnames: {names}    OS: {host.os or '—'}")
    for phase, label in PHASES:
        body = _note_body(host.notes.get(phase, ""), label)
        if note_is_empty(body):
            continue
        pdf.body(label)
        _write_note_pdf(pdf, host, body)


def _write_note_pdf(pdf: _ReportPDF, host: HostSection, body: str) -> None:
    paragraph: list[str] = []

    def flush() -> None:
        if paragraph:
            pdf.body("\n".join(paragraph))
            paragraph.clear()

    for line in body.splitlines():
        matched = _IMAGE.fullmatch(line.strip())
        if matched:
            flush()
            image = _resolve_image(host, matched.group(2))
            if image is not None:
                pdf.embed(image)
            else:
                pdf.body(line)
            continue
        paragraph.append(line)
    flush()


def _find_font(name: str) -> Path | None:
    for directory in _FONT_CANDIDATES:
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None
