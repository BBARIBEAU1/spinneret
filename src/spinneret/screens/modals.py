"""Modal forms: create and edit records, cheat sheet, help, export."""

from __future__ import annotations

from dataclasses import dataclass

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, DataTable, Input, Label, Select, Static, TextArea

from spinneret.cheatsheet import CheatEntry, fill_placeholders, search
from spinneret.clipboard import copy_text
from spinneret.cvss import (
    BASE_METRICS,
    DEFAULT_METRICS,
    METRIC_OPTIONS,
    CVSSError,
    score_vector,
)
from spinneret.models import Finding

HELP_TEXT = """\
F1                 Help
ctrl+q             Quit

Engagements
  n                New engagement
  enter / o        Open
  e                Edit name and client
  d                Delete
  q                Quit this screen

Boxes
  n                New box
  enter / o        Open the workspace
  e                Edit IP, hostnames, lhost
  d                Delete
  s                Executive summary
  x                Export the report
  escape           Back

Workspace  (these work while the note is focused)
  alt+1 … alt+6    Recon, enumeration, exploitation, privesc, loot, scratch
  F2 / ctrl+s      Save the note
  F3               Append a timestamped scratch line
  F4               Add a finding, or edit the selected one
  F5               Cheat sheet
  F8               Capture a screenshot into this note
  F9               Import a clipboard image or a file
  F10              Export the report
  F11              Edit this box
  F12              Back

Cheat sheet
  type to filter
  enter            Copy the best match
  Commands are copied. spinneret does not run them.
"""


@dataclass(frozen=True)
class EngagementDraft:
    name: str
    client: str


@dataclass(frozen=True)
class BoxDraft:
    name: str
    ip: str
    hostnames: list[str]
    os: str
    user: str
    domain: str
    lhost: str


@dataclass(frozen=True)
class ImportChoice:
    kind: str
    path: str = ""


def _tell(screen: ModalScreen, message: str, *, error: bool = False) -> None:
    screen.notify(message, severity="error" if error else "information", markup=False)


class HelpScreen(ModalScreen[None]):
    BINDINGS = [Binding("escape", "close", "Close"), Binding("f1", "close", "Close", priority=True)]

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="help-dialog", classes="dialog"):
            yield Static("Keybindings", classes="modal-title")
            yield Static(Text(HELP_TEXT), id="help-body")
            yield Button("Close", id="close-help")

    def action_close(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close-help":
            self.dismiss(None)


class ConfirmScreen(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "no", "Cancel"), Binding("y", "yes", "Delete")]

    def __init__(self, message: str) -> None:
        super().__init__()
        self.message = message

    def compose(self) -> ComposeResult:
        with VerticalScroll(classes="dialog"):
            yield Static("Confirm", classes="modal-title")
            yield Static(Text(self.message), id="confirm-message")
            with Horizontal(classes="button-row"):
                yield Button("Delete", id="confirm-yes", variant="error")
                yield Button("Cancel", id="confirm-no")

    def action_yes(self) -> None:
        self.dismiss(True)

    def action_no(self) -> None:
        self.dismiss(False)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "confirm-yes":
            self.dismiss(True)
        elif event.button.id == "confirm-no":
            self.dismiss(False)


class EngagementForm(ModalScreen[EngagementDraft | None]):
    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("ctrl+s", "save", "Save", priority=True),
    ]

    def __init__(self, name: str = "", client: str = "", editing: bool = False) -> None:
        super().__init__()
        self._name = name
        self._client = client
        self._editing = editing

    def compose(self) -> ComposeResult:
        title = "Edit engagement" if self._editing else "New engagement"
        with VerticalScroll(classes="dialog"):
            yield Static(title, classes="modal-title")
            yield Label("Name")
            yield Input(value=self._name, placeholder="HTB CPTS", id="eng-name")
            yield Label("Client")
            yield Input(value=self._client, placeholder="optional", id="eng-client")
            with Horizontal(classes="button-row"):
                yield Button("Save", id="save-eng", variant="success")
                yield Button("Cancel", id="cancel-eng")

    def on_mount(self) -> None:
        self.query_one("#eng-name", Input).focus()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_save(self) -> None:
        name = self.query_one("#eng-name", Input).value.strip()
        if not name:
            _tell(self, "Name is required.", error=True)
            return
        client = self.query_one("#eng-client", Input).value.strip()
        self.dismiss(EngagementDraft(name=name, client=client))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save-eng":
            self.action_save()
        elif event.button.id == "cancel-eng":
            self.dismiss(None)


class BoxForm(ModalScreen[BoxDraft | None]):
    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("ctrl+s", "save", "Save", priority=True),
    ]

    def __init__(self, draft: BoxDraft | None = None, editing: bool = False) -> None:
        super().__init__()
        self._draft = draft
        self._editing = editing

    def compose(self) -> ComposeResult:
        draft = self._draft
        title = "Edit box" if self._editing else "New box"
        hosts = ", ".join(draft.hostnames) if draft else ""
        with Vertical(id="box-dialog", classes="dialog"):
            yield Static(title, classes="modal-title")
            yield Static(
                "Hostnames, domain, user, and lhost fill <HOST>, <DOMAIN>, <USER>, and <LHOST>.",
                classes="hint",
            )
            with Grid(id="box-grid"):
                yield Label("Name")
                yield Input(value=draft.name if draft else "", placeholder="Lame", id="box-name")
                yield Label("IP")
                yield Input(value=draft.ip if draft else "", placeholder="10.10.10.3", id="box-ip")
                yield Label("Hosts")
                yield Input(value=hosts, placeholder="lame.htb", id="box-hosts")
                yield Label("OS")
                yield Input(value=draft.os if draft else "", placeholder="Linux", id="box-os")
                yield Label("User")
                yield Input(value=draft.user if draft else "", id="box-user")
                yield Label("Domain")
                yield Input(value=draft.domain if draft else "", id="box-domain")
                yield Label("LHOST")
                yield Input(
                    value=draft.lhost if draft else "",
                    placeholder="tun0",
                    id="box-lhost",
                )
            with Horizontal(classes="button-row"):
                yield Button("Save", id="save-box", variant="success")
                yield Button("Cancel", id="cancel-box")

    def on_mount(self) -> None:
        self.query_one("#box-name", Input).focus()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_save(self) -> None:
        from spinneret.models import parse_hostnames

        name = self.query_one("#box-name", Input).value.strip()
        if not name:
            _tell(self, "Name is required.", error=True)
            return
        self.dismiss(
            BoxDraft(
                name=name,
                ip=self.query_one("#box-ip", Input).value.strip(),
                hostnames=parse_hostnames(self.query_one("#box-hosts", Input).value),
                os=self.query_one("#box-os", Input).value.strip(),
                user=self.query_one("#box-user", Input).value.strip(),
                domain=self.query_one("#box-domain", Input).value.strip(),
                lhost=self.query_one("#box-lhost", Input).value.strip(),
            )
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save-box":
            self.action_save()
        elif event.button.id == "cancel-box":
            self.dismiss(None)


class SummaryScreen(ModalScreen[str | None]):
    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("ctrl+s", "save", "Save", priority=True),
    ]

    def __init__(self, text: str) -> None:
        super().__init__()
        self._text = text

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="summary-dialog", classes="dialog"):
            yield Static("Executive summary", classes="modal-title")
            yield Static(
                "Written to summary.md. An empty summary leaves the report placeholder in place.",
                classes="hint",
            )
            yield TextArea(self._text, id="summary-editor", soft_wrap=True)
            with Horizontal(classes="button-row"):
                yield Button("Save", id="save-summary", variant="success")
                yield Button("Cancel", id="cancel-summary")

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_save(self) -> None:
        self.dismiss(self.query_one("#summary-editor", TextArea).text)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save-summary":
            self.action_save()
        elif event.button.id == "cancel-summary":
            self.dismiss(None)


class ScratchScreen(ModalScreen[str | None]):
    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("ctrl+s", "save", "Append", priority=True),
    ]

    def compose(self) -> ComposeResult:
        with VerticalScroll(classes="dialog"):
            yield Static("Scratch log", classes="modal-title")
            yield Static("Appended to the scratch note with a UTC timestamp.", classes="hint")
            yield TextArea(id="scratch-text", soft_wrap=True)
            with Horizontal(classes="button-row"):
                yield Button("Append", id="append-scratch", variant="success")
                yield Button("Cancel", id="cancel-scratch")

    def on_mount(self) -> None:
        self.query_one("#scratch-text", TextArea).focus()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_save(self) -> None:
        text = self.query_one("#scratch-text", TextArea).text.strip()
        if not text:
            _tell(self, "Scratch note is empty.", error=True)
            return
        self.dismiss(text)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "append-scratch":
            self.action_save()
        elif event.button.id == "cancel-scratch":
            self.dismiss(None)


class ImportScreen(ModalScreen[ImportChoice | None]):
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def compose(self) -> ComposeResult:
        with VerticalScroll(classes="dialog"):
            yield Static("Import screenshot", classes="modal-title")
            yield Static("Clipboard import reads a PNG via wl-paste or xclip.", classes="hint")
            yield Label("File path")
            yield Input(placeholder="/path/to/proof.png", id="import-path")
            with Horizontal(classes="button-row"):
                yield Button("Import file", id="import-file", variant="success")
                yield Button("Clipboard", id="import-clip")
                yield Button("Cancel", id="cancel-import")

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "import-file":
            path = self.query_one("#import-path", Input).value.strip()
            if not path:
                _tell(self, "Enter a file path, or use Clipboard.", error=True)
                return
            self.dismiss(ImportChoice(kind="file", path=path))
        elif event.button.id == "import-clip":
            self.dismiss(ImportChoice(kind="clipboard"))
        elif event.button.id == "cancel-import":
            self.dismiss(None)


class ExportScreen(ModalScreen[tuple[bool, bool] | None]):
    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("ctrl+s", "export", "Export", priority=True),
    ]

    def __init__(self, directory_label: str) -> None:
        super().__init__()
        self._directory_label = directory_label

    def compose(self) -> ComposeResult:
        with VerticalScroll(classes="dialog"):
            yield Static("Export report", classes="modal-title")
            yield Static(Text(self._directory_label), id="export-dest", classes="hint")
            yield Checkbox("Markdown", value=True, id="export-md")
            yield Checkbox("PDF", value=True, id="export-pdf")
            with Horizontal(classes="button-row"):
                yield Button("Export", id="do-export", variant="success")
                yield Button("Cancel", id="cancel-export")

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_export(self) -> None:
        markdown = self.query_one("#export-md", Checkbox).value
        pdf = self.query_one("#export-pdf", Checkbox).value
        if not markdown and not pdf:
            _tell(self, "Choose Markdown, PDF, or both.", error=True)
            return
        self.dismiss((markdown, pdf))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "do-export":
            self.action_export()
        elif event.button.id == "cancel-export":
            self.dismiss(None)


class FindingForm(ModalScreen[Finding | None]):
    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("ctrl+s", "save", "Save", priority=True),
    ]

    def __init__(self, finding: Finding | None = None, default_host: str = "") -> None:
        super().__init__()
        self.finding = finding
        self.default_host = default_host
        self._syncing = False

    def compose(self) -> ComposeResult:
        title = "Edit finding" if self.finding else "New finding"
        with Vertical(id="finding-dialog", classes="dialog"):
            yield Static(title, classes="modal-title")
            with VerticalScroll(id="finding-fields"):
                yield Label("Title")
                yield Input(placeholder="Anonymous FTP write", id="find-title")
                yield Label("Metrics")
                with Grid(id="metric-grid"):
                    for metric in BASE_METRICS:
                        yield Label(metric)
                        yield Select(
                            METRIC_OPTIONS[metric],
                            value=DEFAULT_METRICS[metric],
                            allow_blank=False,
                            id=f"m-{metric.lower()}",
                            compact=True,
                        )
                yield Label("CVSS 3.1 vector")
                yield Input(id="find-vector")
                yield Static("", id="score")
                yield Label("Affected host")
                yield Input(id="find-host")
                yield Label("Description")
                yield TextArea(id="find-description", soft_wrap=True)
                yield Label("Evidence, one path or note per line")
                yield TextArea(id="find-evidence", soft_wrap=True)
                yield Label("Remediation")
                yield TextArea(id="find-remediation", soft_wrap=True)
            with Horizontal(classes="button-row"):
                yield Button("Save", id="save-finding", variant="success")
                yield Button("Cancel", id="cancel-finding")

    def on_mount(self) -> None:
        self._syncing = True
        try:
            if self.finding is not None:
                self.query_one("#find-title", Input).value = self.finding.title
                self.query_one("#find-host", Input).value = self.finding.affected_host
                self.query_one("#find-description", TextArea).load_text(self.finding.description)
                evidence = "\n".join(self.finding.evidence)
                self.query_one("#find-evidence", TextArea).load_text(evidence)
                self.query_one("#find-remediation", TextArea).load_text(self.finding.remediation)
                self.query_one("#find-vector", Input).value = self.finding.vector
                self._sync_selects(self.finding.vector)
            else:
                self.query_one("#find-host", Input).value = self.default_host
                self._write_vector_from_selects()
        finally:
            self._syncing = False
        self._refresh_score()
        self.query_one("#find-title", Input).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        if self._syncing or event.input.id != "find-vector":
            return
        self._sync_selects(event.value)
        self._refresh_score()

    def on_select_changed(self, event: Select.Changed) -> None:
        if self._syncing or not str(event.select.id or "").startswith("m-"):
            return
        self._syncing = True
        try:
            self._write_vector_from_selects()
        finally:
            self._syncing = False
        self._refresh_score()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_save(self) -> None:
        title = self.query_one("#find-title", Input).value.strip()
        if not title:
            _tell(self, "Title is required.", error=True)
            return
        raw = self.query_one("#find-vector", Input).value.strip()
        try:
            base = score_vector(raw)
        except CVSSError as exc:
            _tell(self, str(exc), error=True)
            return
        evidence = [
            line.strip()
            for line in self.query_one("#find-evidence", TextArea).text.splitlines()
            if line.strip()
        ]
        self.dismiss(
            Finding(
                id=self.finding.id if self.finding else "",
                title=title,
                vector=base.vector,
                score=base.score,
                severity=base.severity,
                affected_host=self.query_one("#find-host", Input).value.strip(),
                description=self.query_one("#find-description", TextArea).text.strip(),
                evidence=evidence,
                remediation=self.query_one("#find-remediation", TextArea).text.strip(),
                created=self.finding.created if self.finding else "",
            )
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save-finding":
            self.action_save()
        elif event.button.id == "cancel-finding":
            self.dismiss(None)

    def _metrics(self) -> dict[str, str]:
        return {
            metric: str(self.query_one(f"#m-{metric.lower()}", Select).value)
            for metric in BASE_METRICS
        }

    def _write_vector_from_selects(self) -> None:
        from spinneret.cvss import build_vector

        self.query_one("#find-vector", Input).value = build_vector(self._metrics())

    def _sync_selects(self, raw: str) -> None:
        try:
            base = score_vector(raw)
        except CVSSError:
            return
        self._syncing = True
        try:
            for metric in BASE_METRICS:
                widget = self.query_one(f"#m-{metric.lower()}", Select)
                if widget.value != base.metrics[metric]:
                    widget.value = base.metrics[metric]
        finally:
            self._syncing = False

    def _refresh_score(self) -> None:
        label = self.query_one("#score", Static)
        raw = self.query_one("#find-vector", Input).value.strip()
        try:
            base = score_vector(raw)
        except CVSSError as exc:
            label.update(str(exc))
            label.set_classes("bad-score")
            return
        label.update(f"{base.score:.1f}   {base.severity.title()}")
        label.set_classes(f"severity-{base.severity}")


class CheatSheetScreen(ModalScreen[None]):
    BINDINGS = [
        Binding("escape", "close", "Close"),
        Binding("ctrl+s", "copy", "Copy", priority=True),
    ]

    def __init__(self, entries: list[CheatEntry], values: dict[str, str]) -> None:
        super().__init__()
        self.entries = entries
        self.values = values
        self.matches: list[CheatEntry] = list(entries)
        self.filled_command = ""

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="cheat-dialog", classes="dialog"):
            yield Static("Cheat sheet", classes="modal-title")
            yield Static(
                "Filter, then enter or Copy. Commands are copied, not run.",
                classes="hint",
            )
            yield Input(placeholder="nmap, axfr, certutil, vhost", id="cheat-filter")
            yield DataTable(id="cheat-table")
            yield Static("", id="cheat-preview")
            with Horizontal(classes="button-row"):
                yield Button("Copy", id="copy-cheat", variant="success")
                yield Button("Close", id="close-cheat")

    def on_mount(self) -> None:
        table = self.query_one("#cheat-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Category", "Title")
        self._fill("")
        self.query_one("#cheat-filter", Input).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "cheat-filter":
            self._fill(event.value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "cheat-filter":
            self.action_copy()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id == "cheat-table":
            self._show(str(event.row_key.value))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "cheat-table":
            self._show(str(event.row_key.value))
            self.action_copy()

    def action_close(self) -> None:
        self.dismiss(None)

    def action_copy(self) -> None:
        if not self.filled_command:
            _tell(self, "Nothing to copy.", error=True)
            return
        self.app.copy_to_clipboard(self.filled_command)
        if copy_text(self.filled_command) == "clipboard":
            _tell(self, "Copied to the clipboard.")
        else:
            _tell(
                self,
                "Sent via the terminal clipboard. Install wl-copy or xclip if paste fails.",
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "copy-cheat":
            self.action_copy()
        elif event.button.id == "close-cheat":
            self.dismiss(None)

    def _fill(self, query: str) -> None:
        self.matches = search(self.entries, query)
        table = self.query_one("#cheat-table", DataTable)
        table.clear()
        for entry in self.matches:
            table.add_row(entry.category, entry.title, key=entry.id)
        if self.matches:
            self._show(self.matches[0].id)
        else:
            self.filled_command = ""
            self.query_one("#cheat-preview", Static).update(Text("No matches."))

    def _show(self, entry_id: str) -> None:
        entry = next((item for item in self.matches if item.id == entry_id), None)
        if entry is None:
            return
        filled = fill_placeholders(entry.command, self.values)
        self.filled_command = filled
        preview = filled if not entry.notes else f"{filled}\n\n{entry.notes}"
        self.query_one("#cheat-preview", Static).update(Text(preview))
