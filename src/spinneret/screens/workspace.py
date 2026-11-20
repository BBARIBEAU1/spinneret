"""Notes, findings, screenshots, and the cheat sheet for one box."""

from __future__ import annotations

from pathlib import Path

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Static, TextArea

from spinneret.cheatsheet import CheatsheetError, load_entries
from spinneret.errors import SpinneretError
from spinneret.models import PHASE_LABELS, PHASES, Box, Finding
from spinneret.report import export_engagement
from spinneret.screens.modals import (
    BoxDraft,
    BoxForm,
    CheatSheetScreen,
    ConfirmScreen,
    ExportScreen,
    FindingForm,
    HelpScreen,
    ImportChoice,
    ImportScreen,
    ScratchScreen,
)
from spinneret.screenshots import (
    IMAGE_SUFFIXES,
    append_image_link,
    capture_screenshot,
    import_clipboard_image,
    import_image_file,
    new_screenshot_path,
)
from spinneret.storage import Store
from spinneret.ui import SEVERITY_STYLE, brand, selected_key


class WorkspaceScreen(Screen):
    BINDINGS = [
        Binding("f1", "help", "Help", priority=True),
        Binding("f2", "save", "Save", priority=True),
        Binding("ctrl+s", "save", "Save", show=False, priority=True),
        Binding("f3", "scratch", "Scratch", priority=True),
        Binding("f4", "finding", "Finding", priority=True),
        Binding("f5", "cheat", "Cheats", priority=True),
        Binding("f8", "shot", "Shot", priority=True),
        Binding("f9", "import_image", "Import", priority=True),
        Binding("f10", "export", "Export", priority=True),
        Binding("f11", "metadata", "Meta", priority=True),
        Binding("f12", "back", "Back", priority=True),
        Binding("alt+1", "phase('recon')", "Recon", show=False, priority=True),
        Binding("alt+2", "phase('enumeration')", "Enum", show=False, priority=True),
        Binding("alt+3", "phase('exploitation')", "Exploit", show=False, priority=True),
        Binding("alt+4", "phase('privesc')", "Privesc", show=False, priority=True),
        Binding("alt+5", "phase('loot')", "Loot", show=False, priority=True),
        Binding("alt+6", "phase('scratch')", "Scratch", show=False, priority=True),
    ]

    def __init__(self, engagement_slug: str, box_slug: str) -> None:
        super().__init__()
        self.engagement_slug = engagement_slug
        self.box_slug = box_slug
        self.phase = "recon"
        self._dirty = False
        self._loading = False

    def compose(self) -> ComposeResult:
        yield Static("", id="brand")
        with Horizontal(id="phase-bar"):
            for key, label in PHASES:
                yield Button(label, id=f"phase-{key}", classes="phase")
            yield Static("saved", id="save-state")
        with Horizontal(id="workspace-body"):
            with Vertical(id="editor-pane"):
                yield TextArea(id="note-editor", soft_wrap=True, show_line_numbers=True)
            with Vertical(id="side-pane"):
                yield Static("", id="meta")
                yield Static("Findings", classes="pane-title")
                yield DataTable(id="findings-table")
                with Horizontal(id="finding-actions"):
                    yield Button("Add", id="add-finding")
                    yield Button("Edit", id="edit-finding")
                    yield Button("Del", id="delete-finding")
        with Horizontal(id="action-bar"):
            yield Button("Save", id="save-note")
            yield Button("Scratch", id="scratch")
            yield Button("Cheat", id="cheat")
            yield Button("Shot", id="shot")
            yield Button("Import", id="import")
            yield Button("Export", id="export")
            yield Button("Meta", id="meta-btn")
            yield Button("Back", id="back")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_columns("Title", "Severity", "Score")
        self._refresh_header()
        self._load_note()
        self._reload_findings()
        self._mark_phase()
        self.query_one("#note-editor", TextArea).focus()
        self.set_interval(3.0, self._autosave)

    @property
    def store(self) -> Store:
        return self.app.store  # type: ignore[attr-defined]

    def action_help(self) -> None:
        self.app.push_screen(HelpScreen())

    def action_save(self) -> None:
        self._save_note()
        self.notify("Saved", markup=False)

    def action_phase(self, phase: str) -> None:
        if phase not in PHASE_LABELS:
            return
        if phase != self.phase:
            self._save_note()
            self.phase = phase
            self._load_note()
        self._mark_phase()

    def action_scratch(self) -> None:
        self._save_note()
        self.app.push_screen(ScratchScreen(), self._scratched)

    def action_finding(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        if table.has_focus and table.row_count:
            self._edit_selected()
            return
        self._open_finding(None)

    def action_cheat(self) -> None:
        try:
            entries = load_entries(self.app.cheatsheet_paths())  # type: ignore[attr-defined]
        except CheatsheetError as exc:
            self.notify(str(exc), severity="error", markup=False)
            return
        box = self.store.get_box(self.engagement_slug, self.box_slug)
        self.app.push_screen(CheatSheetScreen(entries, box.placeholders()))

    def action_shot(self) -> None:
        self._save_note()
        directory = self.store.screenshots_dir(self.engagement_slug, self.box_slug)
        dest = new_screenshot_path(directory)
        try:
            tool = capture_screenshot(dest)
        except SpinneretError as exc:
            self.notify(str(exc), severity="error", markup=False)
            return
        self._link_image(dest.name)
        phase = PHASE_LABELS[self.phase]
        self.notify(f"Captured with {tool} and linked into {phase}", markup=False)

    def action_import_image(self) -> None:
        self._save_note()
        self.app.push_screen(ImportScreen(), self._imported)

    def action_export(self) -> None:
        self._save_note()
        directory = self.store.engagement_dir(self.engagement_slug)
        label = f"Writes report.md and report.pdf in {directory}"
        self.app.push_screen(ExportScreen(label), self._exported)

    def action_metadata(self) -> None:
        box = self.store.get_box(self.engagement_slug, self.box_slug)
        draft = BoxDraft(
            name=box.name,
            ip=box.ip,
            hostnames=list(box.hostnames),
            os=box.os,
            user=box.user,
            domain=box.domain,
            lhost=box.lhost,
        )
        self.app.push_screen(
            BoxForm(draft, editing=True),
            lambda updated: self._metadata(box, updated),
        )

    def action_back(self) -> None:
        self._save_note()
        self.app.pop_screen()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id.startswith("phase-"):
            self.action_phase(button_id.removeprefix("phase-"))
            return
        actions = {
            "save-note": self.action_save,
            "scratch": self.action_scratch,
            "cheat": self.action_cheat,
            "shot": self.action_shot,
            "import": self.action_import_image,
            "export": self.action_export,
            "meta-btn": self.action_metadata,
            "back": self.action_back,
            "add-finding": self.action_finding,
            "edit-finding": self._edit_selected,
            "delete-finding": self._delete_selected,
        }
        action = actions.get(button_id)
        if action is not None:
            action()

    def on_text_area_changed(self, event: TextArea.Changed) -> None:
        if self._loading or event.text_area.id != "note-editor":
            return
        self._dirty = True
        state = self.query_one("#save-state", Static)
        state.update("unsaved")
        state.add_class("unsaved")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "findings-table":
            self._edit_selected()

    def _autosave(self) -> None:
        if self._dirty:
            self._save_note()

    def _save_note(self) -> None:
        text = self.query_one("#note-editor", TextArea).text
        self.store.write_note(self.engagement_slug, self.box_slug, self.phase, text)
        self._dirty = False
        state = self.query_one("#save-state", Static)
        state.update("saved")
        state.remove_class("unsaved")

    def _load_note(self) -> None:
        self._loading = True
        text = self.store.read_note(self.engagement_slug, self.box_slug, self.phase)
        self.query_one("#note-editor", TextArea).load_text(text)
        self._dirty = False
        state = self.query_one("#save-state", Static)
        state.update("saved")
        state.remove_class("unsaved")

        def release() -> None:
            self._loading = False

        self.call_after_refresh(release)

    def _mark_phase(self) -> None:
        for key, _label in PHASES:
            self.query_one(f"#phase-{key}", Button).set_class(key == self.phase, "is-current")

    def _refresh_header(self) -> None:
        engagement = self.store.get_engagement(self.engagement_slug)
        box = self.store.get_box(self.engagement_slug, self.box_slug)
        self.query_one("#brand", Static).update(brand(f"{engagement.name}  ·  {box.name}"))
        self.query_one("#meta", Static).update(Text(_meta_text(box)))

    def _reload_findings(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.clear()
        findings = self.store.list_findings(self.engagement_slug, self.box_slug)
        for finding in sorted(findings, key=lambda item: item.sort_key()):
            severity = Text(finding.severity, style=SEVERITY_STYLE.get(finding.severity, ""))
            table.add_row(
                finding.title,
                severity,
                f"{finding.score:.1f}",
                key=finding.id,
            )

    def _open_finding(self, finding: Finding | None) -> None:
        box = self.store.get_box(self.engagement_slug, self.box_slug)
        host = finding.affected_host if finding is not None else (box.ip or "")
        self.app.push_screen(FindingForm(finding, default_host=host), self._finding_saved)

    def _finding_saved(self, finding: Finding | None) -> None:
        if finding is None:
            return
        try:
            saved = self.store.save_finding(self.engagement_slug, self.box_slug, finding)
        except SpinneretError as exc:
            self.notify(str(exc), severity="error", markup=False)
            return
        self._reload_findings()
        self.notify(f"Saved {saved.id}  {saved.score:.1f} {saved.severity}", markup=False)

    def _edit_selected(self) -> None:
        finding_id = selected_key(self.query_one("#findings-table", DataTable))
        if finding_id is None:
            self.notify("Select a finding first.", markup=False)
            return
        finding = next(
            (
                item
                for item in self.store.list_findings(self.engagement_slug, self.box_slug)
                if item.id == finding_id
            ),
            None,
        )
        if finding is None:
            return
        self._open_finding(finding)

    def _delete_selected(self) -> None:
        finding_id = selected_key(self.query_one("#findings-table", DataTable))
        if finding_id is None:
            self.notify("Select a finding first.", markup=False)
            return
        self.app.push_screen(
            ConfirmScreen(f"Delete finding {finding_id}?"),
            lambda confirmed: self._deleted_finding(finding_id, confirmed),
        )

    def _deleted_finding(self, finding_id: str, confirmed: bool | None) -> None:
        if not confirmed:
            return
        try:
            self.store.delete_finding(self.engagement_slug, self.box_slug, finding_id)
        except SpinneretError as exc:
            self.notify(str(exc), severity="error", markup=False)
            return
        self._reload_findings()

    def _scratched(self, text: str | None) -> None:
        if not text:
            return
        try:
            self.store.append_scratch(self.engagement_slug, self.box_slug, text)
        except SpinneretError as exc:
            self.notify(str(exc), severity="error", markup=False)
            return
        if self.phase == "scratch":
            self._load_note()
        self.notify("Appended to scratch", markup=False)

    def _imported(self, choice: ImportChoice | None) -> None:
        if choice is None:
            return
        directory = self.store.screenshots_dir(self.engagement_slug, self.box_slug)
        suffix = ".png"
        source = Path(choice.path).expanduser() if choice.kind == "file" else None
        if source is not None:
            suffix = source.suffix.lower() or ".png"
            if suffix not in IMAGE_SUFFIXES:
                self.notify("Import a png, jpg, gif, or webp file.", severity="error", markup=False)
                return
        dest = new_screenshot_path(directory, suffix=suffix)
        try:
            if choice.kind == "clipboard":
                import_clipboard_image(dest)
            else:
                assert source is not None
                import_image_file(source, dest)
        except SpinneretError as exc:
            self.notify(str(exc), severity="error", markup=False)
            return
        self._link_image(dest.name)
        self.notify(f"Linked {dest.name} into {PHASE_LABELS[self.phase]}", markup=False)

    def _link_image(self, filename: str) -> None:
        editor = self.query_one("#note-editor", TextArea)
        updated = append_image_link(editor.text, filename)
        self._loading = True
        editor.load_text(updated)
        self.store.write_note(self.engagement_slug, self.box_slug, self.phase, updated)
        self._dirty = False
        state = self.query_one("#save-state", Static)
        state.update("saved")
        state.remove_class("unsaved")

        def release() -> None:
            self._loading = False

        self.call_after_refresh(release)

    def _exported(self, choice: tuple[bool, bool] | None) -> None:
        if not choice:
            return
        markdown, pdf = choice
        directory = self.store.engagement_dir(self.engagement_slug)
        try:
            written = export_engagement(
                self.store,
                self.engagement_slug,
                markdown_path=directory / "report.md" if markdown else None,
                pdf_path=directory / "report.pdf" if pdf else None,
            )
        except SpinneretError as exc:
            self.notify(str(exc), severity="error", markup=False)
            return
        self.notify("Wrote " + ", ".join(path.name for path in written), markup=False)

    def _metadata(self, box: Box, draft: BoxDraft | None) -> None:
        if draft is None:
            return
        box.name = draft.name
        box.ip = draft.ip
        box.hostnames = list(draft.hostnames)
        box.os = draft.os
        box.user = draft.user
        box.domain = draft.domain
        box.lhost = draft.lhost
        try:
            self.store.update_box(box)
        except SpinneretError as exc:
            self.notify(str(exc), severity="error", markup=False)
            return
        self._refresh_header()


def _meta_text(box: Box) -> str:
    hosts = ", ".join(box.hostnames) if box.hostnames else "—"
    return (
        f"{box.name}\n"
        f"{box.ip or 'no ip'}   {hosts}\n"
        f"os {box.os or '—'}   user {box.user or '—'}   "
        f"domain {box.domain or '—'}   lhost {box.lhost or '—'}"
    )
