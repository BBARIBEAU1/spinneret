"""Boxes inside one engagement."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Static

from spinneret.errors import SpinneretError
from spinneret.models import Box
from spinneret.report import export_engagement
from spinneret.screens.modals import (
    BoxDraft,
    BoxForm,
    ConfirmScreen,
    ExportScreen,
    HelpScreen,
    SummaryScreen,
)
from spinneret.storage import Store
from spinneret.ui import brand, selected_key


class EngagementScreen(Screen):
    BINDINGS = [
        Binding("n", "new_box", "New box"),
        Binding("o", "open_box", "Open"),
        Binding("e", "edit_box", "Edit"),
        Binding("d", "delete_box", "Delete"),
        Binding("s", "summary", "Summary"),
        Binding("x", "export", "Export"),
        Binding("escape", "back", "Back"),
        Binding("f1", "help", "Help", priority=True),
    ]

    def __init__(self, engagement_slug: str) -> None:
        super().__init__()
        self.engagement_slug = engagement_slug

    def compose(self) -> ComposeResult:
        yield Static("", id="brand")
        yield DataTable(id="box-table")
        with Horizontal(id="action-bar"):
            yield Button("New box", id="new-box")
            yield Button("Summary", id="summary")
            yield Button("Export", id="export-engagement")
            yield Button("Back", id="back-engagement")
        yield Footer()

    def on_mount(self) -> None:
        engagement = self.store.get_engagement(self.engagement_slug)
        if engagement.client:
            subtitle = f"{engagement.name}  ·  {engagement.client}"
        else:
            subtitle = engagement.name
        self.query_one("#brand", Static).update(brand(subtitle))
        table = self.query_one("#box-table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_columns("Box", "IP", "Hostnames", "Findings")
        self.reload()
        table.focus()

    @property
    def store(self) -> Store:
        return self.app.store  # type: ignore[attr-defined]

    def reload(self) -> None:
        table = self.query_one("#box-table", DataTable)
        table.clear()
        for box in self.store.list_boxes(self.engagement_slug):
            hosts = ", ".join(box.hostnames) if box.hostnames else "—"
            count = len(self.store.list_findings(self.engagement_slug, box.slug))
            table.add_row(box.name, box.ip or "—", hosts, str(count), key=box.slug)

    def action_help(self) -> None:
        self.app.push_screen(HelpScreen())

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_new_box(self) -> None:
        self.app.push_screen(BoxForm(), self._created)

    def action_edit_box(self) -> None:
        box = self._selected()
        if box is None:
            return
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
            lambda updated: self._edited(box, updated),
        )

    def action_open_box(self) -> None:
        box = self._selected()
        if box is None:
            return
        from spinneret.screens.workspace import WorkspaceScreen

        self.app.push_screen(WorkspaceScreen(self.engagement_slug, box.slug))

    def action_delete_box(self) -> None:
        box = self._selected()
        if box is None:
            return
        self.app.push_screen(
            ConfirmScreen(f"Delete {box.name} and its notes?"),
            lambda confirmed: self._deleted(box, confirmed),
        )

    def action_summary(self) -> None:
        text = self.store.read_summary(self.engagement_slug)
        self.app.push_screen(SummaryScreen(text), self._summary_saved)

    def action_export(self) -> None:
        directory = self.store.engagement_dir(self.engagement_slug)
        label = f"Writes report.md and report.pdf in {directory}"
        self.app.push_screen(ExportScreen(label), self._exported)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        actions = {
            "new-box": self.action_new_box,
            "summary": self.action_summary,
            "export-engagement": self.action_export,
            "back-engagement": self.action_back,
        }
        action = actions.get(event.button.id or "")
        if action is not None:
            action()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "box-table":
            self.action_open_box()

    def _selected(self) -> Box | None:
        slug = selected_key(self.query_one("#box-table", DataTable))
        if slug is None:
            self.notify("Select a box first.", markup=False)
            return None
        return self.store.get_box(self.engagement_slug, slug)

    def _created(self, draft: BoxDraft | None) -> None:
        if draft is None:
            return
        try:
            box = self.store.create_box(
                self.engagement_slug,
                draft.name,
                ip=draft.ip,
                hostnames=draft.hostnames,
                os=draft.os,
                user=draft.user,
                domain=draft.domain,
                lhost=draft.lhost,
            )
        except SpinneretError as exc:
            self.notify(str(exc), severity="error", markup=False)
            return
        self.reload()
        self.notify(f"Created {box.name}", markup=False)

    def _edited(self, box: Box, draft: BoxDraft | None) -> None:
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
        self.reload()

    def _deleted(self, box: Box, confirmed: bool | None) -> None:
        if not confirmed:
            return
        try:
            self.store.delete_box(self.engagement_slug, box.slug)
        except SpinneretError as exc:
            self.notify(str(exc), severity="error", markup=False)
            return
        self.reload()
        self.notify(f"Deleted {box.name}", markup=False)

    def _summary_saved(self, text: str | None) -> None:
        if text is None:
            return
        self.store.write_summary(self.engagement_slug, text)
        self.notify("Saved summary.md", markup=False)

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
