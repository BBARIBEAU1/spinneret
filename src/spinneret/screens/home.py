"""Engagement list."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Static

from spinneret.errors import SpinneretError
from spinneret.models import Engagement
from spinneret.screens.modals import ConfirmScreen, EngagementDraft, EngagementForm, HelpScreen
from spinneret.storage import Store
from spinneret.ui import Splash, selected_key


class HomeScreen(Screen):
    BINDINGS = [
        Binding("n", "new_engagement", "New"),
        Binding("o", "open_engagement", "Open"),
        Binding("e", "edit_engagement", "Edit"),
        Binding("d", "delete_engagement", "Delete"),
        Binding("q", "quit", "Quit"),
        Binding("f1", "help", "Help", priority=True),
        Binding("question_mark", "help", "Help", show=False),
    ]

    def compose(self) -> ComposeResult:
        yield Splash()
        yield Static("", id="root-path")
        yield Static("No engagements yet. Press n to start one.", id="empty-hint")
        yield DataTable(id="engagement-table")
        with Horizontal(id="action-bar"):
            yield Button("New", id="new-engagement")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#root-path", Static).update(f"Data  {self.store.root}")
        table = self.query_one("#engagement-table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_columns("Engagement", "Client", "Boxes", "Created")
        self.reload()
        table.focus()

    @property
    def store(self) -> Store:
        return self.app.store  # type: ignore[attr-defined]

    def reload(self) -> None:
        table = self.query_one("#engagement-table", DataTable)
        table.clear()
        engagements = self.store.list_engagements()
        self.query_one("#empty-hint", Static).display = not engagements
        for engagement in engagements:
            count = len(self.store.list_boxes(engagement.slug))
            table.add_row(
                engagement.name,
                engagement.client or "—",
                str(count),
                engagement.created[:10],
                key=engagement.slug,
            )

    def action_help(self) -> None:
        self.app.push_screen(HelpScreen())

    def action_quit(self) -> None:
        self.app.exit()

    def action_new_engagement(self) -> None:
        self.app.push_screen(EngagementForm(), self._created)

    def action_edit_engagement(self) -> None:
        engagement = self._selected()
        if engagement is None:
            return
        self.app.push_screen(
            EngagementForm(name=engagement.name, client=engagement.client, editing=True),
            lambda draft: self._edited(engagement, draft),
        )

    def action_open_engagement(self) -> None:
        engagement = self._selected()
        if engagement is None:
            return
        from spinneret.screens.engagement import EngagementScreen

        self.app.push_screen(EngagementScreen(engagement.slug))

    def action_delete_engagement(self) -> None:
        engagement = self._selected()
        if engagement is None:
            return
        self.app.push_screen(
            ConfirmScreen(f"Delete {engagement.name} and all of its notes?"),
            lambda confirmed: self._deleted(engagement, confirmed),
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "new-engagement":
            self.action_new_engagement()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "engagement-table":
            self.action_open_engagement()

    def _selected(self) -> Engagement | None:
        slug = selected_key(self.query_one("#engagement-table", DataTable))
        if slug is None:
            self.notify("Select an engagement first.", markup=False)
            return None
        return self.store.get_engagement(slug)

    def _created(self, draft: EngagementDraft | None) -> None:
        if draft is None:
            return
        try:
            engagement = self.store.create_engagement(draft.name, draft.client)
        except SpinneretError as exc:
            self.notify(str(exc), severity="error", markup=False)
            return
        self.reload()
        self.notify(f"Created {engagement.name}", markup=False)

    def _edited(self, engagement: Engagement, draft: EngagementDraft | None) -> None:
        if draft is None:
            return
        engagement.name = draft.name
        engagement.client = draft.client
        try:
            self.store.update_engagement(engagement)
        except SpinneretError as exc:
            self.notify(str(exc), severity="error", markup=False)
            return
        self.reload()

    def _deleted(self, engagement: Engagement, confirmed: bool | None) -> None:
        if not confirmed:
            return
        try:
            self.store.delete_engagement(engagement.slug)
        except SpinneretError as exc:
            self.notify(str(exc), severity="error", markup=False)
            return
        self.reload()
        self.notify(f"Deleted {engagement.name}", markup=False)
