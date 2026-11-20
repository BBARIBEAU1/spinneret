"""Textual application entry."""

from __future__ import annotations

from pathlib import Path

from textual.app import App
from textual.binding import Binding

from spinneret.screens.home import HomeScreen
from spinneret.storage import Store, default_root


class SpinneretApp(App):
    """Keyboard-driven notes for an engagement."""

    TITLE = "spinneret"
    CSS_PATH = "theme.tcss"
    ENABLE_COMMAND_PALETTE = False
    BINDINGS = [Binding("ctrl+q", "quit", "Quit", priority=True, show=False)]

    def __init__(
        self,
        root: Path | None = None,
        cheatsheet_paths: list[Path] | None = None,
    ) -> None:
        super().__init__()
        self.store = Store(root or default_root())
        self._cheatsheet_paths = cheatsheet_paths

    def cheatsheet_paths(self) -> list[Path]:
        """User sheets that overlay the built-in commands.

        ``None`` at construction means the real config and data-root files.
        Tests pass an explicit list so a developer machine cannot change them.
        """
        if self._cheatsheet_paths is not None:
            return list(self._cheatsheet_paths)
        paths: list[Path] = []
        config = Path.home() / ".config" / "spinneret" / "cheatsheet.yaml"
        if config.is_file():
            paths.append(config)
        local = self.store.root / "cheatsheet.yaml"
        if local.is_file():
            paths.append(local)
        return paths

    def on_mount(self) -> None:
        self.push_screen(HomeScreen())

    def action_quit(self) -> None:
        self.exit()
