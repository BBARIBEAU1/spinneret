"""End-to-end TUI: engagement, notes, finding, cheat sheet, export, screenshot link."""

import asyncio
from pathlib import Path

from textual.widgets import DataTable, Input, TextArea

from spinneret.app import SpinneretApp
from spinneret.screenshots import ScreenshotError


def test_operator_flow(tmp_path: Path, monkeypatch) -> None:
    def fake_capture(dest: Path, **kwargs) -> str:
        dest.write_bytes(b"\x89PNG\r\n\x1a\n")
        return "flameshot"

    monkeypatch.setattr("spinneret.screens.workspace.capture_screenshot", fake_capture)

    async def run() -> None:
        app = SpinneretApp(root=tmp_path, cheatsheet_paths=[])
        async with app.run_test(size=(140, 48)) as pilot:
            await pilot.pause()
            await pilot.press("n")
            await pilot.pause()
            pilot.app.screen.query_one("#eng-name", Input).value = "Academy"
            pilot.app.screen.query_one("#eng-client", Input).value = "HTB"
            await pilot.press("ctrl+s")
            await pilot.pause()

            table = pilot.app.screen.query_one("#engagement-table", DataTable)
            assert table.row_count == 1
            await pilot.press("enter")
            await pilot.pause()

            await pilot.press("n")
            await pilot.pause()
            pilot.app.screen.query_one("#box-name", Input).value = "Lame"
            pilot.app.screen.query_one("#box-ip", Input).value = "10.10.10.3"
            pilot.app.screen.query_one("#box-hosts", Input).value = "lame.htb"
            await pilot.press("ctrl+s")
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()

            editor = pilot.app.screen.query_one("#note-editor", TextArea)
            editor.text = "# Recon\n\nPort 21 open\n"
            await pilot.press("f2")
            await pilot.pause()

            await pilot.press("alt+2")
            await pilot.pause()
            enum_text = pilot.app.screen.query_one("#note-editor", TextArea).text
            assert "Enumeration" in enum_text
            await pilot.press("alt+1")
            await pilot.pause()
            assert "Port 21 open" in pilot.app.screen.query_one("#note-editor", TextArea).text

            await pilot.press("f4")
            await pilot.pause()
            pilot.app.screen.query_one("#find-title", Input).value = "Anonymous FTP"
            pilot.app.screen.query_one(
                "#find-vector", Input
            ).value = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
            await pilot.pause()
            await pilot.press("ctrl+s")
            await pilot.pause()

            await pilot.press("f5")
            await pilot.pause()
            cheat = pilot.app.screen
            cheat.query_one("#cheat-filter", Input).value = "axfr"
            await pilot.pause()
            assert "10.10.10.3" in cheat.filled_command
            assert "axfr" in cheat.filled_command
            await pilot.press("escape")
            await pilot.pause()

            await pilot.press("f8")
            await pilot.pause()
            note = pilot.app.screen.query_one("#note-editor", TextArea).text
            assert "../screenshots/shot-" in note

            await pilot.press("f10")
            await pilot.pause()
            await pilot.press("ctrl+s")
            await pilot.pause()

    asyncio.run(run())

    root = tmp_path / "academy" / "lame"
    assert "Port 21 open" in (root / "notes" / "recon.md").read_text(encoding="utf-8")
    assert "../screenshots/" in (root / "notes" / "recon.md").read_text(encoding="utf-8")
    finding = (root / "findings" / "F-001.yaml").read_text(encoding="utf-8")
    assert "Anonymous FTP" in finding
    assert "7.5" in finding
    report = (tmp_path / "academy" / "report.md").read_text(encoding="utf-8")
    assert "Anonymous FTP" in report
    assert "Placeholder" in report
    assert (tmp_path / "academy" / "report.pdf").read_bytes().startswith(b"%PDF")


def test_screenshot_failure_stays_in_the_note(tmp_path: Path, monkeypatch) -> None:
    def fail(dest: Path, **kwargs) -> str:
        raise ScreenshotError("No screenshot tool found. Install flameshot.")

    monkeypatch.setattr("spinneret.screens.workspace.capture_screenshot", fail)

    async def run() -> None:
        app = SpinneretApp(root=tmp_path, cheatsheet_paths=[])
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.press("n")
            await pilot.pause()
            pilot.app.screen.query_one("#eng-name", Input).value = "Lab"
            await pilot.press("ctrl+s")
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            await pilot.press("n")
            await pilot.pause()
            pilot.app.screen.query_one("#box-name", Input).value = "Box"
            await pilot.press("ctrl+s")
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            before = pilot.app.screen.query_one("#note-editor", TextArea).text
            await pilot.press("f8")
            await pilot.pause()
            after = pilot.app.screen.query_one("#note-editor", TextArea).text
            assert after == before
            assert not list((tmp_path / "lab" / "box" / "screenshots").glob("shot-*"))

    asyncio.run(run())
