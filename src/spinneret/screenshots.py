"""Capture and import screenshots into a box folder.

The capture tool is chosen at runtime from whatever is installed:
flameshot, scrot, gnome-screenshot, maim, then grim. Region selection is
preferred. A missing tool raises :class:`ScreenshotError` with the install
list so the TUI can fall back to importing a file.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from spinneret.errors import SpinneretError

Which = Callable[[str], str | None]
Runner = Callable[..., subprocess.CompletedProcess]

TOOL_ORDER: tuple[str, ...] = (
    "flameshot",
    "scrot",
    "gnome-screenshot",
    "maim",
    "grim",
)
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp"}
_PNG = b"\x89PNG"


class ScreenshotError(SpinneretError):
    """Capture or import could not produce an image file."""


def available_tools(which: Which = shutil.which) -> list[str]:
    """Installed capture tools, in preference order."""
    return [name for name in TOOL_ORDER if which(name)]


def new_screenshot_path(directory: Path, suffix: str = ".png", now: datetime | None = None) -> Path:
    """Return a free ``shot-<timestamp>`` path inside ``directory``."""
    directory.mkdir(parents=True, exist_ok=True)
    moment = now or datetime.now(UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    stamp = moment.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    candidate = directory / f"shot-{stamp}{suffix}"
    counter = 2
    while candidate.exists():
        candidate = directory / f"shot-{stamp}-{counter}{suffix}"
        counter += 1
    return candidate


def image_markdown(filename: str) -> str:
    """Markdown image pointing from a note file at ``../screenshots``."""
    return f"![{filename}](../screenshots/{filename})"


def append_image_link(note: str, filename: str) -> str:
    """Append an image link to a note, keeping a blank line before it."""
    link = image_markdown(filename)
    body = note
    if body and not body.endswith("\n"):
        body += "\n"
    if body and not body.endswith("\n\n"):
        body += "\n"
    return f"{body}{link}\n"


def capture_screenshot(
    dest: Path,
    *,
    which: Which = shutil.which,
    run: Runner = subprocess.run,
) -> str:
    """Run the first available tool and write ``dest``. Returns the tool name."""
    tools = available_tools(which)
    if not tools:
        raise ScreenshotError(
            "No screenshot tool found. Install flameshot, scrot, "
            "gnome-screenshot, maim, or grim, or import a PNG instead."
        )
    dest.parent.mkdir(parents=True, exist_ok=True)
    tool = tools[0]
    try:
        _CAPTURE[tool](dest, which, run)
    except ScreenshotError:
        _drop_empty(dest)
        raise
    if not dest.is_file() or dest.stat().st_size == 0:
        _drop_empty(dest)
        raise ScreenshotError(f"{tool} wrote no image. The capture may have been cancelled.")
    return tool


def import_clipboard_image(
    dest: Path,
    *,
    which: Which = shutil.which,
    run: Runner = subprocess.run,
) -> str:
    """Read a PNG from the Wayland or X clipboard. Returns the tool name."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    attempts: list[tuple[str, Sequence[str]]] = []
    if which("wl-paste"):
        attempts.append(("wl-paste", ["wl-paste", "--type", "image/png"]))
    if which("xclip"):
        attempts.append(("xclip", ["xclip", "-selection", "clipboard", "-t", "image/png", "-o"]))
    if not attempts:
        raise ScreenshotError(
            "Clipboard image import needs wl-paste or xclip. Import a file path instead."
        )
    errors: list[str] = []
    for name, argv in attempts:
        result = run(list(argv), capture_output=True)
        data = result.stdout or b""
        if result.returncode == 0 and data.startswith(_PNG):
            dest.write_bytes(data)
            return name
        errors.append(name)
    raise ScreenshotError("Clipboard has no PNG (" + ", ".join(errors) + " could not read one).")


def import_image_file(src: Path, dest: Path) -> None:
    """Copy an existing image into the box screenshot folder."""
    if not src.is_file():
        raise ScreenshotError(f"No image at {src}.")
    if src.suffix.lower() not in IMAGE_SUFFIXES:
        raise ScreenshotError("Import a png, jpg, gif, or webp file.")
    dest.parent.mkdir(parents=True, exist_ok=True)
    if src.resolve() == dest.resolve():
        return
    shutil.copyfile(src, dest)


def _capture_flameshot(dest: Path, _which: Which, run: Runner) -> None:
    result = run(["flameshot", "gui", "-r"], capture_output=True)
    _write_stdout_image(dest, result, "flameshot")


def _capture_scrot(dest: Path, _which: Which, run: Runner) -> None:
    result = run(["scrot", "-s", str(dest)], capture_output=True)
    _check_status(result, "scrot")


def _capture_gnome(dest: Path, _which: Which, run: Runner) -> None:
    result = run(["gnome-screenshot", "-a", "-f", str(dest)], capture_output=True)
    _check_status(result, "gnome-screenshot")


def _capture_maim(dest: Path, _which: Which, run: Runner) -> None:
    result = run(["maim", "-s"], capture_output=True)
    _write_stdout_image(dest, result, "maim")


def _capture_grim(dest: Path, which: Which, run: Runner) -> None:
    if which("slurp"):
        geo = run(["slurp"], capture_output=True)
        if geo.returncode != 0:
            raise ScreenshotError("Region selection cancelled.")
        geometry = (geo.stdout or b"").decode(errors="replace").strip()
        if not geometry:
            raise ScreenshotError("Region selection cancelled.")
        result = run(["grim", "-g", geometry], capture_output=True)
    else:
        result = run(["grim"], capture_output=True)
    _write_stdout_image(dest, result, "grim")


_CAPTURE = {
    "flameshot": _capture_flameshot,
    "scrot": _capture_scrot,
    "gnome-screenshot": _capture_gnome,
    "maim": _capture_maim,
    "grim": _capture_grim,
}


def _write_stdout_image(dest: Path, result: subprocess.CompletedProcess, tool: str) -> None:
    _check_status(result, tool)
    data = result.stdout or b""
    if not data.startswith(_PNG) and not data.startswith(b"\xff\xd8"):
        raise ScreenshotError(f"{tool} returned no image. The capture may have been cancelled.")
    dest.write_bytes(data)


def _check_status(result: subprocess.CompletedProcess, tool: str) -> None:
    if result.returncode != 0:
        detail = (result.stderr or b"").decode(errors="replace").strip()
        message = f"{tool} exited {result.returncode}."
        if detail:
            message = f"{message} {detail}"
        else:
            message = f"{message} The capture may have been cancelled."
        raise ScreenshotError(message)


def _drop_empty(dest: Path) -> None:
    if dest.exists() and dest.stat().st_size == 0:
        dest.unlink()
