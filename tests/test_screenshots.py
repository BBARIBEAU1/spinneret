"""Screenshot tool selection, clipboard import, and note links."""

import subprocess
from pathlib import Path

import pytest

from spinneret.screenshots import (
    ScreenshotError,
    append_image_link,
    available_tools,
    capture_screenshot,
    import_clipboard_image,
    import_image_file,
    new_screenshot_path,
)

PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\xcf\xc0"
    b"\x00\x00\x00\x03\x00\x01\x00\x05\xfe\xd4\xef\x00\x00\x00\x00IEND\xaeB`\x82"
)


def _which(present: set[str]):
    def which(name: str) -> str | None:
        if name in present:
            return f"/usr/bin/{name}"
        return None

    return which


def test_tools_follow_preference_order() -> None:
    present = {"grim", "scrot", "flameshot", "maim"}
    assert available_tools(_which(present)) == ["flameshot", "scrot", "maim", "grim"]
    assert available_tools(_which(set())) == []


def test_flameshot_is_preferred_and_writes_the_png(tmp_path: Path) -> None:
    seen: list[list[str]] = []

    def run(argv, **kwargs):
        seen.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, stdout=PNG, stderr=b"")

    dest = tmp_path / "shot.png"
    tool = capture_screenshot(dest, which=_which({"scrot", "flameshot"}), run=run)
    assert tool == "flameshot"
    assert seen[0][0] == "flameshot"
    assert dest.read_bytes() == PNG


def test_missing_tool_explains_what_to_install(tmp_path: Path) -> None:
    with pytest.raises(ScreenshotError, match="flameshot"):
        capture_screenshot(tmp_path / "shot.png", which=_which(set()), run=subprocess.run)


def test_grim_uses_slurp_geometry(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def run(argv, **kwargs):
        calls.append(list(argv))
        if argv[0] == "slurp":
            return subprocess.CompletedProcess(argv, 0, stdout=b"0,0 100x80\n", stderr=b"")
        return subprocess.CompletedProcess(argv, 0, stdout=PNG, stderr=b"")

    dest = tmp_path / "shot.png"
    capture_screenshot(dest, which=_which({"grim", "slurp"}), run=run)
    assert calls[0][0] == "slurp"
    assert calls[1][:3] == ["grim", "-g", "0,0 100x80"]
    assert dest.read_bytes().startswith(b"\x89PNG")


def test_cancelled_capture_raises(tmp_path: Path) -> None:
    def run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, stdout=b"", stderr=b"cancelled")

    with pytest.raises(ScreenshotError, match="cancelled"):
        capture_screenshot(tmp_path / "shot.png", which=_which({"flameshot"}), run=run)


def test_clipboard_png_and_file_import(tmp_path: Path) -> None:
    def run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout=PNG, stderr=b"")

    dest = tmp_path / "clip.png"
    tool = import_clipboard_image(dest, which=_which({"xclip"}), run=run)
    assert tool == "xclip"
    assert dest.read_bytes() == PNG

    source = tmp_path / "proof.png"
    source.write_bytes(PNG)
    copied = tmp_path / "box" / "shot.png"
    import_image_file(source, copied)
    assert copied.read_bytes() == PNG

    with pytest.raises(ScreenshotError):
        import_clipboard_image(tmp_path / "nope.png", which=_which(set()), run=run)


def test_note_link_and_unique_names(tmp_path: Path) -> None:
    first = new_screenshot_path(tmp_path)
    first.write_bytes(PNG)
    second = new_screenshot_path(tmp_path)
    assert first != second
    updated = append_image_link("# Recon\n", first.name)
    assert f"![{first.name}](../screenshots/{first.name})" in updated
    assert updated.startswith("# Recon\n")
