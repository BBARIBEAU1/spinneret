"""System clipboard helpers for cheat-sheet copy.

Textual also emits OSC 52, which many terminals honor. wl-copy and xclip
cover Wayland and X on Kali when OSC 52 is ignored.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable, Sequence

Which = Callable[[str], str | None]
Runner = Callable[..., subprocess.CompletedProcess]


def copy_text(
    text: str,
    *,
    which: Which = shutil.which,
    run: Runner = subprocess.run,
) -> str:
    """Copy ``text``. Returns ``clipboard`` or ``unavailable``."""
    payload = text.encode()
    commands: list[tuple[str, Sequence[str]]] = []
    if which("wl-copy"):
        commands.append(("wl-copy", ["wl-copy"]))
    if which("xclip"):
        commands.append(("xclip", ["xclip", "-selection", "clipboard"]))
    if which("xsel"):
        commands.append(("xsel", ["xsel", "--clipboard", "--input"]))
    for _name, argv in commands:
        result = run(list(argv), input=payload, capture_output=True)
        if result.returncode == 0:
            return "clipboard"
    return "unavailable"
