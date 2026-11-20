"""Export a Textual SVG of the workspace for the README.

Run from the repo root with the package installed:

    python scripts/export_screenshot.py
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

from spinneret.app import SpinneretApp
from spinneret.models import Finding
from spinneret.storage import Store

ROOT = Path("/tmp/spinneret-screenshot")
OUTPUT = Path(__file__).resolve().parents[1] / "docs" / "screenshot.svg"


def seed(store: Store) -> None:
    engagement = store.create_engagement("HTB CPTS", client="Hack The Box")
    box = store.create_box(
        engagement.slug,
        "Lame",
        ip="10.10.10.3",
        hostnames=["lame.htb"],
        os="Linux",
        lhost="10.10.14.8",
    )
    store.write_note(
        engagement.slug,
        box.slug,
        "recon",
        "# Recon\n\n"
        "22/tcp   open  ssh\n"
        "21/tcp   open  ftp\n"
        "139/tcp  open  netbios-ssn\n"
        "445/tcp  open  microsoft-ds\n\n"
        "Anonymous FTP accepts a write.\n",
    )
    store.save_finding(
        engagement.slug,
        box.slug,
        Finding(
            id="",
            title="Anonymous FTP write",
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            score=0,
            severity="",
            affected_host="10.10.10.3",
            description="The FTP service allows anonymous users to upload files.",
            remediation="Disable anonymous write, or anonymous login entirely.",
        ),
    )


async def capture() -> None:
    if ROOT.exists():
        shutil.rmtree(ROOT)
    store = Store(ROOT)
    seed(store)
    app = SpinneretApp(root=ROOT, cheatsheet_paths=[])
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        svg = pilot.app.export_screenshot(title="spinneret", simplify=True)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(svg, encoding="utf-8")
    print(f"wrote {OUTPUT} ({OUTPUT.stat().st_size} bytes)")


if __name__ == "__main__":
    asyncio.run(capture())
