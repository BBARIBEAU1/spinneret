"""Console entry point."""

import pytest

from spinneret.cli import main
from spinneret.models import Finding
from spinneret.storage import Store


def test_version_exits_cleanly() -> None:
    with pytest.raises(SystemExit) as caught:
        main(["--version"])
    assert caught.value.code == 0


def test_export_command_writes_both_formats(tmp_path, capsys) -> None:
    store = Store(tmp_path)
    engagement = store.create_engagement("Lab")
    box = store.create_box(engagement.slug, "Host", ip="10.10.10.5")
    store.save_finding(
        engagement.slug,
        box.slug,
        Finding(
            id="",
            title="Info leak",
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            score=0,
            severity="",
            affected_host="10.10.10.5",
        ),
    )
    code = main(["--root", str(tmp_path), "export", engagement.slug])
    assert code == 0
    captured = capsys.readouterr()
    assert "report.md" in captured.out
    assert "report.pdf" in captured.out
    assert (tmp_path / engagement.slug / "report.md").is_file()
    assert (tmp_path / engagement.slug / "report.pdf").read_bytes().startswith(b"%PDF")


def test_export_unknown_engagement(tmp_path, capsys) -> None:
    code = main(["--root", str(tmp_path), "export", "missing"])
    assert code == 1
    assert "No engagement" in capsys.readouterr().err
