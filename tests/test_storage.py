"""Filesystem layout for engagements, notes, and findings."""

from datetime import UTC, datetime

import pytest

from spinneret.storage import StorageError, Store


def test_engagement_box_notes_and_findings_round_trip(tmp_path) -> None:
    store = Store(tmp_path)
    engagement = store.create_engagement("HTB CPTS", client="Hack The Box")
    again = store.create_engagement("HTB CPTS")
    assert engagement.slug == "htb-cpts"
    assert again.slug == "htb-cpts-2"

    box = store.create_box(
        engagement.slug,
        "Lame",
        ip="10.10.10.3",
        hostnames=["lame.htb"],
        os="Linux",
        lhost="10.10.14.5",
    )
    assert (tmp_path / "htb-cpts" / "lame" / "notes" / "recon.md").is_file()
    assert (tmp_path / "htb-cpts" / "lame" / "screenshots").is_dir()

    store.write_note(engagement.slug, box.slug, "recon", "# Recon\n\n22/tcp ssh\n")
    assert "ssh" in store.read_note(engagement.slug, box.slug, "recon")

    stamp = datetime(2026, 11, 20, 21, 44, 2, tzinfo=UTC)
    store.append_scratch(engagement.slug, box.slug, "found port 80", now=stamp)
    scratch = store.read_note(engagement.slug, box.slug, "scratch")
    assert "## 2026-11-20 21:44:02Z" in scratch
    assert "found port 80" in scratch

    from spinneret.models import Finding

    saved = store.save_finding(
        engagement.slug,
        box.slug,
        Finding(
            id="",
            title="Anonymous FTP",
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            score=0,
            severity="",
            affected_host="10.10.10.3",
            description="Writable anonymous FTP.",
            evidence=["screenshots/ftp.png"],
            remediation="Require authentication.",
        ),
    )
    assert saved.id == "F-001"
    assert saved.score == 7.5
    assert saved.severity == "high"
    loaded = store.list_findings(engagement.slug, box.slug)
    assert loaded[0].title == "Anonymous FTP"
    assert loaded[0].evidence == ["screenshots/ftp.png"]

    other = store.create_box(engagement.slug, "Blue", ip="10.10.10.40")
    second = store.save_finding(
        engagement.slug,
        other.slug,
        Finding(
            id="",
            title="SMB",
            vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            score=0,
            severity="",
            affected_host="10.10.10.40",
        ),
    )
    assert second.id == "F-002"

    box.ip = "10.10.10.30"
    store.update_box(box)
    assert store.get_box(engagement.slug, box.slug).ip == "10.10.10.30"

    store.delete_finding(engagement.slug, box.slug, "F-001")
    assert store.list_findings(engagement.slug, box.slug) == []
    store.delete_box(engagement.slug, box.slug)
    assert store.list_boxes(engagement.slug)[0].slug == "blue"
    store.delete_engagement(engagement.slug)
    assert store.list_engagements() == [store.get_engagement(again.slug)]


def test_summary_and_rejected_names(tmp_path) -> None:
    store = Store(tmp_path)
    engagement = store.create_engagement("Lab")
    assert store.read_summary(engagement.slug) == ""
    store.write_summary(engagement.slug, "Short summary.\n")
    assert store.read_summary(engagement.slug) == "Short summary.\n"
    with pytest.raises(StorageError):
        store.create_engagement("   ")
    with pytest.raises(StorageError):
        store.write_note(engagement.slug, "missing", "recon", "x")
    with pytest.raises(StorageError):
        store.read_note(engagement.slug, "nope", "../secrets")


def test_placeholders_skip_blank_fields(tmp_path) -> None:
    store = Store(tmp_path)
    engagement = store.create_engagement("Lab")
    box = store.create_box(engagement.slug, "Lame", ip="10.10.10.3", hostnames=["lame.htb"])
    values = store.get_box(engagement.slug, box.slug).placeholders()
    assert values["IP"] == "10.10.10.3"
    assert values["HOST"] == "lame.htb"
    assert values["DOMAIN"] == "lame.htb"
    assert "LHOST" not in values
    assert "USER" not in values
