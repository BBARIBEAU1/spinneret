"""Built-in cheat sheet plus optional user overlays.

Commands are text. spinneret copies them; it does not run them. Tokens such
as ``<IP>`` are filled from the open box when that field is set.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

import yaml

from spinneret.errors import SpinneretError

_PLACEHOLDER = re.compile(r"<([A-Za-z][A-Za-z0-9_]*)>")


class CheatsheetError(SpinneretError):
    """A cheat sheet file is missing a field or is not valid YAML."""


@dataclass(frozen=True)
class CheatEntry:
    id: str
    title: str
    category: str
    command: str
    notes: str = ""


def bundled_text() -> str:
    """YAML shipped inside the package."""
    return files("spinneret").joinpath("data/cheatsheet.yaml").read_text(encoding="utf-8")


def load_entries(extra_paths: list[Path] | None = None) -> list[CheatEntry]:
    """Load the bundled sheet, then let each extra file override by id."""
    entries = parse_cheatsheet(bundled_text(), source="built-in cheat sheet")
    for path in extra_paths or []:
        if not path.is_file():
            continue
        overlay = parse_cheatsheet(path.read_text(encoding="utf-8"), source=str(path))
        entries = merge_entries(entries, overlay)
    return entries


def parse_cheatsheet(text: str, source: str = "cheat sheet") -> list[CheatEntry]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise CheatsheetError(f"{source} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        raise CheatsheetError(f"{source} needs an 'entries' list.")
    parsed: list[CheatEntry] = []
    seen: set[str] = set()
    for index, raw in enumerate(data["entries"], start=1):
        if not isinstance(raw, dict):
            raise CheatsheetError(f"{source} entry {index} is not a mapping.")
        entry_id = str(raw.get("id") or "").strip()
        title = str(raw.get("title") or "").strip()
        category = str(raw.get("category") or "").strip()
        command = str(raw.get("command") or "").strip()
        notes = str(raw.get("notes") or "").strip()
        if not entry_id or not title or not command:
            raise CheatsheetError(f"{source} entry {index} needs id, title, and command.")
        if entry_id in seen:
            raise CheatsheetError(f"{source} repeats id {entry_id}.")
        seen.add(entry_id)
        parsed.append(
            CheatEntry(
                id=entry_id,
                title=title,
                category=category or "General",
                command=command,
                notes=notes,
            )
        )
    return parsed


def merge_entries(base: list[CheatEntry], overlay: list[CheatEntry]) -> list[CheatEntry]:
    """Overlay wins on the same id. New ids are appended."""
    by_id = {entry.id: entry for entry in base}
    order = [entry.id for entry in base]
    for entry in overlay:
        if entry.id not in by_id:
            order.append(entry.id)
        by_id[entry.id] = entry
    return [by_id[entry_id] for entry_id in order]


def fill_placeholders(command: str, values: dict[str, str]) -> str:
    """Replace ``<TOKEN>`` when ``values`` has a non-empty TOKEN."""

    def replace(match: re.Match[str]) -> str:
        key = match.group(1).upper()
        replacement = values.get(key, "")
        if not replacement:
            return match.group(0)
        return replacement

    return _PLACEHOLDER.sub(replace, command)


def search(entries: list[CheatEntry], query: str) -> list[CheatEntry]:
    """Rank entries for a fuzzy query. An empty query keeps file order."""
    cleaned = query.strip().lower()
    if not cleaned:
        return list(entries)
    ranked: list[tuple[int, int, CheatEntry]] = []
    for index, entry in enumerate(entries):
        score = _score(
            cleaned,
            " ".join((entry.title, entry.category, entry.command, entry.notes, entry.id)),
        )
        if score > 0:
            ranked.append((score, -index, entry))
    ranked.sort(reverse=True)
    return [entry for _score_value, _index, entry in ranked]


def _score(query: str, haystack: str) -> int:
    text = haystack.lower()
    if query in text:
        return 1_000 + max(0, 200 - text.index(query))
    position = 0
    score = 0
    previous = -2
    for index, character in enumerate(text):
        if position < len(query) and character == query[position]:
            score += 5
            if index == previous + 1:
                score += 8
            if index == 0 or text[index - 1] in " /-_.:":
                score += 4
            previous = index
            position += 1
    if position < len(query):
        return 0
    return score
