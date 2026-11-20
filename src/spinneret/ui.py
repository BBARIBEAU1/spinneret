"""Small widgets and helpers shared by the screens."""

from __future__ import annotations

from rich.text import Text
from textual.widgets import DataTable, Static

SEVERITY_STYLE = {
    "critical": "#ff5d5d",
    "high": "#ff9f43",
    "medium": "#f6c945",
    "low": "#6cb6ff",
    "none": "#8ea197",
}


def selected_key(table: DataTable) -> str | None:
    """Row key under the cursor, or None when the table is empty."""
    if table.row_count == 0:
        return None
    row_key, _column_key = table.coordinate_to_cell_key(table.cursor_coordinate)
    value = row_key.value
    return None if value is None else str(value)


def brand(subtitle: str) -> Text:
    """One-line spider mark plus a subtitle."""
    text = Text()
    text.append("\\  |  /  ", style="bold #7dffb3")
    text.append("spinneret", style="bold #e7f0ea")
    if subtitle:
        text.append("  " + subtitle, style="#8ea197")
    return text


class Splash(Static):
    """Home-screen mark. Small on purpose."""

    def render(self) -> Text:
        green = "bold #7dffb3"
        text = Text()
        text.append("  \\  |  /\n", style=green)
        text.append(" --  *  --", style=green)
        text.append("   spinneret\n", style="bold #e7f0ea")
        text.append("  /  |  \\\n", style=green)
        text.append("silk for the engagement", style="#8ea197")
        return text
