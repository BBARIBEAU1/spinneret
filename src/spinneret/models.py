"""On-disk records for an engagement, a target, and a finding."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

PHASES: tuple[tuple[str, str], ...] = (
    ("recon", "Recon"),
    ("enumeration", "Enumeration"),
    ("exploitation", "Exploitation"),
    ("privesc", "Privesc"),
    ("loot", "Loot / Creds"),
    ("scratch", "Scratch"),
)
PHASE_LABELS: dict[str, str] = dict(PHASES)
PHASE_KEYS: tuple[str, ...] = tuple(key for key, _label in PHASES)

SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "none": 4,
}

_SLUG = re.compile(r"[^a-z0-9]+")
_HOST_SPLIT = re.compile(r"[\s,]+")


def slugify(name: str) -> str:
    """Turn a display name into a directory-safe slug."""
    value = _SLUG.sub("-", name.strip().lower()).strip("-")
    return value or "untitled"


def parse_hostnames(raw: str) -> list[str]:
    """Split a comma- or whitespace-separated hostname list."""
    return [part for part in _HOST_SPLIT.split(raw.strip()) if part]


def utc_now(moment: datetime | None = None) -> str:
    """ISO-8601 timestamp in UTC with a Z suffix."""
    current = moment or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    return current.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Engagement:
    name: str
    slug: str
    client: str = ""
    created: str = ""


@dataclass
class Box:
    name: str
    slug: str
    engagement: str
    ip: str = ""
    hostnames: list[str] = field(default_factory=list)
    os: str = ""
    user: str = ""
    domain: str = ""
    lhost: str = ""
    created: str = ""

    def placeholders(self) -> dict[str, str]:
        """Values that fill ``<IP>``-style tokens in the cheat sheet.

        Empty fields are omitted so the token stays visible in the command.
        """
        host = self.hostnames[0] if self.hostnames else ""
        domain = self.domain.strip()
        if not domain and "." in host:
            domain = host
        pairs = {
            "IP": self.ip.strip(),
            "HOST": (host or self.ip).strip(),
            "HOSTNAME": (host or self.name).strip(),
            "DOMAIN": domain,
            "USER": self.user.strip(),
            "BOX": self.name.strip(),
            "LHOST": self.lhost.strip(),
            "OS": self.os.strip(),
        }
        return {key: value for key, value in pairs.items() if value}


@dataclass
class Finding:
    id: str
    title: str
    vector: str
    score: float
    severity: str
    affected_host: str
    description: str = ""
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""
    created: str = ""
    updated: str = ""
    box: str = ""

    def sort_key(self) -> tuple[int, float, str]:
        return (SEVERITY_RANK.get(self.severity, 9), -self.score, self.id)


def note_template(phase: str) -> str:
    """Heading written into a new phase note."""
    label = PHASE_LABELS.get(phase, phase.title())
    return f"# {label}\n\n"


def note_is_empty(text: str) -> bool:
    """True when a note has no body past the phase heading."""
    return not text.strip()
