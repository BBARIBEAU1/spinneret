"""CVSS v3.1 base score.

Implements the base metric equation from the FIRST CVSS v3.1 specification
(section 7.1) and the one-decimal Roundup defined in section 7. Numeric work
uses ``decimal.Decimal`` so the binary-float trap described in Appendix A
does not change a tenth. Temporal and environmental metrics are accepted on
input and ignored, because this module scores the base vector only.

The qualitative rating follows specification section 6:

* 0.0 None
* 0.1–3.9 Low
* 4.0–6.9 Medium
* 7.0–8.9 High
* 9.0–10.0 Critical
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import ROUND_CEILING, Decimal

from spinneret.errors import SpinneretError

_AV = {
    "N": Decimal("0.85"),
    "A": Decimal("0.62"),
    "L": Decimal("0.55"),
    "P": Decimal("0.20"),
}
_AC = {"L": Decimal("0.77"), "H": Decimal("0.44")}
_UI = {"N": Decimal("0.85"), "R": Decimal("0.62")}
_CIA = {"H": Decimal("0.56"), "L": Decimal("0.22"), "N": Decimal("0")}
_PR_UNCHANGED = {"N": Decimal("0.85"), "L": Decimal("0.62"), "H": Decimal("0.27")}
_PR_CHANGED = {"N": Decimal("0.85"), "L": Decimal("0.68"), "H": Decimal("0.50")}

BASE_METRICS: tuple[str, ...] = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

METRIC_VALUES: dict[str, frozenset[str]] = {
    "AV": frozenset(_AV),
    "AC": frozenset(_AC),
    "PR": frozenset(_PR_UNCHANGED),
    "UI": frozenset(_UI),
    "S": frozenset({"U", "C"}),
    "C": frozenset(_CIA),
    "I": frozenset(_CIA),
    "A": frozenset(_CIA),
}

# Optional groups. Present on many pasted NVD vectors; not part of the base score.
_OPTIONAL_VALUES: dict[str, frozenset[str]] = {
    "E": frozenset({"X", "U", "P", "F", "H"}),
    "RL": frozenset({"X", "O", "T", "W", "U"}),
    "RC": frozenset({"X", "U", "R", "C"}),
    "CR": frozenset({"X", "H", "M", "L"}),
    "IR": frozenset({"X", "H", "M", "L"}),
    "AR": frozenset({"X", "H", "M", "L"}),
    "MAV": frozenset({"X", "N", "A", "L", "P"}),
    "MAC": frozenset({"X", "L", "H"}),
    "MPR": frozenset({"X", "N", "L", "H"}),
    "MUI": frozenset({"X", "N", "R"}),
    "MS": frozenset({"X", "U", "C"}),
    "MC": frozenset({"X", "N", "L", "H"}),
    "MI": frozenset({"X", "N", "L", "H"}),
    "MA": frozenset({"X", "N", "L", "H"}),
}

METRIC_OPTIONS: dict[str, tuple[tuple[str, str], ...]] = {
    "AV": (("Network", "N"), ("Adjacent", "A"), ("Local", "L"), ("Physical", "P")),
    "AC": (("Low", "L"), ("High", "H")),
    "PR": (("None", "N"), ("Low", "L"), ("High", "H")),
    "UI": (("None", "N"), ("Required", "R")),
    "S": (("Unchanged", "U"), ("Changed", "C")),
    "C": (("None", "N"), ("Low", "L"), ("High", "H")),
    "I": (("None", "N"), ("Low", "L"), ("High", "H")),
    "A": (("None", "N"), ("Low", "L"), ("High", "H")),
}

DEFAULT_METRICS: dict[str, str] = {
    "AV": "N",
    "AC": "L",
    "PR": "N",
    "UI": "N",
    "S": "U",
    "C": "N",
    "I": "N",
    "A": "N",
}

_SEVERITY_BANDS: tuple[tuple[float, str], ...] = (
    (0.0, "none"),
    (3.9, "low"),
    (6.9, "medium"),
    (8.9, "high"),
    (10.0, "critical"),
)


class CVSSError(SpinneretError):
    """The vector is missing a metric, repeats one, or uses an unknown value."""


@dataclass(frozen=True)
class CVSSBase:
    """A canonical base vector and the score derived from it."""

    vector: str
    score: float
    severity: str
    metrics: dict[str, str]


def round_up(value: Decimal) -> Decimal:
    """Smallest number with one decimal place that is >= ``value``.

    Examples from the specification: Roundup(4.02) is 4.1 and Roundup(4.00)
    is 4.0. ``ROUND_CEILING`` on a Decimal is that ceiling, without the
    ``input * 100000`` float step Appendix A suggests for binary floats.
    """
    return value.quantize(Decimal("0.1"), rounding=ROUND_CEILING)


def severity_for(score: float) -> str:
    """Return the section 6 rating name for a base score."""
    if score < 0 or score > 10:
        raise CVSSError(f"Score {score} is outside 0.0–10.0.")
    for limit, name in _SEVERITY_BANDS:
        if score <= limit:
            return name
    return "critical"


def build_vector(metrics: dict[str, str], version: str = "3.1") -> str:
    """Assemble a canonical ``CVSS:3.1/...`` string from base metric codes."""
    if version not in {"3.0", "3.1"}:
        raise CVSSError(f"Unsupported CVSS version {version}.")
    normalized: dict[str, str] = {}
    for metric in BASE_METRICS:
        if metric not in metrics:
            raise CVSSError(f"Missing {metric}.")
        value = str(metrics[metric]).strip().upper()
        if value not in METRIC_VALUES[metric]:
            raise CVSSError(f"Unknown value {value} for {metric}.")
        normalized[metric] = value
    body = "/".join(f"{metric}:{normalized[metric]}" for metric in BASE_METRICS)
    return f"CVSS:{version}/{body}"


def parse_vector(vector: str) -> tuple[str, dict[str, str]]:
    """Parse a base vector. Returns ``(version, metrics)``.

    Metric order does not matter. Temporal and environmental metrics are
    checked and then dropped.
    """
    text = vector.strip()
    if text.endswith("/"):
        raise CVSSError("Vector has a trailing slash.")
    prefix = text[:9].upper()
    if prefix == "CVSS:3.1/":
        version = "3.1"
        rest = text[9:]
    elif prefix == "CVSS:3.0/":
        version = "3.0"
        rest = text[9:]
    else:
        raise CVSSError("Vector must start with CVSS:3.1/.")

    if not rest:
        raise CVSSError("Vector has no metrics.")

    found: dict[str, str] = {}
    for field in rest.split("/"):
        if not field or ":" not in field:
            raise CVSSError(f"Malformed field {field!r}.")
        metric, value = field.split(":", 1)
        metric = metric.strip().upper()
        value = value.strip().upper()
        if not metric:
            raise CVSSError("Malformed field with an empty metric name.")
        if metric in found:
            raise CVSSError(f"Duplicate metric {metric}.")
        allowed = METRIC_VALUES.get(metric) or _OPTIONAL_VALUES.get(metric)
        if allowed is None:
            raise CVSSError(f"Unknown metric {metric}.")
        if value not in allowed:
            raise CVSSError(f"Unknown value {value} for {metric}.")
        if metric in METRIC_VALUES:
            found[metric] = value

    missing = [metric for metric in BASE_METRICS if metric not in found]
    if missing:
        raise CVSSError(f"Missing {', '.join(missing)}.")
    return version, found


def score_metrics(metrics: dict[str, str], version: str = "3.1") -> CVSSBase:
    """Score an already-split base metric mapping."""
    canonical = build_vector(metrics, version=version)
    _, metrics = parse_vector(canonical)
    changed = metrics["S"] == "C"
    privileges = _PR_CHANGED if changed else _PR_UNCHANGED

    iss = Decimal(1) - (
        (Decimal(1) - _CIA[metrics["C"]])
        * (Decimal(1) - _CIA[metrics["I"]])
        * (Decimal(1) - _CIA[metrics["A"]])
    )
    if changed:
        impact = (
            Decimal("7.52") * (iss - Decimal("0.029"))
            - Decimal("3.25") * (iss - Decimal("0.02")) ** 15
        )
    else:
        impact = Decimal("6.42") * iss

    exploitability = (
        Decimal("8.22")
        * _AV[metrics["AV"]]
        * _AC[metrics["AC"]]
        * privileges[metrics["PR"]]
        * _UI[metrics["UI"]]
    )

    if impact <= 0:
        rounded = Decimal("0.0")
    elif changed:
        rounded = round_up(min(Decimal("1.08") * (impact + exploitability), Decimal(10)))
    else:
        rounded = round_up(min(impact + exploitability, Decimal(10)))

    score = float(rounded)
    return CVSSBase(
        vector=canonical,
        score=score,
        severity=severity_for(score),
        metrics=dict(metrics),
    )


def score_vector(vector: str) -> CVSSBase:
    """Score a CVSS v3.1 (or v3.0 base) vector string."""
    version, metrics = parse_vector(vector)
    return score_metrics(metrics, version=version)
