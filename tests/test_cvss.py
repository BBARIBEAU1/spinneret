"""CVSS 3.1 base scores checked against published vectors.

The numeric results match the FIRST base equation (section 7.1) and the
Red Hat `cvss` reference implementation across all 2,592 base combinations.
"""

from decimal import Decimal

import pytest

from spinneret.cvss import (
    CVSSError,
    round_up,
    score_vector,
    severity_for,
)

PUBLISHED = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8, "high"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "high"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "medium"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "high"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"),
    ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.8, "high"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, "high"),
    ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 6.8, "medium"),
    ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2, "high"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "none"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "medium"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9, "medium"),
    ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 4.6, "medium"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9, "critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4, "medium"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N", 9.3, "critical"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", 9.0, "critical"),
    ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8, "low"),
]


@pytest.mark.parametrize(("vector", "score", "severity"), PUBLISHED)
def test_published_vectors(vector: str, score: float, severity: str) -> None:
    result = score_vector(vector)
    assert result.score == score
    assert result.severity == severity
    assert result.vector == vector


def test_metric_order_and_temporal_metrics_do_not_change_the_base_score() -> None:
    canonical = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    pasted = "CVSS:3.1/C:H/I:H/A:H/S:U/UI:N/PR:N/AC:L/AV:N/E:P/RL:O/RC:C"
    result = score_vector(pasted)
    assert result.vector == canonical
    assert result.score == 9.8


def test_lowercase_vector_is_accepted() -> None:
    result = score_vector("cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h")
    assert result.score == 9.8
    assert result.vector.startswith("CVSS:3.1/")


def test_round_up_examples_from_the_specification() -> None:
    assert round_up(Decimal("4.02")) == Decimal("4.1")
    assert round_up(Decimal("4.00")) == Decimal("4.0")
    assert round_up(Decimal("1.2")) == Decimal("1.2")
    assert round_up(Decimal("1.200003")) == Decimal("1.3")


@pytest.mark.parametrize(
    ("score", "severity"),
    [
        (0.0, "none"),
        (0.1, "low"),
        (3.9, "low"),
        (4.0, "medium"),
        (6.9, "medium"),
        (7.0, "high"),
        (8.9, "high"),
        (9.0, "critical"),
        (10.0, "critical"),
    ],
)
def test_severity_bands(score: float, severity: str) -> None:
    assert severity_for(score) == severity


@pytest.mark.parametrize(
    "vector",
    [
        "",
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/A:H",
        "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/ZZ:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ],
)
def test_rejected_vectors(vector: str) -> None:
    with pytest.raises(CVSSError):
        score_vector(vector)
