"""Plain-file store.

Layout, rooted at ``~/spinneret`` unless another directory is chosen::

    <root>/<engagement>/engagement.yaml
    <root>/<engagement>/summary.md
    <root>/<engagement>/<box>/box.yaml
    <root>/<engagement>/<box>/notes/<phase>.md
    <root>/<engagement>/<box>/findings/F-001.yaml
    <root>/<engagement>/<box>/screenshots/
"""

from __future__ import annotations

import os
import re
import shutil
from datetime import UTC, datetime
from pathlib import Path

import yaml

from spinneret.cvss import CVSSError, score_vector
from spinneret.errors import SpinneretError
from spinneret.models import (
    PHASE_KEYS,
    Box,
    Engagement,
    Finding,
    note_template,
    slugify,
    utc_now,
)

_SLUG_OK = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_FINDING_ID = re.compile(r"F-(\d+)")


def default_root() -> Path:
    """``$SPINNERET_ROOT`` when set, otherwise ``~/spinneret``."""
    env = os.environ.get("SPINNERET_ROOT")
    if env:
        return Path(env).expanduser()
    return Path.home() / "spinneret"


class StorageError(SpinneretError):
    """The store could not read or write a record."""


def _dump(payload: dict) -> str:
    return yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)


def _load(path: Path) -> dict:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise StorageError(f"{path.name} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise StorageError(f"{path.name} must be a YAML mapping.")
    return data


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


class Store:
    """Read and write one spinneret data root."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def engagement_dir(self, slug: str) -> Path:
        return self._under(self._check_slug(slug))

    def box_dir(self, engagement: str, box: str) -> Path:
        return self._under(self._check_slug(engagement), self._check_slug(box))

    def screenshots_dir(self, engagement: str, box: str) -> Path:
        path = self.box_dir(engagement, box) / "screenshots"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def list_engagements(self) -> list[Engagement]:
        found: list[Engagement] = []
        for path in sorted(self.root.iterdir()):
            meta = path / "engagement.yaml"
            if path.is_dir() and meta.is_file():
                found.append(self._engagement_from(meta))
        return sorted(found, key=lambda item: item.name.lower())

    def create_engagement(self, name: str, client: str = "") -> Engagement:
        cleaned = name.strip()
        if not cleaned:
            raise StorageError("Engagement name is required.")
        slug = self._unique_slug(self.root, slugify(cleaned))
        record = Engagement(name=cleaned, slug=slug, client=client.strip(), created=utc_now())
        directory = self.root / slug
        directory.mkdir(parents=True)
        _write(directory / "engagement.yaml", _dump(_engagement_dict(record)))
        _write(directory / "summary.md", "")
        return record

    def get_engagement(self, slug: str) -> Engagement:
        path = self.engagement_dir(slug) / "engagement.yaml"
        if not path.is_file():
            raise StorageError(f"No engagement {slug}.")
        return self._engagement_from(path)

    def update_engagement(self, engagement: Engagement) -> None:
        current = self.get_engagement(engagement.slug)
        updated = Engagement(
            name=engagement.name.strip() or current.name,
            slug=current.slug,
            client=engagement.client.strip(),
            created=current.created,
        )
        path = self.engagement_dir(current.slug) / "engagement.yaml"
        _write(path, _dump(_engagement_dict(updated)))

    def delete_engagement(self, slug: str) -> None:
        target = self.engagement_dir(slug)
        if not (target / "engagement.yaml").is_file():
            raise StorageError(f"No engagement {slug}.")
        _remove_tree(target)

    def read_summary(self, slug: str) -> str:
        path = self.engagement_dir(slug) / "summary.md"
        if not path.is_file():
            return ""
        return path.read_text(encoding="utf-8")

    def write_summary(self, slug: str, text: str) -> None:
        self.get_engagement(slug)
        _write(self.engagement_dir(slug) / "summary.md", text)

    def list_boxes(self, engagement: str) -> list[Box]:
        root = self.engagement_dir(engagement)
        self.get_engagement(engagement)
        found: list[Box] = []
        for path in sorted(root.iterdir()):
            meta = path / "box.yaml"
            if path.is_dir() and meta.is_file():
                found.append(self._box_from(meta, engagement))
        return sorted(found, key=lambda item: item.name.lower())

    def create_box(
        self,
        engagement: str,
        name: str,
        ip: str = "",
        hostnames: list[str] | None = None,
        os: str = "",
        user: str = "",
        domain: str = "",
        lhost: str = "",
    ) -> Box:
        self.get_engagement(engagement)
        cleaned = name.strip()
        if not cleaned:
            raise StorageError("Box name is required.")
        parent = self.engagement_dir(engagement)
        slug = self._unique_slug(parent, slugify(cleaned))
        record = Box(
            name=cleaned,
            slug=slug,
            engagement=engagement,
            ip=ip.strip(),
            hostnames=list(hostnames or []),
            os=os.strip(),
            user=user.strip(),
            domain=domain.strip(),
            lhost=lhost.strip(),
            created=utc_now(),
        )
        directory = parent / slug
        directory.mkdir(parents=True)
        (directory / "findings").mkdir()
        (directory / "screenshots").mkdir()
        notes = directory / "notes"
        notes.mkdir()
        _write(directory / "box.yaml", _dump(_box_dict(record)))
        for phase in PHASE_KEYS:
            _write(notes / f"{phase}.md", note_template(phase))
        return record

    def get_box(self, engagement: str, box: str) -> Box:
        path = self.box_dir(engagement, box) / "box.yaml"
        if not path.is_file():
            raise StorageError(f"No box {box} in {engagement}.")
        return self._box_from(path, engagement)

    def update_box(self, box: Box) -> None:
        current = self.get_box(box.engagement, box.slug)
        updated = Box(
            name=box.name.strip() or current.name,
            slug=current.slug,
            engagement=current.engagement,
            ip=box.ip.strip(),
            hostnames=list(box.hostnames),
            os=box.os.strip(),
            user=box.user.strip(),
            domain=box.domain.strip(),
            lhost=box.lhost.strip(),
            created=current.created,
        )
        path = self.box_dir(current.engagement, current.slug) / "box.yaml"
        _write(path, _dump(_box_dict(updated)))

    def delete_box(self, engagement: str, box: str) -> None:
        target = self.box_dir(engagement, box)
        if not (target / "box.yaml").is_file():
            raise StorageError(f"No box {box} in {engagement}.")
        _remove_tree(target)

    def read_note(self, engagement: str, box: str, phase: str) -> str:
        path = self._note_path(engagement, box, phase)
        if not path.is_file():
            return note_template(phase)
        return path.read_text(encoding="utf-8")

    def write_note(self, engagement: str, box: str, phase: str, text: str) -> None:
        _write(self._note_path(engagement, box, phase), text)

    def append_scratch(
        self,
        engagement: str,
        box: str,
        text: str,
        now: datetime | None = None,
    ) -> str:
        body = text.strip()
        if not body:
            raise StorageError("Scratch note is empty.")
        moment = now or datetime.now(UTC)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)
        stamp = moment.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%SZ")
        current = self.read_note(engagement, box, "scratch")
        if current and not current.endswith("\n"):
            current += "\n"
        updated = f"{current}\n## {stamp}\n\n{body}\n"
        self.write_note(engagement, box, "scratch", updated)
        return updated

    def list_findings(self, engagement: str, box: str) -> list[Finding]:
        directory = self.box_dir(engagement, box) / "findings"
        if not directory.is_dir():
            return []
        findings = [self._finding_from(path, box) for path in sorted(directory.glob("F-*.yaml"))]
        return sorted(findings, key=lambda item: item.id)

    def next_finding_id(self, engagement: str) -> str:
        highest = 0
        for box in self.list_boxes(engagement):
            for finding in self.list_findings(engagement, box.slug):
                match = _FINDING_ID.fullmatch(finding.id)
                if match:
                    highest = max(highest, int(match.group(1)))
        return f"F-{highest + 1:03d}"

    def save_finding(self, engagement: str, box: str, finding: Finding) -> Finding:
        self.get_box(engagement, box)
        record = Finding(
            id=finding.id.strip() or self.next_finding_id(engagement),
            title=finding.title.strip(),
            vector=finding.vector.strip(),
            score=finding.score,
            severity=finding.severity,
            affected_host=finding.affected_host.strip(),
            description=finding.description.strip(),
            evidence=[item.strip() for item in finding.evidence if item.strip()],
            remediation=finding.remediation.strip(),
            created=finding.created or utc_now(),
            updated=utc_now(),
            box=box,
        )
        if not record.title:
            raise StorageError("Finding title is required.")
        if not _FINDING_ID.fullmatch(record.id):
            raise StorageError(f"Finding id {record.id} must look like F-001.")
        try:
            scored = score_vector(record.vector)
        except CVSSError as exc:
            raise StorageError(str(exc)) from exc
        record.vector = scored.vector
        record.score = scored.score
        record.severity = scored.severity
        path = self.box_dir(engagement, box) / "findings" / f"{record.id}.yaml"
        _write(path, _dump(_finding_dict(record)))
        return record

    def delete_finding(self, engagement: str, box: str, finding_id: str) -> None:
        path = self.box_dir(engagement, box) / "findings" / f"{finding_id}.yaml"
        if not path.is_file():
            raise StorageError(f"No finding {finding_id}.")
        path.unlink()

    def _note_path(self, engagement: str, box: str, phase: str) -> Path:
        if phase not in PHASE_KEYS:
            raise StorageError(f"Unknown phase {phase}.")
        self.get_box(engagement, box)
        return self.box_dir(engagement, box) / "notes" / f"{phase}.md"

    def _engagement_from(self, path: Path) -> Engagement:
        data = _load(path)
        return Engagement(
            name=str(data.get("name") or path.parent.name),
            slug=str(data.get("slug") or path.parent.name),
            client=str(data.get("client") or ""),
            created=str(data.get("created") or ""),
        )

    def _box_from(self, path: Path, engagement: str) -> Box:
        data = _load(path)
        hosts = data.get("hostnames") or []
        if isinstance(hosts, str):
            hosts = [hosts]
        return Box(
            name=str(data.get("name") or path.parent.name),
            slug=str(data.get("slug") or path.parent.name),
            engagement=engagement,
            ip=str(data.get("ip") or ""),
            hostnames=[str(item) for item in hosts if str(item).strip()],
            os=str(data.get("os") or ""),
            user=str(data.get("user") or ""),
            domain=str(data.get("domain") or ""),
            lhost=str(data.get("lhost") or ""),
            created=str(data.get("created") or ""),
        )

    def _finding_from(self, path: Path, box: str) -> Finding:
        data = _load(path)
        vector = str(data.get("vector") or "")
        score = _as_float(data.get("score"))
        severity = str(data.get("severity") or "none")
        try:
            scored = score_vector(vector)
            vector = scored.vector
            score = scored.score
            severity = scored.severity
        except CVSSError:
            pass
        evidence = data.get("evidence") or []
        if isinstance(evidence, str):
            evidence = [evidence]
        return Finding(
            id=str(data.get("id") or path.stem),
            title=str(data.get("title") or ""),
            vector=vector,
            score=score,
            severity=severity,
            affected_host=str(data.get("affected_host") or ""),
            description=str(data.get("description") or ""),
            evidence=[str(item) for item in evidence if str(item).strip()],
            remediation=str(data.get("remediation") or ""),
            created=str(data.get("created") or ""),
            updated=str(data.get("updated") or ""),
            box=box,
        )

    def _under(self, *parts: str) -> Path:
        path = self.root.joinpath(*parts).resolve()
        if path != self.root and self.root not in path.parents:
            raise StorageError("Path escapes the data root.")
        return path

    @staticmethod
    def _check_slug(slug: str) -> str:
        if not _SLUG_OK.fullmatch(slug):
            raise StorageError(f"Invalid name {slug!r}.")
        return slug

    @staticmethod
    def _unique_slug(parent: Path, base: str) -> str:
        candidate = base
        suffix = 2
        while (parent / candidate).exists():
            candidate = f"{base}-{suffix}"
            suffix += 1
        return candidate


def _engagement_dict(record: Engagement) -> dict:
    return {
        "name": record.name,
        "slug": record.slug,
        "client": record.client,
        "created": record.created,
    }


def _box_dict(record: Box) -> dict:
    return {
        "name": record.name,
        "slug": record.slug,
        "ip": record.ip,
        "hostnames": list(record.hostnames),
        "os": record.os,
        "user": record.user,
        "domain": record.domain,
        "lhost": record.lhost,
        "created": record.created,
    }


def _finding_dict(record: Finding) -> dict:
    return {
        "id": record.id,
        "title": record.title,
        "vector": record.vector,
        "score": float(f"{record.score:.1f}"),
        "severity": record.severity,
        "affected_host": record.affected_host,
        "description": record.description,
        "evidence": list(record.evidence),
        "remediation": record.remediation,
        "created": record.created,
        "updated": record.updated,
    }


def _as_float(value: object) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0


def _remove_tree(path: Path) -> None:
    shutil.rmtree(path)
