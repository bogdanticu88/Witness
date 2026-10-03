"""Shared adapter plumbing: import context, ids and results."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Protocol

from witness.model.finding import Finding


@dataclass(frozen=True)
class ImportContext:
    report_path: Path
    report_sha256: str
    imported_at: datetime
    # Repository snapshot the findings should be located in, if known.
    repo_root: Path | None = None
    # Absolute roots the scanner may have used for source paths.
    source_prefixes: tuple[str, ...] = ()
    # Revision supplied by the operator. Used only when the report itself
    # declares none, and recorded as operator-supplied.
    operator_revision: str | None = None


@dataclass
class ImportResult:
    format: str
    tool: str
    tool_version: str | None
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class Adapter(Protocol):
    format: str

    def detect(self, document: object) -> bool: ...

    def parse(self, document: object, context: ImportContext) -> ImportResult: ...


def finding_id(context: ImportContext, pointer: str) -> str:
    """Stable id for one record in one report file."""
    digest = hashlib.sha256(f"{context.report_sha256}|{pointer}".encode()).hexdigest()
    return "f-" + digest[:20]


def instance_key(*parts: str | int | None) -> str:
    """Hash of the identifying parts of an affected instance.

    A missing part is encoded as a distinct marker, never dropped, so two
    findings that both lack a field do not collapse into one key by accident
    unless every other part also matches.
    """
    text = "|".join("\x00none" if p is None else str(p) for p in parts)
    return hashlib.sha256(text.encode()).hexdigest()[:32]


def first_text(*values: object) -> str | None:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value
    return None
