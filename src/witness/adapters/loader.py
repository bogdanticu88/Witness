"""Report loader: hash, sniff and dispatch scanner reports to adapters."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from witness.adapters.base import Adapter, ImportContext, ImportResult
from witness.adapters.codeql import CodeQLAdapter
from witness.adapters.mantis import MantisAdapter
from witness.adapters.trivy import TrivyAdapter
from witness.errors import InputError
from witness.security.limits import DEFAULT_LIMITS, Limits, loads_json, read_bounded

_DEFAULT_ADAPTERS: tuple[Adapter, ...] = (CodeQLAdapter(), TrivyAdapter(), MantisAdapter())


def load_report(
    path: Path,
    *,
    source_prefixes: Sequence[str] = (),
    operator_revision: str | None = None,
    limits: Limits = DEFAULT_LIMITS,
    adapters: Sequence[Adapter] | None = None,
) -> ImportResult:
    """Import one scanner report file.

    The raw bytes are hashed before parsing so provenance covers the exact
    file on disk. Exactly one adapter must claim the document: zero matches
    mean the format is unsupported, more than one means the format
    fingerprints are ambiguous and the report is refused rather than guessed.
    """
    data = read_bounded(path, limits)
    digest = hashlib.sha256(data).hexdigest()
    document = loads_json(data, str(path), limits)
    context = ImportContext(
        report_path=path,
        report_sha256=digest,
        imported_at=datetime.now(UTC),
        source_prefixes=tuple(source_prefixes),
        operator_revision=operator_revision,
    )
    candidates = tuple(_DEFAULT_ADAPTERS if adapters is None else adapters)
    matches = [adapter for adapter in candidates if adapter.detect(document)]
    if not matches:
        recognized = ", ".join(adapter.format for adapter in candidates)
        raise InputError(
            f"unsupported report format: {path} "
            f"(no adapter recognized it; recognized formats: {recognized})",
        )
    if len(matches) > 1:
        formats = ", ".join(adapter.format for adapter in matches)
        raise InputError(f"ambiguous report format: {path} matches multiple formats: {formats}")
    return matches[0].parse(document, context)
