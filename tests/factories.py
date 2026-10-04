"""Small builders for findings used across tests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from witness.model.finding import (
    ArtifactIdentity,
    Finding,
    FindingKind,
    FlowStep,
    PackageRef,
    Provenance,
    RuntimeContext,
    ScannerIdentity,
    Severity,
    SourceLocation,
    VulnClass,
)


def loc(path: str, line: int | None) -> SourceLocation:
    return SourceLocation(path=path, reported_uri=path, start_line=line, end_line=line)


def flow(*steps: tuple[str, int]) -> tuple[FlowStep, ...]:
    return tuple(FlowStep(location=loc(path, line)) for path, line in steps)


def _base(finding_id: str, **overrides: Any) -> Finding:
    data: dict[str, Any] = {
        "id": finding_id,
        "instance_key": "key-" + finding_id,
        "kind": FindingKind.SOURCE,
        "category": VulnClass.SQL_INJECTION,
        "category_basis": "test",
        "scanner": ScannerIdentity(name="test", rule_id="rule"),
        "severity": Severity.HIGH,
        "title": "test finding",
        "provenance": Provenance(
            report_path="report.json",
            report_sha256="ab" * 32,
            report_format="test",
            record_pointer="/" + finding_id,
            imported_at=datetime(2026, 10, 1, tzinfo=UTC),
        ),
    }
    data.update(overrides)
    return Finding(**data)


def source(
    finding_id: str,
    path: str | None = "src/A.cs",
    line: int | None = 10,
    *,
    category: VulnClass = VulnClass.SQL_INJECTION,
    **overrides: Any,
) -> Finding:
    location = loc(path, line) if path is not None else None
    return _base(finding_id, category=category, location=location, **overrides)


def dependency(
    finding_id: str,
    name: str = "Newtonsoft.Json",
    *,
    purl: str | None = "pkg:nuget/Newtonsoft.Json@12.0.1",
    ecosystem: str | None = "nuget",
    artifact: ArtifactIdentity | None = None,
    origin: str | None = "src/App/packages.lock.json",
    **overrides: Any,
) -> Finding:
    return _base(
        finding_id,
        kind=FindingKind.DEPENDENCY,
        category=VulnClass.UNCLASSIFIED,
        package=PackageRef(
            name=name, version="12.0.1", ecosystem=ecosystem, purl=purl, origin=origin
        ),
        artifact=artifact or ArtifactIdentity(kind="filesystem", name="app"),
        vulnerability_ids=("GHSA-5crp-9r3c-p9vr",),
        **overrides,
    )


def runtime(
    finding_id: str,
    endpoint: str = "/api/orders/search?status=x",
    *,
    method: str = "GET",
    target: str = "http://127.0.0.1:8080",
    environment: str = "staging",
    category: VulnClass = VulnClass.SQL_INJECTION,
    **overrides: Any,
) -> Finding:
    return _base(
        finding_id,
        kind=FindingKind.RUNTIME,
        category=category,
        runtime=RuntimeContext(
            endpoint=endpoint, method=method, target=target, environment=environment
        ),
        **overrides,
    )
