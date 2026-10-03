"""Common finding schema, ``witness.finding/1``.

A normalized finding keeps what the scanner said and where it came from. It
does not carry Witness's own conclusions; assessments and priorities are
separate records that reference the finding by id.

Fields are optional when scanners legitimately omit them. Adapters must leave
a field empty rather than guess, because downstream correlation treats empty
and unknown as "cannot match", which is the safe direction.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

FINDING_SCHEMA: Literal["witness.finding/1"] = "witness.finding/1"


class FindingKind(StrEnum):
    SOURCE = "source"
    DEPENDENCY = "dependency"
    RUNTIME = "runtime"
    OTHER = "other"


class VulnClass(StrEnum):
    SQL_INJECTION = "sql_injection"
    OPEN_REDIRECT = "open_redirect"
    PATH_TRAVERSAL = "path_traversal"
    UNCLASSIFIED = "unclassified"


SUPPORTED_SOURCE_CLASSES = frozenset(
    {VulnClass.SQL_INJECTION, VulnClass.OPEN_REDIRECT, VulnClass.PATH_TRAVERSAL}
)


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        """Lower is more severe. Unknown sorts with high so it is never quietly ignored."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.UNKNOWN: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ScannerIdentity(_Model):
    name: str
    version: str | None = None
    rule_id: str | None = None
    rule_name: str | None = None


class SourceLocation(_Model):
    # Path relative to the repository root, forward slashes, as resolved by the
    # adapter. ``reported_uri`` keeps the scanner's original text.
    path: str
    reported_uri: str
    start_line: int | None = None
    end_line: int | None = None
    start_column: int | None = None
    end_column: int | None = None


class FlowStep(_Model):
    location: SourceLocation | None = None
    message: str | None = None


class PackageRef(_Model):
    name: str
    version: str | None = None
    ecosystem: str | None = None
    purl: str | None = None
    fixed_versions: tuple[str, ...] = ()
    # Lock file, manifest or binary the scanner read the package from.
    origin: str | None = None


class ArtifactIdentity(_Model):
    kind: Literal["repository", "image", "filesystem", "deployment", "unknown"]
    name: str | None = None
    digest: str | None = None
    revision: str | None = None


class HttpExchange(_Model):
    method: str
    url: str
    status_code: int | None = None
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str | None = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: str | None = None
    duration_ms: int | None = None


class RuntimeContext(_Model):
    environment: str | None = None
    target: str | None = None
    endpoint: str | None = None
    method: str | None = None
    exchanges: tuple[HttpExchange, ...] = ()


class Provenance(_Model):
    report_path: str
    report_sha256: str
    report_format: str
    # JSON pointer to the record inside the original report.
    record_pointer: str
    imported_at: datetime
    scanned_at: datetime | None = None


class Finding(_Model):
    schema_id: Literal["witness.finding/1"] = Field(default=FINDING_SCHEMA, alias="schema")
    id: str
    # Identity of the affected instance, used for duplicate detection. Two
    # findings with equal instance keys describe the same affected thing.
    instance_key: str
    kind: FindingKind
    category: VulnClass
    # Why the adapter chose ``category``: a rule id, CWE tag or check name.
    category_basis: str
    scanner: ScannerIdentity
    severity: Severity
    severity_original: str | None = None
    title: str
    message: str | None = None
    cwe: tuple[str, ...] = ()
    vulnerability_ids: tuple[str, ...] = ()
    location: SourceLocation | None = None
    code_flows: tuple[tuple[FlowStep, ...], ...] = ()
    package: PackageRef | None = None
    artifact: ArtifactIdentity | None = None
    runtime: RuntimeContext | None = None
    # Repository revision the scanner declared it analyzed, if any.
    revision: str | None = None
    revision_source: Literal["report", "operator", "none"] = "none"
    scanner_properties: dict[str, JsonValue] = Field(default_factory=dict)
    provenance: Provenance
    # The untouched source record. Never shown to a model.
    original: JsonValue = None

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)
