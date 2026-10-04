"""Typed views of ``witness.semantic/1`` responses.

Unknown fields are ignored so a newer helper with additional optional fields
stays compatible. The protocol string itself is checked at startup.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

PROTOCOL_VERSION = "witness.semantic/1"


class _Wire(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")


class Span(_Wire):
    path: str
    start_line: int
    end_line: int
    start_column: int = 1
    end_column: int = 1


class SymbolInfo(_Wire):
    id: str
    display: str
    kind: str
    location: Span | None = None
    accessibility: str | None = None


class Sink(_Wire):
    symbol: str
    display: str
    resolution: Literal["resolved", "unresolved_candidate"]
    argument_role: str
    argument_index: int
    note: str | None = None


class Site(_Wire):
    site_id: str
    vuln_class: str
    sink: Sink
    location: Span
    containing: SymbolInfo | None = None
    ordinal: int
    argument_text: str


class ValueNode(_Wire):
    kind: str
    text: str
    location: Span | None = None
    symbol: str | None = None
    detail: str | None = None
    children: tuple[ValueNode, ...] = ()
    facts: dict[str, str] = Field(default_factory=dict)

    def walk(self) -> Iterator[ValueNode]:
        yield self
        for child in self.children:
            yield from child.walk()

    def leaves(self) -> Iterator[ValueNode]:
        for node in self.walk():
            if not node.children:
                yield node


class Guard(_Wire):
    kind: str
    subject_symbol: str
    subject_text: str
    holds_at_sink: Literal["true", "false", "unknown"]
    reassigned_before_sink: bool
    sink_argument_is_subject: bool
    location: Span
    condition_text: str
    facts: dict[str, str] = Field(default_factory=dict)


class SiteAnalysis(_Wire):
    site: Site
    value: ValueNode
    guards: tuple[Guard, ...] = ()
    unresolved: tuple[str, ...] = ()
    truncated: bool = False
    safe_api: str | None = None


class ArgumentAnalysis(_Wire):
    value: ValueNode
    guards: tuple[Guard, ...] = ()
    unresolved: tuple[str, ...] = ()
    truncated: bool = False
    containing: SymbolInfo | None = None


class SafeApiHit(_Wire):
    description: str
    location: Span


class SitesAt(_Wire):
    sites: tuple[Site, ...]
    safe_apis: tuple[SafeApiHit, ...] = ()


class CallArgument(_Wire):
    index: int
    parameter_name: str | None = None
    text: str
    location: Span


class CallSite(_Wire):
    caller: SymbolInfo | None = None
    location: Span
    target: str
    via_dispatch: bool
    arguments: tuple[CallArgument, ...] = ()


class Callers(_Wire):
    target: SymbolInfo
    calls: tuple[CallSite, ...]
    complete: bool
    incomplete_reasons: tuple[str, ...] = ()


class Callee(_Wire):
    symbol: str
    display: str
    resolution: Literal["resolved", "unresolved_candidate"]
    location: Span
    declared_in: str | None = None


class EndpointParameter(_Wire):
    name: str
    type: str
    binding: str


class Endpoint(_Wire):
    kind: str
    http_methods: tuple[str, ...]
    route: str | None = None
    handler: SymbolInfo
    parameters: tuple[EndpointParameter, ...] = ()
    authorization_attributes: tuple[str, ...] = ()
    allow_anonymous: bool = False


class PipelineLayer(_Wire):
    kind: str
    name: str
    location: Span | None = None
    reads_request_input: Literal["true", "false", "unknown"]
    can_reject: Literal["true", "false", "unknown"]
    rewrites_request: Literal["true", "false", "unknown"] = "false"
    scope: str
    handlers: tuple[str, ...] = ()

    @property
    def can_affect_input(self) -> bool:
        """Whether this layer could stop or change a request based on its input."""
        if self.reads_request_input == "false":
            return False
        return self.can_reject != "false" or self.rewrites_request != "false"


class DiRegistration(_Wire):
    service: str
    implementation: str | None = None
    lifetime: str
    conditional: bool
    location: Span


class EntryPoint(_Wire):
    kind: str
    symbol: SymbolInfo
    detail: str | None = None


class PackageReference(_Wire):
    name: str
    version: str | None = None
    resolved: bool
    source: str | None = None


class DiagnosticSample(_Wire):
    id: str
    message: str
    path: str | None = None
    line: int = 0


class Project(_Wire):
    name: str
    path: str
    target_framework: str | None = None
    sdk: str
    documents: int
    project_references: tuple[str, ...] = ()
    package_references: tuple[PackageReference, ...] = ()
    approximations: tuple[str, ...] = ()
    error_count: int = 0
    unresolved_symbol_errors: int = 0
    diagnostic_sample: tuple[DiagnosticSample, ...] = ()


class SkippedFile(_Wire):
    path: str
    reason: str


class LoadResult(_Wire):
    root: str
    projects: tuple[Project, ...]
    skipped: tuple[SkippedFile, ...] = ()
    strategy: str
    load_ms: int


class Member(_Wire):
    symbol: SymbolInfo
    span: Span


class Dependencies(_Wire):
    symbol: str
    files: tuple[str, ...]
    symbols: tuple[str, ...]
    unresolved_references: int


class Hello(_Wire):
    protocol: str
    helper_version: str
    roslyn_version: str
    ref_packs: tuple[dict[str, str], ...] = ()
    strategy: str
