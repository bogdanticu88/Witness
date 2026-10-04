"""A stand-in for the semantic helper, built from protocol objects."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from witness.errors import SemanticError
from witness.model.finding import Finding
from witness.semantic import protocol as p
from witness.triage.engine import TriageRun
from witness.triage.snapshot import Snapshot

HELLO = p.Hello(
    protocol="witness.semantic/1",
    helper_version="0.0.test",
    roslyn_version="x",
    strategy="fake",
    capabilities=tuple(sorted(p.REQUIRED_CAPABILITIES)),
)


def span(path: str = "src/A.cs", line: int = 10) -> p.Span:
    return p.Span(path=path, start_line=line, end_line=line)


def node(kind: str, text: str = "x", *children: p.ValueNode, **extra: Any) -> p.ValueNode:
    return p.ValueNode(kind=kind, text=text, location=span(), children=children, **extra)


def request(name: str = "q") -> p.ValueNode:
    return node(
        "endpoint_parameter", name, symbol=f"parameter:{name}@src/A.cs:5", detail="FromQuery"
    )


def const(text: str = '"SELECT 1"') -> p.ValueNode:
    return node("constant", text, detail=text)


ACTION = "M:App.Controller.Action(System.String)"


def endpoint(handler: str = ACTION, kind: str = "controller_action") -> p.Endpoint:
    return p.Endpoint(
        kind=kind,
        http_methods=("GET",),
        route="/a",
        handler=p.SymbolInfo(id=handler, display="Action", kind="Ordinary"),
    )


def site(
    vuln_class: str = "sql_injection",
    *,
    site_id: str = "s1",
    resolution: str = "resolved",
    role: str = "sql",
    path: str = "src/A.cs",
    line: int = 10,
) -> p.Site:
    return p.Site(
        site_id=site_id,
        vuln_class=vuln_class,
        sink=p.Sink(
            symbol="P:Sink",
            display="Sink",
            resolution=resolution,  # type: ignore[arg-type]
            argument_role=role,
            argument_index=0,
        ),
        location=span(path, line),
        containing=p.SymbolInfo(id=ACTION, display="Action", kind="Ordinary"),
        ordinal=0,
        argument_text="x",
    )


def guard(kind: str, subject: str, **overrides: Any) -> p.Guard:
    data: dict[str, Any] = {
        "kind": kind,
        "subject_symbol": subject,
        "subject_text": subject.split(":")[1].split("@")[0] if ":" in subject else subject,
        "holds_at_sink": "true",
        "reassigned_before_sink": False,
        "sink_argument_is_subject": True,
        "location": span(line=8),
        "condition_text": f"{kind}(...)",
    }
    data.update(overrides)
    return p.Guard(**data)


class FakeHelper:
    """Answers queries from dictionaries. ``fail`` raises on a chosen call."""

    def __init__(
        self,
        *,
        sites: dict[tuple[str, int], list[tuple[p.Site, p.SiteAnalysis]]] | None = None,
        safe_apis: dict[tuple[str, int], list[p.SafeApiHit]] | None = None,
        callers: dict[str, p.Callers] | None = None,
        arguments: dict[tuple[str, int], p.ArgumentAnalysis] | None = None,
        registrations: list[p.DiRegistration] | None = None,
        endpoints: list[p.Endpoint] | None = None,
        layers: list[p.PipelineLayer] | None = None,
        fail: Callable[[str, int], None] | None = None,
    ) -> None:
        self.hello = HELLO
        self._sites = sites or {}
        self._safe = safe_apis or {}
        self._callers = callers or {}
        self._arguments = arguments or {}
        self._registrations = registrations or []
        self._endpoints = [endpoint()] if endpoints is None else endpoints
        self._layers = layers or []
        self._fail = fail
        self.calls = 0
        self.closed = False
        self._analyses: dict[str, p.SiteAnalysis] = {}
        for entries in self._sites.values():
            for s, analysis in entries:
                self._analyses[s.site_id] = analysis

    def _count(self, method: str) -> None:
        self.calls += 1
        if self._fail is not None:
            self._fail(method, self.calls)

    def load(self, root: Path, package_directory: Path | None) -> p.LoadResult:
        self._count("load")
        return p.LoadResult(root=str(root), projects=(), strategy="fake", load_ms=0)

    def sites_at(self, path: str, start_line: int, end_line: int, vuln_class: str) -> p.SitesAt:
        self._count("sites_at")
        found = [s for s, _ in self._sites.get((path, start_line), [])]
        return p.SitesAt(
            sites=tuple(found), safe_apis=tuple(self._safe.get((path, start_line), []))
        )

    def analyze_site(self, site_id: str) -> p.SiteAnalysis:
        self._count("analyze_site")
        return self._analyses[site_id]

    def callers(self, method: str) -> p.Callers:
        self._count("callers")
        if method not in self._callers:
            raise SemanticError(f"fake has no callers for {method}")
        return self._callers[method]

    def analyze_argument(
        self, path: str, line: int, column: int, ordinal: int
    ) -> p.ArgumentAnalysis:
        self._count("analyze_argument")
        return self._arguments[(path, line)]

    def di_registrations(self) -> list[p.DiRegistration]:
        self._count("di_registrations")
        return self._registrations

    def endpoints(self) -> list[p.Endpoint]:
        self._count("endpoints")
        return self._endpoints

    def request_pipeline(self) -> list[p.PipelineLayer]:
        self._count("request_pipeline")
        return self._layers

    def close(self) -> None:
        self.closed = True


def single(
    value: p.ValueNode,
    *,
    vuln_class: str = "sql_injection",
    guards: tuple[p.Guard, ...] = (),
    resolution: str = "resolved",
    role: str = "sql",
    truncated: bool = False,
    unresolved: tuple[str, ...] = (),
    path: str = "src/A.cs",
    line: int = 10,
) -> FakeHelper:
    s = site(vuln_class, resolution=resolution, role=role, path=path, line=line)
    analysis = p.SiteAnalysis(
        site=s, value=value, guards=guards, truncated=truncated, unresolved=unresolved
    )
    return FakeHelper(sites={(path, line): [(s, analysis)]})


def tainted() -> FakeHelper:
    """A helper that reports request data concatenated into SQL at src/A.cs:10."""
    return single(node("concat", "a + q", const(), request()))


def failing(exc: BaseException, after: int, method: str = "sites_at") -> FakeHelper:
    """Raise ``exc`` on every ``method`` query after the first ``after`` ones."""
    helper = tainted()
    seen = [0]

    def fail(name: str, count: int) -> None:
        if name != method:
            return
        seen[0] += 1
        if seen[0] > after:
            raise exc

    helper._fail = fail
    return helper


def triage_run(
    repo: Path,
    helper: FakeHelper,
    findings: Sequence[Finding] = (),
    *,
    revision: str | None = None,
    max_calls: int = 200,
) -> TriageRun:
    snapshot = Snapshot.open(repo, revision=revision)
    return TriageRun(snapshot, helper, list(findings), (), max_calls)  # type: ignore[arg-type]


def write_lock(repo: Path, version: str) -> None:
    entry = {"type": "Direct", "resolved": version}
    lock = {"version": 1, "dependencies": {"net10.0": {"Newtonsoft.Json": entry}}}
    (repo / "src" / "App").mkdir(exist_ok=True)
    (repo / "src" / "App" / "packages.lock.json").write_text(json.dumps(lock))
