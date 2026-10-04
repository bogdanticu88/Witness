from __future__ import annotations

from pathlib import Path

import pytest

from factories import dependency, flow, runtime, source
from witness.adapters.loader import load_report
from witness.correlate import EndpointMapping, correlate, relate
from witness.model.assessment import FindingGroup, GroupRelation
from witness.model.finding import ArtifactIdentity, VulnClass

REPORTS = Path(__file__).resolve().parent.parent / "fixtures" / "reports"


def _repo(name: str) -> ArtifactIdentity:
    return ArtifactIdentity(kind="repository", name=name)


def test_same_instance_key_is_duplicate() -> None:
    a = source("f-a", instance_key="k1")
    b = source("f-b", instance_key="k1")
    group = relate(a, b)
    assert group is not None
    assert group.relation is GroupRelation.DUPLICATE
    assert group.basis == "identity"
    assert group.finding_ids == ("f-a", "f-b")


def test_same_key_in_different_artifacts_is_not_duplicate() -> None:
    a = source("f-a", instance_key="k1", artifact=_repo("orders"))
    b = source("f-b", instance_key="k1", artifact=_repo("billing"))
    assert relate(a, b) is None
    group = relate(a, b, mark_independent=True)
    assert group is not None
    assert group.relation is GroupRelation.INDEPENDENT
    assert "different artifacts" in group.explanation


def test_same_key_at_different_revisions_is_not_duplicate() -> None:
    a = source("f-a", instance_key="k1", revision="aaaa111", revision_source="report")
    b = source("f-b", instance_key="k1", revision="bbbb222", revision_source="report")
    group = relate(a, b, mark_independent=True)
    assert group is not None
    assert group.relation is GroupRelation.INDEPENDENT
    assert "different revisions" in group.explanation


def test_artifact_known_on_one_side_only_blocks_location_rules() -> None:
    a = source("f-a", instance_key="k1")
    b = source("f-b", instance_key="k1", artifact=_repo("orders"))
    assert relate(a, b) is None


def test_same_class_same_file_is_related() -> None:
    group = relate(source("f-a", "src/A.cs", 10), source("f-b", "src/A.cs", 40))
    assert group is not None
    assert group.relation is GroupRelation.RELATED
    assert group.basis == "semantic"


def test_different_class_same_file_is_not_related() -> None:
    a = source("f-a", "src/A.cs", 10)
    b = source("f-b", "src/A.cs", 40, category=VulnClass.PATH_TRAVERSAL)
    assert relate(a, b) is None


def test_unsupported_class_in_same_file_is_not_related() -> None:
    a = source("f-a", "src/A.cs", 10, category=VulnClass.UNCLASSIFIED)
    b = source("f-b", "src/A.cs", 40, category=VulnClass.UNCLASSIFIED)
    assert relate(a, b) is None


def test_unknown_locations_never_relate_by_location() -> None:
    a = source("f-a", None)
    b = source("f-b", None)
    assert relate(a, b) is None
    no_line_a = source("f-c", "src/A.cs", None, code_flows=(flow(("src/A.cs", 5)),))
    no_line_b = source("f-d", "src/B.cs", None, category=VulnClass.PATH_TRAVERSAL)
    assert relate(no_line_a, no_line_b) is None


def test_flow_sink_at_other_findings_location_is_only_a_possible_chain() -> None:
    first = source("f-a", "src/A.cs", 10, code_flows=(flow(("src/A.cs", 10), ("src/B.cs", 30)),))
    second = source("f-b", "src/B.cs", 30, category=VulnClass.PATH_TRAVERSAL)
    group = relate(first, second)
    assert group is not None
    assert group.relation is GroupRelation.POSSIBLE_CHAIN
    assert group.basis == "heuristic"
    assert "not a verified exploit path" in group.explanation


def test_missing_flow_line_does_not_make_a_chain() -> None:
    first = source("f-a", "src/A.cs", 10, code_flows=(flow(("src/A.cs", 10)),))
    flowless = first.model_copy(
        update={"code_flows": ((first.code_flows[0][0].model_copy(update={"location": None}),),)}
    )
    second = source("f-b", "src/A.cs", 10, category=VulnClass.PATH_TRAVERSAL)
    assert relate(flowless, second) is None


def test_relation_and_explanation_do_not_depend_on_order() -> None:
    # Both directions link, which used to pick whichever came first.
    a = source("f-a", "src/A.cs", 10, code_flows=(flow(("src/A.cs", 10), ("src/B.cs", 30)),))
    b = source(
        "f-b",
        "src/B.cs",
        30,
        category=VulnClass.PATH_TRAVERSAL,
        code_flows=(flow(("src/B.cs", 30), ("src/A.cs", 10)),),
    )
    assert relate(a, b) == relate(b, a)
    mapping = [EndpointMapping(endpoint="/api/orders/search", source_path="src/A.cs")]
    r = runtime("f-r")
    assert relate(a, r, mappings=mapping) == relate(r, a, mappings=mapping)


def test_dependency_findings_with_same_package_are_related() -> None:
    group = relate(dependency("f-a"), dependency("f-b"))
    assert group is not None
    assert group.relation is GroupRelation.RELATED


def test_same_package_name_in_another_ecosystem_is_not_related() -> None:
    a = dependency("f-a", "core", purl="pkg:nuget/core@1.0.0", ecosystem="nuget")
    b = dependency("f-b", "core", purl="pkg:npm/core@1.0.0", ecosystem="npm")
    assert relate(a, b) is None


def test_package_without_ecosystem_or_purl_cannot_match() -> None:
    a = dependency("f-a", purl=None, ecosystem=None)
    b = dependency("f-b", purl=None, ecosystem=None)
    assert relate(a, b) is None


def test_same_package_in_repository_and_image_is_related_not_duplicate() -> None:
    repo = dependency("f-a", ecosystem="nuget")
    image = dependency(
        "f-b",
        ecosystem="dotnet-core",
        artifact=ArtifactIdentity(kind="image", name="app:1", digest="sha256:" + "1" * 64),
        origin="app/App.deps.json",
    )
    group = relate(repo, image)
    assert group is not None
    assert group.relation is GroupRelation.RELATED
    assert "different artifacts" in group.explanation


def test_runtime_findings_from_different_environments_are_separate() -> None:
    staging = runtime("f-a", environment="staging", instance_key="k1")
    prod = runtime("f-b", environment="prod", instance_key="k2")
    assert relate(staging, prod) is None


def test_declared_mapping_relates_runtime_to_source() -> None:
    mapping = EndpointMapping(
        endpoint="/api/orders/search",
        method="GET",
        source_path="src/A.cs",
        start_line=5,
        end_line=20,
    )
    r = runtime("f-r")
    s = source("f-s", "src/A.cs", 10)
    group = relate(r, s, mappings=[mapping])
    assert group is not None
    assert group.relation is GroupRelation.RELATED
    assert group.basis == "declared_mapping"


@pytest.mark.parametrize(
    "mapping",
    [
        EndpointMapping(endpoint="/api/orders", source_path="src/A.cs"),
        EndpointMapping(endpoint="/api/orders/search", method="POST", source_path="src/A.cs"),
        EndpointMapping(endpoint="/api/orders/search", source_path="src/B.cs"),
        EndpointMapping(endpoint="/api/orders/search", source_path="src/A.cs", start_line=50),
        EndpointMapping(endpoint="/api/orders/search", source_path="src/A.cs", environment="prod"),
        EndpointMapping(endpoint="/API/orders/search", source_path="src/A.cs"),
    ],
)
def test_mapping_must_match_exactly(mapping: EndpointMapping) -> None:
    assert relate(runtime("f-r"), source("f-s", "src/A.cs", 10), mappings=[mapping]) is None


def test_without_a_mapping_endpoint_and_handler_names_do_not_relate() -> None:
    r = runtime("f-r", endpoint="/api/orders/search")
    s = source("f-s", "src/Controllers/OrdersController.cs", 22)
    s = s.model_copy(update={"scanner_properties": {"endpoint": "/api/orders/search"}})
    assert relate(r, s) is None


def test_self_pair_is_not_a_relation() -> None:
    a = source("f-a")
    assert relate(a, a) is None


def _fixture_findings() -> list:  # type: ignore[type-arg]
    findings = []
    for name in (
        "codeql/acme-orders.sarif",
        "codeql/acme-billing.sarif",
        "trivy/acme-orders-fs.json",
        "trivy/acme-orders-image.json",
        "trivy/acme-billing-fs.json",
        "mantis/acme-orders.json",
    ):
        findings.extend(load_report(REPORTS / name).findings)
    return findings


def test_real_reports_correlate_without_losing_or_merging_findings() -> None:
    findings = _fixture_findings()
    ids = {f.id for f in findings}
    assert len(ids) == len(findings)
    groups = correlate(findings)
    for group in groups:
        assert len(group.finding_ids) == 2
        assert set(group.finding_ids) <= ids
    assert correlate(findings[::-1]) == groups
    assert correlate(findings[1::2] + findings[::2]) == groups

    by_id = {f.id: f for f in findings}
    duplicates = [g for g in groups if g.relation is GroupRelation.DUPLICATE]
    for group in duplicates:
        a, b = (by_id[i] for i in group.finding_ids)
        assert a.instance_key == b.instance_key

    # The image and the filesystem scan report the same packages; they relate
    # across artifacts but are never duplicates of each other.
    def kinds(group: FindingGroup) -> set[str]:
        return {by_id[i].artifact.kind for i in group.finding_ids if by_id[i].artifact}

    cross = [g for g in groups if kinds(g) == {"filesystem", "image"}]
    assert cross
    assert all(g.relation is GroupRelation.RELATED for g in cross)
    # No runtime finding relates to source without an operator mapping.
    for group in groups:
        kinds = {by_id[i].kind.value for i in group.finding_ids}
        assert kinds != {"runtime", "source"}
