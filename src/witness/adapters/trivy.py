"""Trivy JSON adapter (SchemaVersion 2, ``Results[].Vulnerabilities[]``)."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal

from witness.adapters.base import (
    ImportContext,
    ImportResult,
    finding_id,
    first_text,
    instance_key,
)
from witness.errors import InputError
from witness.model.finding import (
    ArtifactIdentity,
    Finding,
    FindingKind,
    PackageRef,
    Provenance,
    ScannerIdentity,
    Severity,
    VulnClass,
)

_IMAGE_TAG = re.compile(r"^[A-Za-z0-9./_-]+:[A-Za-z0-9_.-]+$")
_IMAGE_SUFFIX = re.compile(r"\s+\([^()]*\)$")

_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.UNKNOWN,
}


class TrivyAdapter:
    format = "trivy"

    def detect(self, document: object) -> bool:
        if not isinstance(document, dict):
            return False
        results = document.get("Results")
        if not isinstance(results, list):
            return False
        for result in results:
            if not isinstance(result, dict):
                continue
            vulnerabilities = result.get("Vulnerabilities")
            if not isinstance(vulnerabilities, list):
                continue
            if any(isinstance(v, dict) and "VulnerabilityID" in v for v in vulnerabilities):
                return True
        return False

    def parse(self, document: object, context: ImportContext) -> ImportResult:
        doc = _require_dict(document)
        version = doc.get("SchemaVersion")
        if version != 2:
            raise InputError(f"trivy: expected SchemaVersion 2, found {version!r}")
        results = doc.get("Results")
        if not isinstance(results, list):
            raise InputError("trivy: Results must be a list")

        metadata = doc.get("Metadata")
        tool_version = metadata.get("TrivyVersion") if isinstance(metadata, dict) else None
        artifact_name = doc.get("ArtifactName") if isinstance(metadata, dict) else None
        artifact = ArtifactIdentity(
            kind=_artifact_kind(results),
            name=str(artifact_name) if artifact_name else None,
        )
        scanned_at = _parse_time(doc.get("CreatedAt"))

        findings: list[Finding] = []
        for i, result in enumerate(results):
            if not isinstance(result, dict):
                raise InputError(f"trivy: Results[{i}] must be an object")
            target = result.get("Target")
            pkg_type = result.get("Type")
            vulnerabilities = result.get("Vulnerabilities")
            if not isinstance(vulnerabilities, list):
                continue
            for j, entry in enumerate(vulnerabilities):
                if not isinstance(entry, dict) or not entry.get("VulnerabilityID"):
                    raise InputError(
                        f"trivy: Results[{i}].Vulnerabilities[{j}] is not a vulnerability entry"
                    )
                pointer = f"/results/{i}/vulnerabilities/{j}"
                findings.append(
                    _finding(
                        entry, context, pointer, target, pkg_type,
                        artifact, tool_version, scanned_at,
                    ),
                )
        return ImportResult(
            format=self.format,
            tool="Trivy",
            tool_version=str(tool_version) if tool_version else None,
            findings=findings,
        )


def _finding(
    entry: dict[str, Any],
    context: ImportContext,
    pointer: str,
    target: object,
    pkg_type: object,
    artifact: ArtifactIdentity,
    tool_version: object,
    scanned_at: datetime | None,
) -> Finding:
    vuln_id = str(entry["VulnerabilityID"])
    vendor_ids = entry.get("VendorIDs")
    identifier = entry.get("PkgIdentifier")
    severity_original = entry.get("Severity")
    package = PackageRef(
        name=str(entry.get("PkgName") or "unknown"),
        version=first_text(entry.get("InstalledVersion")),
        ecosystem="nuget" if pkg_type == "nuget" else first_text(pkg_type),
        purl=first_text(identifier.get("PURL")) if isinstance(identifier, dict) else None,
        fixed_versions=_fixed_versions(entry),
        origin=first_text(target),
    )
    return Finding(
        id=finding_id(context, pointer),
        instance_key=instance_key("dependency", package.name, package.version, vuln_id),
        kind=FindingKind.DEPENDENCY,
        category=VulnClass.UNCLASSIFIED,
        category_basis=f"trivy:{pkg_type}" if pkg_type else "trivy:unknown",
        scanner=ScannerIdentity(name="Trivy", version=first_text(tool_version)),
        severity=_SEVERITY.get(str(severity_original).upper(), Severity.UNKNOWN),
        severity_original=first_text(severity_original),
        title=first_text(entry.get("Title"), vuln_id) or vuln_id,
        message=first_text(entry.get("Description")),
        cwe=_cwe_ids(entry.get("CWEIDs")),
        vulnerability_ids=(vuln_id, *_vendor_ids(vendor_ids)),
        location=None,
        package=package,
        artifact=artifact,
        provenance=Provenance(
            report_path=str(context.report_path),
            report_sha256=context.report_sha256,
            report_format="trivy",
            record_pointer=pointer,
            imported_at=context.imported_at,
            scanned_at=scanned_at,
        ),
        original=entry,
    )


def _vendor_ids(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(v) for v in value if isinstance(v, str) and v.strip())


def _cwe_ids(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(c) for c in value if isinstance(c, str) and c.strip())


def _fixed_versions(entry: dict[str, Any]) -> tuple[str, ...]:
    versions = entry.get("FixedVersions")
    if isinstance(versions, list):
        return tuple(str(v).strip() for v in versions if isinstance(v, str) and v.strip())
    fixed = first_text(entry.get("FixedVersion"))
    if fixed:
        return tuple(part.strip() for part in fixed.split(",") if part.strip())
    return ()


def _artifact_kind(results: list[Any]) -> Literal["image", "filesystem"]:
    for result in results:
        if not isinstance(result, dict) or result.get("Class") != "os-pkgs":
            continue
        target = result.get("Target")
        if isinstance(target, str) and _IMAGE_TAG.match(_IMAGE_SUFFIX.sub("", target)):
            return "image"
    return "filesystem"


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _require_dict(document: object) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise InputError("trivy: report must be a JSON object")
    return document
