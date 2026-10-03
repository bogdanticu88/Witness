"""Mantis DAST JSON adapter (native ``application``/``target`` + ``findings[]`` export).

Detection claims only the native JSON format: a document with top-level
``application``, ``target`` and a ``findings`` list. The Mantis SARIF export is
deliberately not claimed. It records the same findings but drops evidence,
confidence, CWE, OWASP, tags, template identity and run metadata (see
``fixtures/reports/PROVENANCE.md``), so importing it would silently lose what
the JSON preserves. Mantis SARIF files therefore match no adapter and are
rejected by the loader as unsupported.

Per the provenance evidence-attachment caveat, Mantis accumulates the
exchanges of earlier probes in multi-path template runs, including probes that
matched nothing. Witness keeps every recorded exchange in ``original`` and
``runtime.exchanges`` and treats exchanges whose URL does not match the
finding's own endpoint as unconfirmed context.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from witness.adapters.base import (
    ImportContext,
    ImportResult,
    finding_id,
    first_text,
    instance_key,
)
from witness.errors import InputError
from witness.model.finding import (
    Finding,
    FindingKind,
    HttpExchange,
    Provenance,
    RuntimeContext,
    ScannerIdentity,
    Severity,
    VulnClass,
)

_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "unknown": Severity.UNKNOWN,
}

# Mapping by CWE keeps classification grounded in the report's own fields: the
# custom templates in fixtures/mantis/templates/ carry CWE-601, CWE-22 and
# CWE-89, and the passive header checks carry none of the supported CWEs.
_CWE_CATEGORY = {
    "CWE-89": VulnClass.SQL_INJECTION,
    "CWE-601": VulnClass.OPEN_REDIRECT,
    "CWE-22": VulnClass.PATH_TRAVERSAL,
    "CWE-23": VulnClass.PATH_TRAVERSAL,
    "CWE-73": VulnClass.PATH_TRAVERSAL,
}


class MantisAdapter:
    format = "mantis"

    def detect(self, document: object) -> bool:
        if not isinstance(document, dict):
            return False
        findings = document.get("findings")
        return (
            isinstance(findings, list)
            and isinstance(document.get("application"), str)
            and isinstance(document.get("target"), str)
        )

    def parse(self, document: object, context: ImportContext) -> ImportResult:
        doc = _require_dict(document)
        findings_raw = doc.get("findings")
        if not isinstance(findings_raw, list):
            raise InputError("mantis: findings must be a list")
        report_environment = first_text(doc.get("environment"))
        report_target = first_text(doc.get("target"))
        report_scanned_at = _parse_time(doc.get("timestamp"))

        findings: list[Finding] = []
        for i, record in enumerate(findings_raw):
            if not isinstance(record, dict):
                raise InputError(f"mantis: findings[{i}] must be an object")
            findings.append(
                _finding(
                    record, i, context, report_environment, report_target, report_scanned_at
                ),
            )
        return ImportResult(format=self.format, tool="Mantis", tool_version=None,
                            findings=findings)


def _finding(
    record: dict[str, Any],
    index: int,
    context: ImportContext,
    report_environment: str | None,
    report_target: str | None,
    report_scanned_at: datetime | None,
) -> Finding:
    name = first_text(record.get("name"))
    if not name:
        raise InputError(f"mantis: findings[{index}] has no name")
    record_id = first_text(record.get("id"))
    severity_original = record.get("severity")
    if not isinstance(severity_original, str) or not severity_original.strip():
        raise InputError(f"mantis: findings[{index}] has no severity")
    severity_text = severity_original.strip().lower()
    endpoint = _optional_str(record, "endpoint", index)
    method = _optional_str(record, "method", index)
    description = first_text(record.get("description"))
    cwe = first_text(record.get("cwe"))
    category = VulnClass.UNCLASSIFIED
    if cwe:
        category = _CWE_CATEGORY.get(cwe.upper(), VulnClass.UNCLASSIFIED)
    tags = _tags(record.get("tags"), index)
    evidence = record.get("evidence")
    if evidence is not None and not isinstance(evidence, dict):
        raise InputError(f"mantis: findings[{index}].evidence must be an object")
    evidence = evidence if isinstance(evidence, dict) else {}
    evidence_description = first_text(evidence.get("description"))
    exchanges = _exchanges(evidence.get("exchanges"), index)

    # Passive checks (tagged "passive") are built-in header checks, not custom
    # templates; only template findings record their template id in `id`.
    template = None if "passive" in tags else record_id
    scanner_properties: dict[str, Any] = {
        "confidence": _confidence(record.get("confidence"), index),
        "owasp": first_text(record.get("owasp")),
        "tags": list(tags),
        "template": template,
    }

    identity = (
        category.value if category is not VulnClass.UNCLASSIFIED else name
    )
    pointer = f"/findings/{index}"
    return Finding(
        id=finding_id(context, pointer),
        instance_key=instance_key("runtime", endpoint, method, identity, record_id),
        kind=FindingKind.RUNTIME,
        category=category,
        category_basis=cwe if cwe else (record_id or "mantis"),
        scanner=ScannerIdentity(
            name="Mantis",
            version=None,
            rule_id=record_id,
            rule_name=name,
        ),
        severity=_SEVERITY.get(severity_text, Severity.UNKNOWN),
        severity_original=severity_original,
        title=name,
        message=first_text(description, evidence_description),
        cwe=(cwe,) if cwe else (),
        location=None,
        runtime=RuntimeContext(
            environment=first_text(record.get("environment"), report_environment),
            target=first_text(record.get("target"), report_target),
            endpoint=endpoint,
            method=method,
            exchanges=exchanges,
        ),
        scanner_properties=scanner_properties,
        provenance=Provenance(
            report_path=str(context.report_path),
            report_sha256=context.report_sha256,
            report_format="mantis",
            record_pointer=pointer,
            imported_at=context.imported_at,
            scanned_at=_parse_time(record.get("timestamp")) or report_scanned_at,
        ),
        original=record,
    )


def _confidence(value: object, index: int) -> int | float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise InputError(f"mantis: findings[{index}].confidence must be a number")
    return value


def _tags(value: object, index: int) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(t, str) for t in value):
        raise InputError(f"mantis: findings[{index}].tags must be a list of strings")
    return tuple(value)


def _exchanges(value: object, index: int) -> tuple[HttpExchange, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise InputError(f"mantis: findings[{index}].evidence.exchanges must be a list")
    exchanges: list[HttpExchange] = []
    for j, entry in enumerate(value):
        if not isinstance(entry, dict):
            raise InputError(f"mantis: findings[{index}].evidence.exchanges[{j}] must be an object")
        exchanges.append(
            HttpExchange(
                method=first_text(entry.get("method")) or "",
                url=first_text(entry.get("url")) or "",
                status_code=_optional_int(entry.get("status_code"), index, j),
                request_headers=_string_map(entry.get("request_headers"), index, j),
                request_body=first_text(entry.get("request_body")),
                response_headers=_string_map(entry.get("response_headers"), index, j),
                response_body=first_text(entry.get("response_body")),
                duration_ms=_optional_int(entry.get("duration_ms"), index, j),
            ),
        )
    return tuple(exchanges)


def _string_map(value: object, index: int, exchange: int) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise InputError(
            f"mantis: findings[{index}].evidence.exchanges[{exchange}] headers must be an object"
        )
    result: dict[str, str] = {}
    for key, item in value.items():
        if isinstance(key, str) and isinstance(item, str | int | float | bool):
            result[key] = str(item)
    return result


def _optional_str(record: dict[str, Any], field: str, index: int) -> str | None:
    value = record.get(field)
    if value is None:
        return None
    if not isinstance(value, str):
        raise InputError(f"mantis: findings[{index}].{field} must be a string")
    return first_text(value)


def _optional_int(value: object, index: int, exchange: int) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise InputError(f"mantis: findings[{index}].evidence.exchanges[{exchange}] has a "
                         "non-integer numeric field")
    return value


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _require_dict(document: object) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise InputError("mantis: report must be a JSON object")
    return document
