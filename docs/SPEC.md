# Witness product specification

Status: release candidate scope, version 0.1.0.

Witness is a command-line application security investigation tool for C#/.NET
codebases. It has two modes that share infrastructure but answer different
questions.

| Mode | Question it answers | Primary input | Output |
|------|---------------------|---------------|--------|
| Triage | "Of the findings our scanners already reported, which are supported by evidence in this code, which have a checked reason to be considered false positives, and which deserve attention first?" | Scanner reports plus a repository snapshot | Per-finding assessment, evidence, remediation priority |
| Review | "Did this pull request introduce a security issue in a supported class, including one no scanner reported?" | Base and head revisions of a git repository | New, pre-existing and uncertain review findings with evidence |

Triage validates claims somebody else made. Review discovers issues. Witness
reports them separately and evaluates them on separate datasets. A good Triage
result says nothing about Review recall, and the reverse.

## What Witness does not do

- It does not certify a repository, image or deployment as safe.
- It does not dismiss scanner findings on its own authority. A finding can be
  assessed as a likely false positive only through deterministic checks, and
  the CI policy still gates on the original scanner result unless the operator
  configures otherwise.
- It does not modify source code, open pull requests or generate fixes.
- It does not execute repository build logic (MSBuild targets, restore,
  analyzers, source generators) during analysis.
- It does not run scanners as part of triage. Reports are imported.

Human review is the intended last step for every conclusion.

## Supported analysis

Source-code vulnerability classes with evaluated support in both modes:

- SQL injection (CWE-89)
- Open redirect (CWE-601)
- Path traversal (CWE-22, CWE-23, CWE-73)

Dependency findings (Trivy) are triaged through package applicability,
intelligence enrichment (CVSS, CISA KEV, EPSS) and operator context. Runtime
findings (Mantis DAST) are normalized, correlated with code where a declared
endpoint mapping exists, and prioritized.

Everything else is imported, preserved, correlated and reported as
`not_assessed`. Witness never sends an unsupported finding through a generic
prompt and calls the result an assessment.

## Assessments

Each finding receives exactly one assessment:

| Assessment | Meaning |
|------------|---------|
| `supported` | Evidence supports the finding. The basis is either a deterministic source-to-sink path or a model-proposed path whose every hop was checked against code and semantic facts. |
| `likely_false_positive` | A deterministic, vulnerability-specific check showed the reported value cannot carry an attack on every relevant path, with all required context resolved. Model opinion alone can never produce this. |
| `inconclusive` | Evidence is insufficient either way. This includes unknown custom sanitizers, unresolved symbols, incomplete call graphs, exhausted budgets and provider failures. |
| `stale` | The finding cannot be located in the analyzed snapshot, or was produced against a different revision. |
| `not_assessed` | The finding is outside the supported classes or finding kinds. |

Priority (P1 to P4) is computed separately from assessment by deterministic,
configurable rules. Unknown factors are listed and never silently lower
priority.

The CI gate is a third, separate decision computed by `witness policy` from
stored results and an operator policy file.

## Investigation profiles

| Profile | Model use | Semantic retrieval |
|---------|-----------|--------------------|
| `economy` | One bounded call per finding | Deterministic facts only |
| `standard` | Tool loop with approved read-only queries | Model may request more context |
| `deep` | Three specialists coordinated by Python: flow tracer, mitigation investigator, challenger | As standard, per specialist |
| `none` | No model | Deterministic facts only |

All profiles use the same evidence requirements. A smaller budget leads to
more `inconclusive` results, not weaker standards.

## Non-goals for 0.1

Authorization flaws, XSS, deserialization, SSRF, secrets and IaC findings are
not assessed. They may be imported and gated on. Languages other than C# are
not analyzed.
