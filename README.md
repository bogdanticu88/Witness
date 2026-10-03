# Witness

Witness is an application security tool for C#/.NET codebases. It is meant to
do two jobs:

- **Triage.** Take the findings your scanners already reported (CodeQL, Trivy,
  Mantis) and check each one against the code. Is there evidence the finding
  is real, a checked reason to call it a false positive, or not enough
  information either way?
- **Review.** Look at a pull request and report security issues it introduced
  in the supported classes, including ones no scanner flagged.

Code questions are answered by a Roslyn-based helper that reads the project
without building it. Model output is never trusted on its own: a finding can
only be marked a likely false positive by a deterministic check, and anything
a model cites is checked against the code first.

Supported vulnerability classes are SQL injection (CWE-89), open redirect
(CWE-601) and path traversal (CWE-22/23/73). Findings outside those are
imported and kept, and reported as `not_assessed` instead of being guessed at.

## Status

Early development. There is no `witness` command yet, and nothing here
produces an assessment. What exists today:

- The normalized finding format (`witness.finding/1`) and assessment schema.
- Importers for CodeQL SARIF, Trivy JSON and Mantis JSON. Every imported
  record points back to the original record in the report, and malformed
  reports are refused rather than partly imported. Mantis SARIF is refused
  because the export drops fields Witness needs.
- Correlation between findings (duplicates, possible chains, related findings).
- A SQLite store for runs and decisions.
- The semantic helper (`semantic/`): static project loading, a sink catalogue
  for the three classes, a bounded value-flow slice, guard detection, callers,
  endpoints and DI registrations, served over a JSON protocol on stdio.
- Two deliberately vulnerable ASP.NET Core apps in `fixtures/apps/` with
  hand-written ground-truth labels, and real reports from running the scanners
  against them in `fixtures/reports/`.

Still to come: the triage verdict engine, model providers, review mode, the
CLI, CI policy gating, reports and packaging.

## Running the tests

Needs Python 3.12+, [uv](https://docs.astral.sh/uv/) and the .NET 10 SDK.

```sh
uv sync
uv run pytest
uv run mypy
uv run ruff check src tests

dotnet test semantic/Witness.Semantic.slnx
```

## Documentation

- [docs/SPEC.md](docs/SPEC.md): what Witness is supposed to do, and what it won't do
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): components and trust boundaries
- [docs/EXECUTION.md](docs/EXECUTION.md): exit codes and error behaviour
- [docs/LIMITATIONS.md](docs/LIMITATIONS.md): known analysis limits
- [fixtures/reports/PROVENANCE.md](fixtures/reports/PROVENANCE.md): how the scanner reports were produced

The fixture apps are vulnerable on purpose. Don't deploy them.

## License

Apache-2.0
