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

Early development. Deterministic triage works: `witness triage` imports
reports, checks each source finding against the code with the semantic helper
and stores one assessment per finding. No model is involved yet. What exists:

- The normalized finding format (`witness.finding/1`) and assessment schema.
- Importers for CodeQL SARIF, Trivy JSON and Mantis JSON. Every imported
  record points back to the original record in the report, and malformed
  reports are refused rather than partly imported. Mantis SARIF is refused
  because the export drops fields Witness needs.
- Deterministic triage for the three supported classes. A finding is
  `supported` when request data reaches the sink with nothing known to stop
  it, and `likely_false_positive` only when every value reaching the sink is
  constant, typed or behind a check whose effect is established (for example
  `Url.IsLocalUrl`, or a normalized path checked against its root). Unknown
  validators, unresolved symbols, configuration values and anything the
  helper could not follow give `inconclusive`. Runtime findings are kept but
  get no code verdict; dependency findings are checked against the lock file
  and otherwise left `inconclusive`.
- Correlation between findings (duplicates, possible chains, related findings,
  operator-declared endpoint mappings).
- A SQLite store for runs, findings, assessments and groups.
- The semantic helper (`semantic/`): static project loading, a sink catalogue
  for the three classes, a bounded value-flow slice, guard detection, callers,
  endpoints and DI registrations, served over a JSON protocol on stdio.
- Two deliberately vulnerable ASP.NET Core apps in `fixtures/apps/` with
  hand-written ground-truth labels, and real reports from running the scanners
  against them in `fixtures/reports/`.

On the two fixture apps, triage agrees with 28 of the 29 hand-written labels;
the other one is an abstention (without restored packages a call does not
resolve). That is agreement on a small fixture set, not a measure of accuracy.
`tests/integration/samples` holds further cases for validators, filters,
middleware and path checks. `docs/LIMITATIONS.md` describes what each verdict
does and does not establish.

Still to come: priority, model providers, review mode, CI policy gating,
rendered reports and packaging.

## Trying it

```sh
dotnet build semantic/Witness.Semantic -c Release
uv run witness triage --repo fixtures/apps/acme-orders \
  --report fixtures/reports/codeql/acme-orders.sarif \
  --report fixtures/reports/trivy/acme-orders-fs.json \
  --report fixtures/reports/mantis/acme-orders.json
```

If .NET is installed somewhere other than the default location, set
`DOTNET_ROOT` so the helper can find the runtime. Results go to
`.witness/witness.db`; add `--json` to print them.

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
