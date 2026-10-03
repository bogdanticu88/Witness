# Scanner report provenance

Every report under `fixtures/reports/` was produced by a real scanner against
the fixture applications in `fixtures/apps/`. This file records what is known
about how each was produced, from the reports themselves and from the
controlled-test records in `fixtures/apps/acme-orders/CONTROLLED_TESTS.md`.
Fields the tools did not record are marked **unknown**, not guessed.

Report hashes are SHA-256 of the file bytes as committed.

## CodeQL (`codeql/`)

| Report | sha256 | Results |
|--------|--------|---------|
| `acme-orders.sarif` | `d853ea09197e4120e4cbe82824da75ed361011d452f6b336b3aa7fff8c131cb1` | 17 (9 `cs/sql-injection`, 5 `cs/path-injection`, 3 `cs/web/unvalidated-url-redirection`) |
| `acme-billing.sarif` | `f8ccc2871258418ffde211cbec6a53a43f5929f46d13672fab9a642e5e9c174e` | 1 (`cs/sql-injection`) |
| `codeql-version.json` | `009eb0307d67d76f1fb20397c8c3248072e1dc307f0159394d861d6664f298d6` | `codeql version --format=json` output |

- Tool: CodeQL CLI **2.27.1** (sha `938af3639d0709b587251e45d9f8d2bdc3505696`,
  recorded in `codeql-version.json` and `tool.driver.semanticVersion` in both
  SARIF files; `tool.driver.version` is absent).
- `codeql-version.json` shows `unpackedLocation: /opt/codeql` and a root config
  path, consistent with a Linux container run. The previous session reported
  the analysis ran in an emulated amd64 container on this host; the container
  image id and exact `codeql database create`/analyze commands were not
  recorded and are **unknown**.
- Ruleset: the 63-rule set bundled in the SARIF (standard CodeQL `codeql/csharp`
  queries for the three supported classes plus others declared).
- Analyzed revision: not embedded in the SARIF; fixture source as of
  2026-10-03. The fixture apps are not under version control, so a revision id
  cannot be recorded (**unknown**).

## Trivy (`trivy/`)

| Report | sha256 | Contents |
|--------|--------|----------|
| `acme-orders-fs.json` | `34b9862b1f93c69afe9a3b264089358f8d5c999a651b92e3b33bcb237abe6587` | filesystem scan: 4 results (Data/Web `packages.lock.json` + built `*.deps.json`), 5 distinct CVEs |
| `acme-billing-fs.json` | `06d6b3d8fe9c1578d7c4a09e8281d3f486c2d954943627d6c500c9c183c3308d` | filesystem scan: 2 results, 2 distinct CVEs |
| `acme-orders-image.json` | `b2e63a20239ca40dc26a24dada6d6206e1db61f60c9e171814a4c98f4f686d0b` | image scan of `witness-fixture/acme-orders:rc`: 14 OS vulnerability records (10 distinct CVEs, ubuntu 24.04) + 5 .NET dependency records |

- Tool version: **0.75.0**, recorded in top-level `Trivy.Version` in all
  three reports. `Metadata.TrivyVersion` is absent.
- Exact scan times are recorded in top-level `CreatedAt`:
  orders fs `2026-10-03T00:50:51.607453+03:00`, billing fs
  `2026-10-03T00:50:51.670349+03:00`, orders image
  `2026-10-03T00:50:52.931495+03:00`.
- Artifact names and types are recorded in top-level `ArtifactName` and
  `ArtifactType`. The image report also records `ArtifactID` and
  `Metadata.ImageID`; these identify different objects and are kept distinct.
- The image digest recorded in `CONTROLLED_TESTS.md` is
  `witness-fixture/acme-orders@sha256:2509d34c09f3649f35adb8a44e1f324d9f4f2207df49487eaf56509696f22799`;
  the image report names the tag `witness-fixture/acme-orders:rc`. This matches the image report
  `Metadata.ImageID`. Whether the filesystem reports correspond to this image
  is **unknown**.
- Distinct dependency CVEs (all also present in the labels):
  CVE-2024-21907 (Newtonsoft.Json 12.0.3), CVE-2021-32840/32841/32842
  (SharpZipLib 1.3.2), CVE-2025-6965 (SQLitePCLRaw.lib.e_sqlite3 2.1.11,
  no fixed version).

## Mantis (`mantis/`)

| Report | sha256 | Contents |
|--------|--------|----------|
| `acme-orders.json` | `3c7393e5681b14c454d6b4650a1327ec3099c761541e734b3b389b426e701665` | 19 findings (6 passive header checks + 13 template findings from 4 custom templates) |
| `acme-orders.sarif` | `ac7c8b78fe302c1cfa96a20ae807a55aa0ae7811d05797a79680e7d820cb3c04` | SARIF export of the same 19 findings; loses evidence, confidence, cwe, owasp, tags, template and run metadata |

- Tool: Mantis (DAST). Tool version: **unknown** (no version field in the
  report).
- Run metadata from the JSON: `application: acme-orders`,
  `environment: staging-local`, `target: http://127.0.0.1:18080`,
  `timestamp: 2026-10-03T00:53:34.899956+03:00`, `gate_passed: false`,
  `exit_code: 1`. `fixtures/mantis/environments.yaml` defines
  `staging-local` as `http://127.0.0.1:18080`.
- The target matches the default-configuration container in
  `CONTROLLED_TESTS.md` (port 18080, `Search__Mode` unset).
- Custom templates live in `fixtures/mantis/templates/` (`acme-open-redirect`,
  `acme-path-traversal`, `acme-sqli-boolean`, `acme-sqli-boolean-customers`).

### Evidence-attachment caveat (verified against this report)

In multi-path template runs, Mantis attaches the accumulated exchanges of
earlier requests in the same template to later findings, including failed
probes and probes that matched nothing. Verified instances: the
`acme-open-redirect` finding for `/links/out` carries the exchanges of the
three earlier redirect probes; the `acme-path-traversal` finding for
`/api/documents/open` carries five earlier exchanges; the `acme-sqli-boolean`
finding for `/api/orders/lookup` carries four earlier exchanges, one of which
(`/api/customers/by-region` returning all customers) is the only record of a
successful exploit of a labeled site that produced no finding of its own
(label `sql-11`). No cross-template contamination was found (no redirect or
traversal exchange appears inside a SQL finding).

Witness records `scanner_properties.exchange_associations`, parallel to
`runtime.exchanges`. Only exact URL (including host and query) and HTTP method
matches are marked `matching_endpoint`; the rest are `unconfirmed_context`.
Even `matching_endpoint` is association, not confirmation of a vulnerability.
Every exchange and the original finding remain preserved. Imports with
unconfirmed context return a warning.

## Fixture build state

- Both fixture apps load under the Witness semantic helper (Roslyn) with zero
  compilation errors and zero unresolved symbol errors (verified 2026-10-03,
  helper 0.1.0, Roslyn 5.9, ref packs 10.0.12, package directory
  `~/.nuget/packages`): acme-orders 2 projects / 14 documents / 31 sink sites /
  27 endpoints; acme-billing 1 project / 1 document / 2 sink sites / 1 endpoint.
- With that package directory, `Microsoft.Data.Sqlite` and
  `SQLitePCLRaw.lib.e_sqlite3` still report as unresolved package references
  while Dapper resolves; without a package directory every `PackageReference`
  is unresolved (see label `sql-08`, expected `inconclusive`).
