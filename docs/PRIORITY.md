# Priority and offline intelligence

Priority says which findings to look at first. It is a separate record from
the assessment and is computed after it. Intelligence never changes whether a
finding is supported, dismissed or inconclusive, and the CI gate (not yet
implemented) will read neither by default.

## Intelligence snapshots

Witness does not download anything. The operator prepares a directory and
passes it with `--intel`. The directory holds the published feed files and an
`intel.json` manifest:

```json
{
  "schema": "witness.intel/1",
  "sources": [
    {
      "kind": "kev",
      "path": "known_exploited_vulnerabilities.json",
      "origin": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
      "retrieved_at": "2026-10-04T06:00:00Z",
      "coverage": "full",
      "synthetic": false,
      "sha256": "<optional, checked when present>"
    }
  ]
}
```

| Kind | File format |
|------|-------------|
| `kev` | The CISA KEV catalog JSON, as published |
| `epss` | The FIRST EPSS daily CSV (plain or gzip) with its `#model_version:...,score_date:...` line |
| `cvss` | An NVD CVE API 2.0 response (`"format": "NVD_CVE"`, `"version": "2.0"`); several files can be listed |

Every field in the manifest is required except `sha256` and `note`.
`coverage` says whether the file is the whole feed or an excerpt.
`synthetic` must be stated: synthetic data is labelled in every report that
uses it. Paths must stay inside the directory.

Each file is validated in full: required fields, CVE id syntax, dates,
scores within range, no duplicate entries, and size and nesting limits. One
malformed file refuses the whole snapshot, and the run stops with exit code 4
before anything is stored. A missing directory or manifest is a usage error
(exit 2).

## Freshness

A source's age is measured from the feed's own date (KEV `dateReleased`,
EPSS `score_date`, NVD `timestamp`), not from when it was copied. It is judged
at the start of the run, or at `--as-of` when given, which is recorded with
the run.

| Kind | Default limit | Why |
|------|---------------|-----|
| KEV | 7 days | CISA adds entries several times a week |
| EPSS | 7 days | FIRST publishes new scores daily |
| CVSS | 30 days | NVD scores change rarely once published |

These limits are Witness defaults, not vendor guidance. A source is
`current`, `outdated`, or `future` (dated more than a day after the evaluation
time, a clock or data problem, treated like outdated).

What each state allows:

- A KEV listing counts from any source, outdated or partial. Entries are
  rarely removed.
- "Not in KEV" is established only by a current source with full coverage.
- An EPSS score at or above the threshold raises priority from any source. A
  score below it counts only from a current source.
- CVSS scores from any source can raise the severity. None can lower it.

Anything not established is listed as an unknown factor on the priority,
with what it could change. Unknown factors never lower a priority.

## Rules

Rules version `witness-priority/1`, applied in order. Each priority records
the rules that fired, their inputs, the factor values with source, feed date,
freshness and the synthetic flag, and any conflicting inputs.

1. **base.severity.** The most severe of the scanner's severity and every
   CVSS v3.x or v4.0 base score for the finding's CVE ids. Scores are banded as
   the CVSS specifications do: 9.0 and above critical, 7.0 high, 4.0 medium,
   below that low. Critical is P1, high P2, medium P3, low and info P4. A
   missing scanner severity counts as high. CVSS v2 scores are recorded but
   not used, because their bands differ.
2. **raise.epss.** An EPSS probability at or above the threshold (default
   0.1) raises the level by one. FIRST publishes no cut-off; 0.1 is a
   starting point to tune.
3. **raise.kev.** A CISA KEV listing makes the finding P1, in line with CISA's
   remediation deadlines for listed vulnerabilities.
4. **lower.likely_false_positive.** A complete deterministic
   `likely_false_positive` assessment sets P4. The priority keeps the
   assessment's assumptions in `conditional_on`, and the report shows the
   dismissal as conditional. This rule can be turned off. An incomplete
   assessment never lowers priority.

Supported, inconclusive, stale and not-assessed findings keep their level.
The last three list why as an unknown factor.

The scanner's own severity is always kept as a factor. When sources
disagree (for example Trivy reports high from GHSA while NVD scores 9.8),
both are kept and the disagreement is listed under conflicts.

## Settings

```toml
# --priority-config priority.toml
[priority]
epss_threshold = 0.1
lower_likely_false_positive = true

[freshness]   # days
kev = 7
epss = 7
cvss = 30
```

Unknown keys and out-of-range values are refused (exit 2). The settings in
force are stored with the run and printed in the report.

## Reports

`witness report` renders a stored run as `report.json` (`witness.report/1`)
and `report.md`. Both come from the same document. Scanner- and
repository-controlled text is escaped in Markdown. Existing report files are
never overwritten. The report keeps two statements apart: whether the
analysis completed, and what it found. A completed analysis with no supported
finding says so, and says that this does not mean there are no
vulnerabilities.
