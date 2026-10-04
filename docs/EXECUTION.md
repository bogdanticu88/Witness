# Execution contract

How Witness is invoked, what it touches, and what it returns. Exit codes are
part of the public interface; CI pipelines branch on them.

## Exit codes

| Code | Name | Meaning |
|------|------|---------|
| 0 | OK | Analysis completed; policy evaluated to pass (or no policy ran). |
| 1 | POLICY_FAILED | Analysis completed; the policy gate failed. |
| 2 | USAGE | Usage or configuration error detected before analysis ran (bad flags, missing config, unreadable inputs). |
| 3 | INCOMPLETE | Analysis ran but is incomplete: provider failure, budget or timeout exhaustion, unsupported blocking inputs. Results on disk are partial and marked incomplete. |
| 4 | EXECUTION_ERROR | Witness itself failed: malformed report, helper crash, storage error. |
| 130 | INTERRUPTED | SIGINT (Ctrl+C). Completed results are kept; nothing partial is cached. |

Expected errors print an actionable message and a hint, no traceback.
`--debug` adds detail and still never prints secrets.

## Inputs and authority

- Scanner reports are imported, never executed. Repository snapshots are read
  only. Witness never runs scanners, never builds repository code, and never
  modifies source.
- The semantic helper is a separate process with a scrubbed environment: no
  model credentials, no network. It speaks `witness.semantic/1` on stdio.
- Model providers are contacted only over operator-configured endpoints.
  Egress is off unless configured.
- Model output cannot change configuration, policy, the query menu or the set
  of findings.

## Modes

- `witness triage --report REPORT [--report ...] --repo PATH` assesses
  imported findings against the snapshot and prioritises them. With
  `--intel DIR` priority uses a local CVSS, KEV and EPSS snapshot
  (`docs/PRIORITY.md`). A missing intelligence directory or manifest is a
  usage error (2); a malformed intelligence file stops the run before
  anything is stored (4), as a malformed scanner report does.
- `witness report [--run ID] [--output DIR]` renders a stored run as JSON and
  Markdown. It exits 0 when the files are written, whatever the run's own
  status, which the report and `--json` output state. It exits 2 for an
  unknown run, a missing database or a report file that already exists, and
  4 for a storage error.
- `witness review --repo PATH --base REV --head REV` reviews a pull request
  for supported classes.
- `witness policy` evaluates stored results against an operator policy file.
- `witness setup`, `witness doctor`, `witness demo` support first use (not
  implemented yet; `scripts/demo-offline.sh` runs the offline triage demo).

## Interruption and storage

On SIGINT the run is marked interrupted, evidence already collected is kept,
and no partial investigation is cached. One SQLite database per workspace
(`.witness/witness.db`), forward-only migrations. Rendered reports go to a
fresh per-run directory and are never overwritten.

## Restore contract (optional dependency restore)

Analysis never restores packages. When packages are needed for symbol
resolution, the operator restores separately:

1. Run `dotnet restore` in a separate container with no model credentials,
   writing to a package directory.
2. Mount that directory read-only into the analysis container.
3. Pass it to the helper as the package directory.

When the package directory is absent, the corresponding symbols stay
unresolved and dependent assessments abstain rather than guess.
