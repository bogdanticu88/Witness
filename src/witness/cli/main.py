"""``witness`` command line: deterministic triage and reports."""

from __future__ import annotations

import collections
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import click

from witness.errors import ExitCode, StoreError, UsageError, WitnessError
from witness.intel import IntelSnapshot, load_intel
from witness.priority import IntelContext, PriorityConfig
from witness.report import FORMATS, write_report
from witness.security.escape import strip_terminal_controls
from witness.store import Store
from witness.triage.engine import TriageOutcome, run_triage, start_helper


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def cli() -> None:
    """Security finding triage for C#/.NET."""


@cli.command()
@click.option(
    "--report",
    "reports",
    multiple=True,
    required=True,
    type=click.Path(path_type=Path),
    help="Scanner report (CodeQL SARIF, Trivy JSON, Mantis JSON). Repeatable.",
)
@click.option(
    "--repo",
    required=True,
    type=click.Path(path_type=Path),
    help="Checkout the reports were produced from. Read only.",
)
@click.option(
    "--db",
    type=click.Path(path_type=Path),
    default=Path(".witness/witness.db"),
    show_default=True,
    help="Workspace database.",
)
@click.option("--helper", help="Path to the witness-semantic helper.")
@click.option("--revision", help="Snapshot revision, when it cannot be read from git.")
@click.option("--report-revision", help="Revision the scanners analyzed, if reports omit it.")
@click.option(
    "--package-directory",
    type=click.Path(path_type=Path),
    help="Restored NuGet packages (global-packages layout) for symbol resolution.",
)
@click.option(
    "--intel",
    type=click.Path(path_type=Path),
    help="Offline intelligence snapshot directory (witness.intel/1 manifest).",
)
@click.option(
    "--as-of",
    "as_of",
    help="Judge intelligence freshness at this ISO 8601 time instead of now.",
)
@click.option(
    "--priority-config",
    type=click.Path(path_type=Path),
    help="TOML file with priority and freshness settings.",
)
@click.option("--json", "as_json", is_flag=True, help="Print the result as JSON.")
@click.option("--timeout", default=300.0, show_default=True, help="Helper timeout per query, s.")
def triage(
    reports: tuple[Path, ...],
    repo: Path,
    db: Path,
    helper: str | None,
    revision: str | None,
    report_revision: str | None,
    package_directory: Path | None,
    intel: Path | None,
    as_of: str | None,
    priority_config: Path | None,
    as_json: bool,
    timeout: float,
) -> None:
    """Assess imported findings against the code, without a model, and
    prioritise them.

    Priority uses CVSS, CISA KEV and EPSS from --intel when given. Nothing is
    downloaded. Missing or outdated intelligence is listed per finding.

    \b
    Exit codes: 0 completed, 3 incomplete (timeout or budget),
    4 execution error (including a malformed report or intelligence file),
    2 usage error, 130 interrupted.

    \b
    Example:
      witness triage --report codeql.sarif --report trivy.json --repo . \\
        --intel intel/2026-10-04
    """
    config = PriorityConfig.load(priority_config) if priority_config else PriorityConfig()
    when = _parse_as_of(as_of) if as_of else datetime.now(UTC)
    snapshot = load_intel(intel) if intel else IntelSnapshot.empty()
    context = IntelContext(snapshot, when, config)
    with Store.open(db) as store:
        outcome = run_triage(
            list(reports),
            repo,
            store=store,
            helper_factory=lambda: start_helper(helper, timeout_s=timeout),
            snapshot_revision=revision,
            report_revision=report_revision,
            package_directory=package_directory,
            intel=context,
        )
    if as_json:
        click.echo(json.dumps(_as_json(outcome), indent=2))
    else:
        _print_summary(outcome)
    sys.exit(int(outcome.exit_code))


def _as_json(outcome: TriageOutcome) -> dict[str, object]:
    return {
        "run_id": outcome.run_id,
        "status": outcome.status,
        "snapshot": {
            "root": str(outcome.snapshot.root),
            "revision": outcome.snapshot.revision,
            "revision_source": outcome.snapshot.revision_source,
        },
        "helper": outcome.helper.model_dump(),
        "incomplete_reasons": outcome.incomplete_reasons,
        "warnings": outcome.warnings,
        "findings": [f.model_dump(mode="json", exclude={"original"}) for f in outcome.findings],
        "assessments": [a.model_dump(mode="json") for a in outcome.assessments],
        "groups": [g.model_dump(mode="json") for g in outcome.groups],
        "priorities": [p.model_dump(mode="json") for p in outcome.priorities],
    }


def _parse_as_of(text: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise UsageError(f"--as-of {text!r} is not an ISO 8601 time") from None
    if parsed.tzinfo is None:
        raise UsageError(f"--as-of {text!r} needs a time zone, for example 2026-10-04T12:00:00Z")
    return parsed.astimezone(UTC)


def _print_summary(outcome: TriageOutcome) -> None:
    counts = collections.Counter(a.status.value for a in outcome.assessments)
    click.echo(f"run {outcome.run_id}: {outcome.status}, {len(outcome.findings)} findings")
    for status in ("supported", "likely_false_positive", "inconclusive", "stale", "not_assessed"):
        click.echo(f"  {status:22} {counts.get(status, 0)}")
    levels = collections.Counter(p.level.value for p in outcome.priorities)
    click.echo(
        "  priority " + ", ".join(f"{lv} {levels.get(lv, 0)}" for lv in ("P1", "P2", "P3", "P4"))
    )
    by_id = {f.id: f for f in outcome.findings}
    for assessment in outcome.assessments:
        finding = by_id[assessment.finding_id]
        if assessment.status.value in ("supported", "likely_false_positive", "stale"):
            where = (
                f"{finding.location.path}:{finding.location.start_line}"
                if finding.location
                else finding.title
            )
            text = strip_terminal_controls(f"{assessment.status.value:22} {where}")
            click.echo(f"  {text}")
    for warning in outcome.warnings:
        click.echo(f"warning: {strip_terminal_controls(warning)}", err=True)


@cli.command()
@click.option("--run", "run_id", help="Run to report on. Default: the latest triage run.")
@click.option(
    "--db",
    type=click.Path(path_type=Path),
    default=Path(".witness/witness.db"),
    show_default=True,
    help="Workspace database.",
)
@click.option(
    "--output",
    type=click.Path(path_type=Path),
    help="Directory for the report files. Default: reports/<run id> next to the database.",
)
@click.option(
    "--format",
    "formats",
    multiple=True,
    type=click.Choice(FORMATS),
    help="json, md or both (default both). Repeatable.",
)
@click.option("--json", "as_json", is_flag=True, help="Print the written paths as JSON.")
def report(
    run_id: str | None, db: Path, output: Path | None, formats: tuple[str, ...], as_json: bool
) -> None:
    """Write a triage report from stored results.

    Nothing is re-analyzed. The report says whether the analysis completed,
    and keeps that apart from whether anything was found. Existing report
    files are never overwritten.

    \b
    Exit codes: 0 written (whatever the run's own status), 2 unknown run,
    missing database or a report file already exists, 4 storage error.

    \b
    Example:
      witness report --run r-0123456789ab --output reports/today
    """
    if not db.is_file():
        raise UsageError(f"no workspace database at {db}", hint="run witness triage first")
    with Store.open(db) as store:
        if run_id is None:
            run_id = store.latest_run("triage")
            if run_id is None:
                raise UsageError(f"no triage run in {db}", hint="run witness triage first")
        else:
            _known_run(store, run_id)
        directory = output if output is not None else db.parent / "reports" / run_id
        written = write_report(store, run_id, directory, formats or FORMATS)
        status = store.get_run(run_id).status
    if as_json:
        click.echo(
            json.dumps({"run_id": run_id, "run_status": status, "files": [str(p) for p in written]})
        )
    else:
        click.echo(f"run {run_id} ({status}): wrote " + ", ".join(str(p) for p in written))
    sys.exit(int(ExitCode.OK))


def _known_run(store: Store, run_id: str) -> None:
    try:
        store.get_run(run_id)
    except StoreError:
        raise UsageError(f"unknown run {run_id!r}") from None


def main() -> None:
    try:
        cli.main(standalone_mode=False)
    except click.exceptions.Abort:
        sys.exit(int(ExitCode.INTERRUPTED))
    except click.ClickException as exc:
        exc.show()
        sys.exit(int(ExitCode.USAGE))
    except WitnessError as exc:
        click.echo(f"error: {strip_terminal_controls(exc.message)}", err=True)
        if exc.hint:
            click.echo(f"hint: {strip_terminal_controls(exc.hint)}", err=True)
        sys.exit(int(exc.exit_code))


if __name__ == "__main__":
    main()
