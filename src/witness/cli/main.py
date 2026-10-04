"""``witness`` command line. Only deterministic triage exists so far."""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

import click

from witness.errors import ExitCode, WitnessError
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
    as_json: bool,
    timeout: float,
) -> None:
    """Assess imported findings against the code, without a model.

    \b
    Exit codes: 0 completed, 3 incomplete (timeout or budget),
    4 execution error, 2 usage error, 130 interrupted.

    \b
    Example:
      witness triage --report codeql.sarif --report trivy.json --repo .
    """
    with Store.open(db) as store:
        outcome = run_triage(
            list(reports),
            repo,
            store=store,
            helper_factory=lambda: start_helper(helper, timeout_s=timeout),
            snapshot_revision=revision,
            report_revision=report_revision,
            package_directory=package_directory,
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
    }


def _print_summary(outcome: TriageOutcome) -> None:
    counts = collections.Counter(a.status.value for a in outcome.assessments)
    click.echo(f"run {outcome.run_id}: {outcome.status}, {len(outcome.findings)} findings")
    for status in ("supported", "likely_false_positive", "inconclusive", "stale", "not_assessed"):
        click.echo(f"  {status:22} {counts.get(status, 0)}")
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
