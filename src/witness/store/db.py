"""SQLite-backed store for witness run state.

One database holds the runs, findings, assessments, priorities, groups,
cache entries, review decisions and report locations for a state directory.
Migrations are forward-only: a database written by a newer version of
witness is refused rather than silently downgraded, because dropping columns
or tables would corrupt history.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from witness.errors import StoreError
from witness.model.assessment import Assessment, FindingGroup, Priority, Usage
from witness.model.finding import Finding

_BUSY_TIMEOUT_MS = 5000

# (version, statements), applied in order. Never edit an applied migration;
# append a new version instead. A database at a version above the last entry
# here is rejected on open.
MIGRATIONS: list[tuple[int, tuple[str, ...]]] = [
    (
        1,
        (
            """CREATE TABLE runs (
                run_id TEXT PRIMARY KEY,
                mode TEXT NOT NULL,
                repo_root TEXT,
                profile TEXT,
                provider TEXT,
                model TEXT,
                status TEXT NOT NULL DEFAULT 'running',
                started_at TEXT NOT NULL,
                finished_at TEXT,
                usage_json TEXT,
                incomplete_reasons_json TEXT
            )""",
            """CREATE TABLE findings (
                run_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                seq INTEGER NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (run_id, finding_id),
                FOREIGN KEY (run_id) REFERENCES runs (run_id)
            )""",
            """CREATE TABLE assessments (
                run_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (run_id, finding_id),
                FOREIGN KEY (run_id) REFERENCES runs (run_id)
            )""",
            """CREATE TABLE priorities (
                run_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (run_id, finding_id),
                FOREIGN KEY (run_id) REFERENCES runs (run_id)
            )""",
            """CREATE TABLE groups (
                run_id TEXT NOT NULL,
                group_id TEXT NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (run_id, group_id),
                FOREIGN KEY (run_id) REFERENCES runs (run_id)
            )""",
            """CREATE TABLE cache_entries (
                namespace TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (namespace, key)
            )""",
            """CREATE TABLE decisions (
                decision_id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                identity TEXT NOT NULL,
                decision TEXT NOT NULL,
                rationale TEXT NOT NULL,
                created_at TEXT NOT NULL,
                run_id TEXT
            )""",
            """CREATE TABLE report_dirs (
                run_id TEXT PRIMARY KEY,
                path TEXT NOT NULL
            )""",
        ),
    ),
]


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class RunRecord:
    run_id: str
    mode: str
    repo_root: str | None
    profile: str | None
    provider: str | None
    model: str | None
    status: str
    started_at: str
    finished_at: str | None
    usage: Usage | None
    incomplete_reasons: tuple[str, ...]


class Decision(BaseModel):
    """A reviewer's decision about a finding. Decisions are never deleted."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision_id: str
    finding_id: str
    identity: str
    decision: Literal["confirmed", "dismissed", "needs_review"]
    rationale: str
    created_at: datetime
    run_id: str | None = None


class Store:
    """SQLite persistence for one witness state database.

    A fresh store per process is the expected use; writes are serialized with
    an in-process re-entrant lock so concurrent threads cannot interleave
    statements within one transaction.
    """

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection
        self._lock = threading.RLock()

    @classmethod
    def open(cls, path: Path) -> Store:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            connection = sqlite3.connect(path)
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
        except sqlite3.Error as exc:
            raise StoreError(f"cannot open database at {path}: {exc}") from exc
        store = cls(connection)
        try:
            store.migrate()
        except Exception:
            connection.close()
            raise
        return store

    def migrate(self) -> None:
        with self._locked_tx() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                "version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
            current = int(row[0]) if row is not None and row[0] is not None else 0
        latest = MIGRATIONS[-1][0] if MIGRATIONS else 0
        if current > latest:
            raise StoreError(
                f"database schema is version {current}, newer than this witness build "
                f"supports ({latest})",
                hint="upgrade witness instead of downgrading the database",
            )
        for version, statements in MIGRATIONS:
            if version <= current:
                continue
            with self._locked_tx() as conn:
                for statement in statements:
                    conn.execute(statement)
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (version, _utc_now()),
                )

    def start_run(
        self,
        mode: str,
        repo_root: Path | str | None,
        profile: str | None,
        provider: str | None,
        model: str | None,
    ) -> RunRecord:
        run_id = f"r-{uuid.uuid4().hex[:12]}"
        started_at = _utc_now()
        with self._locked_tx() as conn:
            conn.execute(
                "INSERT INTO runs (run_id, mode, repo_root, profile, provider, model, started_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    mode,
                    str(repo_root) if repo_root is not None else None,
                    profile,
                    provider,
                    model,
                    started_at,
                ),
            )
        return RunRecord(
            run_id=run_id,
            mode=mode,
            repo_root=str(repo_root) if repo_root is not None else None,
            profile=profile,
            provider=provider,
            model=model,
            status="running",
            started_at=started_at,
            finished_at=None,
            usage=None,
            incomplete_reasons=(),
        )

    def set_run_status(
        self,
        run_id: str,
        status: str,
        *,
        usage: Usage | None = None,
        incomplete_reasons: tuple[str, ...] = (),
        finished: bool = False,
    ) -> None:
        assignments = ["status = ?"]
        params: list[object] = [status]
        if usage is not None:
            assignments.append("usage_json = ?")
            params.append(usage.model_dump_json())
        if incomplete_reasons:
            assignments.append("incomplete_reasons_json = ?")
            params.append(json.dumps(list(incomplete_reasons)))
        if finished:
            assignments.append("finished_at = ?")
            params.append(_utc_now())
        params.append(run_id)
        # assignments are internal column literals ("col = ?"); values are bound.
        sql = f"UPDATE runs SET {', '.join(assignments)} WHERE run_id = ?"  # noqa: S608
        with self._locked_tx() as conn:
            cursor = conn.execute(sql, params)
            if cursor.rowcount == 0:
                raise StoreError(f"unknown run: {run_id}")

    def get_run(self, run_id: str) -> RunRecord:
        row = self._query_one(
            "SELECT run_id, mode, repo_root, profile, provider, model, status, started_at,"
            " finished_at, usage_json, incomplete_reasons_json"
            " FROM runs WHERE run_id = ?",
            (run_id,),
        )
        if row is None:
            raise StoreError(f"unknown run: {run_id}")
        return RunRecord(
            run_id=row[0],
            mode=row[1],
            repo_root=row[2],
            profile=row[3],
            provider=row[4],
            model=row[5],
            status=row[6],
            started_at=row[7],
            finished_at=row[8],
            usage=Usage.model_validate_json(row[9]) if row[9] else None,
            incomplete_reasons=tuple(json.loads(row[10])) if row[10] else (),
        )

    def save_findings(self, run_id: str, findings: Sequence[Finding]) -> None:
        with self._locked_tx() as conn:
            for seq, finding in enumerate(findings):
                conn.execute(
                    "INSERT OR REPLACE INTO findings (run_id, finding_id, seq, data)"
                    " VALUES (?, ?, ?, ?)",
                    (run_id, finding.id, seq, finding.model_dump_json()),
                )

    def list_findings(self, run_id: str) -> list[Finding]:
        rows = self._query(
            "SELECT data FROM findings WHERE run_id = ? ORDER BY seq", (run_id,)
        )
        return [Finding.model_validate_json(row[0]) for row in rows]

    def save_assessment(self, run_id: str, assessment: Assessment) -> None:
        with self._locked_tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO assessments (run_id, finding_id, data) VALUES (?, ?, ?)",
                (run_id, assessment.finding_id, assessment.model_dump_json()),
            )

    def get_assessment(self, run_id: str, finding_id: str) -> Assessment | None:
        row = self._query_one(
            "SELECT data FROM assessments WHERE run_id = ? AND finding_id = ?",
            (run_id, finding_id),
        )
        return Assessment.model_validate_json(row[0]) if row is not None else None

    def list_assessments(self, run_id: str) -> list[Assessment]:
        rows = self._query(
            "SELECT data FROM assessments WHERE run_id = ? ORDER BY finding_id", (run_id,)
        )
        return [Assessment.model_validate_json(row[0]) for row in rows]

    def save_priority(self, run_id: str, priority: Priority) -> None:
        with self._locked_tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO priorities (run_id, finding_id, data) VALUES (?, ?, ?)",
                (run_id, priority.finding_id, priority.model_dump_json()),
            )

    def list_priorities(self, run_id: str) -> list[Priority]:
        rows = self._query(
            "SELECT data FROM priorities WHERE run_id = ? ORDER BY finding_id", (run_id,)
        )
        return [Priority.model_validate_json(row[0]) for row in rows]

    def save_groups(self, run_id: str, groups: Sequence[FindingGroup]) -> None:
        with self._locked_tx() as conn:
            for group in groups:
                conn.execute(
                    "INSERT OR REPLACE INTO groups (run_id, group_id, data) VALUES (?, ?, ?)",
                    (run_id, group.id, group.model_dump_json()),
                )

    def list_groups(self, run_id: str) -> list[FindingGroup]:
        rows = self._query(
            "SELECT data FROM groups WHERE run_id = ? ORDER BY group_id", (run_id,)
        )
        return [FindingGroup.model_validate_json(row[0]) for row in rows]

    def cache_put(self, namespace: str, key: str, value: str) -> None:
        if not namespace.strip():
            raise StoreError("cache namespace must be non-empty")
        with self._locked_tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cache_entries (namespace, key, value, created_at)"
                " VALUES (?, ?, ?, ?)",
                (namespace, key, value, _utc_now()),
            )

    def cache_get(self, namespace: str, key: str) -> str | None:
        row = self._query_one(
            "SELECT value FROM cache_entries WHERE namespace = ? AND key = ?",
            (namespace, key),
        )
        return row[0] if row is not None else None

    def record_report_dir(self, run_id: str, path: Path) -> str:
        recorded = str(path)
        with self._locked_tx() as conn:
            row = conn.execute(
                "SELECT path FROM report_dirs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO report_dirs (run_id, path) VALUES (?, ?)",
                    (run_id, recorded),
                )
            elif row[0] != recorded:
                raise StoreError(
                    f"run {run_id} already has a different report directory recorded: {row[0]}",
                    hint="reports are never silently relocated; use the recorded directory",
                )
        return recorded

    def add_decision(self, decision: Decision) -> None:
        with self._locked_tx() as conn:
            try:
                conn.execute(
                    "INSERT INTO decisions (decision_id, finding_id, identity, decision,"
                    " rationale, created_at, run_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        decision.decision_id,
                        decision.finding_id,
                        decision.identity,
                        decision.decision,
                        decision.rationale,
                        decision.created_at.isoformat(),
                        decision.run_id,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise StoreError(f"decision already exists: {decision.decision_id}") from exc

    def list_decisions(self) -> list[Decision]:
        rows = self._query(
            "SELECT decision_id, finding_id, identity, decision, rationale, created_at, run_id"
            " FROM decisions ORDER BY created_at, decision_id"
        )
        return [
            Decision(
                decision_id=row[0],
                finding_id=row[1],
                identity=row[2],
                decision=row[3],
                rationale=row[4],
                created_at=datetime.fromisoformat(row[5]),
                run_id=row[6],
            )
            for row in rows
        ]

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    @contextmanager
    def _locked_tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                with self._connection:
                    yield self._connection
            except StoreError:
                raise
            except sqlite3.Error as exc:
                raise StoreError(f"database error: {exc}") from exc

    def _query(self, sql: str, params: Sequence[object] = ()) -> list[Any]:
        with self._lock:
            try:
                return self._connection.execute(sql, params).fetchall()
            except sqlite3.Error as exc:
                raise StoreError(f"database error: {exc}") from exc

    def _query_one(self, sql: str, params: Sequence[object] = ()) -> Any | None:
        rows = self._query(sql, params)
        return rows[0] if rows else None
