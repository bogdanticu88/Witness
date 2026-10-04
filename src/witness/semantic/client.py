"""Process client for the Roslyn semantic helper.

The helper reads untrusted repository content, so it runs with a minimal,
explicitly constructed environment. Model credentials and anything else from
the orchestrator's environment are never passed through.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel, TypeAdapter, ValidationError

from witness.errors import SemanticError, SemanticRequestError, SemanticTimeout
from witness.semantic import protocol as p

log = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

# Variables the helper legitimately needs. Everything else is dropped.
_PASSTHROUGH_ENV = (
    "PATH", "DOTNET_ROOT", "WITNESS_REF_PACKS", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL",
)
_MAX_RESPONSE_BYTES = 64 * 1024 * 1024


def helper_environment(source: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ if source is None else source
    clean = {k: env[k] for k in _PASSTHROUGH_ENV if k in env}
    clean.update(
        {
            "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
            "DOTNET_NOLOGO": "1",
            "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
            # The helper has no business writing a home directory.
            "HOME": clean.get("TMPDIR", "/tmp"),  # noqa: S108
        }
    )
    return clean


def locate_helper(configured: str | None) -> Path:
    """Find the helper executable: config, environment, PATH, then a dev build."""
    if configured:
        # An explicit choice is never replaced by another helper.
        path = Path(configured)
        if path.is_file() and os.access(path, os.X_OK):
            return path
        raise SemanticError(
            f"the configured semantic helper is not an executable file: {configured}",
            hint="check the --helper path or build the helper",
        )
    candidates: list[Path] = []
    if env_path := os.environ.get("WITNESS_SEMANTIC_HELPER"):
        candidates.append(Path(env_path))
    if found := shutil.which("witness-semantic"):
        candidates.append(Path(found))
    repo = Path(__file__).resolve().parents[3]
    candidates.append(repo / "semantic/Witness.Semantic/bin/Release/net10.0/witness-semantic")
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise SemanticError(
        "the Roslyn semantic helper (witness-semantic) was not found",
        hint="build it with 'dotnet publish semantic/Witness.Semantic -c Release', set "
        "WITNESS_SEMANTIC_HELPER, or use the container image. Semantic analysis is required.",
    )


class SemanticClient:
    def __init__(self, helper: Path, *, timeout_s: float = 300.0) -> None:
        self._helper = helper
        self._timeout_s = timeout_s
        self._next_id = 0
        self._lock = threading.Lock()
        self._lines: queue.Queue[bytes | None] = queue.Queue()
        try:
            self._proc = subprocess.Popen(
                [str(helper)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=helper_environment(),
                cwd=os.environ.get("TMPDIR", "/tmp"),  # noqa: S108
            )
        except OSError as exc:
            raise SemanticError(f"cannot start semantic helper {helper}: {exc}") from exc
        self._stderr_tail: list[str] = []
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()
        try:
            self.hello = self.call("hello", {}, p.Hello)
        except SemanticError as exc:
            if self._proc.poll() is None or exc.hint:
                raise
            raise SemanticError(
                exc.message,
                hint="the helper exited during startup; if .NET is installed outside the "
                "default location, set DOTNET_ROOT",
            ) from exc
        if self.hello.protocol != p.PROTOCOL_VERSION:
            self.close()
            raise SemanticError(
                f"semantic helper speaks {self.hello.protocol}, Witness needs {p.PROTOCOL_VERSION}",
                hint="rebuild the helper from the same Witness release",
            )

    def _read_stdout(self) -> None:
        assert self._proc.stdout is not None
        for line in iter(lambda: self._proc.stdout.readline(_MAX_RESPONSE_BYTES + 1), b""):  # type: ignore[union-attr]
            self._lines.put(line)
        self._lines.put(None)

    def _read_stderr(self) -> None:
        assert self._proc.stderr is not None
        for raw in self._proc.stderr:
            text = raw.decode("utf-8", "replace").rstrip()
            log.debug("semantic helper: %s", text)
            self._stderr_tail = [*self._stderr_tail, text][-20:]

    def call(self, method: str, params: dict[str, Any], model: type[T]) -> T:
        return self._validate(model, self.raw(method, params), method)

    def call_list(self, method: str, params: dict[str, Any], item: type[T]) -> list[T]:
        result = self.raw(method, params)
        try:
            return TypeAdapter(list[item]).validate_python(result)  # type: ignore[valid-type]
        except ValidationError as exc:
            raise SemanticError(
                f"semantic helper returned malformed {method} result: {exc}"
            ) from exc

    def call_optional(self, method: str, params: dict[str, Any], model: type[T]) -> T | None:
        result = self.raw(method, params)
        return None if result is None else self._validate(model, result, method)

    def raw(self, method: str, params: dict[str, Any]) -> Any:
        with self._lock:
            if self._proc.poll() is not None:
                raise SemanticError(self._died_message())
            self._next_id += 1
            request_id = self._next_id
            payload = json.dumps({"id": request_id, "method": method, "params": params}) + "\n"
            try:
                assert self._proc.stdin is not None
                self._proc.stdin.write(payload.encode())
                self._proc.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                raise SemanticError(self._died_message()) from exc

            deadline = time.monotonic() + self._timeout_s
            try:
                line = self._lines.get(timeout=max(0.1, deadline - time.monotonic()))
            except queue.Empty as exc:
                # A helper that stopped answering gets no shutdown request.
                self._kill()
                raise SemanticTimeout(
                    f"semantic helper did not answer {method} within {self._timeout_s:.0f}s",
                    hint="raise semantic.timeout_seconds or analyze a smaller scope",
                ) from exc
            if line is None:
                raise SemanticError(self._died_message())
            if len(line) > _MAX_RESPONSE_BYTES:
                raise SemanticError(f"semantic helper response to {method} exceeds the size limit")
            try:
                response = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SemanticError(f"semantic helper sent invalid JSON for {method}") from exc
            if not isinstance(response, dict) or response.get("id") != request_id:
                raise SemanticError(f"semantic helper answered out of order for {method}")
            if error := response.get("error"):
                if not isinstance(error, dict):
                    raise SemanticError(f"semantic helper sent a malformed error for {method}")
                code = error.get("code")
                message = error.get("message")
                raise SemanticRequestError(
                    f"semantic helper {method} failed: {code}: {message}", code=code
                )
            return response.get("result")

    @staticmethod
    def _validate(model: type[T], value: Any, method: str) -> T:
        try:
            return model.model_validate(value)
        except ValidationError as exc:
            raise SemanticError(
                f"semantic helper returned malformed {method} result: {exc}"
            ) from exc

    def _died_message(self) -> str:
        tail = "; ".join(self._stderr_tail[-3:])
        return f"semantic helper exited (code {self._proc.poll()}){': ' + tail if tail else ''}"

    def close(self) -> None:
        if self._proc.poll() is None:
            try:
                assert self._proc.stdin is not None
                self._proc.stdin.write(b'{"id":0,"method":"shutdown"}\n')
                self._proc.stdin.flush()
                self._proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                self._kill()

    def _kill(self) -> None:
        self._proc.kill()
        self._proc.wait()

    def __enter__(self) -> SemanticClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
