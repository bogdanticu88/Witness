"""Error types and the process exit-code contract.

Exit codes are part of the public interface because CI pipelines branch on
them. Keep this table in sync with docs/EXECUTION.md.
"""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0
    # Analysis completed and the policy evaluated to fail.
    POLICY_FAILED = 1
    # Usage or configuration error detected before any analysis ran.
    USAGE = 2
    # Analysis ran but is incomplete (provider outage, budget, timeout,
    # unsupported inputs the policy treats as blocking).
    INCOMPLETE = 3
    # Witness itself failed: bad input file, helper crash, storage error.
    EXECUTION_ERROR = 4
    INTERRUPTED = 130


class WitnessError(Exception):
    """An expected failure with a message meant for the user.

    ``hint`` says what to do next. Unexpected exceptions are not WitnessErrors
    and print a traceback only with --debug.
    """

    exit_code: ExitCode = ExitCode.EXECUTION_ERROR

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint


class UsageError(WitnessError):
    exit_code = ExitCode.USAGE


class ConfigError(WitnessError):
    exit_code = ExitCode.USAGE


class InputError(WitnessError):
    """A report, repository or decision file could not be used."""


class SemanticError(WitnessError):
    """The semantic helper is missing, incompatible or failed."""


class SemanticTimeout(SemanticError):
    """The helper did not answer in time. The process is stopped."""


class SemanticRequestError(SemanticError):
    """The helper answered one request with an error and is still usable."""

    def __init__(self, message: str, *, code: str | None, hint: str | None = None) -> None:
        super().__init__(message, hint=hint)
        self.code = code


class ProviderError(WitnessError):
    """A model provider call failed. Never fatal for a run; recorded as incomplete."""


class StoreError(WitnessError):
    pass


class PathRejected(InputError):
    pass
