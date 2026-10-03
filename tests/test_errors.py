from __future__ import annotations

import pytest

from witness.errors import (
    ConfigError,
    ExitCode,
    InputError,
    PathRejected,
    ProviderError,
    SemanticError,
    StoreError,
    UsageError,
    WitnessError,
)


@pytest.mark.parametrize(
    ("error_type", "exit_code"),
    [
        (WitnessError, ExitCode.EXECUTION_ERROR),
        (UsageError, ExitCode.USAGE),
        (ConfigError, ExitCode.USAGE),
        (InputError, ExitCode.EXECUTION_ERROR),
        (SemanticError, ExitCode.EXECUTION_ERROR),
        (ProviderError, ExitCode.EXECUTION_ERROR),
        (StoreError, ExitCode.EXECUTION_ERROR),
        (PathRejected, ExitCode.EXECUTION_ERROR),
    ],
)
def test_error_subclass_carries_documented_exit_code(
    error_type: type[WitnessError], exit_code: ExitCode
) -> None:
    error = error_type("something failed")
    assert error.exit_code is exit_code
    assert int(error.exit_code) == int(exit_code)


def test_exit_code_values_match_contract() -> None:
    assert ExitCode.OK == 0
    assert ExitCode.POLICY_FAILED == 1
    assert ExitCode.USAGE == 2
    assert ExitCode.INCOMPLETE == 3
    assert ExitCode.EXECUTION_ERROR == 4
    assert ExitCode.INTERRUPTED == 130


def test_hint_attached_and_rendered() -> None:
    error = UsageError("unknown flag --wat", hint="run witness --help")
    assert error.hint == "run witness --help"
    assert error.message == "unknown flag --wat"
    assert str(error) == "unknown flag --wat"
    assert error.args == ("unknown flag --wat",)


def test_hint_defaults_to_none() -> None:
    assert InputError("bad report").hint is None


def test_path_rejected_is_an_input_error() -> None:
    assert issubclass(PathRejected, InputError)
    assert PathRejected("nope").exit_code is ExitCode.EXECUTION_ERROR
