from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from conftest import CAPABILITIES
from witness.semantic.client import SemanticClient

pytestmark = pytest.mark.integration


def test_helper_environment_has_no_credentials(
    fake_helper: Callable[[str], Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"):
        monkeypatch.setenv(name, "secret-value")
    helper = fake_helper(
        "reply({'id': request['id'], 'result': {'protocol': 'witness.semantic/1', "
        "'helper_version': '1', 'roslyn_version': 'x', 'strategy': ','.join(sorted(os.environ)), "
        f"'capabilities': {CAPABILITIES}}}}})"
    )
    with SemanticClient(helper, timeout_s=10) as client:
        names = set(client.hello.strategy.split(","))
    assert not names & {
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
    }
    assert "PATH" in names
