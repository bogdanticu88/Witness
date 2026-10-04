from __future__ import annotations

import sys
import textwrap
from collections.abc import Callable
from pathlib import Path

import pytest

from witness.errors import SemanticError
from witness.semantic.client import locate_helper

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def helper_path() -> Path:
    try:
        return locate_helper(None)
    except SemanticError:
        pytest.skip("semantic helper not built (dotnet build semantic/Witness.Semantic -c Release)")


@pytest.fixture
def fake_helper(tmp_path: Path) -> Callable[[str], Path]:
    """Write an executable that plays the helper. ``body`` handles one request.

    ``body`` sees ``request`` (the parsed line) and ``count``, and calls
    ``reply(obj)`` to answer.
    """

    def make(body: str) -> Path:
        script = tmp_path / "fake-helper"
        script.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys, time\n"
            "def reply(obj):\n"
            "    sys.stdout.write(json.dumps(obj) + '\\n')\n"
            "    sys.stdout.flush()\n"
            "count = 0\n"
            "for line in sys.stdin:\n"
            "    request = json.loads(line)\n"
            "    count += 1\n"
            "    if request.get('method') == 'shutdown':\n"
            "        break\n" + textwrap.indent(textwrap.dedent(body), "    ")
        )
        script.chmod(0o755)
        return script

    return make


HELLO = (
    "{'id': request['id'], 'result': {'protocol': 'witness.semantic/1', "
    "'helper_version': '9.9.9', 'roslyn_version': 'fake', 'strategy': 'fake'}}"
)
