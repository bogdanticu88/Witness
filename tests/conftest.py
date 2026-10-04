from __future__ import annotations

import os
from pathlib import Path

import pytest

# The helper is a framework-dependent .NET app. When .NET lives in the user's
# home directory it needs DOTNET_ROOT to find the runtime.
_local_dotnet = Path.home() / ".dotnet"
if "DOTNET_ROOT" not in os.environ and (_local_dotnet / "dotnet").exists():
    os.environ["DOTNET_ROOT"] = str(_local_dotnet)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A small snapshot with one 40-line C# file at src/A.cs."""
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "A.cs").write_text("\n".join(f"// line {i}" for i in range(1, 41)))
    return root
