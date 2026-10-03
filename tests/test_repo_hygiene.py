from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_no_internal_milestone_labels() -> None:
    # internal milestone and gate numbers from planning mean nothing to a reader
    files = subprocess.run(
        ["git", "ls-files", "*.md", "*.py", "*.cs", "*.yaml", "*.yml", "*.toml", "*.sh"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    label = re.compile(r"\b(milestone|gate) [MG]?\d|\b[MG]\d{1,2}\b")
    found = [
        f"{name}:{i}"
        for name in files
        if (ROOT / name).is_file()
        for i, line in enumerate((ROOT / name).read_text().splitlines(), 1)
        if label.search(line)
    ]
    assert found == []
