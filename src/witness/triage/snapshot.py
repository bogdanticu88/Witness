"""The repository snapshot a triage run analyzes.

The revision is read from git's files directly. Running ``git`` inside an
untrusted repository could execute configured hooks or helpers, so it is
never invoked.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from witness.errors import PathRejected, UsageError
from witness.security.paths import confine

_SHA = re.compile(r"^[0-9a-f]{7,64}$")
_MIN_PREFIX = 7


@dataclass(frozen=True)
class Snapshot:
    root: Path
    revision: str | None
    revision_source: Literal["git", "operator", "none"]

    @classmethod
    def open(cls, root: Path, *, revision: str | None = None) -> Snapshot:
        if not root.is_dir():
            raise UsageError(
                f"repository snapshot not found: {root}",
                hint="pass --repo with the checkout the reports were produced from",
            )
        resolved = root.resolve()
        if revision:
            return cls(resolved, revision, "operator")
        found = read_git_head(resolved)
        return cls(resolved, found, "git" if found else "none")

    def locate(self, relative: str) -> Path | None:
        """Absolute path of a file in the snapshot, or None when it is absent.

        Raises PathRejected when the path would escape the snapshot.
        """
        path = confine(self.root, relative, must_exist=False)
        return path if path.is_file() else None

    def line_count(self, path: Path) -> int:
        with path.open("rb") as handle:
            return sum(1 for _ in handle)


def same_revision(a: str, b: str) -> bool:
    """Exact match, or one full git object id abbreviating the other."""
    if a == b:
        return True
    a, b = a.lower(), b.lower()
    if not (_SHA.match(a) and _SHA.match(b)):
        return False
    shorter, longer = sorted((a, b), key=len)
    return len(shorter) >= _MIN_PREFIX and longer.startswith(shorter)


def read_git_head(start: Path) -> str | None:
    git_dir = _find_git_dir(start)
    if git_dir is None:
        return None
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if _SHA.match(head):
        return head
    if not head.startswith("ref: "):
        return None
    ref = head[5:].strip()
    if ".." in ref.split("/"):
        return None
    for base in (git_dir, _common_dir(git_dir)):
        try:
            value = (base / ref).read_text(encoding="utf-8").strip()
        except OSError:
            value = ""
        if _SHA.match(value):
            return value
        packed = _packed_ref(base, ref)
        if packed:
            return packed
    return None


def _find_git_dir(start: Path) -> Path | None:
    for directory in (start, *start.parents):
        candidate = directory / ".git"
        if candidate.is_dir():
            return candidate
        if candidate.is_file():
            # Worktrees and submodules: ".git" holds "gitdir: <path>".
            try:
                text = candidate.read_text(encoding="utf-8").strip()
            except OSError:
                return None
            if not text.startswith("gitdir: "):
                return None
            target = (directory / text[8:].strip()).resolve()
            return target if target.is_dir() else None
    return None


def _common_dir(git_dir: Path) -> Path:
    try:
        text = (git_dir / "commondir").read_text(encoding="utf-8").strip()
    except OSError:
        return git_dir
    return (git_dir / text).resolve()


def _packed_ref(base: Path, ref: str) -> str | None:
    try:
        lines = (base / "packed-refs").read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        parts = line.split(" ", 1)
        if len(parts) == 2 and parts[1].strip() == ref and _SHA.match(parts[0]):
            return parts[0]
    return None


__all__ = ["PathRejected", "Snapshot", "read_git_head", "same_revision"]
