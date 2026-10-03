"""Confining scanner- and model-supplied paths to a repository snapshot.

Every path that originates outside Witness (SARIF URIs, Trivy targets, model
citations, reviewer files) goes through ``confine`` before it is opened.
"""

from __future__ import annotations

import posixpath
import re
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

from witness.errors import PathRejected

_DRIVE = re.compile(r"^[A-Za-z]:")


def normalize_reported_path(reported: str, *, strip_prefixes: tuple[str, ...] = ()) -> str:
    """Turn a scanner path or URI into a clean repository-relative POSIX path.

    ``strip_prefixes`` are absolute roots the scanner is known to have used
    (for example a SARIF ``%SRCROOT%`` value). A ``file:`` URI or absolute
    path that does not start with one of them is rejected, because there is
    no safe way to know what it refers to.
    """
    if not reported or "\x00" in reported:
        raise PathRejected(f"empty or NUL-containing path: {reported!r}")

    text = reported
    parts = urlsplit(text)
    if parts.scheme == "file":
        text = parts.path
    elif parts.scheme and len(parts.scheme) > 1:
        raise PathRejected(f"unsupported URI scheme {parts.scheme!r} in {reported!r}")

    # Decode once. A second round would let %252e%252e slip through as "..";
    # anything still percent-encoded after one round is rejected below.
    text = unquote(text)
    if re.search(r"%[0-9A-Fa-f]{2}", text):
        raise PathRejected(f"path is percent-encoded more than once: {reported!r}")
    text = text.replace("\\", "/")

    if text.startswith("/") or _DRIVE.match(text):
        for prefix in strip_prefixes:
            clean = prefix.replace("\\", "/").rstrip("/") + "/"
            if text.startswith(clean):
                text = text[len(clean) :]
                break
        else:
            raise PathRejected(f"absolute path outside the declared source root: {reported!r}")

    segments = [s for s in text.split("/") if s not in ("", ".")]
    if not segments:
        raise PathRejected(f"path has no file component: {reported!r}")
    if any(s == ".." for s in segments):
        raise PathRejected(f"path traverses upward: {reported!r}")
    return posixpath.join(*segments)


def confine(root: Path, relative: str, *, must_exist: bool = True) -> Path:
    """Resolve ``relative`` under ``root`` and refuse anything that escapes it.

    Symlinks are followed only if their final target stays inside ``root``.
    """
    clean = normalize_reported_path(relative)
    root_resolved = root.resolve(strict=True)
    candidate = root_resolved.joinpath(*PurePosixPath(clean).parts)
    try:
        resolved = candidate.resolve(strict=must_exist)
    except FileNotFoundError as exc:
        raise PathRejected(f"file not found in snapshot: {clean}") from exc
    except (OSError, RuntimeError) as exc:
        raise PathRejected(f"cannot resolve {clean}: {exc}") from exc
    if not resolved.is_relative_to(root_resolved):
        raise PathRejected(f"path resolves outside the repository: {clean}")
    return resolved
