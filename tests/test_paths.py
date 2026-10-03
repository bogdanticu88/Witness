from __future__ import annotations

from pathlib import Path

import pytest

from witness.errors import PathRejected
from witness.security.paths import confine, normalize_reported_path


def test_normal_relative_path_passes_through() -> None:
    assert normalize_reported_path("src/app/Controller.cs") == "src/app/Controller.cs"


def test_redundant_slashes_and_dot_segments_collapse() -> None:
    assert normalize_reported_path("src//app/./Controller.cs") == "src/app/Controller.cs"


def test_backslashes_are_normalized() -> None:
    assert normalize_reported_path("src\\app\\Controller.cs") == "src/app/Controller.cs"


def test_file_uri_becomes_relative_path() -> None:
    assert normalize_reported_path("file:src/app/Controller.cs") == "src/app/Controller.cs"


def test_file_uri_percent_decoding_applies_once() -> None:
    assert (
        normalize_reported_path("file:///src/app/My%20Controller.cs", strip_prefixes=("/src",))
        == "app/My Controller.cs"
    )
    assert normalize_reported_path("file:///src/a%2Fb.cs", strip_prefixes=("/src",)) == "a/b.cs"


def test_double_percent_encoding_rejected() -> None:
    with pytest.raises(PathRejected):
        normalize_reported_path("file:///src/a%252e%252e/b.cs", strip_prefixes=("/src",))
    with pytest.raises(PathRejected):
        normalize_reported_path("a%252fb.cs")


def test_non_file_scheme_rejected() -> None:
    with pytest.raises(PathRejected):
        normalize_reported_path("https://example.com/Controller.cs")
    with pytest.raises(PathRejected):
        normalize_reported_path("sarif://runs/0/results/0")


def test_absolute_path_with_matching_strip_prefix() -> None:
    assert (
        normalize_reported_path("/src/root/src/app/Controller.cs", strip_prefixes=("/src/root",))
        == "src/app/Controller.cs"
    )


def test_strip_prefix_tolerates_trailing_separator() -> None:
    assert (
        normalize_reported_path("/src/root/app/a.cs", strip_prefixes=("/src/root/",)) == "app/a.cs"
    )
    assert normalize_reported_path("C:\\src\\app\\a.cs", strip_prefixes=("C:\\src",)) == "app/a.cs"


def test_absolute_path_without_prefix_rejected() -> None:
    with pytest.raises(PathRejected):
        normalize_reported_path("/etc/passwd")
    with pytest.raises(PathRejected):
        normalize_reported_path("/other/root/a.cs", strip_prefixes=("/src/root",))


def test_parent_segments_rejected() -> None:
    for reported in ("..", "../a.cs", "a/../b.cs", "src/../../app/a.cs", "a/b/.."):
        with pytest.raises(PathRejected):
            normalize_reported_path(reported)


def test_dot_only_paths_rejected() -> None:
    for reported in (".", "./", "/."):
        with pytest.raises(PathRejected):
            normalize_reported_path(reported, strip_prefixes=("/",))


def test_nul_rejected() -> None:
    with pytest.raises(PathRejected):
        normalize_reported_path("src/\x00app.cs")


def test_empty_rejected() -> None:
    with pytest.raises(PathRejected):
        normalize_reported_path("")


def test_confine_returns_existing_file_inside_root(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    root.mkdir()
    target = root / "src" / "app.cs"
    target.parent.mkdir()
    target.write_text("class App {}", encoding="utf-8")
    assert confine(root, "src/app.cs") == target.resolve()


def test_confine_rejects_symlink_escaping_root(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    root.mkdir()
    outside = tmp_path / "secret.cs"
    outside.write_text("secret", encoding="utf-8")
    (root / "link.cs").symlink_to(outside)
    with pytest.raises(PathRejected):
        confine(root, "link.cs")


def test_confine_rejects_symlinked_directory_escape(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    root.mkdir()
    outside_dir = tmp_path / "elsewhere"
    outside_dir.mkdir()
    (outside_dir / "inner.cs").write_text("x", encoding="utf-8")
    (root / "dirlink").symlink_to(outside_dir, target_is_directory=True)
    with pytest.raises(PathRejected):
        confine(root, "dirlink/inner.cs")


def test_confine_rejects_dotdot_escape(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    root.mkdir()
    (tmp_path / "outside.cs").write_text("x", encoding="utf-8")
    with pytest.raises(PathRejected):
        confine(root, "../outside.cs")
    with pytest.raises(PathRejected):
        confine(root, "sub/../../outside.cs")


def test_confine_missing_file_tolerated_when_must_exist_false(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    root.mkdir()
    resolved = confine(root, "missing/dir/new.cs", must_exist=False)
    assert resolved == root.resolve() / "missing" / "dir" / "new.cs"


def test_confine_missing_file_rejected_by_default(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    root.mkdir()
    with pytest.raises(PathRejected):
        confine(root, "missing.cs")
