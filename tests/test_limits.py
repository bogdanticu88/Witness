from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from witness.errors import InputError
from witness.security.limits import Limits, load_json, load_yaml, loads_json, read_bounded


def test_loads_json_rejects_invalid_json() -> None:
    with pytest.raises(InputError):
        loads_json(b"{not json", "report.json")
    with pytest.raises(InputError):
        loads_json("[1, 2", "report.json")


def test_loads_json_parses_document() -> None:
    assert loads_json(b'{"a": [1, 2]}', "report.json") == {"a": [1, 2]}
    assert loads_json('{"a": 1}', "report.json") == {"a": 1}


def _nested(wraps: int) -> dict[str, Any]:
    value: Any = 0
    for _ in range(wraps):
        value = {"a": value}
    return value


def test_loads_json_accepts_nesting_up_to_max_depth() -> None:
    limits = Limits(max_depth=4)
    assert loads_json(json.dumps(_nested(3)), "doc", limits) == _nested(3)


def test_loads_json_rejects_nesting_beyond_max_depth() -> None:
    limits = Limits(max_depth=4)
    with pytest.raises(InputError):
        loads_json(json.dumps(_nested(4)), "doc", limits)


def test_max_items_enforced() -> None:
    limits = Limits(max_items=5)
    assert loads_json("[1, 2, 3, 4, 5]", "doc", limits) == [1, 2, 3, 4, 5]
    with pytest.raises(InputError):
        loads_json("[1, 2, 3, 4, 5, 6]", "doc", limits)


def test_oversized_bytes_rejected() -> None:
    limits = Limits(max_bytes=8)
    with pytest.raises(InputError):
        loads_json(b" " * 9, "doc", limits)


def test_read_bounded_rejects_oversized_file(tmp_path: Path) -> None:
    blob = tmp_path / "blob.bin"
    blob.write_bytes(b"12345")
    with pytest.raises(InputError):
        read_bounded(blob, Limits(max_bytes=4))
    assert read_bounded(blob, Limits(max_bytes=5)) == b"12345"


def test_read_bounded_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(InputError):
        read_bounded(tmp_path / "missing.bin", Limits(max_bytes=4))


def test_load_json_round_trip(tmp_path: Path) -> None:
    doc = tmp_path / "doc.json"
    doc.write_text('{"runs": [{"results": []}]}', encoding="utf-8")
    assert load_json(doc) == {"runs": [{"results": []}]}


def test_load_yaml_parses_simple_document(tmp_path: Path) -> None:
    doc = tmp_path / "doc.yaml"
    doc.write_text("name: witness\nversion: 1\nitems:\n  - a\n  - b\n", encoding="utf-8")
    assert load_yaml(doc) == {"name": "witness", "version": 1, "items": ["a", "b"]}


def test_load_yaml_rejects_malformed_document(tmp_path: Path) -> None:
    doc = tmp_path / "doc.yaml"
    doc.write_text("a: [unclosed\n", encoding="utf-8")
    with pytest.raises(InputError):
        load_yaml(doc)


def test_deeply_nested_json_raises_input_error_not_recursion_error() -> None:
    deep = "[" * 100_000 + "]" * 100_000
    with pytest.raises(InputError):
        loads_json(deep, "hostile.json")


def test_load_yaml_enforces_limits(tmp_path: Path) -> None:
    doc = tmp_path / "deep.yaml"
    doc.write_text("a: " + "[" * 100 + "]" * 100 + "\n", encoding="utf-8")
    with pytest.raises(InputError):
        load_yaml(doc, Limits(max_depth=8))
