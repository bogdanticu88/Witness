"""Bounded loading of untrusted structured input."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from witness.errors import InputError


@dataclass(frozen=True)
class Limits:
    max_bytes: int = 256 * 1024 * 1024
    max_depth: int = 64
    max_items: int = 200_000


DEFAULT_LIMITS = Limits()


def _check_depth(value: Any, limits: Limits, label: str) -> None:
    # Iterative so a hostile document cannot exhaust the Python stack here.
    stack: list[tuple[Any, int]] = [(value, 1)]
    items = 0
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise InputError(f"{label}: nesting deeper than {limits.max_depth} levels")
        if isinstance(node, dict):
            items += len(node)
            stack.extend((v, depth + 1) for v in node.values())
        elif isinstance(node, list):
            items += len(node)
            stack.extend((v, depth + 1) for v in node)
        if items > limits.max_items:
            raise InputError(f"{label}: more than {limits.max_items} values")


def read_bounded(path: Path, limits: Limits = DEFAULT_LIMITS) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc.strerror or exc}") from exc
    if size > limits.max_bytes:
        raise InputError(
            f"{path} is {size} bytes, over the {limits.max_bytes} byte limit",
        )
    with path.open("rb") as handle:
        data = handle.read(limits.max_bytes + 1)
    if len(data) > limits.max_bytes:
        raise InputError(f"{path} grew past the size limit while reading")
    return data


def loads_json(data: bytes | str, label: str, limits: Limits = DEFAULT_LIMITS) -> Any:
    if len(data) > limits.max_bytes:
        raise InputError(f"{label}: over the {limits.max_bytes} byte limit")
    try:
        value = json.loads(data)
    except RecursionError as exc:
        raise InputError(f"{label}: nesting too deep to parse") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise InputError(f"{label}: not valid JSON ({exc})") from exc
    _check_depth(value, limits, label)
    return value


def load_json(path: Path, limits: Limits = DEFAULT_LIMITS) -> Any:
    return loads_json(read_bounded(path, limits), str(path), limits)


def load_yaml(path: Path, limits: Limits = DEFAULT_LIMITS) -> Any:
    data = read_bounded(path, limits)
    try:
        # safe_load never constructs arbitrary Python objects.
        value = yaml.safe_load(data)
    except yaml.YAMLError as exc:
        raise InputError(f"{path}: not valid YAML ({exc})") from exc
    except RecursionError as exc:
        raise InputError(f"{path}: nesting too deep to parse") from exc
    _check_depth(value, limits, str(path))
    return value
