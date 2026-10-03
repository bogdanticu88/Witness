"""Escaping for every place untrusted text is rendered.

Repository content and scanner messages end up in Markdown reports, HTML,
terminal output and CI log annotations. Each sink has its own rules.
"""

from __future__ import annotations

import html
import re

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x9b]")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b.")
_MD_SPECIAL = re.compile(r"([\\`*_\[\]|~])")


def strip_terminal_controls(text: str) -> str:
    """Remove ANSI sequences and C0 controls so untrusted text cannot drive the terminal."""
    return _CONTROL.sub("", _ANSI.sub("", text))


def md_inline(text: str | None, *, limit: int = 500) -> str:
    """Escape text for a single Markdown line or table cell."""
    if not text:
        return ""
    clean = strip_terminal_controls(text).replace("\r", " ").replace("\n", " ")
    if len(clean) > limit:
        clean = clean[: limit - 3] + "..."
    # Entities neutralize raw HTML and autolinks; backslashes neutralize the
    # inline constructs that could form links, emphasis or table columns.
    return _MD_SPECIAL.sub(r"\\\1", html.escape(clean, quote=False))


def md_code_block(text: str, language: str = "") -> str:
    """Fence untrusted text with a backtick run longer than any inside it."""
    clean = strip_terminal_controls(text.replace("\r\n", "\n"))
    longest = max((len(m) for m in re.findall(r"`+", clean)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{language}\n{clean}\n{fence}"


def html_text(text: str | None) -> str:
    return html.escape(strip_terminal_controls(text or ""), quote=True)


def github_command_data(text: str) -> str:
    """Escape the message part of a GitHub Actions workflow command."""
    return (
        strip_terminal_controls(text)
        .replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
    )


def github_command_property(text: str) -> str:
    return github_command_data(text).replace(":", "%3A").replace(",", "%2C")


def azdo_command_value(text: str) -> str:
    """Escape a value inside an Azure DevOps ``##vso[...]`` logging command."""
    return (
        strip_terminal_controls(text)
        .replace("%", "%AZP25")
        .replace(";", "%3B")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace("]", "%5D")
    )


def neutralize_log_line(text: str) -> str:
    """Make untrusted text safe to print in a CI log.

    GitHub treats lines starting with ``::`` as commands and Azure DevOps
    treats ``##vso[`` and ``##[`` anywhere in a line as commands. We break
    both patterns and strip controls. Newlines are kept as separate lines
    only after each line is neutralized.
    """
    out = []
    for line in strip_terminal_controls(text).splitlines():
        line = line.replace("##vso[", "##​vso[").replace("##[", "##​[")
        if line.lstrip().startswith("::"):
            line = "​" + line
        out.append(line)
    return "\n".join(out)
