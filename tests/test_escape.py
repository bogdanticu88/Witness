from __future__ import annotations

from witness.security.escape import (
    azdo_command_value,
    github_command_data,
    github_command_property,
    html_text,
    md_code_block,
    md_inline,
    neutralize_log_line,
    strip_terminal_controls,
)


def test_ansi_sequences_stripped() -> None:
    assert strip_terminal_controls("\x1b[31mred\x1b[0m plain") == "red plain"
    assert strip_terminal_controls("\x1b[1;42m\x1b[2Ktext") == "text"


def test_control_characters_stripped() -> None:
    assert strip_terminal_controls("a\x00b\x07\x08c") == "abc"
    assert strip_terminal_controls("a\x7f\x9bb") == "ab"


def test_tab_and_newline_survive() -> None:
    assert strip_terminal_controls("a\tb\nc\rd") == "a\tb\nc\rd"


def test_md_inline_escapes_markdown_specials() -> None:
    assert md_inline("*b* `c` [d] e_f g|h \\i ~j~") == (
        "\\*b\\* \\`c\\` \\[d\\] e\\_f g\\|h \\\\i \\~j\\~"
    )


def test_md_inline_neutralizes_raw_html() -> None:
    assert md_inline("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert md_inline("a & b < c") == "a &amp; b &lt; c"


def test_md_inline_leaves_quotes_and_flattens_newlines() -> None:
    assert md_inline('say "hi"') == 'say "hi"'
    assert md_inline("one\ntwo\rthree") == "one two three"


def test_md_inline_empty_is_empty() -> None:
    assert md_inline(None) == ""
    assert md_inline("") == ""


def test_md_inline_truncates_to_limit() -> None:
    out = md_inline("x" * 600)
    assert out == "x" * 497 + "..."
    assert len(md_inline("x" * 600, limit=10)) == 10


def test_md_code_block_default_fence() -> None:
    assert md_code_block("hello") == "```\nhello\n```"
    assert md_code_block("hello", "cs") == "```cs\nhello\n```"


def test_md_code_block_lengthens_fence_when_content_has_backticks() -> None:
    out = md_code_block("a\n```\nb")
    assert out == "````\na\n```\nb\n````"
    out = md_code_block("```` four")
    assert out == "`````\n```` four\n`````"


def test_html_text_escapes_quotes_and_tags() -> None:
    assert html_text('<a href="x">') == "&lt;a href=&quot;x&quot;&gt;"
    assert html_text("it's") == "it&#x27;s"
    assert html_text(None) == ""


def test_github_command_data_escapes_mandated_characters() -> None:
    assert github_command_data("100%\r\n") == "100%25%0D%0A"
    assert github_command_data("plain") == "plain"


def test_github_command_property_adds_colon_and_comma() -> None:
    assert github_command_property("x:y\r\n%,") == "x%3Ay%0D%0A%25%2C"


def test_azdo_command_value_escapes_mandated_characters() -> None:
    assert azdo_command_value("a;b]c\r\n%") == "a%3Bb%5Dc%0D%0A%AZP25"


def test_neutralize_log_line_defuses_github_commands() -> None:
    assert neutralize_log_line("::error::boom") == "\u200b::error::boom"
    assert neutralize_log_line("  ::warning::careful") == "\u200b  ::warning::careful"


def test_neutralize_log_line_defuses_azdo_commands() -> None:
    assert neutralize_log_line("##vso[task.setvariable]x") == "##\u200bvso[task.setvariable]x"
    assert neutralize_log_line("a ##[section] b") == "a ##\u200b[section] b"


def test_neutralize_log_line_leaves_ordinary_lines() -> None:
    assert neutralize_log_line("just a log line") == "just a log line"
    assert neutralize_log_line("a\nb") == "a\nb"


def test_neutralize_log_line_strips_controls() -> None:
    assert neutralize_log_line("\x1b[31m::ok\x1b[0m") == "\u200b::ok"
