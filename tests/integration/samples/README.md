Small ASP.NET projects for verdict regression tests. They are loaded by the
semantic helper only; nothing here is built or run. Each sink line ends with
a `// case: Vnn` marker that `tests/integration/test_verdict_regressions.py`
looks up. They are vulnerable on purpose.
