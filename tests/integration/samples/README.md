Small ASP.NET projects for verdict regression tests. They are loaded by the
semantic helper only; nothing here is built or run. Each sink line ends with
a `// case: <id>` marker that `tests/integration/test_verdict_regressions.py`
looks up. They are vulnerable on purpose.

`Deployment.Root` in case V46 is deliberately undefined, to test a path
prefix built from code that does not resolve. Cases V49, V50 and V52 use a
long chain of locals to exceed the helper's slice budget.
