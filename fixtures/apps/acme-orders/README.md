# acme-orders (test fixture)

A deliberately vulnerable ASP.NET Core application used to test and evaluate
Witness. It contains labelled SQL injection, open redirect and path traversal
sites next to safe look-alikes. Never deploy it or expose it to a network.

- `LABELS.yaml` records ground truth per site, written before any scanner or
  Witness run.
- `CONTROLLED_TESTS.md` records requests sent to a local container and what
  came back, as independent evidence for the labels.
- Scanner reports produced from this app live in `fixtures/reports/`.
