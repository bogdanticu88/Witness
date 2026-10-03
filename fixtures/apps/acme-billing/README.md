# acme-billing (test fixture)

A deliberately vulnerable ASP.NET Core application used to test and evaluate
Witness. It contains one labelled SQL injection site and shares a vulnerable
package version with acme-orders. Never deploy it or expose it to a network.

- `LABELS.yaml` records ground truth per site, written before any scanner or
  Witness run.
- Scanner reports produced from this app live in `fixtures/reports/`.
