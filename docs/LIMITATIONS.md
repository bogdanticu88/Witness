# Analysis limitations

Witness is conservative by design. The following limits can turn an assessment
`inconclusive`; none of them can support a finding or dismiss one.

## Semantic helper (Roslyn)

- Project loading is static reconstruction, not MSBuild evaluation.
  Conditions, imports, `Directory.Build.*`, custom targets and computed
  properties are skipped and reported as approximations per project.
- Only the shipped reference packs (`Microsoft.NETCore.App.Ref`,
  `Microsoft.AspNetCore.App.Ref`) resolve by default. A `PackageReference`
  resolves only from an operator-supplied package directory; otherwise every
  symbol it provides stays unresolved. Unresolved symbols are never matched to
  the sink catalogue by name; they are `unresolved_candidate` facts.
- Analyzers and source generators never run. Generated code is absent.
- The value-flow slice is a bounded backward slice within a method over
  `IOperation` trees. It is flow-insensitive inside a method, which
  over-approximates origins. It is not a taint engine. Caller expansion is
  bounded and driven by the orchestrator.
- Dynamic dispatch through interfaces or virtuals may be incomplete; when
  coverage is incomplete the cache widens invalidation and the assessment
  lists the gap.
- An unresolved path is never proof of unreachability.

## Scanners and evidence

- Scanner findings are claims. Witness checks them against code; it does not
  re-run scanners.
- Mantis multi-path templates attach accumulated exchanges from earlier
  requests (including failed probes) to later findings of the same template.
  Witness treats exchanges that do not match the finding's own endpoint as
  unconfirmed context, never as confirmation.
- Trivy dependency findings carry no reachability proof. Package applicability
  is assessed from manifests, lock files and (where declared) usage.

## Models

- Model citations are verified against the snapshot before use, but a valid
  citation shows the cited code exists, not that the conclusion is right.
  Well-cited misleading arguments are bounded by deterministic verdict rules
  and human review.
- Model failure, timeouts and budget exhaustion produce `inconclusive` and
  mark the run incomplete.
