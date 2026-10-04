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
  `IOperation` trees. It lists every definition of a variable with ordering
  facts rather than computing data flow, so it is not a taint engine. Caller
  expansion is bounded and driven by the orchestrator.
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

## Deterministic triage

What a `supported` verdict establishes: the sink resolved, and request data
(an endpoint parameter, or a request accessor in a method shown to be called
from an endpoint) reaches it through plain propagation. No check, model
validation attribute, route constraint, filter or middleware was found on
the way whose effect on the value is unknown. Each such verdict also records
two assumptions: the endpoint is routed as declared, and branch conditions
that do not involve the value can be satisfied.

What a `likely_false_positive` establishes: every value that can reach the
sink is constant, of a safe type (numbers, dates, GUIDs, enums and
collections of them), or behind a mitigation whose meaning is known at that
position. The mitigations recognized are `Url.IsLocalUrl` on the whole
redirect target, a constant redirect prefix that keeps the destination on
the site (`/x...` or `scheme://host/...`), `Path.GetFileName` on the last
component of a file path, and an ordinal `StartsWith` check of a
`GetFullPath` result against a trusted root ending in a separator, with an
early exit. For the prefix check the helper must report that it listed
everything the root is built from (a constant, or locals, parameters and
fields that are then traced); a root built from anything else (calls,
properties, array elements, unresolved code) is not trusted. Path dismissals
assume no symbolic link inside the directory points outside it.

Validation the analysis looks for, and treats as blocking confirmation
unless its effect is known:

- Checks and calls on the value earlier in the sink's method, in nested
  blocks, `using` and `lock` statements, and `try` blocks whose catch clauses
  all leave the method. A call that cannot throw (by inspection of its source,
  or because it is a string, path or logging helper) is ignored, and so is an
  `async` validator whose task is not awaited.
- A local computed from the value and checked later (`ok = Check(v); if
  (!ok) return;`).
- Checks in callers before they pass the value, in inlined helpers before
  they return it, and in constructors or methods before they store it in a
  field. These are never used to dismiss a finding.
- Model validation attributes on the bound parameter or DTO property
  (length-only attributes are ignored), `IValidatableObject`, custom model
  binders, and route constraints other than type and length constraints.
- Custom middleware and MVC or endpoint filters that read request input and
  can reject or rewrite the request. Framework middleware is not counted.
  Layers whose code is outside the analyzed source count as able to do both.

Not modeled: validation libraries registered through dependency injection
(FluentValidation and similar), checks reached only through events or
reflection, middleware registered from another assembly, and authorization.
A finding that depends on one of these can be `supported` even though the
request is rejected in practice.

Other limits:

- Variable definitions are ordered within one method: a value overwritten on
  every path before the sink does not count, a definition after the sink
  does not count unless a loop could carry it back, and a method with `goto`
  is not ordered at all. A field written in more than one place counts as
  tainted only when every write is.
- A self reference such as `x = x.Trim()` is resolved at its own read, so
  the earlier value it carries is not lost. When a loop carries a variable's
  value back into its own definition, that earlier value is not resolved: it
  blocks a dismissal, and a confirmation then rests on the other definitions
  alone. A constant built up in a loop is therefore `inconclusive`, not a
  likely false positive.
- Request data read outside an endpoint (for example through
  `IHttpContextAccessor` in a service) counts only when a call chain from an
  endpoint handler to that method is found within four levels. Reads inside
  minimal API lambdas through `HttpContext` are reported against the program
  entry point and stay inconclusive.
- A call reached only through interface dispatch counts as a path when the
  implementation is registered for dependency injection, including
  conditional registrations. The registration is recorded as an assumption.
- Callers are expanded four levels deep, the search for endpoints that call
  a method reading request data stops at the same depth, the helper's slice
  has a node and depth budget, and each finding has a budget of 200 helper
  queries. Hitting any of them makes the assessment incomplete and
  `inconclusive`, even when a tainted path was found in the analyzed part,
  and marks the run incomplete (exit 3). When several sinks share the
  finding's location and one of them was not fully analyzed, the finding is
  `inconclusive` even if another sink has a verdict.
- Witness refuses a semantic helper that does not report every fact set its
  verdicts depend on, including an older build that speaks the same
  protocol version.
- A finding on a line with a safe API call and no recognized sink is
  dismissed only when its column starts inside that call. Without a column it
  stays inconclusive.
- Paths from `IHostEnvironment.ContentRootPath` and
  `IWebHostEnvironment.WebRootPath` are treated as deployment configuration,
  not request data, and the assumption is recorded on each assessment that
  relies on it. Other configuration values are of unknown trust.
- Revisions are compared exactly, or as an abbreviated git object id of at
  least seven characters. When the report or the snapshot has no revision the
  finding is assumed to describe the snapshot, and the assessment says so.
- Dependency findings get no code verdict. The only check is whether a NuGet
  `packages.lock.json` in the snapshot still resolves the reported version;
  when it resolves a different one the finding is `stale`.
- Runtime findings are `not_assessed`. An HTTP exchange that matches the
  finding's endpoint shows the endpoint was exercised, not that the
  vulnerability exists.

## Priority and intelligence

- Priority reads the assessment and never changes it. Intelligence feeds
  priority only.
- Intelligence comes only from a local snapshot the operator prepares.
  Witness does not check that a file really came from the origin the
  manifest names; the manifest's `sha256` only pins the file to what the
  operator recorded.
- Only CVE ids are looked up. A dependency finding with only a GHSA or vendor
  id gets no CVSS, KEV or EPSS factor, and says so.
- CVSS v2 scores are recorded but not used. Environmental and temporal CVSS
  metrics are not applied.
- KEV absence is established only by a current, full catalog. An outdated or
  partial catalog leaves it unknown.
- Priority does not use reachability, exposure, asset value or business
  context. The default EPSS threshold and freshness limits are Witness
  defaults, not vendor guidance (`docs/PRIORITY.md`).
- Source findings take their severity from the scanner. CodeQL's
  `security-severity` rule property is not read yet; the SARIF level is used.
- A `likely_false_positive` assessment lowers priority to P4 by default. That
  ranks it last; it is not a dismissal, and the report shows it as
  conditional on the assessment's assumptions.

## Models

- Model citations are verified against the snapshot before use, but a valid
  citation shows the cited code exists, not that the conclusion is right.
  Well-cited misleading arguments are bounded by deterministic verdict rules
  and human review.
- Model failure, timeouts and budget exhaustion produce `inconclusive` and
  mark the run incomplete.
