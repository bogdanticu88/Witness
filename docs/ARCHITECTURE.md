# Architecture and trust boundaries

## Components

```
                     operator config, policy, reviewer decisions (trusted)
                                         |
 scanner reports  -->  adapters  -->  normalized findings  -->  correlation
 (untrusted)          (Python)        (witness.finding/1)        |
                                                                 v
 repository snapshot --> semantic helper (C#, Roslyn) <--> orchestrator (Python)
 (untrusted, read-only)   witness.semantic/1 over stdio        |      |
                                                               |      v
                                         approved read-only    |   provider adapters
                                         query menu  <---------+   (OpenAI-compatible,
                                                               |    Anthropic, replay)
                                                               v
                                   verdict engine -> priority -> store (SQLite)
                                                                      |
                                                     reports, policy gate, exports
```

### Python orchestrator (`src/witness`)

Ordinary code holds all authority. It parses inputs, schedules
investigations, enforces budgets and timeouts, issues provider calls, records
evidence, computes verdicts and priority, evaluates policy and writes reports.
No model output is executed, and no model output changes configuration,
policy, the query menu or the set of findings.

### Semantic helper (`semantic/Witness.Semantic`)

A .NET 10 console program built on Roslyn. It speaks a line-delimited JSON
protocol (`witness.semantic/1`) on stdin/stdout. It never writes to the
repository and never makes network calls.

At startup the helper reports its protocol version and the fact sets it
produces (`definitions/2`, `guards/2` and so on). Verdicts depend on those
facts, so Witness refuses a helper that lacks any fact set it needs, even
when the protocol version matches. A missing fact is never read as an empty
one.

Project loading is static and ad hoc:

- `.csproj` files are read as XML. `Compile` items default to the SDK glob.
  `ProjectReference` edges are followed. `TargetFramework`, `Nullable`,
  `ImplicitUsings`, `LangVersion` and `DefineConstants` are read literally.
- MSBuild conditions, imports, `Directory.Build.props/targets`, custom targets
  and properties computed by evaluation are **not** evaluated. Each skipped
  construct is reported as an approximation for that project.
- Metadata references come from the reference packs shipped with the helper
  (`Microsoft.NETCore.App.Ref`, `Microsoft.AspNetCore.App.Ref`). A
  `PackageReference` resolves only if an operator-supplied package directory
  already contains it. Otherwise it is reported as unresolved and every symbol
  it would have provided stays unresolved.
- Analyzers and source generators are never loaded. Generated code is absent
  and reported as an approximation when a project declares generators.

An unresolved symbol is never matched against the sink catalogue by name. A
call to an unresolved `Query(string)` is reported as an
`unresolved_candidate`. It can make an assessment inconclusive. It cannot
support a finding or dismiss one.

Value-flow facts are a bounded backward slice within a method over
`IOperation` trees, plus caller expansion driven by Python. The slice is flow
insensitive inside a method, which over-approximates origins. It is not a
taint engine. Its limits are listed in `docs/LIMITATIONS.md`.

Optional dependency restore is outside analysis. The documented contract
(`docs/EXECUTION.md`) runs `dotnet restore` as a separate step, in a
separate container with no model credentials, writing to a package directory
that analysis later mounts read-only.

### Provider adapters

`openai_compat` (Chat Completions with tool calling and JSON output) and
`anthropic` (Messages API with tool use). Each declares its capabilities.
`replay` serves recorded responses keyed by request digest. Model credentials
are read from environment variables and are never passed to the semantic
helper process, whose environment is scrubbed.

## Trust boundaries

| Boundary | Untrusted side | Controls |
|----------|----------------|----------|
| Report import | Scanner report files | Size limits, depth limits, schema validation, no path is trusted until confined to the snapshot root |
| Repository snapshot | All file contents, names, symlinks, project files | Read-only access, symlink and `..` confinement, file size and count limits, no build execution |
| Model input | Everything the model sees, including code, comments, scanner text and HTTP evidence | Treated as data, but delimiters are not isolation. Consequences are limited by the authority rules below |
| Model output | Claims, citations, requested queries | Schema validation, query menu allowlist, per-run limits, citation verification, deterministic verdict rules |
| Reports and CI annotations | Any repository- or scanner-controlled string | Markdown and HTML escaping, CI log-command neutralization |
| Cache | Entries written by other runs | Namespaced by repository and trust context. Untrusted runs never write to trusted namespaces |

### Authority rules

1. Only deterministic checks can produce `likely_false_positive`.
2. A model claim that a finding is genuine counts only when every cited hop
   exists in the snapshot and matches a semantic fact (for example, an
   invocation edge that Roslyn resolved).
3. Valid citations show that the cited code exists. They do not show that the
   conclusion is right. Injected input can produce a well-cited wrong
   argument. The verdict rules and human review limit what such an argument
   can change.
4. Provider failure, budget exhaustion and timeouts produce `inconclusive`
   and mark the run incomplete. They never produce a clean result.
5. The policy gate reads assessments but defaults to the original scanner
   gate. Turning model or deterministic dismissals into gate exceptions is an
   explicit policy option.

## Storage

One SQLite database per workspace (`.witness/witness.db` by default), with a
schema version and forward-only migrations. Runs, findings, evidence,
assessments, the investigation cache and reviewer decisions live there.
Rendered reports go to a per-run directory that is never overwritten.

## Change impact and cache

A cached investigation is keyed by the finding identity, the content hashes of
every file whose spans were retrieved, the semantic dependency set (symbols
and their declaring files), the project-file fingerprint, the analysis
version, the profile, provider, model, parameters, prompt and schema versions,
and the trust namespace.

When dependency coverage is incomplete (unresolved symbols, unresolved
dispatch), invalidation widens to every source file in the affected project.
Changes to project files, `Directory.Build.*`, `global.json`,
`appsettings*.json` and package lock files invalidate every entry for the
repository.
