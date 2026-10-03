# Controlled tests for acme-orders

Independent evidence for `LABELS.yaml`. Requests were sent to two local
containers built from this directory (image
`witness-fixture/acme-orders@sha256:2509d34c09f3649f35adb8a44e1f324d9f4f2207df49487eaf56509696f22799`),
published on 127.0.0.1 only:

- default configuration on port 18080
- `Search__Mode=legacy` on port 18081 (selects `LegacyOrderSearch`)

Date: 2026-10-03. Commands:

```
docker build -t witness-fixture/acme-orders:rc .
docker run -d --name acme-orders-test -p 127.0.0.1:18080:8080 witness-fixture/acme-orders:rc
docker run -d --name acme-orders-legacy -e Search__Mode=legacy -p 127.0.0.1:18081:8080 witness-fixture/acme-orders:rc
./controlled-tests.sh http://127.0.0.1:18080 http://127.0.0.1:18081
```

Observed output (response bodies truncated to 160 bytes):

```
## SQL injection
sql-01 baseline: [{"id":100,"status":"shipped","total":42.5},{"id":103,"status":"shipped","total":7.25}]
sql-01 payload:  [{"id":100,"status":"shipped","total":42.5},{"id":101,"status":"pending","total":12},{"id":102,"status":"cancelled","total":99.99},{"id":103,"status":"shipped",
sql-02 payload:  []
sql-03 payload:  [{"id":1,"name":"Ana Popescu","email":"ana@example.test"},{"id":2,"name":"Ben Carter","email":"ben@example.test"},{"id":3,"name":"Chloe Martin","email":"chloe@e
sql-04 payload:  HTTP 404
sql-06 payload:  []
sql-07 default:  []
sql-07 legacy:   [{"id":100,"status":"shipped","total":42.5},{"id":101,"status":"pending","total":12},{"id":102,"status":"cancelled","total":99.99},{"id":103,"status":"shipped",
sql-08 payload:  ["ana@example.test","ben@example.test","chloe@example.test"]
sql-10 payload:  [{"id":100,"status":"shipped","total":42.5},{"id":101,"status":"pending","total":12},{"id":102,"status":"cancelled","total":99.99},{"id":103,"status":"shipped",
sql-11 payload:  [{"id":1,"name":"Ana Popescu"},{"id":2,"name":"Ben Carter"},{"id":3,"name":"Chloe Martin"}]
sql-12 unsafe:   [{"id":100,"status":"shipped"},{"id":101,"status":"pending"},{"id":102,"status":"cancelled"},{"id":103,"status":"shipped"}]
sql-12 exact:    []
sql-13 bad col:  HTTP 500
sql-13 probe t:  [{"id":100,"status":"shipped","total":42.5},{"id":103,"status":"shipped","total":7.25}]
sql-13 probe f:  [{"id":103,"status":"shipped","total":7.25},{"id":100,"status":"shipped","total":42.5}]
## Open redirect
redir-01: 302 https://evil.example/
redir-02: 302 http://127.0.0.1:18080/
redir-03: 500 
redir-04: 302 https://evil.example/
redir-05: 302 https://evil.example/
redir-06: 302 http://evil.example/
## Path traversal
path-01: root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x
path-02: HTTP 500
path-03: HTTP 400
path-04: root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x
path-05: root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x
path-06: root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x
path-03 control (legit file): Returns are accepted within 30 days. 
```

Reading the results against the labels:

| Site | Truth | Observation |
|------|-------|-------------|
| sql-01, sql-03, sql-08, sql-10, sql-11 | vulnerable | the `' OR '1'='1` payload returns every row |
| sql-02, sql-06, sql-12-safe | not vulnerable | the same payload returns no rows |
| sql-04 | not vulnerable | the route constraint rejects non-integers (404) |
| sql-07 | vulnerable under legacy mode | no rows by default, every row with `Search__Mode=legacy` |
| sql-12 | vulnerable | the LIKE branch returns every row; the exact branch none |
| sql-13 | vulnerable | an unknown column gives 500, and a CASE expression in `sort` flips the order depending on a secret value (boolean oracle) |
| redir-01, redir-04, redir-05, redir-06 | vulnerable | 302 to an external host; `//evil.example/` resolves to `http://evil.example/` |
| redir-02 | not vulnerable | 302 to the local root |
| redir-03 | not vulnerable | `LocalRedirect` throws (500), no redirect |
| path-01, path-04, path-05, path-06 | vulnerable | `/etc/passwd` returned |
| path-02 | not vulnerable | 500: `GetFileName` reduced the name to `passwd`, which does not exist under the root |
| path-03 | not vulnerable | 400 from the prefix check; a legitimate file is still served |

sql-05, sql-09, sql-07-safe and path-07 have no request-driven input and were
not exercised; their labels rest on source review alone.
