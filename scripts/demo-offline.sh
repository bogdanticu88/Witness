#!/bin/sh
# Offline triage demo: the acme-orders fixture app, the real scanner reports
# in fixtures/reports, the real semantic helper and the synthetic intelligence
# snapshot in fixtures/intel/demo. No network access is needed.
#
# Usage: scripts/demo-offline.sh [OUTPUT_DIR]   (default: demo-output)
#
# Build the helper first: dotnet build semantic/Witness.Semantic -c Release
set -eu
cd "$(dirname "$0")/.."

out=${1:-demo-output}
witness=${WITNESS:-.venv/bin/witness}
if [ -e "$out" ]; then
    echo "error: $out already exists; pass a new directory" >&2
    exit 2
fi

# Freshness is judged at a fixed time so the demo gives the same priorities
# whenever it runs.
set +e
"$witness" triage \
    --repo fixtures/apps/acme-orders \
    --report fixtures/reports/codeql/acme-orders.sarif \
    --report fixtures/reports/trivy/acme-orders-fs.json \
    --report fixtures/reports/trivy/acme-orders-image.json \
    --report fixtures/reports/mantis/acme-orders.json \
    --intel fixtures/intel/demo \
    --as-of 2026-10-04T12:00:00Z \
    --db "$out/witness.db"
status=$?
set -e
# 3 means the run is incomplete; its report still says which parts are partial.
if [ "$status" -ne 0 ] && [ "$status" -ne 3 ]; then
    exit "$status"
fi
"$witness" report --db "$out/witness.db" --output "$out/report"
exit "$status"
