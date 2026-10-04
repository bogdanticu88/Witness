# Demo intelligence snapshot (synthetic)

Used by `scripts/demo-offline.sh` and `tests/integration/test_offline_demo.py`.
Every source is marked `"synthetic": true` in `intel.json`, and every report
that uses them says so. Do not use the resulting priorities for anything real.

| File | What it is |
|------|------------|
| `nvd-excerpt.json` | The NVD CVSS scores Trivy recorded in `fixtures/reports/trivy/acme-orders-fs.json`, written by hand in the NVD CVE API 2.0 shape. The scores are Trivy's copy of NVD's; the file was not retrieved from NVD. |
| `epss-excerpt.csv` | Invented probabilities in the FIRST EPSS CSV format. They are not EPSS scores. |
| `kev-excerpt.json` | One entry in the CISA KEV catalog format, dated 2026-08-01 so it is outdated at the demo's evaluation time. It is not the real catalog. None of the fixture CVEs is in it. |

The demo judges freshness at 2026-10-04T12:00:00Z (`--as-of`), so its
priorities do not drift as the files age.
