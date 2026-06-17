# Analysis scripts

This directory contains small, dependency-free helper scripts used to produce the SBOM analysis reports.

## `spdx_package_inventory.py`

Creates a normalized CSV inventory from an SPDX JSON SBOM. The inventory adds review-friendly fields such as inferred ecosystem, PURLs/CPE counts, duplicate package/version flags, relationship counts, and package metadata.

```sh
python3 scripts/spdx_package_inventory.py \
  --input openfe.spdx.json \
  --output reports/package-inventory.csv
```

Output: `reports/package-inventory.csv`

## `vulnerability_risk_report.py`

Generates the vulnerability triage report from Grype JSON output and the package inventory CSV. The script preserves all Grype findings in a full inventory table and adds pragmatic triage labels for CPE-only matches, duplicate `UnknownPackage` rows, and GitHub Advisory ecosystem/name collisions.

Typical workflow:

```sh
grype openfe.spdx.json -o json > reports/grype-openfe.json
python3 scripts/vulnerability_risk_report.py \
  --grype-json reports/grype-openfe.json \
  --inventory reports/package-inventory.csv \
  --output reports/vulnerability-risk.md
```

Output: `reports/vulnerability-risk.md`

Notes:
- The script does not run Grype itself; it consumes a saved Grype JSON file so scanner output remains auditable.
- OSV scanner status is documented in the report via `--osv-status` when applicable.
- The confidence labels are triage aids, not scanner-provided proof of exploitability.
