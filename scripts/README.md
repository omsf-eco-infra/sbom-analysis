# Analysis scripts

Use Python 3.11+; source mapping also requires PyYAML. The committed `pixi.lock`
pins both. Install with `pixi install --locked` and run with `pixi run --locked`.
Paths are relative to the current working directory; all output parents are created.

## Repeatable workflow

From the repository root, using a downloaded CI SBOM:

```sh
pixi install --locked
mkdir -p reports/openff
pixi run --locked python scripts/spdx_package_inventory.py \
  --input openff.spdx.json --output reports/openff/inventory.csv
pixi run --locked python scripts/deduplication_analysis.py \
  --input reports/openff/inventory.csv --output reports/openff/deduplication.md
pixi run --locked python scripts/dependency_source_map.py \
  --inventory reports/openff/inventory.csv --manifest pixi.toml --lock pixi.lock \
  --environment openff --platform linux-64 \
  --output reports/openff/source-map.csv --summary reports/openff/source-summary.md

# Scan once; preserve this JSON to reproduce the report without database drift.
pixi run --locked grype openff.spdx.json -o json > reports/openff/grype.json
pixi run --locked python scripts/vulnerability_risk_report.py \
  --grype-json reports/openff/grype.json --inventory reports/openff/inventory.csv \
  --sbom openff.spdx.json --output reports/openff/vulnerability-risk.md
```

Choose the environment and platform that produced the SBOM, not the host platform.
Use separate output directories for separate SBOMs to avoid mixing inventories.
All scripts support `--help`.

## Behavior and limits

- **Inventory** normalizes SPDX package records, identity metadata, duplicate
  signals, and both `DEPENDS_ON` and `DEPENDENCY_OF` relationships.
- **Deduplication** groups names/versions and flags suspicious metadata. These
  are heuristics, not proof of installed duplicates or permission to remove packages.
- **Source mapping** uses structured YAML parsing and only the selected
  environment/platform graph. Default-feature dependencies and platform targets
  are included. Currently supports Pixi lock v7 and conda dependencies; unsupported
  lock versions and PyPI dependencies fail explicitly rather than silently
  producing incomplete mappings. Name normalization remains a heuristic, not
  verified artifact identity. Virtual packages without lock entries are not mapped.
- **Vulnerability triage** retains every Grype finding, derives fixed versions
  from scanner data, and applies severity/confidence priorities without package-name
  exceptions. Unknown artifact types are not automatically suppressed. OSV status
  defaults to `not supplied`; use `--osv-status` to supply actual coverage evidence.
  Reports do not establish reachability, direct/transitive status, or exploitability.

## Reproduction evidence

Reports contain no wall-clock generation timestamp. Reusing the same input files,
arguments, and locked tools produces stable outputs without network access.
Archive the SBOM, inventory, Grype JSON, manifest, lockfile, script revision, and
invocation together. For example, record checksums with:

```sh
shasum -a 256 openff.spdx.json pixi.toml pixi.lock scripts/*.py reports/openff/*
```

A fresh Grype scan is **not** guaranteed to reproduce saved results: its advisory
DB updates independently of the pinned executable. Preserve the raw JSON (which
records scanner/DB metadata), and archive the DB snapshot and scanner configuration
if the scan itself must be replayed. SBOM generation is also a separate CI step;
replaying report generation does not recreate the original scanned environment.
