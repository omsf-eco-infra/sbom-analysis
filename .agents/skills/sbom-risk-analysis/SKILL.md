---
name: sbom-risk-analysis
description: Repeatable SBOM dependency risk analysis workflow for SPDX JSON files. Use when asked to analyze an SBOM for dependency risk, licenses, vulnerabilities, provenance, native/binary risk, removability, or environment split recommendations.
compatibility: Requires Python 3.11+. Pixi source mapping requires PyYAML; use the repository's committed Pixi lock. Uses optional external scanners such as grype or osv-scanner when available.
---

# SBOM Risk Analysis

Use this skill to turn an SPDX JSON SBOM into a reproducible dependency risk analysis package. The workflow is designed for Syft-generated SPDX 2.2/2.3 JSON files, but the first-pass inventory script works with any SPDX JSON document that contains `packages` and `relationships`.

## Expected inputs

At minimum:

- an SPDX JSON SBOM, for example `openfe.spdx.json`

Optional but useful:

- package/environment manifests such as `pixi.toml`, `pixi.lock`, `pyproject.toml`, `requirements*.txt`, `environment.yml`, `conda-lock.yml`, `package-lock.json`, etc.
- prior scanner outputs
- project policy on accepted licenses, distribution model, and deployment/runtime target

## Standard output directory

Write outputs under `reports/` unless the user requests another location. For multiple SBOMs, use separate directories such as `reports/<environment>/<platform>/` and substitute that directory for every `reports/` path below. Never mix one SBOM's inventory with another SBOM's scanner output.

Recommended report set:

- `reports/package-inventory.csv`
- `reports/deduplication-analysis.md`
- `reports/license-risk.md`
- `reports/vulnerability-risk.md`
- `reports/grype-db-update.log`, `reports/grype-db-status.json`, and raw Grype outputs when Grype is available
- `reports/dependency-source-map.csv` if lock/manifest files are available
- `reports/dependency-source-summary.md` if lock/manifest files are available
- `reports/removal-candidates.md`
- `reports/environment-split-recommendations.md`
- `reports/provenance-risk.md`
- `reports/native-dependency-risk.md`
- `reports/dependency-risk-model.md`
- `reports/dependency-risk-summary.md`

## Workflow

Always use subagents or equivalent delegated/parallel agent workflows when the execution environment supports them. Prefer delegating independent analysis work even for moderately sized SBOMs; only do the work inline when delegation is unavailable, too small to justify, blocked by missing context, or the user explicitly asks not to use subagents.

### 1. Locate and inspect the SBOM

Find SPDX JSON candidates if the user did not specify one:

```bash
find . -maxdepth 4 -type f \( -name '*spdx*.json' -o -name '*sbom*.json' \) | sort
```

Inspect shape before deeper work:

```bash
python3 - path/to/sbom.spdx.json <<'PY'
import json, sys
from collections import Counter
path = sys.argv[1]
with open(path, encoding='utf-8') as handle:
    d = json.load(handle)
print('spdxVersion:', d.get('spdxVersion'))
print('packages:', len(d.get('packages', [])))
print('relationships:', len(d.get('relationships', [])))
print('files:', len(d.get('files', [])))
print('creationInfo:', d.get('creationInfo', {}).get('creators'))
print('relationship types:', Counter(r.get('relationshipType') for r in d.get('relationships', [])).most_common(20))
print('external refs:', Counter(ref.get('referenceType') for p in d.get('packages', []) for ref in p.get('externalRefs', [])).most_common(20))
PY
```

### 2. Generate the normalized package inventory

Scripts live in `scripts/` at the repository root, not in the skill directory. For this checkout, resolve `../../..` against this skill directory to locate the repository root, then run the commands below there. If the skill is installed separately, locate a checkout containing the scripts; do not assume they were bundled with the skill. Read `scripts/README.md` at that root for CLI details and supported formats.

```bash
pixi install --locked
pixi run --locked python scripts/spdx_package_inventory.py \
  --input path/to/sbom.spdx.json \
  --output reports/package-inventory.csv
```

The inventory and report scripts use the standard library; source mapping also uses PyYAML, pinned in `pixi.lock`. Python 3.11+ is required for the full workflow. Always pass the SBOM input explicitly.

The CSV includes package identity, inferred ecosystem, license fields, purls, CPE counts, SPDX relationship counts, duplicate/multiple-version indicators, `NOASSERTION` flags, suspicious version flags, and source metadata.

### 3. Choose saved-result replay or a fresh vulnerability scan

Prefer scanner-native SBOM input. Use what is installed; do not fail the whole analysis if scanners are unavailable.

For reproducible report regeneration, reuse saved Grype JSON without refreshing the database or rescanning. Record its scanner/DB metadata and any missing provenance or freshness evidence; historical results are not a current security assessment.

For a **fresh assessment**, explicitly download the latest vulnerability database and save evidence of the refresh and resulting database status. A successful `grype db update` includes the case where the installed database is already current. Use locked tooling:

```bash
(
  set -euo pipefail
  mkdir -p reports

  pixi run --locked grype db update 2>&1 | tee reports/grype-db-update.log
  pixi run --locked grype db status -o json \
    > reports/grype-db-status.json \
    2> reports/grype-db-status.stderr.log

  pixi run --locked python - <<'PY'
import json
status = json.load(open('reports/grype-db-status.json'))
if not status.get('valid'):
    raise SystemExit('Grype vulnerability database is not valid')
print('Grype DB:', status.get('schemaVersion'), status.get('built'))
PY

  GRYPE_DB_AUTO_UPDATE=false pixi run --locked grype path/to/sbom.spdx.json -o json \
    > reports/grype-sbom.json \
    2> reports/grype-sbom.stderr.log
)
```

For fresh scans, treat the database refresh and status commands as prerequisites, not best-effort decoration:

- Only run the Grype scans if both commands succeed and `grype-db-status.json` reports a valid database.
- If refresh or status validation fails, do not silently scan with the cached database. Mark Grype vulnerability scanning as blocked, preserve the logs, and continue non-vulnerability analysis.
- Record the database build timestamp, schema/version, validity, and refresh result in `vulnerability-risk.md` and the final summary.
- Inspect saved scanner stderr; do not infer that no freshness warning occurred merely because JSON/stdout lacks one.
- Refresh again for release decisions or a new assessment, not when replaying an archived report.

Generate the triage report from the saved scanner JSON in either mode:

```bash
pixi run --locked python scripts/vulnerability_risk_report.py \
  --grype-json reports/grype-sbom.json \
  --inventory reports/package-inventory.csv \
  --sbom path/to/sbom.spdx.json \
  --output reports/vulnerability-risk.md
```

The script requires `--grype-json`. OSV status defaults to `not supplied`; use `--osv-status` only to describe actual coverage. Fixed versions come from scanner data, and package priorities use severity/confidence rather than package-name exceptions. Every finding remains visible; `UnknownPackage` and CPE matches are not grounds for automatic suppression. The generated report does not read refresh logs or independently verify the `--sbom` label: review saved provenance and document it in the final summary.

If OSV Scanner supports the available SBOM format in the local version, use it too. Update any scanner-specific advisory data first when the tool supports an explicit update operation. Treat CPE-only findings as candidates for triage rather than verified exposure.

### 4. Create specialized analysis reports

Generate baseline deduplication and Pixi source reports with the existing scripts before adding specialist interpretation:

```bash
pixi run --locked python scripts/deduplication_analysis.py \
  --input reports/package-inventory.csv --output reports/deduplication-analysis.md
pixi run --locked python scripts/dependency_source_map.py \
  --inventory reports/package-inventory.csv --manifest pixi.toml --lock pixi.lock \
  --environment <environment> --platform <platform> \
  --output reports/dependency-source-map.csv --summary reports/dependency-source-summary.md
```

Replace the environment/platform placeholders with the target that produced the SBOM, not the local host. Obtain that context before source mapping if it is unknown. The mapper supports conda dependencies in Pixi lock v7 and fails explicitly on unsupported lock versions or PyPI dependencies. Do not bypass these checks: report the limitation and use a suitable parser or evidence-based manual review for other formats. Mapping is restricted to the selected graph; normalized-name matches do not prove artifact identity or runtime usage.

Delegate the specialized reports below to subagents whenever possible. Adapt the delegation format to the current agent runtime: include a clear goal, required inputs, expected output file, analysis standards, and a request for a concise completion summary. Prefer `/goal` when the runtime supports goal-style prompts. If the runtime has a specific completion callback or handoff protocol, use it.

Use the prompt templates in `references/subagent-goals.md` as reusable starting points, preserving `/goal` syntax when supported by the current agent.

Recommended order:

1. Inventory first: `reports/package-inventory.csv`
2. Independent reports:
   - deduplication
   - license risk
   - vulnerability risk
   - provenance risk
   - native/binary/platform risk
   - dependency source mapping, if manifests/lockfiles exist
   - environment split recommendations
   - removal candidates
   - dependency risk model
3. Final executive summary after all other reports are complete

### 5. Analysis standards

Be evidence-based and cautious:

- Distinguish confirmed risk from scanner or SBOM artifact noise.
- For fresh scans, require the database refresh/status prerequisite; otherwise report scanning as blocked. Saved findings may be replayed as historical evidence with their original DB metadata and explicit freshness limitations.
- Do not claim a package is unused unless actual usage was checked.
- Report raw records and unique name/version counts separately. Confirm identity and source locations before collapsing records into installed-package counts; name/version equality alone is not proof of duplication.
- Call out when Syft or SPDX metadata is incomplete, especially `NOASSERTION`, missing purls, missing suppliers, and generated CPE noise.
- Separate license compliance risk from security vulnerability risk.
- Separate runtime risk from dev/test/docs/notebook/build-only risk where possible.
- Prefer actionable remediation: upgrade, remove, split environment, improve SBOM generation, or monitor.
- Do not infer advisory compatibility, direct/transitive status, or reachability solely from a vulnerability triage label. Support specialist conclusions with evidence and retain unresolved findings.
- Archive the SBOM, inventory, raw scanner JSON/stderr, manifest, lockfile, script revision, commands, and input checksums. Report generation is deterministic for fixed inputs and arguments; a fresh scan is not, because advisory data changes. Archive the scanner DB snapshot and configuration if scan replay is required. Keep original generated reports separate from manually reviewed additions.

### 6. Final summary requirements

The final `reports/dependency-risk-summary.md` should include:

- SBOM package count, unique name count, and unique name/version count
- package manager/source mapping totals, if available
- direct roots, if available
- vulnerability posture and caveats, including fresh-scan versus saved-result mode, scanner database refresh result when available, validity, and build timestamp
- highest-priority license issues
- provenance/metadata gaps
- native/binary/platform concerns
- duplicate/multiple-version cleanup candidates
- best removal or environment-separation candidates
- prioritized actions grouped as:
  - fix immediately
  - investigate soon
  - cleanup/refactor
  - monitor
- links/references to detailed report files

## Repository resources

- `scripts/spdx_package_inventory.py` at the repository root — dependency-free SPDX JSON to normalized CSV converter
- `scripts/deduplication_analysis.py`, `scripts/dependency_source_map.py`, and `scripts/vulnerability_risk_report.py` at the repository root — baseline analysis generators
- `scripts/README.md` at the repository root — locked commands, supported formats, and reproducibility limits
- `references/subagent-goals.md` — reusable `/goal` prompts for Herdr subagents
