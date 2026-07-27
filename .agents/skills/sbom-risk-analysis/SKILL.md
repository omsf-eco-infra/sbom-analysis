---
name: sbom-risk-analysis
description: Repeatable SBOM dependency risk analysis workflow for SPDX JSON files. Use when asked to analyze an SBOM for dependency risk, licenses, vulnerabilities, provenance, native/binary risk, removability, or environment split recommendations.
compatibility: Requires Python 3. Uses optional external scanners such as grype or osv-scanner when available.
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

Write outputs under `reports/` unless the user requests another location.

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
python3 - <<'PY'
import json, sys
from collections import Counter
path = sys.argv[1]
d = json.load(open(path))
print('spdxVersion:', d.get('spdxVersion'))
print('packages:', len(d.get('packages', [])))
print('relationships:', len(d.get('relationships', [])))
print('files:', len(d.get('files', [])))
print('creationInfo:', d.get('creationInfo', {}).get('creators'))
print('relationship types:', Counter(r.get('relationshipType') for r in d.get('relationships', [])).most_common(20))
print('external refs:', Counter(ref.get('referenceType') for p in d.get('packages', []) for ref in p.get('externalRefs', [])).most_common(20))
PY path/to/sbom.spdx.json
```

### 2. Generate the normalized package inventory

Use the bundled dependency-free script from the skill directory. Resolve relative paths against the skill directory when invoking it.

```bash
python3 .agents/skills/sbom-risk-analysis/scripts/spdx_package_inventory.py \
  --input path/to/sbom.spdx.json \
  --output reports/package-inventory.csv
```

If the skill is installed globally, use its actual installed path for the script.

The CSV includes package identity, inferred ecosystem, license fields, purls, CPE counts, SPDX relationship counts, duplicate/multiple-version indicators, `NOASSERTION` flags, suspicious version flags, and source metadata.

### 3. Refresh the vulnerability database and scan

Prefer scanner-native SBOM input. Use what is installed; do not fail the whole analysis if scanners are unavailable.

Before every Grype scan, explicitly download the latest vulnerability database and save evidence of the refresh and resulting database status. A successful `grype db update` includes the case where the installed database is already current.

```bash
(
  set -euo pipefail
  mkdir -p reports

  grype db update 2>&1 | tee reports/grype-db-update.log
  grype db status -o json \
    > reports/grype-db-status.json \
    2> reports/grype-db-status.stderr.log

  python3 - <<'PY'
import json
status = json.load(open('reports/grype-db-status.json'))
if not status.get('valid'):
    raise SystemExit('Grype vulnerability database is not valid')
print('Grype DB:', status.get('schemaVersion'), status.get('built'))
PY

  grype path/to/sbom.spdx.json -o json \
    > reports/grype-sbom.json \
    2> reports/grype-sbom.stderr.log
  grype path/to/sbom.spdx.json -o table \
    > reports/grype-sbom.txt \
    2>> reports/grype-sbom.stderr.log
)
```

Treat the database refresh and status commands as prerequisites, not best-effort decoration:

- Only run the Grype scans if both commands succeed and `grype-db-status.json` reports a valid database.
- If refresh or status validation fails, do not silently scan with the cached database. Mark Grype vulnerability scanning as blocked, preserve the logs, and continue non-vulnerability analysis.
- Record the database build timestamp, schema/version, validity, and refresh result in `vulnerability-risk.md` and the final summary.
- Inspect saved scanner stderr; do not infer that no freshness warning occurred merely because JSON/stdout lacks one.
- Refresh again for release decisions or when re-running an older analysis package.

If OSV Scanner supports the available SBOM format in the local version, use it too. Update any scanner-specific advisory data first when the tool supports an explicit update operation. Treat CPE-only findings as candidates for triage rather than verified exposure.

### 4. Create specialized analysis reports

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
- Do not present Grype findings unless the database refresh/status prerequisite succeeded; otherwise report vulnerability scanning as blocked.
- Do not claim a package is unused unless actual usage was checked.
- Deduplicate package/version rows before summarizing counts.
- Call out when Syft or SPDX metadata is incomplete, especially `NOASSERTION`, missing purls, missing suppliers, and generated CPE noise.
- Separate license compliance risk from security vulnerability risk.
- Separate runtime risk from dev/test/docs/notebook/build-only risk where possible.
- Prefer actionable remediation: upgrade, remove, split environment, improve SBOM generation, or monitor.

### 6. Final summary requirements

The final `reports/dependency-risk-summary.md` should include:

- SBOM package count, unique name count, and unique name/version count
- package manager/source mapping totals, if available
- direct roots, if available
- vulnerability posture and caveats, including scanner database refresh result, validity, and build timestamp
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

## Bundled files

- `scripts/spdx_package_inventory.py` — dependency-free SPDX JSON to normalized CSV converter
- `references/subagent-goals.md` — reusable `/goal` prompts for Herdr subagents
