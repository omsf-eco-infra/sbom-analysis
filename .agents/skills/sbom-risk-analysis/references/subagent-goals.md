# SBOM Risk Analysis Subagent Goal Templates

Replace placeholders such as `<SBOM_PATH>`, `<REPORTS_DIR>`, `<ENVIRONMENT>`, and `<PLATFORM>` before launching. Use one report directory per SBOM/environment/platform. `<WORKDIR>` must identify the repository checkout containing `scripts/`; read its `scripts/README.md` for locked commands and supported inputs. Tell each subagent to call `herdr_subagent_done` when finished if that callback is available; otherwise use the runtime's completion protocol.

For all reports, preserve input paths/checksums, tool versions, commands, and source evidence. Keep generated baselines separate from specialist additions. Do not copy package-specific conclusions from prior assessments without verifying them against the current inputs.

## Deduplication analysis

```text
/goal SBOM package deduplication analysis

You are working in <WORKDIR>.

Inputs:
- <REPORTS_DIR>/package-inventory.csv
- <SBOM_PATH> if needed

Goal: Analyze duplicate and redundant package records.

Deliverable:
- <REPORTS_DIR>/deduplication-analysis.md

Instructions:
- Generate the baseline with `pixi run --locked python scripts/deduplication_analysis.py --input <REPORTS_DIR>/package-inventory.csv --output <REPORTS_DIR>/deduplication-analysis.md`.
- Group packages by name and by name+version.
- Identify exact duplicate name/version records, packages with multiple versions, likely version-format duplicates, suspicious versions, and duplicated ecosystems such as conda plus PyPI metadata for the same package.
- Treat ecosystem overlaps and suspicious versions as hypotheses. Confirm source locations and identities before claiming scanner duplication, actual simultaneous installations, or bundled artifacts; never suppress records by package name alone.
- Include a table with package, versions, record count, ecosystems, concern, and recommended follow-up.
```

## License risk review

```text
/goal SBOM license risk review

You are working in <WORKDIR>.

Inputs:
- <REPORTS_DIR>/package-inventory.csv

Goal: Classify dependency license risk.

Deliverable:
- <REPORTS_DIR>/license-risk.md

Instructions:
- Distinguish raw record counts from unique name/version counts. Before collapsing installed-package identities, verify sources and preserve differing license declarations.
- Bucket packages into low concern, review required, policy-sensitive, and unknown/missing license.
- Pay special attention to NOASSERTION, GPL, LGPL, MPL, LicenseRef, vendor EULAs, and Creative Commons licenses.
- Produce a table with package, version, license declared, ecosystem, risk level, reason, and recommended action.
- Include a short summary of highest-priority license issues.
```

## Vulnerability scan and triage

```text
/goal SBOM vulnerability scan and triage

You are working in <WORKDIR>.

Inputs:
- <SBOM_PATH>
- <REPORTS_DIR>/package-inventory.csv
- existing scanner outputs under <REPORTS_DIR> if present

Goal: Scan the SBOM for known vulnerabilities and triage practical risk.

Deliverable:
- <REPORTS_DIR>/vulnerability-risk.md

Instructions:
- Decide whether this is saved-result replay or a fresh assessment. For replay, consume existing JSON without refreshing or rescanning; label the findings historical and record missing provenance/freshness evidence.
- For fresh assessments, use `pixi run --locked grype db update`, then `pixi run --locked grype db status -o json`; save the update log and status JSON under <REPORTS_DIR>.
- Only perform a fresh scan if update/status commands succeed and status reports a valid database. Never silently fall back to a stale cached database; if refresh fails, preserve logs and report fresh scanning as blocked.
- Save raw scanner JSON and stderr under <REPORTS_DIR>. Disable automatic DB updates during the scan after the explicit refresh (`GRYPE_DB_AUTO_UPDATE=false`) and inspect stderr for freshness warnings. Preserve DB snapshots/configuration if scan replay is required.
- Generate the baseline from saved JSON with `pixi run --locked python scripts/vulnerability_risk_report.py --grype-json <REPORTS_DIR>/grype-sbom.json --inventory <REPORTS_DIR>/package-inventory.csv --sbom <SBOM_PATH> --output <REPORTS_DIR>/vulnerability-risk.md`; substitute the actual saved JSON path. Supply `--osv-status` only from observed coverage evidence.
- Capture the database refresh result, build timestamp, schema/version, and validity alongside package, version, vulnerability ID, severity, fixed version, source database, and scanner confidence if available.
- Keep every scanner finding. CPE matches, `UnknownPackage`, or ecosystem/name similarities alone do not justify suppression; confirm identity and advisory applicability.
- Use fixed versions from the supplied findings, not hardcoded package exceptions or prior-report recommendations.
- Distinguish direct runtime risk, transitive risk, native/library risk, and verified scanner noise only when supported by dependency and usage evidence. Baseline triage labels do not establish reachability or direct/transitive status.
- Produce a prioritized remediation table.
```

## Dependency source mapping

```text
/goal SBOM dependency source mapping

You are working in <WORKDIR>.

Inputs:
- <REPORTS_DIR>/package-inventory.csv
- available manifests/lockfiles such as pixi.toml, pixi.lock, pyproject.toml, requirements files, environment.yml, package-lock.json, etc.
- <SBOM_PATH> if needed

Goal: Map SBOM packages back to project manifests/lockfiles to determine why each dependency is present.

Deliverables:
- <REPORTS_DIR>/dependency-source-map.csv
- <REPORTS_DIR>/dependency-source-summary.md

Instructions:
- Obtain the scanned environment and platform from the caller or generation evidence; do not assume the host platform or an environment name.
- For supported Pixi inputs, run `pixi run --locked python scripts/dependency_source_map.py --inventory <REPORTS_DIR>/package-inventory.csv --manifest <WORKDIR>/pixi.toml --lock <WORKDIR>/pixi.lock --environment <ENVIRONMENT> --platform <PLATFORM> --output <REPORTS_DIR>/dependency-source-map.csv --summary <REPORTS_DIR>/dependency-source-summary.md`.
- The mapper uses PyYAML from the committed Pixi lock and supports conda dependencies in Pixi lock v7. Report unsupported lock versions/PyPI dependencies rather than bypassing the checks; use suitable parsers or a documented manual review for other formats.
- Parse available manifest and lock files.
- Restrict dependency paths and version comparisons to the selected environment/platform. Normalized-name matching is heuristic, not verified artifact identity; do not union graphs from unrelated environments/platforms.
- Identify whether each package is direct, transitive, or unknown where inferable.
- Label the selected environment/profile and distinguish caller-supplied scope from inferred SBOM membership.
- Flag packages present in the SBOM but not found in lock/manifest metadata.
- Produce a CSV with package, version, ecosystem, direct/transitive/unknown, source/root dependency if inferable, environment/profile, and notes.
- Produce a concise Markdown summary of mismatches and surprising packages.
```

## Removal candidate analysis

```text
/goal SBOM dependency removal candidate analysis

You are working in <WORKDIR>.

Inputs:
- <REPORTS_DIR>/package-inventory.csv
- deduplication, license, vulnerability, source-map, provenance, native-risk, and environment-split reports if available
- manifests/lockfiles if available

Goal: Identify dependencies that may be removable, separable, or moved to optional environments.

Deliverable:
- <REPORTS_DIR>/removal-candidates.md

Instructions:
- Identify candidates in categories: duplicates, multiple versions, dev/test/docs packages in runtime, notebook/GUI/plotting packages, GPU/CUDA/vendor packages, large native libraries, weak metadata, risky licenses, and vulnerability-driven splits.
- For each candidate include package, version(s), reason it may be removable/separable, likely owner/root dependency if inferable, risk of removing, and recommended next step.
- Do not claim a dependency is unused unless verified; use cautious wording.
- Prioritize actionable findings over exhaustive listing.
```

## Runtime vs development environment split

```text
/goal SBOM runtime vs development dependency split

You are working in <WORKDIR>.

Inputs:
- <REPORTS_DIR>/package-inventory.csv
- available manifests/lockfiles
- existing reports under <REPORTS_DIR>

Goal: Determine whether the current environment mixes runtime, development, test, docs, notebooks, optional backends, and platform/system dependencies.

Deliverable:
- <REPORTS_DIR>/environment-split-recommendations.md

Instructions:
- Classify observed dependencies into runtime, test, docs, notebook/tutorial, build, optional backend, platform/system, or unknown where reasonable.
- Recommend whether separate SBOMs should be generated for runtime, dev/test, docs/tutorial, GPU-enabled, minimal, and other project-specific profiles.
- Include concrete environment/manifest suggestions if appropriate.
- Keep claims evidence-based and cite package examples from the inventory.
```

## Provenance and metadata quality review

```text
/goal SBOM provenance and metadata quality review

You are working in <WORKDIR>.

Inputs:
- <REPORTS_DIR>/package-inventory.csv
- <SBOM_PATH> if needed
- existing reports under <REPORTS_DIR>

Goal: Identify packages with weak or missing supply-chain metadata.

Deliverable:
- <REPORTS_DIR>/provenance-risk.md

Instructions:
- Flag packages with no purl, no supplier, NOASSERTION supplier, suspicious versions, no download location, custom/local/binary records, many CPEs but no purl, and ambiguous source information.
- Prioritize packages that look runtime-relevant or security-sensitive.
- Produce a table with package, version, ecosystem, missing metadata, risk level, and recommended enrichment/follow-up.
- Include a concise summary of top provenance risks and likely SBOM/scanner artifact noise.
```

## Native, binary, and platform dependency review

```text
/goal SBOM native, binary, and platform dependency review

You are working in <WORKDIR>.

Inputs:
- <REPORTS_DIR>/package-inventory.csv
- license and vulnerability reports if available
- manifests/lockfiles if useful

Goal: Review native/binary/system dependencies for operational, security, and removal/isolation risk.

Deliverable:
- <REPORTS_DIR>/native-dependency-risk.md

Instructions:
- Identify likely compiled/native/system/binary dependencies, including scientific libraries, MPI/OpenMP, CUDA/GPU/vendor packages, compression/crypto/network libraries, GUI/system packages, and packages with many contained files.
- Classify each as expected core dependency, optional backend, platform artifact, or possible removal/isolation candidate.
- Include visible license or vulnerability concerns when relevant.
- Keep recommendations practical for the project domain.
```

## Dependency risk scoring model

```text
/goal SBOM dependency risk scoring model

You are working in <WORKDIR>.

Inputs:
- <REPORTS_DIR>/package-inventory.csv
- existing reports under <REPORTS_DIR>

Goal: Create a reusable scoring model for ranking dependency risk.

Deliverable:
- <REPORTS_DIR>/dependency-risk-model.md

Instructions:
- Define a practical scoring rubric using known vulnerabilities, license concern, missing provenance, native/binary code, multiple versions, suspicious version, direct/transitive status, runtime reachability, and removability.
- Provide score bands: critical, high, medium, low, and removal candidate.
- Include example scores for representative packages from the current inventory.
- Make the model simple enough to apply manually or script later.
```

## Final executive summary

```text
/goal Final executive SBOM dependency risk summary

You are working in <WORKDIR>.

Inputs:
- all reports under <REPORTS_DIR>
- <REPORTS_DIR>/package-inventory.csv

Goal: Combine all prior reports into a concise executive risk and cleanup summary.

Deliverable:
- <REPORTS_DIR>/dependency-risk-summary.md

Instructions:
- Summarize total package count, unique package count, package-manager/source mapping results, vulnerability posture, highest-risk licenses, provenance concerns, native/platform concerns, duplicate/multiple-version issues, and best removal/separation candidates.
- State the SBOM/environment/platform scope, whether scanner results are fresh or replayed, original scanner/DB metadata, and any blocked or unsupported analysis. Distinguish record totals from confirmed installed identities.
- Include a prioritized action list grouped as fix immediately, investigate soon, cleanup/refactor, and monitor.
- Keep it readable for technical and non-technical stakeholders.
- Include concrete references to underlying report files for details.
- Avoid overstating certainty; distinguish verified findings from scanner/SBOM noise.
```
