# SBOM Risk Analysis Subagent Goal Templates

Replace placeholders such as `<SBOM_PATH>` and `<REPORTS_DIR>` before launching. Tell each subagent to call `herdr_subagent_done` when finished.

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
- Group packages by name and by name+version.
- Identify exact duplicate name/version records, packages with multiple versions, likely version-format duplicates, suspicious versions, and duplicated ecosystems such as conda plus PyPI metadata for the same package.
- For each finding, explain whether it looks like normal SBOM scanner duplication, conda/PyPI duplication, actual simultaneous versions, bundled binary/package artifact, or cleanup candidate.
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
- Deduplicate package/version rows before summarizing.
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
- Run available scanners such as grype against the SBOM. Save raw outputs under <REPORTS_DIR>.
- Capture package, version, vulnerability ID, severity, fixed version if available, source database, and scanner confidence if available.
- Triage likely false positives, especially CPE-based matches.
- Distinguish direct runtime risk, transitive risk, native/library risk, and likely scanner noise.
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
- Parse available manifest and lock files.
- Identify whether each package is direct, transitive, or unknown where inferable.
- Identify environment/profile membership where inferable.
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
- Include a prioritized action list grouped as fix immediately, investigate soon, cleanup/refactor, and monitor.
- Keep it readable for technical and non-technical stakeholders.
- Include concrete references to underlying report files for details.
- Avoid overstating certainty; distinguish verified findings from scanner/SBOM noise.
```
