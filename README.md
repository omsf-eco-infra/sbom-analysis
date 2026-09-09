# SBOM Analysis

A repeatable workflow for generating SPDX software bills of materials (SBOMs) for Pixi environments and reviewing dependency risk.

The repository combines:

> Interactive visualizations require [FrameJS](https://framejs.io/) to be installed.

- **Pixi** for reproducible `openfe` and `openff` environments
- **Syft** for SPDX SBOM generation
- **Grype** for vulnerability scanning
- Optional **OSV-Scanner** coverage
- Small Python scripts for normalization and triage (source mapping uses PyYAML)
- An agent skill for delegated license, provenance, native dependency, removal, and environment-split analysis

## Environments

[`pixi.toml`](pixi.toml) defines two environments:

- `openfe`, rooted at `openfe==1.12.0`
- `openff`, rooted at `openff-toolkit==0.18.1`

The resolved dependency graph is recorded in [`pixi.lock`](pixi.lock).

## Workflow

```mermaid
flowchart TD
    A[Pixi environment] --> B[Syft -> SPDX JSON SBOM]
    B --> C[normalized package inventory]
    B --> D[Grype vulnerability scan]
    B --> E[Pixi lock/source mapping]
    B --> F[delegated specialist analysis]
    C --> G[Markdown risk reports]
    D --> G
    E --> G
    F --> G
```

### SBOM generation

GitHub Actions generates SBOMs on pushes to `main` for both environments. See [`.github/workflows/generate_sbom.yaml`](.github/workflows/generate_sbom.yaml).

The workflow scans `.pixi/envs/<environment>` with Syft and uses [`syft.yaml`](syft.yaml) to enable Conda and Cargo-auditable-binary catalogers. The resulting artifacts are named `openfe.spdx.json` and `openff.spdx.json`.

SBOMs are generated only in CI, so the scanned environment matches the Linux user environment rather than the local macOS one. Download the `openfe.spdx.json` or `openff.spdx.json` artifact from the workflow run and place it in the repository root before running the analysis tasks.

### Inventory and scanner output

Create a normalized inventory (downloads the SBOM artifact from CI first, or use a locally generated one):

```sh
pixi run inventory openfe
```

Run Grype and preserve its raw JSON output:

```sh
pixi run grype-scan openfe
```

Create the vulnerability triage report:

```sh
pixi run vuln-report openfe
```

Each task takes the environment name and expects `<env>.spdx.json` in the repository root, writing `reports/package-inventory.csv`, `reports/grype-<env>.json`, and `reports/vulnerability-risk.md`. The underlying scripts can also be run directly with `python3`.

The scripts retain scanner findings and flag CPE matches and incomplete package identities for review, without package-specific suppressions. See [`scripts/README.md`](scripts/README.md) for a locked, environment-separated workflow and reproduction limits.

### Additional analysis

The remaining reports are produced from the inventory, SBOM, lockfile, manifests, and existing reports:

- [`scripts/deduplication_analysis.py`](scripts/deduplication_analysis.py) — duplicate and multiple-version review
- [`scripts/dependency_source_map.py`](scripts/dependency_source_map.py) — maps packages to Pixi roots and environments
- Agent skill — license, provenance, native/binary, removal, environment split, risk model, and executive summary reviews

Run deduplication analysis and source mapping with:

```sh
pixi run dedup
pixi run --locked source-map openfe linux-64
```

The source mapping script reads `pixi.toml`, `pixi.lock`, and `reports/package-inventory.csv`, then writes:

- `reports/dependency-source-map.csv`
- `reports/dependency-source-summary.md`

## Agent skill

The workflow definition is [`.agents/skills/sbom-risk-analysis/SKILL.md`](.agents/skills/sbom-risk-analysis/SKILL.md).

It instructs an agent to:

1. Inspect an SPDX JSON document
2. Generate the normalized inventory
3. Run available vulnerability scanners
4. Delegate independent analysis tasks when supported
5. Combine the results into `dependency-risk-summary.md`

The reusable delegation prompts are in [`.agents/skills/sbom-risk-analysis/references/subagent-goals.md`](.agents/skills/sbom-risk-analysis/references/subagent-goals.md).

The skill is an analysis playbook rather than a standalone scanner. The current GitHub workflow automates SBOM generation; the deeper risk-report generation can be run by an agent or locally using the scripts and reports as inputs.

## Report set

Reports are normally written under `reports/`:

- `package-inventory.csv`
- `deduplication-analysis.md`
- `vulnerability-risk.md`
- `license-risk.md`
- `dependency-source-map.csv`
- `dependency-source-summary.md`
- `removal-candidates.md`
- `environment-split-recommendations.md`
- `provenance-risk.md`
- `native-dependency-risk.md`
- `dependency-risk-model.md`
- `dependency-risk-summary.md`

Raw Grype JSON and text output should remain alongside the reports for traceability.

## Interpretation guidelines

Scanner output is evidence for triage, not proof that a vulnerability is exploitable. Review findings in the context of:

- Package ecosystem and build source
- Runtime versus development or optional dependencies
- CPE-only and cross-ecosystem matches
- Missing PURLs, suppliers, or download locations
- The intended license and redistribution model

Do not claim a package is unused without checking actual project usage or dependency paths.
