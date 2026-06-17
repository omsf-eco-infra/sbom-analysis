#!/usr/bin/env python3
"""Map SBOM package inventory rows back to Pixi direct and locked deps."""

from __future__ import annotations

import csv
import re
import tomllib
from collections import Counter, defaultdict, deque
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
PIXI_TOML = ROOT / "pixi.toml"
PIXI_LOCK = ROOT / "pixi.lock"
INVENTORY = ROOT / "reports" / "package-inventory.csv"
OUT_CSV = ROOT / "reports" / "dependency-source-map.csv"
OUT_MD = ROOT / "reports" / "dependency-source-summary.md"


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", (name or "").strip().lower())


def package_from_conda_url(url: str) -> tuple[str, str, str]:
    filename = Path(urlparse(url).path).name
    if filename.endswith(".tar.bz2"):
        stem = filename[:-8]
    elif filename.endswith(".conda"):
        stem = filename[:-6]
    else:
        stem = filename
    name, version, build = stem.rsplit("-", 2)
    return name, version, build


def dep_name(spec: str) -> str:
    return re.split(r"[\s<>=!~]", spec.strip(), maxsplit=1)[0]


def parse_pixi_toml() -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    data = tomllib.loads(PIXI_TOML.read_text())
    feature_deps = {
        feature: list((content.get("dependencies") or {}).keys())
        for feature, content in (data.get("feature") or {}).items()
    }
    env_roots: dict[str, list[str]] = {}
    for env, content in (data.get("environments") or {}).items():
        roots: list[str] = []
        for feature in content.get("features", []):
            roots.extend(feature_deps.get(feature, []))
        env_roots[env] = roots
    if data.get("dependencies"):
        env_roots.setdefault("default", []).extend(data["dependencies"].keys())
    return feature_deps, env_roots


def parse_pixi_lock() -> tuple[dict[str, set[str]], dict[str, dict[str, set[str]]]]:
    env_packages: dict[str, set[str]] = defaultdict(set)
    packages: dict[str, dict[str, set[str]]] = defaultdict(lambda: {"names": set(), "versions": set(), "deps": set()})

    current_env = None
    in_top_envs = False
    in_packages = False
    current_pkg_norm = None
    in_depends = False

    for raw in PIXI_LOCK.read_text().splitlines():
        line = raw.rstrip("\n")

        if line == "environments:":
            in_top_envs = True
            continue
        if line == "packages:":
            in_top_envs = False
            in_packages = True
            current_env = None
            continue

        if in_top_envs:
            m_env = re.match(r"^  ([A-Za-z0-9_.-]+):$", line)
            if m_env:
                current_env = m_env.group(1)
                continue
            m_conda = re.match(r"^      - conda: (\S+)$", line)
            if m_conda and current_env:
                name, _version, _build = package_from_conda_url(m_conda.group(1))
                env_packages[current_env].add(norm(name))
            continue

        if in_packages:
            m_pkg = re.match(r"^- conda: (\S+)$", line)
            if m_pkg:
                name, version, _build = package_from_conda_url(m_pkg.group(1))
                current_pkg_norm = norm(name)
                packages[current_pkg_norm]["names"].add(name)
                packages[current_pkg_norm]["versions"].add(version)
                in_depends = False
                continue
            if current_pkg_norm is None:
                continue
            if line == "  depends:":
                in_depends = True
                continue
            if re.match(r"^  [A-Za-z_].*:$", line):
                in_depends = False
                continue
            if in_depends:
                m_dep = re.match(r"^  - (.+)$", line)
                if m_dep:
                    packages[current_pkg_norm]["deps"].add(norm(dep_name(m_dep.group(1))))

    return env_packages, packages


def compute_sources(env_roots: dict[str, list[str]], packages: dict[str, dict[str, set[str]]]) -> dict[str, set[str]]:
    source_roots: dict[str, set[str]] = defaultdict(set)
    for env, roots in env_roots.items():
        for root in roots:
            root_n = norm(root)
            queue = deque([root_n])
            seen = set()
            while queue:
                pkg = queue.popleft()
                if pkg in seen or pkg not in packages:
                    continue
                seen.add(pkg)
                source_roots[pkg].add(root)
                for dep in packages[pkg]["deps"]:
                    if dep not in seen:
                        queue.append(dep)
    return source_roots


def environment_for(pkg: str, env_packages: dict[str, set[str]]) -> str:
    envs = sorted(env for env, packages in env_packages.items() if pkg in packages and env != "default")
    if len(envs) > 1:
        return "shared"
    if len(envs) == 1:
        return envs[0]
    return "unknown"


def main() -> None:
    _feature_deps, env_roots = parse_pixi_toml()
    direct = {norm(dep): dep for deps in env_roots.values() for dep in deps}
    env_packages, lock_packages = parse_pixi_lock()
    source_roots = compute_sources(env_roots, lock_packages)

    rows = list(csv.DictReader(INVENTORY.open()))
    out_rows = []
    counters = Counter()
    unknown_rows = []
    version_mismatch_rows = []
    duplicate_names = Counter(row["name"] for row in rows)

    for row in rows:
        name = row["name"]
        version = row["version"]
        pkg_n = norm(name)
        lock_info = lock_packages.get(pkg_n)
        found = lock_info is not None
        version_match = found and (not version or version in lock_info["versions"])

        if pkg_n in direct:
            relationship = "direct"
        elif found:
            relationship = "transitive"
        else:
            relationship = "unknown"

        env = environment_for(pkg_n, env_packages) if found else "unknown"
        roots = sorted(source_roots.get(pkg_n, []))
        root_dependency = ";".join(roots) if roots else (direct.get(pkg_n, "") if relationship == "direct" else "")

        notes = []
        if not found:
            notes.append("SBOM package not found in pixi.lock package metadata")
            unknown_rows.append(row)
        elif not version_match:
            notes.append("name found in pixi.lock but SBOM version not found among locked versions: " + ";".join(sorted(lock_info["versions"])))
            version_mismatch_rows.append(row)
        if row["ecosystem"] == "pypi" and found:
            notes.append("SBOM Python distribution metadata maps to a locked conda package by normalized name")
        if found and not roots and relationship != "direct":
            notes.append("locked package found but no dependency path from pixi.toml roots was inferred")
        if duplicate_names[name] > 1:
            notes.append("duplicate SBOM records exist for this package name")

        out = {
            "package": name,
            "version": version,
            "ecosystem": row["ecosystem"],
            "relationship": relationship,
            "root_dependency": root_dependency,
            "environment": env,
            "pixi_lock_match": "yes" if found else "no",
            "pixi_lock_versions": ";".join(sorted(lock_info["versions"])) if found else "",
            "notes": "; ".join(notes),
        }
        counters[(relationship, env)] += 1
        counters[("found" if found else "missing",)] += 1
        out_rows.append(out)

    with OUT_CSV.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(out_rows[0]))
        writer.writeheader()
        writer.writerows(out_rows)

    total = len(out_rows)
    missing = counters[("missing",)]
    found = counters[("found",)]
    direct_count = sum(1 for r in out_rows if r["relationship"] == "direct")
    transitive_count = sum(1 for r in out_rows if r["relationship"] == "transitive")
    unknown_count = sum(1 for r in out_rows if r["relationship"] == "unknown")
    env_counts = Counter(r["environment"] for r in out_rows)
    eco_counts = Counter(r["ecosystem"] for r in out_rows)

    missing_by_eco = Counter(r["ecosystem"] for r in unknown_rows)
    missing_examples = sorted({r["name"] for r in unknown_rows})[:30]
    mismatch_examples = [f"{r['name']} {r['version']}" for r in version_mismatch_rows[:20]]
    direct_seen = sorted({r["package"] for r in out_rows if r["relationship"] == "direct"})
    pypi_mapped = sum(1 for r in out_rows if r["ecosystem"] == "pypi" and r["pixi_lock_match"] == "yes")

    md = []
    md.append("# Dependency source map summary\n")
    md.append("Generated from `reports/package-inventory.csv`, `pixi.toml`, and `pixi.lock`. Package matching normalizes case and treats `-`, `_`, and `.` as equivalent.\n")
    md.append("## Totals\n")
    md.append(f"- SBOM package records: {total}")
    md.append(f"- Matched to Pixi lock metadata: {found}")
    md.append(f"- Not found in Pixi metadata: {missing}")
    md.append(f"- Direct records: {direct_count}")
    md.append(f"- Transitive records: {transitive_count}")
    md.append(f"- Unknown records: {unknown_count}")
    md.append("- Ecosystems: " + ", ".join(f"{k}={v}" for k, v in sorted(eco_counts.items())))
    md.append("- Environment inference: " + ", ".join(f"{k}={v}" for k, v in sorted(env_counts.items())))
    md.append("\n## Direct roots from `pixi.toml`\n")
    for env, roots in sorted(env_roots.items()):
        md.append(f"- `{env}`: " + (", ".join(f"`{r}`" for r in roots) or "none"))
    md.append("\nDirect packages observed in the SBOM: " + (", ".join(f"`{p}`" for p in direct_seen) or "none"))
    md.append("\n## Mismatches and surprising packages\n")
    md.append(f"- {missing} SBOM records were not found as Pixi locked package names. By ecosystem: " + (", ".join(f"{k}={v}" for k, v in sorted(missing_by_eco.items())) or "none"))
    if missing_examples:
        md.append("- Missing examples: " + ", ".join(f"`{name}`" for name in missing_examples))
    if version_mismatch_rows:
        md.append("- Version mismatches where name matched the lock but version did not: " + ", ".join(f"`{x}`" for x in mismatch_examples))
    else:
        md.append("- No version mismatches were found for matched package names.")
    md.append(f"- {pypi_mapped} PyPI SBOM records mapped back to locked conda packages by normalized name; these are usually Python distribution metadata emitted from conda-installed packages, not standalone Pixi PyPI dependencies.")
    md.append("- Vendored Python distributions under packages such as `setuptools/_vendor` commonly appear in the SBOM but are not separate Pixi lock entries; these remain `unknown` in the CSV.")
    md.append("- The SBOM appears to describe `.pixi/envs/openfe`, while `pixi.lock` contains both `openfe` and `openff`; packages present in both locked environments are marked `shared`.\n")
    md.append("## Output\n")
    md.append("See `reports/dependency-source-map.csv` for per-record source classification, root dependency, environment, lock match status, and notes.\n")

    OUT_MD.write_text("\n".join(md))


if __name__ == "__main__":
    main()
