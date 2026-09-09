#!/usr/bin/env python3
"""Map SBOM package inventory rows back to Pixi direct and locked deps."""

from __future__ import annotations

import argparse
import csv

import yaml
import re
import tomllib
from collections import Counter, defaultdict, deque
from pathlib import Path
from urllib.parse import urlparse

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path("pixi.toml"))
    parser.add_argument("--lock", type=Path, default=Path("pixi.lock"))
    parser.add_argument("--inventory", type=Path, default=Path("reports/package-inventory.csv"))
    parser.add_argument("--output", type=Path, default=Path("reports/dependency-source-map.csv"))
    parser.add_argument("--summary", type=Path, default=Path("reports/dependency-source-summary.md"))
    parser.add_argument("--platform", required=True, help="Locked platform of the scanned environment.")
    parser.add_argument("--environment", required=True, help="Locked environment to analyze.")
    return parser.parse_args()


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
    return re.split(r"[\s<>=!~]", spec.strip().rsplit("::", 1)[-1], maxsplit=1)[0]


def parse_pixi_toml(path: Path, platform: str) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    def dependencies(content):
        if content.get("pypi-dependencies"):
            raise ValueError("Source mapping currently supports conda dependencies only")
        deps = list(content.get("dependencies", {}))
        for selector, target in content.get("target", {}).items():
            if target.get("pypi-dependencies"):
                raise ValueError("Source mapping currently supports conda dependencies only")
            if selector == platform or selector == platform.split("-", 1)[0] or (selector == "unix" and not platform.startswith("win-")):
                deps.extend(target.get("dependencies", {}))
        return deps
    feature_deps = {
        feature: dependencies(content)
        for feature, content in (data.get("feature") or {}).items()
    }
    env_roots: dict[str, list[str]] = {}
    default_deps = dependencies(data)
    for env, content in (data.get("environments") or {}).items():
        if isinstance(content, list):
            content = {"features": content}
        roots = [] if content.get("no-default-feature", False) else list(default_deps)
        for feature in content.get("features", []):
            roots.extend(feature_deps[feature])
        env_roots[env] = sorted(set(roots))
    env_roots.setdefault("default", sorted(set(default_deps)))
    return feature_deps, env_roots


def parse_pixi_lock(path: Path, environment: str, platform: str) -> tuple[dict[str, set[str]], dict[str, dict[str, set[str]]]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data.get("version") != 7:
        raise ValueError("Source mapping supports Pixi lock version 7")
    environments = data["environments"]
    if environment not in environments or platform not in environments[environment]["packages"]:
        raise ValueError(f"No locked environment/platform: {environment}/{platform}")
    entries = environments[environment]["packages"][platform]
    if any("pypi" in entry for entry in entries):
        raise ValueError("Source mapping currently supports conda lock entries only")
    selected = {entry["conda"] for entry in entries}
    metadata = {entry["conda"]: entry for entry in data["packages"] if "conda" in entry}
    packages: dict[str, dict[str, set[str]]] = defaultdict(lambda: {"names": set(), "versions": set(), "deps": set()})
    for url in sorted(selected):
        entry = metadata[url]
        name, version, _build = package_from_conda_url(url)
        package = packages[norm(name)]
        package["names"].add(name)
        package["versions"].add(version)
        package["deps"].update(norm(dep_name(dep)) for dep in entry.get("depends", []))
    return {environment: set(packages)}, packages


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
    envs = sorted(env for env, packages in env_packages.items() if pkg in packages)
    if len(envs) > 1:
        return "shared"
    if len(envs) == 1:
        return envs[0]
    return "unknown"


def main() -> None:
    args = parse_args()
    _feature_deps, all_roots = parse_pixi_toml(args.manifest, args.platform)
    env_roots = {args.environment: all_roots[args.environment]}
    direct = {norm(dep): dep for deps in env_roots.values() for dep in deps}
    env_packages, lock_packages = parse_pixi_lock(args.lock, args.environment, args.platform)
    source_roots = compute_sources(env_roots, lock_packages)

    with args.inventory.open(encoding="utf-8", newline="") as handle:
        rows = sorted(csv.DictReader(handle), key=lambda row: tuple(sorted(row.items())))
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
        version_match = found and version in lock_info["versions"]

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

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["package", "version", "ecosystem", "relationship", "root_dependency", "environment", "pixi_lock_match", "pixi_lock_versions", "notes"])
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
    md.append(f"Generated from `{args.inventory}`, `{args.manifest}`, and `{args.lock}` for `{args.environment}/{args.platform}`. Package matching normalizes case and treats `-`, `_`, and `.` as equivalent. Name matches are heuristic, not proof of artifact identity.\n")
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
    md.append("- Mapping is restricted to the requested environment/platform; this selection is supplied by the caller, not inferred from the SBOM.\n")
    md.append("## Output\n")
    md.append(f"See `{args.output}` for per-record source classification, root dependency, environment, lock match status, and notes.\n")

    args.summary.write_text("\n".join(md), encoding="utf-8")


if __name__ == "__main__":
    main()
