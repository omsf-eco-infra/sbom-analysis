#!/usr/bin/env python3
"""Create a normalized package inventory CSV from an SPDX JSON SBOM.

This script is intentionally dependency-free. It reads the package records from an
SPDX 2.2/2.3 JSON document, enriches them with simple relationship counts and
identity/duplication signals, and writes a CSV that is easier to review than the
raw SBOM.

Example:
    python3 scripts/spdx_package_inventory.py \
        --input openfe.spdx.json \
        --output reports/package-inventory.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

NO_VALUE = {None, "", "NOASSERTION", "NONE"}
SUSPICIOUS_VERSION_RE = re.compile(
    r"(^0\.0\.0$|unknown|untagged|dirty|dev|snapshot)", re.IGNORECASE
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Normalize package records from an SPDX JSON SBOM into CSV."
    )
    parser.add_argument(
        "--input",
        "-i",
        required=True,
        help="Input SPDX JSON file.",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="reports/package-inventory.csv",
        help="Output CSV file. Parent directories are created automatically. Default: reports/package-inventory.csv",
    )
    return parser.parse_args()


def clean(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def join_values(values: list[str], limit: int | None = None) -> str:
    unique_values = sorted({value for value in values if value})
    if limit is not None:
        unique_values = unique_values[:limit]
    return "; ".join(unique_values)


def external_refs(package: dict[str, Any], reference_type: str) -> list[str]:
    refs = []
    for ref in package.get("externalRefs", []):
        if ref.get("referenceType") == reference_type:
            refs.append(clean(ref.get("referenceLocator")))
    return refs


def infer_ecosystem(package: dict[str, Any], purls: list[str]) -> str:
    spdx_id = clean(package.get("SPDXID")).lower()
    source_info = clean(package.get("sourceInfo")).lower()

    purl_types = []
    for purl in purls:
        # PURLs look like pkg:pypi/name@version or pkg:generic/name@version.
        if purl.startswith("pkg:"):
            purl_types.append(purl.removeprefix("pkg:").split("/", 1)[0])
    if purl_types:
        return join_values(purl_types)

    if "conda metadata" in source_info or "package-conda" in spdx_id:
        return "conda"
    if "site-packages" in source_info or "package-python" in spdx_id:
        return "python"
    if "package-binary" in spdx_id:
        return "binary"
    if "package-file" in spdx_id:
        return "file"
    return "unknown"


def version_sort_key(version: str) -> tuple[str, ...]:
    # Stable, simple sort for display only. Avoids adding packaging.version as a dependency.
    return tuple(re.split(r"([0-9]+)", version or ""))


def build_relationship_counts(relationships: list[dict[str, Any]]) -> dict[str, Counter[str]]:
    counts: dict[str, Counter[str]] = defaultdict(Counter)

    for relationship in relationships:
        left = relationship.get("spdxElementId")
        right = relationship.get("relatedSpdxElement")
        relationship_type = relationship.get("relationshipType")

        if not left or not relationship_type:
            continue

        counts[left][f"out_{relationship_type}"] += 1

        if right:
            counts[right][f"in_{relationship_type}"] += 1

        if relationship_type == "CONTAINS" and right:
            counts[left]["contains_count"] += 1
        elif relationship_type == "DEPENDENCY_OF" and right:
            # SPDX: A DEPENDENCY_OF B means A is a dependency of B.
            counts[left]["dependent_count"] += 1
            counts[right]["dependency_count"] += 1
        elif relationship_type == "DEPENDS_ON" and right:
            counts[left]["dependency_count"] += 1
            counts[right]["dependent_count"] += 1

    return counts


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)

    with input_path.open("r", encoding="utf-8") as f:
        document = json.load(f)

    packages = document.get("packages", [])
    relationships = document.get("relationships", [])
    rel_counts = build_relationship_counts(relationships)

    by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_name_version: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    versions_by_name: dict[str, set[str]] = defaultdict(set)

    for package in packages:
        name = clean(package.get("name"))
        version = clean(package.get("versionInfo"))
        by_name[name].append(package)
        by_name_version[(name, version)].append(package)
        versions_by_name[name].add(version)

    fieldnames = [
        "name",
        "version",
        "spdx_id",
        "ecosystem",
        "license_declared",
        "license_concluded",
        "primary_package_purpose",
        "supplier",
        "originator",
        "download_location",
        "files_analyzed",
        "contains_file_count",
        "dependency_count",
        "dependent_count",
        "package_record_count_for_name",
        "package_record_count_for_name_version",
        "version_count_for_name",
        "versions_for_name",
        "is_duplicate_name_version",
        "has_multiple_versions",
        "has_purl",
        "purls",
        "purl_count",
        "cpe_count",
        "cpes_sample",
        "has_noassertion_declared_license",
        "has_noassertion_concluded_license",
        "has_noassertion_supplier",
        "has_suspicious_version",
        "copyright_text",
        "source_info",
    ]

    rows: list[dict[str, Any]] = []
    for package in packages:
        name = clean(package.get("name"))
        version = clean(package.get("versionInfo"))
        spdx_id = clean(package.get("SPDXID"))
        purls = external_refs(package, "purl")
        cpes = external_refs(package, "cpe23Type")
        counts = rel_counts[spdx_id]
        license_declared = clean(package.get("licenseDeclared"))
        license_concluded = clean(package.get("licenseConcluded"))
        supplier = clean(package.get("supplier"))
        versions = sorted(versions_by_name[name], key=version_sort_key)

        rows.append(
            {
                "name": name,
                "version": version,
                "spdx_id": spdx_id,
                "ecosystem": infer_ecosystem(package, purls),
                "license_declared": license_declared,
                "license_concluded": license_concluded,
                "primary_package_purpose": clean(package.get("primaryPackagePurpose")),
                "supplier": supplier,
                "originator": clean(package.get("originator")),
                "download_location": clean(package.get("downloadLocation")),
                "files_analyzed": clean(package.get("filesAnalyzed")),
                "contains_file_count": counts["contains_count"],
                "dependency_count": counts["dependency_count"],
                "dependent_count": counts["dependent_count"],
                "package_record_count_for_name": len(by_name[name]),
                "package_record_count_for_name_version": len(by_name_version[(name, version)]),
                "version_count_for_name": len(versions_by_name[name]),
                "versions_for_name": "; ".join(versions),
                "is_duplicate_name_version": len(by_name_version[(name, version)]) > 1,
                "has_multiple_versions": len(versions_by_name[name]) > 1,
                "has_purl": bool(purls),
                "purls": join_values(purls),
                "purl_count": len(set(purls)),
                "cpe_count": len(set(cpes)),
                "cpes_sample": join_values(cpes, limit=5),
                "has_noassertion_declared_license": license_declared == "NOASSERTION",
                "has_noassertion_concluded_license": license_concluded == "NOASSERTION",
                "has_noassertion_supplier": supplier == "NOASSERTION",
                "has_suspicious_version": bool(SUSPICIOUS_VERSION_RE.search(version)),
                "copyright_text": clean(package.get("copyrightText")),
                "source_info": clean(package.get("sourceInfo")),
            }
        )

    rows.sort(key=lambda row: (row["name"].lower(), row["version"], row["spdx_id"]))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="raise")
        writer.writeheader()
        writer.writerows(rows)

    unique_names = len(by_name)
    unique_name_versions = len(by_name_version)
    print(f"Wrote {len(rows)} package records to {output_path}")
    print(f"Unique package names: {unique_names}")
    print(f"Unique package name/version pairs: {unique_name_versions}")


if __name__ == "__main__":
    main()
