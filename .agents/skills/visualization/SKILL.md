---
name: visualization
description: Create or improve interactive, evidence-rich visualizations and dashboards for analysis findings. Use for project health, dependency, security, license, provenance, risk, compliance, scientific, or operational reports where users need summary context, explanatory text, sensible defaults, drill-downs, and links to source evidence. Pair with the framejs skill when publishing a browser visualization, or the omsf-pdf skill (https://github.com/omsf-eco-infra/omsf-pdf-skill) for a PDF report when framejs is unavailable.
---

# Visualization

Create visualizations that explain findings rather than merely displaying metrics.

When `framejs` is available and the user wants a shareable browser visualization, load that skill and follow its publishing, input, update, and lifecycle rules. When `framejs` is not available, use the `omsf-pdf` skill at https://github.com/omsf-eco-infra/omsf-pdf-skill instead (clone it to a temp dir on demand, do not vendor it) and deliver the same findings as a PDF report following its schema and render workflow. This skill defines the product and information-design preferences; do not duplicate FrameJS or OMSF PDF mechanics here.

## Core standard

A useful visualization answers, in this order:

1. **What is being analyzed?** Name the project, dataset, scope, date, and relevant tool versions.
2. **What matters most?** Lead with the highest-priority verified finding and the next action.
3. **How should the numbers be interpreted?** Explain deduplication, confidence, scope, and important limitations.
4. **What is behind each aggregate?** Let users select a category or entity and inspect its records.
5. **Where can the evidence be checked?** Link findings to authoritative source material when URLs exist.

Do not ship a dashboard made only of counters and charts. Add enough plain-language text for a reader who did not perform the analysis.

## Default view

Choose the project's primary entity or declared root as the default analysis target. Examples include the application, repository, service, environment root, experiment, or top-level package.

- Show the primary entity first.
- Keep components and subpackages available as optional drill-downs.
- Do not default to an interesting subcomponent merely because it has richer data.
- Do not render the root twice as both context and selection.
- If the source lacks a direct edge from the root, distinguish environment membership or inferred containment from a proven dependency edge.

The initial screen should be a compact working dashboard, not a landing page.

## Explanatory text

Every major panel should include one or two concise sentences covering:

- what the panel measures;
- why it matters;
- how to interpret uncertainty;
- what interaction is available.

Also include a collapsible **Methodology, definitions, and limitations** section when the analysis uses scanners, heuristics, inferred relationships, deduplication, or incomplete metadata.

Define domain terms inline or in a compact glossary. Avoid filler and instructions that simply narrate obvious controls.

## Evidence and uncertainty

Keep claims proportional to evidence.

- Separate observed records from canonical entities.
- Deduplicate aliases before displaying totals, while retaining aliases in drill-down evidence.
- Distinguish identity matches, heuristic matches, inferred relationships, and confirmed applicability.
- State that installation, membership, or a dependency edge does not prove runtime reachability or usage.
- Label known false positives rather than silently mixing them with applicable findings.
- Keep authoritative report totals when a drill-down dataset is only an explanatory projection.
- Verify every displayed count against the source data before publishing.

Use language such as “candidate,” “investigate,” or “validate then separate” when evidence does not justify “vulnerable,” “unused,” or “remove.”

## Finding drill-downs

Aggregates must lead to inspectable records.

For finding-oriented panels:

1. Provide meaningful category filters.
2. Select a sensible high-priority record by default.
3. Let the user select a project, package, service, experiment, or other entity.
4. Show the record identifier, category/severity, concise description, relevant version or scope, and recommended action.
5. Link to the authoritative advisory, standard, documentation, source record, or upstream issue when available.
6. Open external sources in a new tab with safe link attributes.
7. Clearly label missing source URLs or custom/unresolved terms.

For compliance or license-like findings, show the declared expression or governing term, classification rationale, recommended action, and links to recognized standard texts. Do not imply that “review required” means forbidden.

## Hierarchy and dependency views

When visualizing a hierarchy or dependency graph:

- Keep the primary project/root as the default target.
- Offer subcomponents through an optional selector.
- Show the relationship type: direct edge, transitive edge, containment, environment membership, or inference.
- Use a stable responsive canvas or SVG view box.
- Avoid an unreadable full graph when a ranked structural summary is clearer.

An XKCD-inspired “important dependency” view may use a stack or keystone metaphor. Define the heuristic beside the graphic. A defensible default heuristic is:

1. Build the selected target's reachable dependency closure.
2. For each reachable dependency, count how many nodes in that closure can transitively reach it.
3. Rank by that support count, breaking ties by direct dependents.
4. Highlight the top dependency and list the next few candidates.

For a root whose direct dependency edges are missing, a closure may combine declared environment membership with recorded component edges. Label synthetic membership links explicitly; do not present them as direct dependencies. Describe the result as structural importance, not proof of runtime criticality, maintenance risk, or irreplaceability.

## Interaction and layout

Prefer a calm, dense, scannable interface.

- Use summary metrics, one clear priority callout, then detailed panels.
- Use familiar filters, tabs, selects, details, and links.
- Make selected state obvious.
- Keep touch targets usable and layouts responsive on mobile.
- Prevent text overflow and avoid fixed widths that exceed the viewport.
- Use color as a secondary signal; include text labels for status and severity.
- Avoid decorative gradients, oversized hero content, nested cards, and chart effects that do not improve comprehension.
- Preserve accessibility basics: semantic controls, labels, keyboard operation, sufficient contrast, and descriptive link text.

## Source data

Prefer structured inputs over manually copied findings.

- Upload or embed compact machine-readable derivatives rather than a huge raw source when only a small subset is needed.
- Keep derivation reproducible and record what was filtered or normalized.
- Use the detailed report as the classification authority when raw fields alone cannot reproduce reviewed categories.
- Do not expose secrets, private URLs, or unnecessary source content in a shareable visualization.

## Update workflow

When modifying an existing visualization:

1. Fetch and inspect its current code and inputs first.
2. Preserve its stable URL, inputs, modules, and Open Graph metadata unless the request changes them.
3. Make the smallest coherent update.
4. Re-run syntax checks (framejs route) or a successful PDF render (omsf-pdf route) and assert that required handlers, inputs, defaults, and links remain present.
5. Verify the key displayed counts against source data.
6. Report the live URL and relevant link-lifecycle caveat (framejs route), or the PDF's absolute path (omsf-pdf route).

Do not declare completion after a failed patch or syntax check. Fix and revalidate first.

## Completion checklist

Before publishing, confirm:

- the project/root is the default target;
- the main finding and action are obvious;
- each major panel explains itself;
- aggregate findings have drill-down records;
- external evidence links are present where available;
- inferred and synthetic relationships are labeled;
- false positives and uncertainty are visible;
- counts match source data;
- desktop and mobile layouts are usable;
- browser JavaScript passes a syntax check (framejs route), or the PDF renders cleanly (omsf-pdf route);
- the visualization update preserves the existing live URL when applicable.
