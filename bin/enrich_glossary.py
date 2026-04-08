#!/usr/bin/env python3
"""Post-process the consolidated OSCAL glossary to add:

0. Redirect entries for commonly-used alias terms
1. OSCAL JSON Reference links (from schema analysis)
2. Cross-reference anchor links between glossary terms

Usage:
    hatch run bin/enrich_glossary.py
    hatch run bin/enrich_glossary.py --glossary path/to/glossary.md
    hatch run bin/enrich_glossary.py --schema path/to/schema.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

GLOSSARY_DEFAULT = Path("data/oscal_docs/oscal-glossary.md")
SCHEMA_DEFAULT = Path(
    "src/mcp_server_for_oscal/oscal_schemas/oscal_complete_schema.json"
)
BASE_URL_TEMPLATE = (
    "https://pages.nist.gov/OSCAL-Reference/models/v{version}/complete/json-reference/"
)

ROOT_MODELS = [
    "catalog",
    "mapping-collection",
    "profile",
    "component-definition",
    "system-security-plan",
    "assessment-plan",
    "assessment-results",
    "plan-of-action-and-milestones",
]

MODEL_SHORT = {
    "catalog": "Catalog",
    "mapping-collection": "Mapping Collection",
    "profile": "Profile",
    "component-definition": "Component Definition",
    "system-security-plan": "SSP",
    "assessment-plan": "Assessment Plan",
    "assessment-results": "Assessment Results",
    "plan-of-action-and-milestones": "POA&M",
}

# Properties to skip — ubiquitous and not glossary terms
SKIP_PROPS = {
    "props", "links", "remarks", "uuid", "title", "description",
    "class", "id", "name", "ns", "value", "type", "href", "text",
    "prose", "label", "usage", "values", "choice", "how-many",
    "media-type", "published", "last-modified", "version",
    "oscal-version", "revisions", "roles", "locations", "parties",
    "email-addresses", "urls", "short-name", "external-ids",
    "member-of-organizations", "location-uuids", "addresses",
    "hashes", "rlinks", "base64", "citation", "resources",
    "filename", "expression", "tests", "with-child-controls",
    "with-ids", "pattern", "scheme", "depends-on",
}

# Glossary term -> JSON property names to search for
TERM_TO_PROPS = {
    "Action": ["actions"],
    "Activity": ["activities"],
    "Address": ["address"],
    "Assessment Assets": ["assessment-assets"],
    "Assessment Method": ["objectives-and-methods"],
    "Assessment Part": ["parts"],
    "Assessment Plan": ["assessment-plan"],
    "Assessment Results": ["assessment-results"],
    "Assessment Subject": ["assessment-subjects"],
    "Assessment Subject Placeholder": [],
    "Associated Risk": ["related-risks"],
    "Authorization Boundary": ["authorization-boundary"],
    "Authorized Privilege": ["authorized-privileges"],
    "Back Matter": ["back-matter"],
    "Capability": ["capabilities"],
    "Catalog": ["catalog"],
    "Characterization": ["characterizations"],
    "Component": ["components"],
    "Component Definition": ["component-definition"],
    "Confidence Score": ["confidence-score"],
    "Control": ["controls"],
    "Control Implementation": ["control-implementation", "control-implementations"],
    "Coverage": ["coverage"],
    "Data Flow": ["data-flow"],
    "Defined Component": ["components"],
    "Diagram": ["diagrams"],
    "Document Id": ["document-ids"],
    "Finding": ["findings"],
    "Finding Target": ["target"],
    "Gap Summary": ["source-gap-summary", "target-gap-summary"],
    "Group": ["groups"],
    "Impact": [
        "confidentiality-impact", "integrity-impact", "availability-impact",
    ],
    "Implementation Status": ["implementation-status"],
    "Implemented Requirement": ["implemented-requirements"],
    "Incorporates Component": ["incorporates-components"],
    "Inventory Item": ["inventory-items"],
    "Local Definitions": ["local-definitions"],
    "Local Objective": ["objectives-and-methods"],
    "Logged By": ["logged-by"],
    "Map": ["maps"],
    "Mapping": ["mappings"],
    "Mapping Collection": ["mapping-collection"],
    "Mapping Item": ["sources", "targets"],
    "Mapping Provenance": ["provenance"],
    "Mapping Resource Reference": ["source-resource", "target-resource"],
    "Matching": ["matching"],
    "Network Architecture": ["network-architecture"],
    "Observation": ["observations"],
    "Origin": ["origins"],
    "Origin Actor": ["actors"],
    "Parameter": ["params"],
    "Parameter Constraint": ["constraints"],
    "Parameter Guideline": ["guidelines"],
    "Parameter Selection": ["select"],
    "Part": ["parts"],
    "Plan Of Action And Milestones": ["plan-of-action-and-milestones"],
    "POA&M Item": ["poam-items"],
    "Port Range": ["port-ranges"],
    "Profile": ["profile"],
    "Protocol": ["protocols"],
    "Qualifier Item": ["qualifiers"],
    "Response": ["remediations"],
    "Responsible Party": ["responsible-parties"],
    "Responsible Role": ["responsible-roles"],
    "Result": ["results"],
    "Reviewed Controls": ["reviewed-controls"],
    "Risk": ["risks"],
    "Security Impact Level": ["security-impact-level"],
    "Select Control By Id": [],
    "Select Objective By Id": [],
    "Select Subject By Id": ["exclude-subjects"],
    "Statement": ["statements"],
    "Status": ["status"],
    "Subject Reference": ["subjects"],
    "System Characteristics": ["system-characteristics"],
    "System Component": ["components"],
    "System Id": ["system-ids", "system-id"],
    "System Implementation": ["system-implementation"],
    "System Information": ["system-information"],
    "System Security Plan": ["system-security-plan"],
    "System User": ["users"],
    "Task": ["tasks"],
    "Telephone Number": ["telephone-numbers"],
    "Threat Id": ["threat-ids"],
}

# Curated overrides: for terms sharing the same property name,
# specify which paths belong to which glossary term.
# "Assessment Part" and "Part" both map to "parts" — split them.
TERM_PATH_OVERRIDES = {
    "Assessment Part": [
        "#/assessment-plan/local-definitions/objectives-and-methods/parts",
        "#/assessment-plan/terms-and-conditions/parts",
        "#/assessment-results/local-definitions/objectives-and-methods/parts",
        "#/assessment-results/results/attestations/parts",
    ],
    "Part": [
        "#/catalog/controls/parts",
        "#/catalog/groups/parts",
        "#/profile/modify/alters/adds/parts",
        "#/profile/merge/custom/groups/parts",
    ],
    # "Defined Component" = component-definition context
    "Defined Component": [
        "#/component-definition/components",
    ],
    # "Component" = unified entry, show both primary contexts
    "Component": [
        "#/component-definition/components",
        "#/system-security-plan/system-implementation/components",
        "#/assessment-plan/local-definitions/components",
    ],
    # "System Component" = SSP / assessment context
    "System Component": [
        "#/system-security-plan/system-implementation/components",
        "#/assessment-plan/local-definitions/components",
        "#/assessment-plan/assessment-assets/components",
    ],
    # "Assessment Method" and "Local Objective" share objectives-and-methods
    "Assessment Method": [
        "#/assessment-plan/local-definitions/objectives-and-methods",
        "#/assessment-results/local-definitions/objectives-and-methods",
    ],
    "Local Objective": [
        "#/assessment-plan/local-definitions/objectives-and-methods",
        "#/assessment-results/local-definitions/objectives-and-methods",
    ],
    # "Finding Target" uses "target" which is too generic — scope it
    "Finding Target": [
        "#/assessment-results/results/findings/target",
        "#/plan-of-action-and-milestones/findings/target",
    ],
    # "Mapping Item" uses sources/targets inside maps
    "Mapping Item": [
        "#/mapping-collection/mappings/maps/sources",
        "#/mapping-collection/mappings/maps/targets",
    ],
    # "Origin Actor" uses actors inside origins
    "Origin Actor": [
        "#/assessment-results/results/observations/origins/actors",
        "#/plan-of-action-and-milestones/observations/origins/actors",
    ],
    # "Subject Reference" uses subjects — pick representative paths
    "Subject Reference": [
        "#/assessment-plan/tasks/subjects",
        "#/assessment-results/results/observations/subjects",
    ],
}


# ---------------------------------------------------------------------------
# Schema walking
# ---------------------------------------------------------------------------

def load_schema(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def extract_oscal_version(schema: dict) -> str:
    """Extract the OSCAL version from the schema ``$id`` field.

    Returns the version string (e.g. ``1.2.1``) or ``unknown``.
    """
    schema_id = schema.get("$id", "")
    m = re.search(r"/ns/oscal/[\d.]+/([\d.]+)/", schema_id)
    return m.group(1) if m else "unknown"


def resolve_ref(schema: dict, ref: str) -> dict | None:
    if not ref.startswith("#/definitions/"):
        return None
    name = ref[len("#/definitions/"):]
    return schema.get("definitions", {}).get(name)


def get_properties(defn: dict) -> dict:
    if "properties" in defn:
        return defn["properties"]
    for key in ("anyOf", "oneOf", "allOf"):
        if key in defn:
            merged = {}
            for v in defn[key]:
                if "properties" in v:
                    merged.update(v["properties"])
            if merged:
                return merged
    return {}


def walk(schema, defn, path_parts, depth, max_depth, results, visited):
    if depth > max_depth:
        return
    for prop_name, prop_schema in get_properties(defn).items():
        cur = path_parts + [prop_name]
        path_str = "#/" + "/".join(cur)
        if prop_name not in SKIP_PROPS:
            results[prop_name].add(path_str)
        if depth + 1 <= max_depth:
            _recurse(schema, prop_schema, cur, depth + 1, max_depth, results, visited)


def _recurse(schema, target, cur, depth, max_depth, results, visited):
    for k in ("anyOf", "oneOf"):
        if k in target:
            for v in target[k]:
                _recurse(schema, v, cur, depth, max_depth, results, visited)
            return
    if target.get("type") == "array" and "items" in target:
        target = target["items"]
    if "$ref" in target:
        ref = target["$ref"]
        if ref.startswith("#/definitions/"):
            dk = ref[len("#/definitions/"):]
            if dk not in visited:
                resolved = resolve_ref(schema, ref)
                if resolved:
                    visited.add(dk)
                    walk(schema, resolved, cur, depth, max_depth, results, visited)
                    visited.discard(dk)
    else:
        walk(schema, target, cur, depth, max_depth, results, visited)


def find_root_def(schema, root_name):
    defs = schema.get("definitions", {})
    for key, val in defs.items():
        if key.endswith(f":{root_name}"):
            return val
    return None


def build_all_paths(schema: dict) -> dict[str, set[str]]:
    all_results: dict[str, set[str]] = defaultdict(set)
    for root in ROOT_MODELS:
        root_def = find_root_def(schema, root)
        if not root_def:
            continue
        results: dict[str, set[str]] = defaultdict(set)
        walk(schema, root_def, [root], 0, 3, results, set())
        for prop_name, paths in results.items():
            all_results[prop_name].update(paths)
    return all_results


# ---------------------------------------------------------------------------
# Reference link generation
# ---------------------------------------------------------------------------

def build_ref_links(term: str, all_paths: dict[str, set[str]], base_url: str) -> str:
    """Build a Reference: line for a glossary term."""
    prop_names = TERM_TO_PROPS.get(term, [])
    if not prop_names:
        return ""

    # Use override paths if available
    if term in TERM_PATH_OVERRIDES:
        paths = TERM_PATH_OVERRIDES[term]
    else:
        paths_set: set[str] = set()
        root_set = set(ROOT_MODELS)
        for pn in prop_names:
            if pn in root_set:
                paths_set.add(f"#/{pn}")
            if pn in all_paths:
                paths_set.update(all_paths[pn])
        paths = sorted(paths_set)

    if not paths:
        return ""

    # Group by relative path for dedup
    by_relpath: dict[str, list[tuple[str, str]]] = {}
    for p in paths:
        parts = p.lstrip("#/").split("/")
        root = parts[0]
        relpath = "/".join(parts[1:]) if len(parts) > 1 else ""
        by_relpath.setdefault(relpath, []).append((root, p))

    links = []
    for relpath, entries in by_relpath.items():
        if not relpath:
            root, path = entries[0]
            links.append((MODEL_SHORT.get(root, root), f"{base_url}{path}"))
        elif len(entries) >= 6:
            root, path = entries[0]
            display = f"All models > {relpath.replace('/', ' > ')}"
            links.append((display, f"{base_url}{path}"))
        else:
            for root, path in entries:
                model = MODEL_SHORT.get(root, root)
                display = f"{model} > {relpath.replace('/', ' > ')}" if relpath else model
                links.append((display, f"{base_url}{path}"))

    links.sort(key=lambda x: x[0])
    if len(links) > 8:
        links = links[:8]

    parts_strs = [f"[{d}]({u})" for d, u in links]
    return "Reference: " + " | ".join(parts_strs)


# ---------------------------------------------------------------------------
# Cross-reference linking
# ---------------------------------------------------------------------------

def heading_to_anchor(heading: str) -> str:
    anchor = heading.lower()
    anchor = re.sub(r"[^\w\s-]", "", anchor)
    anchor = anchor.strip().replace(" ", "-")
    return re.sub(r"-+", "-", anchor)


def is_in_protected(text: str, start: int, end: int) -> bool:
    """Check if position is inside a markdown link, Reference/Source/AKA/Note line."""
    for pat in [
        r"\[.*?\]\(.*?\)",
        r"^Reference:.*$",
        r"^\*Sources?:.*$",
        r"^\*\*Also known as:\*\*.*$",
        r"^Note:.*$",
    ]:
        for m in re.finditer(pat, text, re.MULTILINE):
            if start < m.end() and end > m.start():
                return True
    return False


def add_crossrefs(text: str) -> str:
    """Add anchor links to related glossary terms within each definition.

    Multi-word terms (e.g. "Assessment Plan") are matched case-insensitively.
    Single-word terms (e.g. "Control", "Risk") are only matched when they
    appear Capitalized in the text — this avoids false positives where the
    word is used as common English rather than as an OSCAL object reference.
    """
    # Parse sections: find all ## headings
    heading_pat = re.compile(r"^## (.+)$", re.MULTILINE)
    matches = list(heading_pat.finditer(text))
    if not matches:
        return text

    terms = [m.group(1).strip() for m in matches]

    # Build patterns sorted longest-first
    term_entries = []
    for t in terms:
        anchor = heading_to_anchor(t)
        escaped = re.escape(t)
        is_single_word = " " not in t and "&" not in t

        # Build a plural-aware suffix pattern
        # "Activity" -> "Activities", "Capability" -> "Capabilities"
        # "Control" -> "Controls", "Risk" -> "Risks"
        if t.endswith("y"):
            # y -> ies plural: match "Activity" or "Activities"
            base = re.escape(t[:-1])
            plural_pat = base + r"(?:y|ies)"
        elif t.endswith("s") or t.endswith("x") or t.endswith("ch"):
            plural_pat = escaped + r"(?:es)?"
        else:
            plural_pat = escaped + r"s?"

        if is_single_word:
            pat = re.compile(
                r"(?<!\[)(?<!\w)(" + plural_pat + r")(?!\w)(?!\])(?!\()",
            )
        else:
            pat = re.compile(
                r"(?<!\[)(?<!\w)(" + plural_pat + r")(?!\w)(?!\])(?!\()",
                re.IGNORECASE,
            )
        term_entries.append((t, anchor, pat))
    term_entries.sort(key=lambda x: -len(x[0]))

    # Process each section independently
    sections = []
    for i, m in enumerate(matches):
        sec_end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        heading_line = m.group(0)
        body = text[m.end():sec_end]
        current_term = m.group(1).strip()
        current_lower = current_term.lower()

        linked = set()
        for term, anchor, pat in term_entries:
            if term.lower() == current_lower:
                continue
            if term in linked:
                continue
            for match in pat.finditer(body):
                ms, me = match.start(), match.end()
                if is_in_protected(body, ms, me):
                    continue
                match_text = match.group(0)
                link = f"[{match_text}](#{anchor})"
                body = body[:ms] + link + body[me:]
                linked.add(term)
                break

        sections.append((m.start(), heading_line, body))

    # Reconstruct
    result = text[:matches[0].start()]
    for _sec_start, heading, body in sections:
        result += heading + body
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Redirect entries: (alias_heading, target_heading, target_anchor).
# These create "See X." entries for commonly-used alias terms so that
# readers searching for the alias find the canonical definition.
ALIAS_REDIRECTS = [
    ("Constraint", "Parameter Constraint", "parameter-constraint"),
    ("Control Group", "Group", "group"),
    ("Guideline", "Parameter Guideline", "parameter-guideline"),
    ("Identified Risk", "Risk", "risk"),
    ("Impact Level", "Impact", "impact"),
    ("Objective Status", "Finding Target", "finding-target"),
    ("Privilege", "Authorized Privilege", "authorized-privilege"),
    ("SAP", "Assessment Plan", "assessment-plan"),
    ("SAR", "Assessment Results", "assessment-results"),
    ("Selection", "Parameter Selection", "parameter-selection"),
    ("SSP", "System Security Plan", "system-security-plan"),
]


def add_redirects(text: str) -> str:
    """Insert alphabetically-sorted redirect entries for alias terms.

    Skips aliases that already have a heading in the glossary.
    """
    heading_pat = re.compile(r"^## (.+)$", re.MULTILINE)
    existing = {m.group(1).strip().lower() for m in heading_pat.finditer(text)}

    for alias, target, anchor in ALIAS_REDIRECTS:
        if alias.lower() in existing:
            continue
        block = f"\n\n## {alias}\n\nSee [{target}](#{anchor}).\n"
        headings = [
            (m.group(1).strip(), m.start())
            for m in heading_pat.finditer(text)
        ]
        inserted = False
        for h_name, h_pos in headings:
            if h_name.lower() > alias.lower():
                text = text[:h_pos] + block + "\n" + text[h_pos:]
                inserted = True
                break
        if not inserted:
            text = text.rstrip() + block
        existing.add(alias.lower())

    return text


def _strip_enrichment(text: str) -> str:
    """Remove previously added Reference lines, cross-reference links,
    and redirect entries.

    This makes the script idempotent — safe to re-run on already-enriched
    glossaries.
    """
    # Remove Reference: lines (and the blank line after them)
    text = re.sub(r"^Reference: .+\n\n", "", text, flags=re.MULTILINE)
    # Remove cross-reference anchor links: [text](#anchor) -> text
    text = re.sub(r"\[([^\]]+)\]\(#[a-z0-9-]+\)", r"\1", text)
    # Remove redirect sections added by add_redirects()
    redirect_headings = {alias.lower() for alias, _, _ in ALIAS_REDIRECTS}
    heading_pat = re.compile(r"^## (.+)$", re.MULTILINE)
    matches = list(heading_pat.finditer(text))
    # Walk in reverse to preserve positions
    for i in reversed(range(len(matches))):
        term = matches[i].group(1).strip()
        if term.lower() in redirect_headings:
            start = matches[i].start()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            text = text[:start] + text[end:]
    return text


def main():
    parser = argparse.ArgumentParser(description="Enrich OSCAL glossary with links")
    parser.add_argument("--glossary", type=Path, default=GLOSSARY_DEFAULT)
    parser.add_argument("--schema", type=Path, default=SCHEMA_DEFAULT)
    parser.add_argument("--skip-refs", action="store_true", help="Skip reference links")
    parser.add_argument("--skip-crossrefs", action="store_true", help="Skip cross-references")
    parser.add_argument("--skip-redirects", action="store_true", help="Skip alias redirect entries")
    args = parser.parse_args()

    text = args.glossary.read_text()

    # Strip any previous enrichment so the script is idempotent
    text = _strip_enrichment(text)

    # Step 0: Add redirect entries for alias terms
    if not args.skip_redirects:
        text = add_redirects(text)

    # Step 1: Add reference links
    if not args.skip_refs:
        schema = load_schema(args.schema)
        version = extract_oscal_version(schema)
        base_url = BASE_URL_TEMPLATE.format(version=version)
        all_paths = build_all_paths(schema)

        heading_pat = re.compile(r"^## (.+)$", re.MULTILINE)
        headings = list(heading_pat.finditer(text))
        for idx in reversed(range(len(headings))):
            m = headings[idx]
            term = m.group(1).strip()
            ref_line = build_ref_links(term, all_paths, base_url)
            if not ref_line:
                continue
            # Insert before the *Source: line if present, otherwise at the
            # end of the section content (before the next heading).
            sec_end = headings[idx + 1].start() if idx + 1 < len(headings) else len(text)
            after = text[m.end():sec_end]
            source_match = re.search(r"^\*Sources?: ", after, re.MULTILINE)
            if source_match:
                insert_pos = m.end() + source_match.start()
                text = text[:insert_pos] + ref_line + "\n\n" + text[insert_pos:]
            else:
                # Append after the last non-blank line in the section
                stripped = after.rstrip()
                insert_pos = m.end() + len(stripped)
                text = text[:insert_pos] + "\n\n" + ref_line + text[insert_pos:]

    # Normalize whitespace: collapse 3+ consecutive blank lines to 2
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    # Ensure exactly two blank lines before each ## heading for readability
    text = re.sub(r"\n{2,}(## )", r"\n\n\n\1", text)

    # Step 2: Add cross-references
    if not args.skip_crossrefs:
        text = add_crossrefs(text)

    args.glossary.write_text(text)
    count = len(re.findall(r"^## ", text, re.MULTILINE))
    print(f"Done! Enriched {count} glossary entries.")


if __name__ == "__main__":
    main()
