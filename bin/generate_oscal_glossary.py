#!/usr/bin/env python3
"""
Generate a markdown glossary of OSCAL object types with definitions from
the OSCAL terminology page (priority) and the NIST CSRC glossary (fallback).

This script supports a two-step workflow with human-in-the-loop curation:

  Step 1 — Extract terms from the OSCAL schema:
    hatch run bin/generate_oscal_glossary.py --extract-terms
    hatch run bin/generate_oscal_glossary.py --extract-terms --schema path/to/schema.json --terms path/to/terms.txt

  Step 2 — Generate the glossary from the curated term list:
    hatch run bin/generate_oscal_glossary.py
    hatch run bin/generate_oscal_glossary.py --verbose
    hatch run bin/generate_oscal_glossary.py --terms path/to/terms.txt --output path/to/output.md
    hatch run bin/generate_oscal_glossary.py --oscal-terms-page path/to/terminology.md

Between steps, edit the term list file to remove noisy terms, add custom
terms, or fix names to improve matching.

In Generate Mode, definitions are sourced from the OSCAL terminology page
(priority) and the NIST CSRC glossary (fallback).  Use --oscal-terms-page
to specify a custom path to the OSCAL terminology markdown file.

Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 7.1, 7.8, 8.1, 9.1, 9.2, 9.3, 9.4, 9.5, 14.1, 14.2, 14.3, 14.4
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@dataclass
class MatchedTerm:
    """A matched OSCAL term with its NIST CSRC glossary data."""

    short_name: str  # e.g., "back-matter"
    human_name: str  # e.g., "Back Matter"
    definitions: list[dict] = field(default_factory=list)
    link: str = ""
    abbr_syn: list[dict] | None = None
    source: str = "NIST CSRC"  # Definition_Source: "OSCAL Page" or "NIST CSRC"
    oscal_definition: str = ""  # Plain text definition from OSCAL page


def to_human_readable(short_name: str) -> str:
    """Convert a hyphenated short name to a title-cased display name.

    Example: ``back-matter`` → ``Back Matter``
    """
    return short_name.replace("-", " ").title()


def _fatal(msg: str) -> NoReturn:
    """Log a fatal error and exit with status 1."""
    logger.error(msg)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Pipeline stubs — implemented in subsequent tasks
# ---------------------------------------------------------------------------


def _is_object_type(definition: dict) -> bool:
    """Return True if a schema definition represents an Object_Type."""
    # Direct "type": "object"
    if definition.get("type") == "object":
        return True

    # anyOf/oneOf containing at least one object-typed variant
    for key in ("anyOf", "oneOf"):
        variants = definition.get(key)
        if variants and any(v.get("type") == "object" for v in variants):
            return True

    return False


def extract_oscal_version(schema_path: Path) -> str:
    """Extract the OSCAL version from the schema ``$id`` field.

    The ``$id`` follows the pattern
    ``http://csrc.nist.gov/ns/oscal/1.0/<version>/oscal-complete-schema.json``.
    Returns the version string (e.g. ``1.2.1``) or ``"unknown"`` if it
    cannot be determined.
    """
    try:
        raw = schema_path.read_text(encoding="utf-8")
        schema = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return "unknown"

    schema_id = schema.get("$id", "")
    # Pattern: .../ns/oscal/1.0/<version>/oscal-complete-schema.json
    import re as _re

    m = _re.search(r"/ns/oscal/[\d.]+/([\d.]+)/", schema_id)
    return m.group(1) if m else "unknown"


def parse_schema(schema_path: Path) -> list[str]:
    """Load the OSCAL schema and return deduplicated, sorted short names.

    Also warns about formal names (``title`` fields) that appear across
    multiple definition keys but are not themselves represented as a
    short name in the output.  This catches cases like "Component" being
    split across ``defined-component`` and ``system-component`` without
    a unified ``component`` entry.
    """
    if not schema_path.exists():
        _fatal(f"Schema file not found: {schema_path}")

    try:
        raw = schema_path.read_text(encoding="utf-8")
    except OSError as exc:
        _fatal(f"Cannot read schema file {schema_path}: {exc}")

    try:
        schema = json.loads(raw)
    except json.JSONDecodeError as exc:
        _fatal(f"Invalid JSON in schema file {schema_path}: {exc}")

    if "definitions" not in schema:
        _fatal(f"Schema file {schema_path} is missing the 'definitions' key")

    definitions: dict = schema["definitions"]
    seen: dict[str, bool] = {}
    result: list[str] = []
    # Track formal-name → set of short names for shared-name detection
    formal_to_shorts: dict[str, set[str]] = {}

    for key, entry in definitions.items():
        if not isinstance(entry, dict):
            continue

        if not _is_object_type(entry):
            continue

        # Strip namespace prefix (everything before and including ':')
        short_name = key.split(":")[-1] if ":" in key else key

        # Deduplicate by short name, keeping first occurrence
        if short_name not in seen:
            seen[short_name] = True
            result.append(short_name)

        # Record formal name mapping
        title = entry.get("title", "")
        if title:
            formal_to_shorts.setdefault(title, set()).add(short_name)

    # Warn about formal names shared across multiple definitions whose
    # hyphenated form is not already in the result set.
    result_set = set(result)
    for formal_name, shorts in sorted(formal_to_shorts.items()):
        if len(shorts) <= 1:
            continue
        candidate = formal_name.lower().replace(" ", "-")
        if candidate not in result_set:
            logger.warning(
                "Formal name '%s' is shared by definitions %s but '%s' "
                "is not in the extracted terms — consider adding it to "
                "the terms list",
                formal_name,
                sorted(shorts),
                candidate,
            )

    return sorted(result)


def extract_terms(short_names: list[str], terms_path: Path) -> None:
    """Write extracted short names to the Term List File.

    Creates the output directory (including intermediates) if needed,
    writes a comment header with file purpose and ISO 8601 timestamp,
    then writes each short name on its own line sorted alphabetically.

    Requirements: 7.2, 7.3, 7.4, 7.5, 7.6, 7.7
    """
    try:
        terms_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        _fatal(f"Cannot create output directory {terms_path.parent}: {exc}")

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    lines: list[str] = []
    lines.append(
        "# OSCAL object type terms extracted from the OSCAL complete schema"
    )
    lines.append(f"# Generated: {timestamp}")
    for name in sorted(short_names):
        lines.append(name)

    content = "\n".join(lines) + "\n"

    try:
        terms_path.write_text(content, encoding="utf-8")
    except OSError as exc:
        _fatal(f"Cannot write term list file {terms_path}: {exc}")


def read_terms(terms_path: Path) -> list[str]:
    """Read terms from the Term List File and return a deduplicated list.

    Loads the file, skips comment lines (starting with ``#``) and blank
    lines, strips leading/trailing whitespace from each term, and
    deduplicates by first occurrence (case-sensitive).

    Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6
    """
    if not terms_path.exists():
        _fatal(
            f"Term list file not found: {terms_path} "
            "— run with --extract-terms to generate it"
        )

    try:
        raw = terms_path.read_text(encoding="utf-8")
    except OSError as exc:
        _fatal(f"Cannot read term list file {terms_path}: {exc}")

    seen: set[str] = set()
    terms: list[str] = []

    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped not in seen:
            seen.add(stripped)
            terms.append(stripped)

    if not terms:
        _fatal(f"Term list file {terms_path} contains no terms")

    return terms


def parse_oscal_terms_page(page_path: Path) -> dict[str, str]:
    """Parse the Hugo-format OSCAL terminology page into a term index.

    Returns a dict mapping lowercase term names to their definition text
    (prose paragraphs + callout content, with Hugo shortcode delimiters
    stripped).  Degrades gracefully: missing file or no ``###`` headings
    result in a WARNING and an empty dict.

    Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7, 11.8, 11.9, 11.10
    """
    if not page_path.exists():
        logger.warning("OSCAL terms page not found: %s", page_path)
        return {}

    try:
        raw = page_path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("Cannot read OSCAL terms page %s: %s", page_path, exc)
        return {}

    lines = raw.splitlines()

    # --- Skip Hugo front matter ---
    content_start = 0
    if lines and lines[0].strip() == "---":
        for i in range(1, len(lines)):
            if lines[i].strip() == "---":
                content_start = i + 1
                break

    # --- Parse content line by line ---
    terms: dict[str, list[str]] = {}
    current_term: str | None = None
    current_lines: list[str] = []
    in_todo = False

    for line in lines[content_start:]:
        stripped = line.strip()

        # Handle todo block boundaries
        if "{{<todo>}}" in stripped:
            in_todo = True
            continue
        if "{{</todo>}}" in stripped:
            in_todo = False
            continue
        if in_todo:
            continue

        # Strip callout delimiters (both percent and angle-bracket variants)
        if stripped in (
            "{{% callout %}}",
            "{{<callout>}}",
            "{{% /callout %}}",
            "{{</callout>}}",
        ):
            continue

        # Inline callout markers on the same line as content
        for marker in (
            "{{% callout %}}",
            "{{<callout>}}",
            "{{% /callout %}}",
            "{{</callout>}}",
        ):
            stripped = stripped.replace(marker, "")
        line = line.replace("{{% callout %}}", "").replace("{{<callout>}}", "")
        line = line.replace("{{% /callout %}}", "").replace("{{</callout>}}", "")

        # Detect heading levels
        if stripped.startswith("#"):
            # Count the heading level
            level = 0
            for ch in stripped:
                if ch == "#":
                    level += 1
                else:
                    break

            # Must be followed by a space to be a valid heading
            if level < len(stripped) and stripped[level] == " ":
                heading_text = stripped[level:].strip()

                if level == 2:
                    # ## heading: section boundary — close current term
                    if current_term is not None:
                        terms[current_term] = current_lines
                        current_term = None
                        current_lines = []
                elif level == 3:
                    # ### heading: new term entry
                    if current_term is not None:
                        terms[current_term] = current_lines
                    current_term = heading_text
                    current_lines = []
                # #### or deeper: sub-section, content continues accumulating
                # under the current ### term — just add the line
                elif level >= 4 and current_term is not None:
                    current_lines.append(line)
                continue

        # Accumulate prose lines under the current term
        if current_term is not None:
            current_lines.append(line)

    # Flush the last term if the file ends without a closing ## heading
    if current_term is not None:
        terms[current_term] = current_lines

    # Build the lowercase index, joining accumulated lines
    index: dict[str, str] = {}
    for term_name, def_lines in terms.items():
        definition = "\n".join(def_lines)
        index[term_name.lower()] = definition

    if not index:
        logger.warning(
            "OSCAL terms page %s contains no parseable ### headings",
            page_path,
        )

    return index


def load_glossary(glossary_path: Path) -> dict[str, dict]:
    """Load the NIST CSRC glossary and return a case-insensitive index.

    Returns a dict mapping lowercase term strings to their full ``parentTerms``
    entry (with ``term``, ``link``, ``definitions``, ``abbrSyn`` fields).
    """
    if not glossary_path.exists():
        _fatal(f"Glossary file not found: {glossary_path}")

    try:
        raw = glossary_path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        _fatal(f"Cannot read glossary file {glossary_path}: {exc}")

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        _fatal(f"Invalid JSON in glossary file {glossary_path}: {exc}")

    if not isinstance(data, dict) or "parentTerms" not in data:
        _fatal(
            f"Glossary file {glossary_path} does not contain "
            "the expected 'parentTerms' array"
        )

    parent_terms = data["parentTerms"]
    if not isinstance(parent_terms, list):
        _fatal(
            f"Glossary file {glossary_path}: 'parentTerms' is not an array"
        )

    index: dict[str, dict] = {}
    for entry in parent_terms:
        term = entry.get("term", "")
        key = term.lower()
        if key not in index:
            index[key] = entry

    return index


def match_terms(
    short_names: list[str],
    glossary: dict[str, dict],
    oscal_terms: dict[str, str] | None = None,
) -> tuple[list[MatchedTerm], list[str]]:
    """Match OSCAL short names against both the OSCAL terms page and NIST glossary.

    For each short name, converts hyphens to spaces and normalises to
    lowercase for lookup.  The OSCAL terms page index is checked first
    (priority); if not found there, the NIST glossary is used as a
    fallback.  A term is classified as *matched* only when a definition
    is available from either source; otherwise it is *unmatched*.

    When ``oscal_terms`` is ``None`` or empty the function behaves
    exactly as before (NIST-only matching).

    Returns a tuple of (matched_terms, unmatched_short_names).

    Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.7, 12.1, 12.2, 12.3, 12.4, 12.5, 13.1, 13.2, 13.3
    """
    matched: list[MatchedTerm] = []
    unmatched: list[str] = []
    oscal_count = 0
    nist_count = 0
    override_count = 0

    use_oscal = bool(oscal_terms)

    for short_name in short_names:
        lookup_key = short_name.replace("-", " ").lower()

        # --- Priority lookup: OSCAL terms page ---
        if use_oscal and lookup_key in oscal_terms:
            oscal_def = oscal_terms[lookup_key]
            logger.debug("Matched (OSCAL Page): %s", short_name)

            # Check if NIST glossary also has a definition for this term
            nist_entry = glossary.get(lookup_key)
            if nist_entry is not None:
                nist_defs = nist_entry.get("definitions")
                if nist_defs:
                    logger.warning(
                        "OSCAL page definition overriding NIST definition "
                        "for term '%s'",
                        short_name,
                    )
                    override_count += 1

            matched.append(
                MatchedTerm(
                    short_name=short_name,
                    human_name=to_human_readable(short_name),
                    definitions=[],
                    link="",
                    abbr_syn=None,
                    source="OSCAL Page",
                    oscal_definition=oscal_def,
                )
            )
            oscal_count += 1
            continue

        # --- Fallback lookup: NIST glossary ---
        entry = glossary.get(lookup_key)
        if entry is not None:
            definitions = entry.get("definitions")
            if definitions:
                logger.debug("Matched (NIST CSRC): %s", short_name)
                matched.append(
                    MatchedTerm(
                        short_name=short_name,
                        human_name=to_human_readable(short_name),
                        definitions=definitions,
                        link=entry.get("link", ""),
                        abbr_syn=entry.get("abbrSyn"),
                        source="NIST CSRC",
                    )
                )
                nist_count += 1
                continue

        logger.debug("Unmatched: %s", short_name)
        unmatched.append(short_name)

    logger.info(
        "Term matching complete: %d matched, %d unmatched, %d total "
        "(OSCAL Page: %d, NIST CSRC: %d, overrides: %d)",
        len(matched),
        len(unmatched),
        len(short_names),
        oscal_count,
        nist_count,
        override_count,
    )
    return matched, unmatched


def generate_markdown(
    matched: list[MatchedTerm], unmatched: list[str], output_path: Path,
    oscal_version: str = "unknown",
) -> None:
    """Render matched and unmatched terms to a markdown glossary file.

    Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.9, 4.10
    """
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        _fatal(f"Cannot create output directory {output_path.parent}: {exc}")

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    lines: list[str] = []
    lines.append("# OSCAL Glossary")
    lines.append("")
    lines.append(
        f"Definitions for OSCAL v{oscal_version} object types and related "
        "terms, sourced from the "
        "[OSCAL Terminology Page]"
        "(https://pages.nist.gov/OSCAL/learn/concepts/terminology/) "
        "and the "
        "[NIST CSRC Glossary](https://csrc.nist.gov/glossary)."
    )
    lines.append("")
    lines.append(f"*OSCAL version: {oscal_version} — Generated: {timestamp}*")
    lines.append("")

    # Matched terms in case-insensitive alphabetical order by human_name
    sorted_matched = sorted(matched, key=lambda t: t.human_name.lower())

    for term in sorted_matched:
        lines.append(f"## {term.human_name}")
        lines.append("")

        if term.source == "OSCAL Page":
            # OSCAL-sourced: definition text as body, no numbered list,
            # no CSRC link, no "Also known as:"
            if term.oscal_definition:
                lines.append(term.oscal_definition)
                lines.append("")

            lines.append("*Source: OSCAL Page*")
            lines.append("")
        else:
            # NIST-sourced: existing rendering with source annotation

            # Abbreviations / synonyms
            if term.abbr_syn:
                abbr_texts = [
                    a.get("text", "") for a in term.abbr_syn if a.get("text")
                ]
                if abbr_texts:
                    lines.append(
                        f"**Also known as:** {', '.join(abbr_texts)}"
                    )
                    lines.append("")

            # Definitions
            if term.definitions:
                for idx, defn in enumerate(term.definitions, start=1):
                    text = defn.get("text", "")
                    lines.append(f"{idx}. {text}")

                    # Inline source references
                    sources = defn.get("sources") or []
                    for source in sources:
                        src_text = source.get("text", "")
                        src_link = source.get("link", "")
                        if src_text and src_link:
                            lines.append(
                                f"   *Source: [{src_text}]({src_link})*"
                            )
                        elif src_text:
                            lines.append(f"   *Source: {src_text}*")

                    lines.append("")
            else:
                lines.append("*No definition available from NIST.*")
                lines.append("")

            # CSRC glossary link
            if term.link:
                lines.append(
                    f"[CSRC Glossary: {term.human_name}]({term.link})"
                )
                lines.append("")

            lines.append("*Source: NIST CSRC*")
            lines.append("")

        lines.append("---")
        lines.append("")

    # Unmatched terms section
    if unmatched:
        lines.append("## Unmatched Terms")
        lines.append("")
        lines.append(
            "The following OSCAL object types did not have matching "
            "entries in the OSCAL terminology page or the "
            "NIST CSRC glossary:"
        )
        lines.append("")
        sorted_unmatched = sorted(
            unmatched, key=lambda s: to_human_readable(s).lower()
        )
        for short_name in sorted_unmatched:
            lines.append(f"- {to_human_readable(short_name)}")
        lines.append("")

    content = "\n".join(lines)

    try:
        output_path.write_text(content, encoding="utf-8")
    except OSError as exc:
        _fatal(f"Cannot write output file {output_path}: {exc}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Parse arguments, run the pipeline, and report results.

    Supports two operational modes:

    Extract Mode (``--extract-terms``):
        Parses the OSCAL schema and writes extracted object type short names
        to the Term List File for human curation.

    Generate Mode (default):
        Reads terms from the curated Term List File, parses the OSCAL
        terminology page for OSCAL-specific definitions, loads the NIST
        glossary, matches terms against both sources (OSCAL page priority),
        and produces the Markdown Glossary with Definition_Source annotations.
    """
    parser = argparse.ArgumentParser(
        description=(
            "OSCAL Glossary Generator — two-step workflow.\n\n"
            "Step 1: Extract terms from the OSCAL schema into a curated "
            "term list file:\n"
            "  %(prog)s --extract-terms\n\n"
            "Step 2: Generate the glossary from the curated term list:\n"
            "  %(prog)s\n"
            "  %(prog)s --oscal-terms-page path/to/terminology.md\n\n"
            "Between steps, edit the term list to remove noisy terms, add "
            "custom terms, or fix names to improve matching.\n\n"
            "In Generate Mode, definitions are sourced from the OSCAL "
            "terminology page (priority) and the NIST CSRC glossary "
            "(fallback). Use --oscal-terms-page to specify a custom path "
            "to the OSCAL terminology markdown file."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--extract-terms",
        action="store_true",
        help=(
            "Activate Extract Mode: parse the OSCAL schema and write "
            "extracted object type short names to the term list file"
        ),
    )
    parser.add_argument(
        "--terms",
        type=Path,
        default=Path("data/oscal-terms.txt"),
        help=(
            "Path to the term list file "
            "(default: data/oscal-terms.txt)"
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/oscal_docs/oscal-glossary.md"),
        help="Output markdown file path (default: data/oscal_docs/oscal-glossary.md)",
    )
    parser.add_argument(
        "--schema",
        type=Path,
        default=Path(
            "src/mcp_server_for_oscal/oscal_schemas/oscal_complete_schema.json"
        ),
        help="Path to the OSCAL complete JSON schema (used in Extract Mode)",
    )
    parser.add_argument(
        "--glossary",
        type=Path,
        default=Path("data/glossary-export.json"),
        help="Path to the NIST CSRC glossary export JSON (used in Generate Mode)",
    )
    parser.add_argument(
        "--oscal-terms-page",
        type=Path,
        default=Path(
            "data/oscal_docs/OSCAL-Pages-main/src/content/learn/"
            "concepts/terminology/_index.md"
        ),
        help=(
            "Path to the OSCAL terminology markdown page for "
            "OSCAL-specific definitions (used in Generate Mode; "
            "ignored in Extract Mode). "
            "(default: data/oscal_docs/OSCAL-Pages-main/src/content/"
            "learn/concepts/terminology/_index.md)"
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help=(
            "Log each term's match result including which source "
            "provided the definition (OSCAL Page or NIST CSRC)"
        ),
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.extract_terms:
        # --- Extract Mode ---
        # --oscal-terms-page is ignored in Extract Mode
        logger.info("Starting OSCAL term extraction")
        short_names = parse_schema(args.schema)
        extract_terms(short_names, args.terms)
        logger.info(
            "Done — wrote %d terms to %s",
            len(short_names),
            args.terms,
        )
        sys.exit(0)

    # --- Generate Mode (default) ---
    logger.info("Starting OSCAL glossary generation")
    short_names = read_terms(args.terms)
    oscal_terms = parse_oscal_terms_page(args.oscal_terms_page)
    glossary = load_glossary(args.glossary)
    matched, unmatched = match_terms(short_names, glossary, oscal_terms)

    # When --verbose is set, log each term's match result with source
    if args.verbose:
        for term in matched:
            logger.debug(
                "Term '%s': matched (source: %s)",
                term.short_name,
                term.source,
            )
        for short_name in unmatched:
            logger.debug(
                "Term '%s': unmatched (no definition in OSCAL Page or NIST CSRC)",
                short_name,
            )

    generate_markdown(matched, unmatched, args.output,
                      oscal_version=extract_oscal_version(args.schema))

    logger.info(
        "Done — wrote %s (%d matched, %d unmatched)",
        args.output,
        len(matched),
        len(unmatched),
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
