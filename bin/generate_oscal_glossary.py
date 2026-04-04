#!/usr/bin/env python3
"""
Generate a markdown glossary of OSCAL object types with NIST CSRC definitions.

This script supports a two-step workflow with human-in-the-loop curation:

  Step 1 — Extract terms from the OSCAL schema:
    hatch run bin/generate_oscal_glossary.py --extract-terms
    hatch run bin/generate_oscal_glossary.py --extract-terms --schema path/to/schema.json --terms path/to/terms.txt

  Step 2 — Generate the glossary from the curated term list:
    hatch run bin/generate_oscal_glossary.py
    hatch run bin/generate_oscal_glossary.py --verbose
    hatch run bin/generate_oscal_glossary.py --terms path/to/terms.txt --output path/to/output.md

Between steps, edit the term list file to remove noisy terms, add custom
terms, or fix names to improve NIST glossary matching.

Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 7.1, 7.8, 8.1, 9.1, 9.2, 9.3, 9.4, 9.5
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


def parse_schema(schema_path: Path) -> list[str]:
    """Load the OSCAL schema and return deduplicated, sorted short names."""
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
    short_names: list[str], glossary: dict[str, dict]
) -> tuple[list[MatchedTerm], list[str]]:
    """Match OSCAL short names against the glossary index.

    For each short name, converts hyphens to spaces and performs a
    case-insensitive lookup in the glossary.  A term is classified as
    *matched* only when the glossary entry has a non-null, non-empty
    ``definitions`` list; otherwise it is *unmatched*.

    Returns a tuple of (matched_terms, unmatched_short_names).

    Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6
    """
    matched: list[MatchedTerm] = []
    unmatched: list[str] = []

    for short_name in short_names:
        lookup_key = short_name.replace("-", " ").lower()
        entry = glossary.get(lookup_key)

        if entry is not None:
            definitions = entry.get("definitions")
            if definitions:
                logger.debug("Matched: %s", short_name)
                matched.append(
                    MatchedTerm(
                        short_name=short_name,
                        human_name=to_human_readable(short_name),
                        definitions=definitions,
                        link=entry.get("link", ""),
                        abbr_syn=entry.get("abbrSyn"),
                    )
                )
                continue

        logger.debug("Unmatched: %s", short_name)
        unmatched.append(short_name)

    logger.info(
        "Term matching complete: %d matched, %d unmatched, %d total",
        len(matched),
        len(unmatched),
        len(short_names),
    )
    return matched, unmatched


def generate_markdown(
    matched: list[MatchedTerm], unmatched: list[str], output_path: Path
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
        "Definitions sourced from the "
        "[NIST CSRC Glossary](https://csrc.nist.gov/glossary)."
    )
    lines.append("")
    lines.append(f"*Generated: {timestamp}*")
    lines.append("")

    # Matched terms in case-insensitive alphabetical order by human_name
    sorted_matched = sorted(matched, key=lambda t: t.human_name.lower())

    for term in sorted_matched:
        lines.append(f"## {term.human_name}")
        lines.append("")

        # Abbreviations / synonyms
        if term.abbr_syn:
            abbr_texts = [a.get("text", "") for a in term.abbr_syn if a.get("text")]
            if abbr_texts:
                lines.append(f"**Also known as:** {', '.join(abbr_texts)}")
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
                        lines.append(f"   *Source: [{src_text}]({src_link})*")
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

        lines.append("---")
        lines.append("")

    # Unmatched terms section
    if unmatched:
        lines.append("## Unmatched Terms")
        lines.append("")
        lines.append(
            "The following OSCAL object types did not have matching "
            "entries in the NIST CSRC glossary:"
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
        Reads terms from the curated Term List File, matches them against
        the NIST glossary, and produces the Markdown Glossary.
    """
    parser = argparse.ArgumentParser(
        description=(
            "OSCAL Glossary Generator — two-step workflow.\n\n"
            "Step 1: Extract terms from the OSCAL schema into a curated "
            "term list file:\n"
            "  %(prog)s --extract-terms\n\n"
            "Step 2: Generate the glossary from the curated term list:\n"
            "  %(prog)s\n\n"
            "Between steps, edit the term list to remove noisy terms, add "
            "custom terms, or fix names to improve NIST glossary matching."
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
        "--verbose",
        action="store_true",
        help="Log each term's match status during processing",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.extract_terms:
        # --- Extract Mode ---
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
    glossary = load_glossary(args.glossary)
    matched, unmatched = match_terms(short_names, glossary)
    generate_markdown(matched, unmatched, args.output)

    logger.info(
        "Done — wrote %s (%d matched, %d unmatched)",
        args.output,
        len(matched),
        len(unmatched),
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
