# Implementation Plan: OSCAL Glossary Generator

## Overview

Build a single-file Python utility script (`bin/generate_oscal_glossary.py`) that parses the OSCAL complete JSON schema, matches extracted object type names against the NIST CSRC glossary export, and generates a markdown glossary. The implementation follows the existing `bin/` script patterns (e.g., `build_oscal_db.py`) and uses only stdlib dependencies. Property-based tests use Hypothesis (already a project dev dependency).

## Tasks

- [x] 1. Create the glossary generator script with core data types and CLI
  - [x] 1.1 Create `bin/generate_oscal_glossary.py` with shebang, imports, `MatchedTerm` dataclass, `to_human_readable()` helper, `_fatal()` error helper, `argparse` CLI in `main()`, and script entry point
    - Define `MatchedTerm` dataclass with fields: `short_name`, `human_name`, `definitions`, `link`, `abbr_syn`
    - Implement `to_human_readable(short_name: str) -> str` converting hyphens to spaces with title casing
    - Implement `_fatal(msg: str) -> NoReturn` that logs error and calls `sys.exit(1)`
    - Set up `argparse` with `--output` (default `data/oscal_docs/oscal-glossary.md`), `--schema` (default `src/mcp_server_for_oscal/oscal_schemas/oscal_complete_schema.json`), `--glossary` (default `data/glossary-export.json`), `--verbose` flag
    - Wire `main()` to call the pipeline: `parse_schema()` → `load_glossary()` → `match_terms()` → `generate_markdown()`
    - Log summary on success (output path, matched count, unmatched count) and exit 0
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8_

- [x] 2. Implement schema parsing
  - [x] 2.1 Implement `parse_schema(schema_path: Path) -> list[str]`
    - Load JSON from `schema_path`, validate `definitions` key exists
    - Classify each definition: Object_Type if `"type": "object"` or `anyOf`/`oneOf` contains object-typed variant
    - Exclude Scalar_Types: `string`, `integer`, `boolean`, `number`, `$ref`-only aliases without `properties`/`anyOf`/`oneOf` with objects
    - Strip namespace prefix (everything before and including `:`) from definition keys
    - Deduplicate by short name (keep first occurrence)
    - Return sorted list of unique short names
    - Call `_fatal()` on missing file, invalid JSON, or missing `definitions` key
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8_

  - [x] 2.2 Write property test: Object Type Classification (Property 1)
    - **Property 1: Object Type Classification**
    - **Validates: Requirements 1.3**
    - Generate random schema definition entries with `"type": "object"` or `anyOf`/`oneOf` containing object variants; verify all are classified as Object_Type

  - [x] 2.3 Write property test: Scalar Type Exclusion (Property 2)
    - **Property 2: Scalar Type Exclusion**
    - **Validates: Requirements 1.4**
    - Generate random scalar definition entries (`string`, `integer`, `boolean`, `number`, `$ref`-only); verify all are excluded

  - [x] 2.4 Write property test: Namespace Prefix Stripping (Property 3)
    - **Property 3: Namespace Prefix Stripping**
    - **Validates: Requirements 1.5**
    - Generate random definition keys with/without colons; verify short name extraction is correct

  - [x] 2.5 Write property test: Short Name Deduplication (Property 4)
    - **Property 4: Short Name Deduplication**
    - **Validates: Requirements 1.6**
    - Generate lists of definition keys with controlled short name collisions; verify output has exactly one entry per unique short name

- [x] 3. Implement glossary loading and term matching
  - [x] 3.1 Implement `load_glossary(glossary_path: Path) -> dict[str, dict]`
    - Load JSON from `glossary_path`, validate `parentTerms` array exists
    - Index each entry by `entry["term"].lower()` → full entry dict (with `term`, `link`, `definitions`, `abbrSyn`)
    - Index entries even when `definitions` is `null` or empty (so `abbrSyn`/`link` remain available)
    - Call `_fatal()` on missing file, invalid JSON, or missing `parentTerms`
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6_

  - [x] 3.2 Implement `match_terms(short_names: list[str], glossary: dict[str, dict]) -> tuple[list[MatchedTerm], list[str]]`
    - For each short name: convert hyphens to spaces, case-insensitive lookup in glossary
    - Classify as Matched_Term if entry found with non-null, non-empty `definitions`; otherwise Unmatched_Term
    - Retain all definitions for multi-definition entries
    - Log summary: matched count, unmatched count, total processed
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6_

  - [x] 3.3 Write property test: Case-Insensitive Glossary Indexing (Property 5)
    - **Property 5: Case-Insensitive Glossary Indexing**
    - **Validates: Requirements 2.2, 2.3**
    - Generate glossary entries with varying case; verify any case variant of a term returns the same entry

  - [x] 3.4 Write property test: Term Matching Classification (Property 6)
    - **Property 6: Term Matching Classification**
    - **Validates: Requirements 3.1, 3.2, 3.3, 3.4**
    - Generate short names and glossary entries with/without definitions; verify classification correctness

- [x] 4. Checkpoint - Verify core logic
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Implement markdown generation
  - [x] 5.1 Implement `generate_markdown(matched: list[MatchedTerm], unmatched: list[str], output_path: Path) -> None`
    - Create output directory (including intermediates) if it doesn't exist
    - Write level-1 heading, intro paragraph referencing NIST CSRC glossary, ISO 8601 generation timestamp
    - Render matched terms in case-insensitive alphabetical order by `human_name`
    - Each matched term: level-2 heading (human_name), "Also known as:" line if `abbrSyn` present, numbered definitions with inline source references, CSRC glossary link
    - Multi-definition entries: each definition as a separate numbered entry with source `text` fields inline
    - Render level-2 "Unmatched Terms" heading with alphabetical bulleted list of human-readable names
    - Handle write errors with `_fatal()`
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.9, 4.10_

  - [x] 5.2 Write property test: Alphabetical Ordering (Property 7)
    - **Property 7: Alphabetical Ordering**
    - **Validates: Requirements 4.3**
    - Generate sets of matched terms; verify they appear in case-insensitive alphabetical order in output

  - [x] 5.3 Write property test: Matched Term Rendering Completeness (Property 8)
    - **Property 8: Matched Term Rendering Completeness**
    - **Validates: Requirements 4.4, 4.5**
    - Generate matched terms with varying definition counts; verify heading, numbered definitions, source references, and CSRC link all present

  - [x] 5.4 Write property test: Abbreviation/Synonym Rendering (Property 9)
    - **Property 9: Abbreviation/Synonym Rendering**
    - **Validates: Requirements 4.6**
    - Generate matched terms with non-empty `abbrSyn`; verify "Also known as:" line appears before definitions

- [x] 6. Implement end-to-end integrity properties
  - [x] 6.1 Write property test: Glossary Entry Completeness Invariant (Property 10)
    - **Property 10: Glossary Entry Completeness Invariant**
    - **Validates: Requirements 6.1, 6.2**
    - Generate schema + glossary combinations; verify matched + unmatched count equals total deduplicated Object_Types

  - [x] 6.2 Write property test: Definition and Link Fidelity (Property 11)
    - **Property 11: Definition and Link Fidelity**
    - **Validates: Requirements 6.3, 6.4**
    - Generate matched terms with special characters and HTML; verify character-for-character reproduction (with only HTML tag removal)

  - [x] 6.3 Write property test: Deterministic Output (Property 12)
    - **Property 12: Deterministic Output**
    - **Validates: Requirements 6.5**
    - Generate random schema + glossary inputs; run twice; verify byte-identical output after excluding timestamp line

- [x] 7. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- All property tests go in `tests/test_glossary_generator_properties.py` using Hypothesis with `@settings(max_examples=100, deadline=None)`
- The script follows the same patterns as `bin/build_oscal_db.py` (logging, `_fatal()` for errors, `sys.exit()`)

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["2.1", "3.1"] },
    { "id": 2, "tasks": ["2.2", "2.3", "2.4", "2.5", "3.2"] },
    { "id": 3, "tasks": ["3.3", "3.4", "5.1"] },
    { "id": 4, "tasks": ["5.2", "5.3", "5.4"] },
    { "id": 5, "tasks": ["6.1", "6.2", "6.3"] }
  ]
}
```
