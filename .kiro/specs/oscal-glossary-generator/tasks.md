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

- [x] 8. Implement term extraction and writing
  - [x] 8.1 Implement `extract_terms(short_names: list[str], terms_path: Path) -> None` in `bin/generate_oscal_glossary.py`
    - Create the output directory (including intermediates) if it doesn't exist
    - Write a comment header line starting with `#` that includes the file purpose and an ISO 8601 generation timestamp
    - Write each short name on its own line, sorted alphabetically, with no blank lines between terms
    - Call `_fatal()` on write failure (permissions, disk full)
    - _Requirements: 7.2, 7.3, 7.4, 7.5, 7.6, 7.7_

  - [x] 8.2 Implement `read_terms(terms_path: Path) -> list[str]` in `bin/generate_oscal_glossary.py`
    - Load the file; exit with error if missing, advising user to run `--extract-terms` first
    - For each line: strip leading/trailing whitespace, skip blank lines, skip lines starting with `#`
    - Treat remaining lines as terms (hyphenated short names)
    - Deduplicate terms retaining only the first occurrence (case-sensitive comparison)
    - Exit with error if no valid terms found after filtering
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6_

- [ ] 9. Update CLI for two-step workflow
  - [x] 9.1 Update `main()` in `bin/generate_oscal_glossary.py` to add `--extract-terms` flag and `--terms` argument
    - Add `--extract-terms` flag (store_true) that activates Extract_Mode
    - Add `--terms` argument (default: `data/oscal-terms.txt`) for the Term_List_File path
    - When `--extract-terms` is set: call `parse_schema()` then `extract_terms()`, log output path and count, exit 0
    - When `--extract-terms` is not set: call `read_terms()` instead of `parse_schema()`, then proceed with existing `load_glossary()` → `match_terms()` → `generate_markdown()` pipeline
    - Update `--help` description to document the two-step workflow
    - _Requirements: 7.1, 7.8, 8.1, 9.1, 9.2, 9.3, 9.4, 9.5_

- [x] 10. Checkpoint - Verify term extraction and reading
  - Ensure all tests pass, ask the user if questions arise.

- [x] 11. Write unit tests for extract_terms and read_terms
  - [x] 11.1 Write unit tests for `extract_terms()` in `tests/test_glossary_generator.py`
    - Test output file contains comment header starting with `#` and ISO 8601 timestamp
    - Test output file contains sorted short names, one per line, no blank lines between terms
    - Test output directory is created if it doesn't exist
    - Test `_fatal()` is called on write failure
    - _Requirements: 7.3, 7.4, 7.5, 7.6, 7.7_

  - [x] 11.2 Write unit tests for `read_terms()` in `tests/test_glossary_generator.py`
    - Test reading a valid term list file returns correct terms
    - Test comment lines (starting with `#`) are skipped
    - Test blank lines are skipped
    - Test leading/trailing whitespace is stripped from terms
    - Test duplicate terms are deduplicated (first occurrence kept, case-sensitive)
    - Test missing file exits with status 1 and advises running `--extract-terms`
    - Test file with only comments/blanks exits with status 1
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6_

- [ ] 12. Write property tests for term list round trip and reading
  - [ ]* 12.1 Write property test: Term List File Round Trip (Property 13)
    - **Property 13: Term List File Round Trip**
    - **Validates: Requirements 10.5**
    - Generate random sorted, deduplicated lists of valid short names; write with `extract_terms()` then read back with `read_terms()`; verify the lists are identical

  - [ ]* 12.2 Write property test: Term List Reading Correctness (Property 14)
    - **Property 14: Term List Reading Correctness**
    - **Validates: Requirements 8.2, 8.3, 8.4**
    - Generate random term list file content with valid terms, comment lines, blank lines, and duplicate terms; write to file; call `read_terms()`; verify only valid terms returned, comments and blanks skipped, duplicates removed (first occurrence kept), whitespace stripped

- [x] 13. Update Property 10 to use read_terms instead of parse_schema
  - [x] 13.1 Refactor Property 10 (Glossary Entry Completeness Invariant) in `tests/test_glossary_generator_properties.py`
    - Update the test to build a Term_List_File (using `extract_terms()` or direct file write), then call `read_terms()` to get short names instead of calling `parse_schema()` directly
    - This validates the end-to-end flow: terms file → `read_terms()` → `match_terms()` → `generate_markdown()` → completeness check
    - Import `extract_terms` and `read_terms` at the top of the test file
    - **Property 10: Glossary Entry Completeness Invariant**
    - **Validates: Requirements 6.1, 6.2**

- [x] 14. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- All property tests go in `tests/test_glossary_generator_properties.py` using Hypothesis with `@settings(max_examples=100, deadline=None)`
- The script follows the same patterns as `bin/build_oscal_db.py` (logging, `_fatal()` for errors, `sys.exit()`)
- Tasks 1–7 implemented Requirements 1–6 and Properties 1–12 (all completed)
- Tasks 8–14 implement Requirements 7–10 and Properties 13–14 (term extraction, term list reading, two-step CLI workflow)

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["2.1", "3.1"] },
    { "id": 2, "tasks": ["2.2", "2.3", "2.4", "2.5", "3.2"] },
    { "id": 3, "tasks": ["3.3", "3.4", "5.1"] },
    { "id": 4, "tasks": ["5.2", "5.3", "5.4"] },
    { "id": 5, "tasks": ["6.1", "6.2", "6.3"] },
    { "id": 6, "tasks": ["8.1", "8.2"] },
    { "id": 7, "tasks": ["9.1"] },
    { "id": 8, "tasks": ["11.1", "11.2"] },
    { "id": 9, "tasks": ["12.1", "12.2", "13.1"] }
  ]
}
```
