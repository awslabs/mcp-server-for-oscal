# Requirements Document

## Introduction

This document specifies the requirements for a build-time utility script that generates a markdown glossary of OSCAL object types with definitions sourced from the NIST CSRC glossary. OSCAL (Open Security Controls Assessment Language) uses NIST security and compliance terminology without providing inline definitions. This feature bridges that gap by parsing OSCAL JSON schemas to extract non-primitive object type names, matching them against the NIST glossary export (`data/glossary-export.json`), and producing a human-readable markdown glossary. The output glossary is a bundled resource in the project, not a runtime MCP tool.

## Glossary

- **Glossary_Generator**: The build-time Python utility script (`bin/generate_oscal_glossary.py`) that orchestrates schema parsing, term matching, and markdown generation
- **OSCAL_Schema**: The bundled JSON Schema file (`oscal_complete_schema.json`) containing all OSCAL model definitions in JSON Schema draft-07 format under the `definitions` key
- **Schema_Parser**: The component of the Glossary_Generator responsible for extracting object type definitions from the OSCAL_Schema `definitions` section
- **NIST_Glossary**: The JSON export of the NIST CSRC glossary (`data/glossary-export.json`) containing approximately 9,870 term records with definitions and source references
- **Object_Type**: A definition entry in the OSCAL_Schema that has `"type": "object"` or contains `anyOf`/`oneOf` with object variants, representing a security or compliance concept (e.g., `catalog`, `control`, `system-security-plan`). This excludes scalar/primitive datatypes
- **Scalar_Type**: A definition entry in the OSCAL_Schema that resolves to a simple JSON Schema type (`string`, `integer`, `boolean`, `number`) or is a `$ref`-only alias to another scalar, such as `UUIDDatatype`, `TokenDatatype`, or `StringDatatype`. These are excluded from the glossary
- **Term_Matcher**: The component of the Glossary_Generator responsible for matching extracted OSCAL object type names against NIST_Glossary entries
- **Matched_Term**: An OSCAL object type name for which the Term_Matcher found a corresponding entry in the NIST_Glossary
- **Unmatched_Term**: An OSCAL object type name for which the Term_Matcher found no corresponding entry in the NIST_Glossary
- **Human_Readable_Name**: The display name derived from an OSCAL definition key by stripping the namespace prefix (e.g., `oscal-complete-oscal-catalog:`) and converting hyphens to spaces with title casing (e.g., `oscal-complete-oscal-catalog:back-matter` becomes `Back Matter`)
- **Markdown_Glossary**: The output markdown file containing all matched OSCAL terms with their NIST definitions, organized alphabetically

## Requirements

### Requirement 1: OSCAL Schema Parsing

**User Story:** As a developer, I want the generator to extract all non-primitive object type definitions from the OSCAL complete schema, so that the glossary covers every security and compliance concept modeled in OSCAL.

#### Acceptance Criteria

1. WHEN the Glossary_Generator is invoked, THE Schema_Parser SHALL load and parse the OSCAL_Schema from `src/mcp_server_for_oscal/oscal_schemas/oscal_complete_schema.json`
2. WHEN parsing the OSCAL_Schema, THE Schema_Parser SHALL iterate over all entries in the `definitions` section
3. WHEN a definition entry has `"type": "object"` or contains `anyOf`/`oneOf` with at least one object-typed variant, THE Schema_Parser SHALL classify the entry as an Object_Type
4. WHEN a definition entry resolves to a scalar JSON Schema type (`string`, `integer`, `boolean`, `number`), is a `$ref`-only alias to a Scalar_Type, or is a `$ref`-only alias without a `"type"` field and without `properties`/`anyOf`/`oneOf` containing object-typed variants, THE Schema_Parser SHALL exclude the entry from the glossary
5. WHEN extracting Object_Type names, THE Schema_Parser SHALL derive the short name by stripping the namespace prefix (all text before and including the colon character `:`) from definition keys that contain a colon, and by using the full key as the short name for definition keys that do not contain a colon (e.g., `oscal-complete-oscal-catalog:catalog` becomes `catalog`; `include-all` remains `include-all`)
6. WHEN multiple namespaced definitions resolve to the same short name, THE Schema_Parser SHALL deduplicate and retain exactly one entry per unique short name, keeping the first occurrence encountered during iteration
7. IF the OSCAL_Schema file is missing or contains invalid JSON, THEN THE Glossary_Generator SHALL exit with a non-zero status code and an error message indicating the file path and the nature of the failure (missing file or parse error)
8. IF the OSCAL_Schema file is valid JSON but does not contain a `definitions` key, THEN THE Glossary_Generator SHALL exit with a non-zero status code and an error message indicating the missing `definitions` section

### Requirement 2: NIST Glossary Loading and Lookup

**User Story:** As a developer, I want the generator to load the NIST CSRC glossary export and provide efficient term lookup, so that OSCAL object types can be matched to authoritative NIST definitions.

#### Acceptance Criteria

1. WHEN the Glossary_Generator is invoked, THE Term_Matcher SHALL load and parse the NIST_Glossary from `data/glossary-export.json` and validate that it contains a `parentTerms` array
2. WHEN loading the NIST_Glossary, THE Term_Matcher SHALL index all `parentTerms` entries by their `term` field, storing each entry's `term`, `link`, `definitions`, and `abbrSyn` fields for downstream use
3. WHEN indexing terms, THE Term_Matcher SHALL normalize lookup keys to lowercase so that lookups by OSCAL short name are case-insensitive
4. WHEN a `parentTerms` entry has a `definitions` value of `null` or an empty array, THE Term_Matcher SHALL still index the entry so that its `abbrSyn` and `link` data remain available for matching
5. IF the NIST_Glossary file is missing or contains invalid JSON, THEN THE Glossary_Generator SHALL exit with a non-zero status code and an error message that includes the file path and the reason for failure
6. IF the NIST_Glossary file is valid JSON but does not contain a `parentTerms` array, THEN THE Glossary_Generator SHALL exit with a non-zero status code and an error message indicating the expected structure was not found

### Requirement 3: Term Matching

**User Story:** As a developer, I want the generator to match OSCAL object type names against NIST glossary terms using flexible matching strategies, so that the glossary captures as many definitions as possible despite naming differences.

#### Acceptance Criteria

1. WHEN matching an OSCAL short name to the NIST_Glossary, THE Term_Matcher SHALL convert the hyphenated short name to a space-separated form (e.g., `back-matter` becomes `back matter`) and perform a case-insensitive lookup
2. WHEN a direct match is found and the NIST_Glossary entry contains at least one definition, THE Term_Matcher SHALL classify the term as a Matched_Term and record all definition texts with their source references
3. WHEN no direct match is found, THE Term_Matcher SHALL classify the term as an Unmatched_Term
4. IF a direct match is found but the NIST_Glossary entry has a null or empty `definitions` field, THEN THE Term_Matcher SHALL classify the term as an Unmatched_Term
5. WHEN a NIST_Glossary entry contains multiple definitions, THE Term_Matcher SHALL retain all definitions for the Matched_Term
6. WHEN matching is complete, THE Glossary_Generator SHALL log a summary reporting the count of Matched_Terms, the count of Unmatched_Terms, and the total number of Object_Types processed

### Requirement 4: Markdown Glossary Generation

**User Story:** As a developer, I want the generator to produce a well-formatted markdown glossary file, so that the OSCAL terms and their NIST definitions are easy to read and reference.

#### Acceptance Criteria

1. WHEN all term matching is complete, THE Glossary_Generator SHALL produce a Markdown_Glossary file at the configured output path
2. THE Markdown_Glossary SHALL contain a level-1 heading as the title, an introductory paragraph stating that definitions are sourced from the NIST CSRC glossary, and a generation timestamp in ISO 8601 format (e.g., `2024-01-15T10:30:00Z`)
3. THE Markdown_Glossary SHALL list all Matched_Terms in case-insensitive alphabetical order by Human_Readable_Name
4. WHEN rendering a Matched_Term, THE Markdown_Glossary SHALL include the Human_Readable_Name as a level-2 heading, all NIST definitions as body text, and a hyperlink to the CSRC glossary page using the `link` field from the NIST_Glossary entry
5. WHEN a Matched_Term has multiple definitions, THE Markdown_Glossary SHALL render each definition as a separate numbered entry, with each entry's source references listed inline using the `text` field from each source in the definition's `sources` array
6. WHEN rendering a Matched_Term that has abbreviations or synonyms in the NIST_Glossary entry (`abbrSyn` field), THE Markdown_Glossary SHALL render them as a comma-separated list labeled "Also known as:" placed immediately before the definitions
7. THE Markdown_Glossary SHALL include a level-2 heading for unmatched terms, followed by all Unmatched_Terms listed alphabetically as a bulleted list of Human_Readable_Names
8. IF the output directory does not exist, THEN THE Glossary_Generator SHALL create the directory (including any intermediate directories) before writing the file
9. IF a Matched_Term has a `null` or empty `definitions` field in the NIST_Glossary entry, THEN THE Glossary_Generator SHALL render the term entry with its heading and CSRC link but display a note indicating that no definition is available from NIST
10. IF the Glossary_Generator fails to write the Markdown_Glossary file, THEN THE Glossary_Generator SHALL exit with a non-zero status code and a descriptive error message indicating the file path and failure reason

### Requirement 5: CLI Interface and Configuration

**User Story:** As a developer, I want to run the glossary generator from the command line with sensible defaults and optional overrides, so that the script integrates into the project build workflow.

#### Acceptance Criteria

1. THE Glossary_Generator SHALL be executable as `hatch run bin/generate_oscal_glossary.py`
2. THE Glossary_Generator SHALL accept an optional `--output` argument to specify the output file path, defaulting to `data/oscal_docs/oscal-glossary.md`
3. THE Glossary_Generator SHALL accept an optional `--schema` argument to specify the OSCAL schema path, defaulting to `src/mcp_server_for_oscal/oscal_schemas/oscal_complete_schema.json`
4. THE Glossary_Generator SHALL accept an optional `--glossary` argument to specify the NIST glossary export path, defaulting to `data/glossary-export.json`
5. THE Glossary_Generator SHALL accept an optional `--verbose` flag that, when set, causes the Term_Matcher to log each term's short name and whether it was classified as a Matched_Term or Unmatched_Term
6. WHEN invoked with `--help`, THE Glossary_Generator SHALL display usage information describing all accepted arguments and their default values
7. WHEN the Glossary_Generator completes successfully, THE Glossary_Generator SHALL exit with status code 0 and log the output file path, the count of Matched_Terms, and the count of Unmatched_Terms
8. IF the Glossary_Generator is invoked with an unrecognized argument, THEN THE Glossary_Generator SHALL exit with a non-zero status code and display an error message indicating the unrecognized argument

### Requirement 6: Glossary Round-Trip Integrity

**User Story:** As a developer, I want confidence that the generated glossary accurately represents the schema contents and NIST definitions, so that the glossary is trustworthy as a reference document.

#### Acceptance Criteria

1. THE Markdown_Glossary SHALL contain an entry for every Object_Type extracted from the OSCAL_Schema, with each Object_Type appearing exactly once by its Human_Readable_Name in either the matched terms section or the unmatched terms section
2. THE Markdown_Glossary SHALL contain no entries that do not correspond to an Object_Type extracted from the OSCAL_Schema, ensuring the total count of entries (matched plus unmatched) equals the total count of deduplicated Object_Types
3. FOR EACH Matched_Term in the Markdown_Glossary, THE definition text SHALL be a character-for-character reproduction of the `text` field from the corresponding NIST_Glossary `definitions` entry, with only HTML tag removal or conversion to markdown formatting permitted as transformation
4. FOR EACH Matched_Term in the Markdown_Glossary, THE CSRC link SHALL exactly reproduce the `link` field value from the corresponding NIST_Glossary `parentTerms` entry, and each source reference within definitions SHALL reproduce the `text` and `link` fields from the corresponding `sources` entry
5. WHEN the Glossary_Generator is run twice on the same OSCAL_Schema and NIST_Glossary input files without modification, THE Markdown_Glossary output SHALL be byte-identical after excluding the generation timestamp line
