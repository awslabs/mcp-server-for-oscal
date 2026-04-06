# Requirements Document

## Introduction

This document specifies the requirements for a build-time utility script that generates a markdown glossary of OSCAL object types with definitions sourced from two complementary sources: the NIST CSRC glossary and the OSCAL terminology page. OSCAL (Open Security Controls Assessment Language) uses NIST security and compliance terminology without providing inline definitions. This feature bridges that gap by parsing OSCAL JSON schemas to extract non-primitive object type names, matching them against both the NIST glossary export (`data/glossary-export.json`) and the OSCAL terminology page (`data/oscal_docs/OSCAL-Pages-main/src/content/learn/concepts/terminology/_index.md`), and producing a human-readable markdown glossary. The output glossary is a bundled resource in the project, not a runtime MCP tool.

The OSCAL terminology page is a Hugo-format markdown file maintained by the NIST OSCAL team that provides authoritative, OSCAL-specific definitions for key concepts like Control, Catalog, and Baseline. When a term is defined in both the OSCAL terminology page and the NIST CSRC glossary, the OSCAL page definition takes priority because it is more specific to the OSCAL context. The generated glossary indicates the source of each definition so users can trace provenance.

The workflow is split into two distinct steps with a human-in-the-loop curation stage between them:

1. **Term Extraction**: Parse the OSCAL schema and write extracted object type short names to a curated term list file (`data/oscal-terms.txt`).
2. **Glossary Generation**: Read terms from the curated term list file, match them against the OSCAL terminology page (priority source) and the NIST glossary (secondary source), and generate the markdown glossary.

This split allows users to edit the term list between extraction and generation — removing noisy terms, adding custom terms not in the schema, or fixing term names to improve matching.

## Glossary

- **Glossary_Generator**: The build-time Python utility script (`bin/generate_oscal_glossary.py`) that orchestrates schema parsing, term extraction, term matching, and markdown generation
- **OSCAL_Schema**: The bundled JSON Schema file (`oscal_complete_schema.json`) containing all OSCAL model definitions in JSON Schema draft-07 format under the `definitions` key
- **Schema_Parser**: The component of the Glossary_Generator responsible for extracting object type definitions from the OSCAL_Schema `definitions` section
- **NIST_Glossary**: The JSON export of the NIST CSRC glossary (`data/glossary-export.json`) containing approximately 9,870 term records with definitions and source references
- **Object_Type**: A definition entry in the OSCAL_Schema that has `"type": "object"` or contains `anyOf`/`oneOf` with object variants, representing a security or compliance concept (e.g., `catalog`, `control`, `system-security-plan`). This excludes scalar/primitive datatypes
- **Scalar_Type**: A definition entry in the OSCAL_Schema that resolves to a simple JSON Schema type (`string`, `integer`, `boolean`, `number`) or is a `$ref`-only alias to another scalar, such as `UUIDDatatype`, `TokenDatatype`, or `StringDatatype`. These are excluded from the glossary
- **Term_List_File**: A plain-text file (default path: `data/oscal-terms.txt`) containing one term per line (hyphenated short names), with lines starting with `#` treated as comments and blank lines ignored. This file serves as the curated input for glossary generation
- **Term_Matcher**: The component of the Glossary_Generator responsible for matching extracted OSCAL object type names against NIST_Glossary entries
- **Matched_Term**: An OSCAL object type name for which the Term_Matcher found a corresponding entry in either the OSCAL_Terms_Page or the NIST_Glossary (or both)
- **Unmatched_Term**: An OSCAL object type name for which the Term_Matcher found no corresponding entry in either the OSCAL_Terms_Page or the NIST_Glossary
- **Human_Readable_Name**: The display name derived from an OSCAL definition key by stripping the namespace prefix (e.g., `oscal-complete-oscal-catalog:`) and converting hyphens to spaces with title casing (e.g., `oscal-complete-oscal-catalog:back-matter` becomes `Back Matter`)
- **Markdown_Glossary**: The output markdown file containing all matched OSCAL terms with their definitions from the OSCAL_Terms_Page or NIST_Glossary, organized alphabetically, with each definition annotated by its Definition_Source
- **Extract_Mode**: The operational mode of the Glossary_Generator activated by the `--extract-terms` flag, which parses the OSCAL_Schema and writes extracted short names to the Term_List_File
- **Generate_Mode**: The default operational mode of the Glossary_Generator, which reads terms from the Term_List_File and produces the Markdown_Glossary
- **OSCAL_Terms_Page**: The local Hugo-format markdown file containing OSCAL-specific term definitions maintained by the NIST OSCAL team (default path: `data/oscal_docs/OSCAL-Pages-main/src/content/learn/concepts/terminology/_index.md`). Term names are level-3 headings (`###`), definitions are the prose paragraphs following each heading, and `{{% callout %}}` blocks contain supplementary context
- **OSCAL_Terms_Parser**: The component of the Glossary_Generator responsible for parsing the OSCAL_Terms_Page to extract term names and their definitions
- **Hugo_Front_Matter**: The YAML metadata block at the top of the OSCAL_Terms_Page, delimited by `---` markers, containing page configuration (title, date, weight, aliases). This block is skipped during parsing
- **Callout_Block**: A Hugo shortcode block delimited by `{{% callout %}}` and `{{% /callout %}}` (or `{{<callout>}}` and `{{</callout>}}`) markers in the OSCAL_Terms_Page that contains supplementary quotes, references, or context for a term definition
- **Todo_Block**: A Hugo shortcode block delimited by `{{<todo>}}` and `{{</todo>}}` markers in the OSCAL_Terms_Page that indicates incomplete or placeholder content that is not ready for use
- **Definition_Source**: A label indicating the origin of a term's definition in the Markdown_Glossary, either "OSCAL Page" for definitions from the OSCAL_Terms_Page or "NIST CSRC" for definitions from the NIST_Glossary

## Requirements

### Requirement 1: OSCAL Schema Parsing

**User Story:** As a developer, I want the generator to extract all non-primitive object type definitions from the OSCAL complete schema, so that the glossary covers every security and compliance concept modeled in OSCAL.

#### Acceptance Criteria

1. WHEN the Glossary_Generator is invoked in Extract_Mode, THE Schema_Parser SHALL load and parse the OSCAL_Schema from the path specified by the `--schema` argument (default: `src/mcp_server_for_oscal/oscal_schemas/oscal_complete_schema.json`)
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

1. WHEN the Glossary_Generator is invoked in Generate_Mode, THE Term_Matcher SHALL load and parse the NIST_Glossary from `data/glossary-export.json` and validate that it contains a `parentTerms` array
2. WHEN loading the NIST_Glossary, THE Term_Matcher SHALL index all `parentTerms` entries by their `term` field, storing each entry's `term`, `link`, `definitions`, and `abbrSyn` fields for downstream use
3. WHEN indexing terms, THE Term_Matcher SHALL normalize lookup keys to lowercase so that lookups by OSCAL short name are case-insensitive
4. WHEN a `parentTerms` entry has a `definitions` value of `null` or an empty array, THE Term_Matcher SHALL still index the entry so that its `abbrSyn` and `link` data remain available for matching
5. IF the NIST_Glossary file is missing or contains invalid JSON, THEN THE Glossary_Generator SHALL exit with a non-zero status code and an error message that includes the file path and the reason for failure
6. IF the NIST_Glossary file is valid JSON but does not contain a `parentTerms` array, THEN THE Glossary_Generator SHALL exit with a non-zero status code and an error message indicating the expected structure was not found

### Requirement 3: Term Matching

**User Story:** As a developer, I want the generator to match OSCAL object type names against both the OSCAL terminology page and the NIST glossary using flexible matching strategies, so that the glossary captures as many definitions as possible with OSCAL-specific definitions taking priority.

#### Acceptance Criteria

1. WHEN matching an OSCAL short name, THE Term_Matcher SHALL convert the hyphenated short name to a space-separated form (e.g., `back-matter` becomes `back matter`) and perform a case-insensitive lookup against both the OSCAL_Terms_Page index and the NIST_Glossary index
2. WHEN a term is found in the OSCAL_Terms_Page index, THE Term_Matcher SHALL use the OSCAL_Terms_Page definition regardless of whether the term also exists in the NIST_Glossary
3. WHEN a term is found in the NIST_Glossary but not in the OSCAL_Terms_Page, and the NIST_Glossary entry contains at least one definition, THE Term_Matcher SHALL classify the term as a Matched_Term using the NIST_Glossary definition
4. WHEN no match is found in either the OSCAL_Terms_Page or the NIST_Glossary, THE Term_Matcher SHALL classify the term as an Unmatched_Term
5. IF a match is found in the NIST_Glossary but the entry has a null or empty `definitions` field and no match exists in the OSCAL_Terms_Page, THEN THE Term_Matcher SHALL classify the term as an Unmatched_Term
6. WHEN a NIST_Glossary entry contains multiple definitions, THE Term_Matcher SHALL retain all definitions for the Matched_Term
7. WHEN matching is complete, THE Glossary_Generator SHALL log a summary reporting the count of Matched_Terms, the count of Unmatched_Terms, the count of terms sourced from the OSCAL_Terms_Page, the count of terms sourced from the NIST_Glossary, and the total number of terms processed

### Requirement 4: Markdown Glossary Generation

**User Story:** As a developer, I want the generator to produce a well-formatted markdown glossary file with clear source attribution, so that the OSCAL terms and their definitions are easy to read and their provenance is transparent.

#### Acceptance Criteria

1. WHEN all term matching is complete, THE Glossary_Generator SHALL produce a Markdown_Glossary file at the configured output path
2. THE Markdown_Glossary SHALL contain a level-1 heading as the title, an introductory paragraph stating that definitions are sourced from the OSCAL terminology page and the NIST CSRC glossary, and a generation timestamp in ISO 8601 format (e.g., `2024-01-15T10:30:00Z`)
3. THE Markdown_Glossary SHALL list all Matched_Terms in case-insensitive alphabetical order by Human_Readable_Name
4. WHEN rendering a Matched_Term sourced from the NIST_Glossary, THE Markdown_Glossary SHALL include the Human_Readable_Name as a level-2 heading, all NIST definitions as body text, a hyperlink to the CSRC glossary page using the `link` field from the NIST_Glossary entry, and a Definition_Source label of "NIST CSRC"
5. WHEN a Matched_Term sourced from the NIST_Glossary has multiple definitions, THE Markdown_Glossary SHALL render each definition as a separate numbered entry, with each entry's source references listed inline using the `text` field from each source in the definition's `sources` array
6. WHEN rendering a Matched_Term that has abbreviations or synonyms in the NIST_Glossary entry (`abbrSyn` field), THE Markdown_Glossary SHALL render them as a comma-separated list labeled "Also known as:" placed immediately before the definitions
7. WHEN rendering a Matched_Term sourced from the OSCAL_Terms_Page, THE Markdown_Glossary SHALL include the Human_Readable_Name as a level-2 heading, the parsed definition text (including Callout_Block content) as body text, and a Definition_Source label of "OSCAL Page"
8. THE Markdown_Glossary SHALL include a level-2 heading for unmatched terms, followed by all Unmatched_Terms listed alphabetically as a bulleted list of Human_Readable_Names
9. IF the output directory does not exist, THEN THE Glossary_Generator SHALL create the directory (including any intermediate directories) before writing the file
10. IF a Matched_Term has a `null` or empty `definitions` field in the NIST_Glossary entry and no OSCAL_Terms_Page definition, THEN THE Glossary_Generator SHALL render the term entry with its heading and CSRC link but display a note indicating that no definition is available from NIST
11. IF the Glossary_Generator fails to write the Markdown_Glossary file, THEN THE Glossary_Generator SHALL exit with a non-zero status code and a descriptive error message indicating the file path and failure reason
12. WHEN rendering a Matched_Term, THE Markdown_Glossary SHALL include a Definition_Source annotation (e.g., `*Source: OSCAL Page*` or `*Source: NIST CSRC*`) so the reader can identify the origin of the definition

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

**User Story:** As a developer, I want confidence that the generated glossary accurately represents the schema contents and definitions from both sources, so that the glossary is trustworthy as a reference document.

#### Acceptance Criteria

1. THE Markdown_Glossary SHALL contain an entry for every term read from the Term_List_File, with each term appearing exactly once by its Human_Readable_Name in either the matched terms section or the unmatched terms section
2. THE Markdown_Glossary SHALL contain no entries that do not correspond to a term from the Term_List_File, ensuring the total count of entries (matched plus unmatched) equals the total count of terms in the input
3. FOR EACH Matched_Term sourced from the NIST_Glossary in the Markdown_Glossary, THE definition text SHALL be a character-for-character reproduction of the `text` field from the corresponding NIST_Glossary `definitions` entry, with only HTML tag removal or conversion to markdown formatting permitted as transformation
4. FOR EACH Matched_Term sourced from the NIST_Glossary in the Markdown_Glossary, THE CSRC link SHALL exactly reproduce the `link` field value from the corresponding NIST_Glossary `parentTerms` entry, and each source reference within definitions SHALL reproduce the `text` and `link` fields from the corresponding `sources` entry
5. WHEN the Glossary_Generator is run twice on the same Term_List_File, NIST_Glossary, and OSCAL_Terms_Page input files without modification, THE Markdown_Glossary output SHALL be byte-identical after excluding the generation timestamp line

### Requirement 7: Term Extraction Mode

**User Story:** As a developer, I want to extract OSCAL object type names from the schema into a curated term list file, so that I can review and edit the terms before generating the glossary.

#### Acceptance Criteria

1. WHEN the Glossary_Generator is invoked with the `--extract-terms` flag, THE Glossary_Generator SHALL operate in Extract_Mode instead of Generate_Mode
2. WHEN operating in Extract_Mode, THE Schema_Parser SHALL parse the OSCAL_Schema using the existing `parse_schema()` logic and produce a sorted, deduplicated list of Object_Type short names
3. WHEN Extract_Mode completes parsing, THE Glossary_Generator SHALL write the extracted short names to the Term_List_File at the path specified by the `--terms` argument (default: `data/oscal-terms.txt`)
4. THE Term_List_File output SHALL contain a comment header line starting with `#` that describes the file purpose and generation timestamp
5. THE Term_List_File output SHALL contain one short name per line, sorted alphabetically, with no blank lines between terms
6. IF the Term_List_File output directory does not exist, THEN THE Glossary_Generator SHALL create the directory (including any intermediate directories) before writing the file
7. IF the Glossary_Generator fails to write the Term_List_File, THEN THE Glossary_Generator SHALL exit with a non-zero status code and a descriptive error message indicating the file path and failure reason
8. WHEN Extract_Mode completes successfully, THE Glossary_Generator SHALL log the output file path and the count of extracted terms, and exit with status code 0

### Requirement 8: Term List File Reading

**User Story:** As a developer, I want the glossary generator to read terms from a curated term list file instead of parsing the schema directly, so that I can control which terms appear in the glossary and improve NIST matching by editing term names.

#### Acceptance Criteria

1. WHEN the Glossary_Generator is invoked in Generate_Mode (the default, without `--extract-terms`), THE Glossary_Generator SHALL read terms from the Term_List_File at the path specified by the `--terms` argument (default: `data/oscal-terms.txt`)
2. WHEN reading the Term_List_File, THE Glossary_Generator SHALL treat each non-blank line that does not start with `#` as a term (the hyphenated short name), after stripping leading and trailing whitespace
3. WHEN reading the Term_List_File, THE Glossary_Generator SHALL skip lines that start with `#` (comment lines) and blank lines (lines containing only whitespace)
4. WHEN reading the Term_List_File, THE Glossary_Generator SHALL deduplicate terms, retaining only the first occurrence of each unique term (case-sensitive comparison)
5. IF the Term_List_File is missing, THEN THE Glossary_Generator SHALL exit with a non-zero status code and an error message indicating the file path and advising the user to run `--extract-terms` first
6. IF the Term_List_File contains no valid terms (all lines are comments or blank), THEN THE Glossary_Generator SHALL exit with a non-zero status code and an error message indicating that the file contains no terms

### Requirement 9: CLI Enhancements for Two-Step Workflow

**User Story:** As a developer, I want the CLI to support both extraction and generation modes with clear argument handling, so that the two-step workflow is intuitive and well-documented.

#### Acceptance Criteria

1. THE Glossary_Generator SHALL accept an optional `--extract-terms` flag that activates Extract_Mode
2. THE Glossary_Generator SHALL accept an optional `--terms` argument to specify the Term_List_File path, defaulting to `data/oscal-terms.txt`
3. WHEN the `--extract-terms` flag is provided, THE Glossary_Generator SHALL require the `--schema` argument (or use its default) and SHALL ignore the `--glossary` and `--output` arguments
4. WHEN the `--extract-terms` flag is not provided, THE Glossary_Generator SHALL require the `--terms` argument (or use its default) and SHALL no longer require the `--schema` argument
5. WHEN invoked with `--help`, THE Glossary_Generator SHALL display updated usage information describing the two-step workflow, the `--extract-terms` flag, the `--terms` argument, and all other accepted arguments with their default values

### Requirement 10: Term List File Format

**User Story:** As a developer, I want the term list file to use a simple, human-editable format, so that I can easily add, remove, or modify terms between extraction and generation.

#### Acceptance Criteria

1. THE Term_List_File SHALL use a plain-text format with one term per line, where each term is the hyphenated short name (e.g., `back-matter`, `system-security-plan`)
2. THE Term_List_File SHALL treat lines starting with `#` (after optional leading whitespace) as comments that are ignored during reading
3. THE Term_List_File SHALL treat blank lines (lines containing only whitespace) as separators that are ignored during reading
4. THE Term_List_File SHALL support terms that contain hyphens, lowercase letters, uppercase letters, and digits
5. WHEN the Glossary_Generator writes the Term_List_File in Extract_Mode, THE Glossary_Generator SHALL produce a file that the Glossary_Generator can read back in Generate_Mode without loss of terms (write-then-read round trip)

### Requirement 11: OSCAL Terminology Page Parsing

**User Story:** As a developer, I want the generator to parse the local OSCAL terminology markdown file to extract term definitions, so that the glossary includes authoritative OSCAL-specific definitions maintained by the NIST OSCAL team.

#### Acceptance Criteria

1. WHEN the Glossary_Generator is invoked in Generate_Mode, THE OSCAL_Terms_Parser SHALL load and parse the OSCAL_Terms_Page from the path specified by the `--oscal-terms-page` argument (default: `data/oscal_docs/OSCAL-Pages-main/src/content/learn/concepts/terminology/_index.md`)
2. WHEN parsing the OSCAL_Terms_Page, THE OSCAL_Terms_Parser SHALL skip the Hugo_Front_Matter block (the YAML content between the opening `---` and closing `---` markers at the top of the file)
3. WHEN parsing the OSCAL_Terms_Page, THE OSCAL_Terms_Parser SHALL treat each level-3 heading (`###`) as a top-level term name (e.g., `### Control` defines the term "Control", `### Catalog` defines the term "Catalog")
4. WHEN parsing the OSCAL_Terms_Page, THE OSCAL_Terms_Parser SHALL treat level-4 headings (`####`) and deeper as sub-sections of the preceding level-3 term, not as separate top-level terms (e.g., `#### Examples of Controls and Catalogs` is a sub-section, not a term)
5. WHEN extracting a term definition, THE OSCAL_Terms_Parser SHALL collect all prose paragraphs following the level-3 heading up to the next level-2 or level-3 heading, concatenating them as the definition text
6. WHEN a term's content contains a Callout_Block (`{{% callout %}}...{{% /callout %}}` or `{{<callout>}}...{{</callout>}}`), THE OSCAL_Terms_Parser SHALL include the callout content as part of the term definition, stripping the Hugo shortcode delimiters
7. WHEN a term's content contains a Todo_Block (`{{<todo>}}...{{</todo>}}`), THE OSCAL_Terms_Parser SHALL skip all content within the Todo_Block (inclusive of the delimiters), treating it as incomplete content not ready for the glossary
8. WHEN building the term index, THE OSCAL_Terms_Parser SHALL normalize term names to lowercase for case-insensitive matching against OSCAL short names (e.g., heading `### Control` matches short name `control`)
9. IF the OSCAL_Terms_Page file is missing, THEN THE Glossary_Generator SHALL log a warning indicating the file path and continue glossary generation using only the NIST_Glossary as the definition source
10. IF the OSCAL_Terms_Page file exists but contains no parseable level-3 headings, THEN THE Glossary_Generator SHALL log a warning and continue glossary generation using only the NIST_Glossary

### Requirement 12: OSCAL Page Definition Priority and Overwrite Logging

**User Story:** As a developer, I want OSCAL terminology page definitions to take priority over NIST CSRC glossary definitions when both sources define the same term, and I want to be warned when an overwrite occurs, so that I get the most OSCAL-specific definitions while maintaining visibility into source conflicts.

#### Acceptance Criteria

1. WHEN a term is defined in both the OSCAL_Terms_Page and the NIST_Glossary, THE Term_Matcher SHALL use the OSCAL_Terms_Page definition and discard the NIST_Glossary definition for that term
2. WHEN an OSCAL_Terms_Page definition overwrites a NIST_Glossary definition for a term, THE Glossary_Generator SHALL log a WARNING-level message identifying the term name and indicating that the OSCAL page definition is overriding the NIST CSRC definition
3. WHEN a term is defined only in the OSCAL_Terms_Page and not in the NIST_Glossary, THE Term_Matcher SHALL classify the term as a Matched_Term using the OSCAL_Terms_Page definition without logging a warning
4. WHEN a term is defined only in the NIST_Glossary and not in the OSCAL_Terms_Page, THE Term_Matcher SHALL classify the term as a Matched_Term using the NIST_Glossary definition without logging a warning
5. WHEN matching is complete, THE Glossary_Generator SHALL log a summary that includes the count of terms where the OSCAL_Terms_Page definition overrode a NIST_Glossary definition

### Requirement 13: OSCAL Terminology Page Term Matching

**User Story:** As a developer, I want the OSCAL terminology page terms to be matched against the term list using the same flexible matching as the NIST glossary, so that terms like `system-security-plan` can match heading `### System Security Plan` if it exists.

#### Acceptance Criteria

1. WHEN matching an OSCAL short name against the OSCAL_Terms_Page index, THE Term_Matcher SHALL convert the hyphenated short name to a space-separated form (e.g., `back-matter` becomes `back matter`) and perform a case-insensitive lookup
2. WHEN the OSCAL_Terms_Page contains a level-3 heading that matches a term from the Term_List_File after hyphen-to-space conversion and case normalization, THE Term_Matcher SHALL use the corresponding definition from the OSCAL_Terms_Page
3. WHEN the OSCAL_Terms_Page does not contain a matching level-3 heading for a term, THE Term_Matcher SHALL fall back to the NIST_Glossary for that term

### Requirement 14: CLI Argument for OSCAL Terminology Page

**User Story:** As a developer, I want a CLI argument to specify the path to the OSCAL terminology markdown file, so that I can point the generator at different versions of the OSCAL documentation.

#### Acceptance Criteria

1. THE Glossary_Generator SHALL accept an optional `--oscal-terms-page` argument to specify the path to the OSCAL_Terms_Page file, defaulting to `data/oscal_docs/OSCAL-Pages-main/src/content/learn/concepts/terminology/_index.md`
2. WHEN the `--extract-terms` flag is provided, THE Glossary_Generator SHALL ignore the `--oscal-terms-page` argument (the OSCAL_Terms_Page is only used during Generate_Mode)
3. WHEN invoked with `--help`, THE Glossary_Generator SHALL display the `--oscal-terms-page` argument with its description and default value
4. WHEN the `--verbose` flag is set, THE Glossary_Generator SHALL log each term's match result including which source provided the definition (OSCAL_Terms_Page or NIST_Glossary)
