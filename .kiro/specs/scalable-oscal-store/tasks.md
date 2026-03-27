# Implementation Plan: Scalable OSCAL Store

## Overview

Replace the in-memory `ComponentDefinitionStore` with a SQLite-backed `OscalStore` supporting all eight OSCAL model types, lazy loading, FTS5 search, pagination, and three database modes (bundled, persistent, ephemeral). Implementation proceeds bottom-up: config → schema/store core → scanning/ingestion → query API → MCP tool wrappers → build script → backward-compat migration → tests.

## Tasks

- [x] 1. Configuration and data model foundations
  - [x] 1.1 Add new config fields to Config class
    - Add `oscal_store_db_path`, `oscal_store_cache_size`, and `oscal_documents_dir` to `src/mcp_server_for_oscal/config.py`
    - Read from `OSCAL_STORE_DB_PATH`, `OSCAL_STORE_CACHE_SIZE` (default 100), `OSCAL_DOCUMENTS_DIR` (default empty)
    - _Requirements: 8.1, 8.2, 8.3, 8.4_

  - [x] 1.2 Create OscalStore module with SQLite schema initialization
    - Create `src/mcp_server_for_oscal/tools/oscal_store.py`
    - Implement `OscalStore.__init__` with database mode resolution (bundled/persistent/ephemeral)
    - Implement `_init_schema()` to create `documents`, `child_elements`, and `fts_index` tables with all indexes per the design schema
    - Define `BUNDLED_DB_PATH` constant pointing to `src/mcp_server_for_oscal/oscal_store.db`
    - Define `ROOT_KEY_TO_MODEL_TYPE` usage from `utils.py` and the child element type mapping dict
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9_

  - [x] 1.3 Write unit tests for config fields and schema initialization
    - Test env var reading for all three new config fields with defaults
    - Test that `OscalStore.__init__` creates all tables and indexes in a temp DB
    - Test database mode resolution for all four combinations (DB_PATH set/unset × bundled DB exists/not)
    - _Requirements: 8.1, 8.2, 8.3, 1.2, 1.3, 1.5, 1.6_

- [x] 2. Directory scanning and document ingestion
  - [x] 2.1 Implement `scan_directory()` and `_detect_model_type()`
    - Implement `_detect_model_type()` to read only the root JSON key and map via `ROOT_KEY_TO_MODEL_TYPE`
    - Implement `scan_directory()` to walk directories for `.json` and `.zip` files, extract metadata (UUID, title, model_type, file_path, file_size, file_mtime, raw_json), and UPSERT into `documents` table with `indexed=0`
    - Implement change detection: skip files where mtime and size match stored values
    - Handle missing/empty directories gracefully (log info, return 0)
    - Support `model_type_filter` parameter to scope scanning
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 3.1, 3.4, 3.5, 9.1, 9.2_

  - [x] 2.2 Implement `_ensure_indexed()` and `_extract_child_elements()`
    - Implement `_ensure_indexed(doc_id)` to check the `indexed` flag and trigger full parsing + child extraction when needed
    - Implement `_extract_child_elements(model_type, parsed_model)` with the child element type mapping for all 8 OSCAL model types per the design table
    - Insert child elements into `child_elements` table and FTS entries into `fts_index`
    - Set `indexed=1` after successful extraction
    - _Requirements: 1.7, 2.5, 3.2, 3.4_

  - [x] 2.3 Implement LRU cache for parsed Trestle models
    - Implement `get_parsed_model(doc_id)` using `functools.lru_cache` with configurable `cache_size`
    - Parse from `raw_json` stored in SQLite (no file system dependency after ingestion)
    - Use the Trestle model mapping table from the design to select the correct parser per model type
    - _Requirements: 3.2, 3.3_

  - [x] 2.4 Write property test for model type detection (Property 3)
    - **Property 3: Model type detection and multi-model acceptance**
    - Generate JSON with each valid root key from `ROOT_KEY_TO_MODEL_TYPE`, verify detection returns correct `OSCALModelType`
    - **Validates: Requirements 2.1, 2.2**

  - [x] 2.5 Write property test for incremental re-indexing (Property 6)
    - **Property 6: Incremental re-indexing**
    - Ingest documents, re-initialize store with same DB, re-scan unchanged files, verify zero re-processing and data intact
    - **Validates: Requirements 3.4, 3.5, 9.5**

- [x] 3. Checkpoint - Verify scanning and ingestion
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Query and list API
  - [x] 4.1 Implement `query()` method
    - Implement unified `query()` with `oscal_model_type` filter, `query_type` (all/by_uuid/by_title/by_type), `query_value`, `offset`, `limit`
    - `by_uuid`: direct index lookup on `documents.uuid`
    - `by_title`: case-insensitive exact match first, FTS fallback
    - `by_type`: filter on `model_type` column
    - `all`: paginated scan
    - Trigger `_ensure_indexed()` for documents in results
    - Return `Page_Response` dict
    - Raise `ValueError` when `query_value` missing for by_uuid/by_title/by_type
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6_

  - [x] 4.2 Implement `list_documents()` and `list_child_elements()`
    - `list_documents()`: query `documents` table for summaries (UUID, title, model_type, child_count via subquery, sizeInBytes), support `oscal_model_type` filter, return `Page_Response`
    - `list_child_elements()`: query `child_elements` with optional `parent_doc_uuid` and `element_type` filters, include `parentDocumentTitle` and `parentDocumentUuid` via JOIN, return `Page_Response`
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 2.6_

  - [x] 4.3 Implement `text_search()` method
    - Query FTS5 virtual table with `MATCH` syntax
    - Support `oscal_model_type` scoping
    - Return `Page_Response` with results ranked by relevance
    - Catch `sqlite3.OperationalError` on bad FTS syntax, fall back to LIKE query
    - _Requirements: 6.1, 6.2, 6.3, 6.4_

  - [x] 4.4 Write property test for pagination correctness (Property 7)
    - **Property 7: Pagination correctness**
    - Generate N documents, test with random offset/limit, verify `len(items) == min(limit, N - offset)`, `total == N`, `hasMore == (offset + limit < N)`
    - **Validates: Requirements 4.3**

  - [x] 4.5 Write property test for UUID lookup (Property 9)
    - **Property 9: UUID lookup returns exact match**
    - Generate documents with known UUIDs, query each by UUID, verify exactly one result with matching UUID
    - **Validates: Requirements 5.3**

  - [x] 4.6 Write property test for case-insensitive title search (Property 10)
    - **Property 10: Case-insensitive title search**
    - Generate documents with known titles, query with random case variations, verify match
    - **Validates: Requirements 5.4**

- [~] 5. Checkpoint - Verify query API
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 6. MCP tool wrappers and backward compatibility
  - [~] 6.1 Implement backward-compatible MCP tool wrappers
    - Refactor `query_component_definition.py` to delegate to `OscalStore` singleton
    - `query_component_definition` → `_store.query(oscal_model_type=COMPONENT_DEFINITION, ...)`
    - `list_component_definitions` → `_store.list_documents(oscal_model_type=COMPONENT_DEFINITION, ...)`
    - `list_components` → `_store.list_child_elements(element_type="component", ...)`
    - `list_capabilities` → `_store.list_child_elements(element_type="capability", ...)`
    - `get_capability` → `_store.query(oscal_model_type=COMPONENT_DEFINITION, query_type="by_uuid", ...)`
    - Preserve existing tool signatures, docstrings, and return format keys
    - Implement `load_external_component_definition` on `OscalStore` for backward compat (local zip + remote URI)
    - _Requirements: 7.1, 7.2, 7.3, 7.4_

  - [~] 6.2 Add new MCP tools for other OSCAL model types
    - Add `query_catalog`, `list_catalogs` tools
    - Add `query_ssp`, `list_ssps` tools
    - Add `query_profile`, `list_profiles` tools
    - Add `query_assessment_plan`, `list_assessment_plans` tools
    - Add `query_assessment_results`, `list_assessment_results` tools
    - Add `query_poam`, `list_poams` tools
    - Add `query_mapping_collection`, `list_mapping_collections` tools
    - All follow same parameter/return conventions as component definition tools
    - _Requirements: 7.3_

  - [~] 6.3 Register new tools in `tools/__init__.py` and update `main.py` startup
    - Add all new tool functions to `get_tool_list()` in `tools/__init__.py`
    - Update `main.py` to initialize `OscalStore` singleton before `_setup_tools()`
    - Call `scan_directory()` for both `component_definitions_dir` and `oscal_documents_dir`
    - Ensure scanning completes before `mcp.run()`
    - _Requirements: 9.3, 9.6_

  - [~] 6.4 Write property test for backward-compatible return format (Property 12)
    - **Property 12: Backward-compatible return format for component definition queries**
    - Generate component definition queries, verify return dict contains expected top-level keys
    - **Validates: Requirements 7.2**

  - [~] 6.5 Write property test for model type filtering (Property 5)
    - **Property 5: Model type filtering**
    - Generate mixed-type document sets, filter by each type, verify only matching docs returned and count matches
    - **Validates: Requirements 2.6, 5.1**

- [~] 7. Checkpoint - Verify MCP tools and backward compatibility
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 8. Build script and bundled database
  - [~] 8.1 Create build script `bin/build_oscal_db.py`
    - Initialize `OscalStore` with explicit `db_path` pointing to `src/mcp_server_for_oscal/oscal_store.db`
    - Scan `component_definitions/` and `oscal_docs/` directories
    - Eagerly index all documents (full parse + child element extraction + FTS population)
    - Compute SHA-256 of resulting DB and update `hashes.json`
    - Log stats (docs indexed, children, DB size)
    - Ensure idempotency: running twice with same input produces identical logical content
    - _Requirements: 10.1, 10.2, 10.3, 10.4_

  - [~] 8.2 Add `build-db` hatch script and update `pyproject.toml` package data
    - Add `build-db` script entry in `pyproject.toml` hatch scripts section
    - Add `oscal_store.db` to package data includes
    - Update `rehash` script to include the bundled DB directory if needed
    - _Requirements: 10.3_

  - [~] 8.3 Implement bundled DB integrity verification at startup
    - Verify bundled DB SHA-256 against `hashes.json` at startup (reuse `verify_package_integrity` pattern)
    - On integrity failure: log warning, fall back to ephemeral DB built from bundled JSON/zip files
    - On bundled DB copy to persistent path: seed from bundled DB when `OSCAL_STORE_DB_PATH` is set but file missing
    - _Requirements: 10.4, 10.5, 9.6, 9.7_

  - [~] 8.4 Write property test for bundled database completeness (Property 13)
    - **Property 13: Bundled database completeness**
    - Build bundled DB from test fixtures, open without scanning, verify all bundled docs queryable with children and FTS
    - **Validates: Requirements 10.1, 10.2**

  - [~] 8.5 Write property test for database mode resolution (Property 14)
    - **Property 14: Database mode resolution**
    - Generate all 4 combinations of DB_PATH × bundled DB presence, verify each resolves to correct mode deterministically
    - **Validates: Requirements 1.2, 1.3, 1.4, 1.5**

- [~] 9. Checkpoint - Verify build script and bundled DB
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 10. Remaining property tests and integration
  - [~] 10.1 Write property test for document metadata round-trip (Property 1)
    - **Property 1: Document metadata persistence round-trip**
    - Generate random document metadata, ingest, query back by UUID, verify UUID/title/model_type/file_path/sizeInBytes match
    - **Validates: Requirements 1.1, 4.1**

  - [~] 10.2 Write property test for child element metadata persistence (Property 2)
    - **Property 2: Child element metadata persistence**
    - Generate documents with child elements, fully index, verify child UUID/title/element_type match and parent_doc_id is valid
    - **Validates: Requirements 1.4**

  - [~] 10.3 Write property test for child element type correctness (Property 4)
    - **Property 4: Child element type correctness per model type**
    - Generate documents of each model type, index, verify child element_types are subset of expected types for that model
    - **Validates: Requirements 2.5**

  - [~] 10.4 Write property test for child element parent info (Property 8)
    - **Property 8: Child element listings include parent info**
    - Generate documents with children, list children, verify `parentDocumentTitle` and `parentDocumentUuid` present and correct
    - **Validates: Requirements 4.4**

  - [~] 10.5 Write property test for FTS with model type scoping (Property 11)
    - **Property 11: Full-text search relevance with model type scoping**
    - Generate documents with known text, search for terms, verify found; scope by type, verify filtering
    - **Validates: Requirements 6.2, 6.3**

- [ ] 11. Update existing tests for backward compatibility
  - [~] 11.1 Update `tests/tools/test_query_component_definition.py`
    - Update test imports and fixtures to work with the new `OscalStore`-backed implementation
    - Ensure all existing test cases pass with the new store (same assertions, same return formats)
    - Update `_store._reset()` calls to use the new store's reset/reinit mechanism
    - Add any needed test fixtures for the new store initialization
    - _Requirements: 7.1, 7.2_

  - [~] 11.2 Write integration tests for new MCP tools
    - Test `query_catalog`, `list_catalogs` with sample catalog fixtures
    - Test `query_ssp`, `list_ssps` with sample SSP fixtures
    - Test cross-model `text_search` returning results from multiple model types
    - _Requirements: 7.3, 6.2, 6.3_

- [~] 12. Final checkpoint - Full test suite
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document (Properties 1–14)
- Unit tests validate specific examples and edge cases
- The implementation language is Python, matching the existing codebase and design document
- Hypothesis is already in devtest dependencies; property tests should use `@settings(max_examples=100)` and `@pytest.mark.slow`
- Existing test fixtures in `tests/fixtures/` should be reused for backward compatibility testing

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.2"] },
    { "id": 1, "tasks": ["1.3", "2.1"] },
    { "id": 2, "tasks": ["2.2", "2.3"] },
    { "id": 3, "tasks": ["2.4", "2.5"] },
    { "id": 4, "tasks": ["4.1", "4.2", "4.3"] },
    { "id": 5, "tasks": ["4.4", "4.5", "4.6"] },
    { "id": 6, "tasks": ["6.1", "6.2"] },
    { "id": 7, "tasks": ["6.3"] },
    { "id": 8, "tasks": ["6.4", "6.5"] },
    { "id": 9, "tasks": ["8.1"] },
    { "id": 10, "tasks": ["8.2", "8.3"] },
    { "id": 11, "tasks": ["8.4", "8.5"] },
    { "id": 12, "tasks": ["10.1", "10.2", "10.3", "10.4", "10.5"] },
    { "id": 13, "tasks": ["11.1", "11.2"] }
  ]
}
```
