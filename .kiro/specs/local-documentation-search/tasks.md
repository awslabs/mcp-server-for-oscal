# Implementation Plan: Local Documentation Search

## Overview

Replace the `query_local()` stub with working FTS5 search over bundled markdown documentation, make the tool unconditionally available, and upgrade file change detection to SHA-256 content hashing. Implementation proceeds in parallel tracks: SHA-256 change detection and markdown indexing are independent store modifications, then documentation search builds on indexing, query_documentation refactor builds on search, and startup wiring ties everything together.

## Tasks

- [x] 1. SHA-256 change detection in OscalStore
  - [x] 1.1 Add `content_hash` column and migrate existing schema
    - In `src/mcp_server_for_oscal/tools/oscal_store.py`, modify `_init_schema()` to add `content_hash TEXT` column to the `documents` CREATE TABLE statement
    - Add migration logic: `ALTER TABLE documents ADD COLUMN content_hash TEXT` wrapped in try/except for existing DBs
    - When `content_hash` is NULL (pre-migration rows), `_file_unchanged()` must return `False` to force re-indexing
    - _Requirements: 6.5, 6.6_

  - [x] 1.2 Replace mtime+size change detection with SHA-256 hashing
    - In `src/mcp_server_for_oscal/tools/oscal_store.py`, modify `_file_unchanged()` to compare stored SHA-256 hash against computed hash instead of mtime+size
    - Modify `_process_json_file()` to compute SHA-256 of file content (binary read, `hashlib.sha256`) and pass `content_hash` to `_file_unchanged()` and `_upsert_document()`
    - Modify `_process_zip_file()` similarly for inner file content
    - Modify `_upsert_document()` to accept and store `content_hash` in INSERT and ON CONFLICT UPDATE clauses
    - Reuse the same hashing approach as `verify_package_integrity()` in `utils.py`
    - _Requirements: 6.1, 6.2, 6.3, 6.4_

  - [x] 1.3 Write property test for SHA-256 change detection
    - **Property 3: SHA-256 Change Detection**
    - Generate two distinct content strings, write first to a temp file, scan, write second to same path, scan again, verify re-indexing occurred and `content_hash` updated — even when byte lengths are identical
    - Use `@settings(max_examples=100)` with Hypothesis
    - Place test in `tests/tools/test_local_doc_search.py`
    - **Validates: Requirements 1.3, 6.4**

- [x] 2. Markdown indexing in OscalStore
  - [x] 2.1 Implement `_process_markdown_file()` method
    - In `src/mcp_server_for_oscal/tools/oscal_store.py`, add new method `_process_markdown_file(md_file: Path) -> bool`
    - Read file as UTF-8, skip empty files with warning log
    - Derive title from first markdown heading (`# ...`, `## ...`, etc.) or fall back to filename with `.md` stripped and hyphens/underscores replaced by spaces
    - Generate deterministic UUID via `uuid5(NAMESPACE_URL, file_path_str)`
    - Compute SHA-256 content hash, check `_file_unchanged()`, call `_upsert_document()` with `model_type="documentation"` and `raw_json` = markdown text
    - Insert into `fts_index` with `entity_type="documentation"`, full markdown body in `description` column
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.6_

  - [x] 2.2 Extend `scan_directory()` to process markdown files
    - In `src/mcp_server_for_oscal/tools/oscal_store.py`, modify `scan_directory()` to glob for `*.md` files and call `_process_markdown_file()` for each
    - _Requirements: 1.1, 1.5_

  - [x] 2.3 Write property test for markdown indexing round-trip
    - **Property 1: Markdown Indexing Round-Trip**
    - Generate random markdown strings with `st.text()`, write to temp files, scan, verify `documents` table has row with `model_type="documentation"`, correct `content_hash`, and `fts_index` has corresponding `entity_type="documentation"` entry with full body in `description`
    - Use `@settings(max_examples=100)` with Hypothesis
    - Place test in `tests/tools/test_local_doc_search.py`
    - **Validates: Requirements 1.1, 1.4, 6.1**

  - [x] 2.4 Write property test for title derivation
    - **Property 2: Title Derivation from Markdown Content**
    - Generate markdown content with `st.one_of(heading_strategy, no_heading_strategy)` and random filenames, verify title extraction matches first heading or filename-derived fallback
    - Use `@settings(max_examples=100)` with Hypothesis
    - Place test in `tests/tools/test_local_doc_search.py`
    - **Validates: Requirements 1.2**

- [x] 3. Checkpoint - Verify store modifications
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Documentation-scoped search method
  - [x] 4.1 Implement `search_documentation()` on OscalStore
    - In `src/mcp_server_for_oscal/tools/oscal_store.py`, add new method `search_documentation(query_text: str, offset: int = 0, limit: int = 10) -> dict`
    - Return empty page response for empty/whitespace-only queries
    - Execute FTS5 MATCH on `fts_index` filtered to `entity_type = 'documentation'`, ordered by rank
    - On `sqlite3.OperationalError`, fall back to case-insensitive LIKE search on title and description columns
    - Each result item: `title`, `snippet` (up to 200 chars via FTS5 `snippet()` function), `source` (file_path from documents table)
    - Return standard page response: `items`, `total`, `offset`, `limit`, `hasMore`
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6_

  - [x] 4.2 Write property test for documentation search scoping
    - **Property 4: Documentation Search Scoping**
    - Generate a mix of markdown and JSON OSCAL files, index both, search via `search_documentation()`, verify all results have `entity_type` of `"documentation"` — no OSCAL model content appears
    - Use `@settings(max_examples=100)` with Hypothesis
    - Place test in `tests/tools/test_local_doc_search.py`
    - **Validates: Requirements 2.1**

  - [x] 4.3 Write property test for search result structure
    - **Property 5: Search Result Structure**
    - Generate markdown content containing searchable terms, index, search, verify each result item has `title`, `snippet` (≤200 chars), and `source` keys; response has `items`, `total`, `offset`, `limit`, `hasMore`
    - Use `@settings(max_examples=100)` with Hypothesis
    - Place test in `tests/tools/test_local_doc_search.py`
    - **Validates: Requirements 2.3, 2.6**

  - [x] 4.4 Write property test for empty query behavior
    - **Property 6: Empty Query Returns Empty Response**
    - Generate whitespace-only strings via `st.from_regex(r'^\s*$')`, call `search_documentation()`, verify `items` is empty, `total` is 0, `hasMore` is `False`
    - Use `@settings(max_examples=100)` with Hypothesis
    - Place test in `tests/tools/test_local_doc_search.py`
    - **Validates: Requirements 2.4, 3.5**

- [x] 5. Refactor query_documentation module
  - [x] 5.1 Add `init_store()` / `_get_store()` and replace `query_local()` stub
    - In `src/mcp_server_for_oscal/tools/query_documentation.py`, add `init_store(store: OscalStore)` and `_get_store()` following the `query_oscal_models.py` pattern
    - Replace `query_local()` body: if `_store is None`, return `{"error": "OscalStore has not been initialized"}`; otherwise delegate to `_store.search_documentation(query)` and return result unchanged
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 5.1, 5.5_

  - [x] 5.2 Update `query_oscal_documentation()` with fallback and logging
    - In `src/mcp_server_for_oscal/tools/query_documentation.py`, modify `query_oscal_documentation()` to:
      - Log which search path (KB or local) is being used
      - When `config.knowledge_base_id` is set, try `query_kb()`; on exception, fall back to `query_local()`
      - When `config.knowledge_base_id` is not set, call `query_local()` directly
      - If local search is invoked and store is unavailable, return error dict
    - Preserve existing `query_kb()` behavior unchanged
    - _Requirements: 4.2, 4.3, 4.4, 4.5, 4.6, 7.1, 7.2, 7.3_

  - [x] 5.3 Make tool registration unconditional
    - In `src/mcp_server_for_oscal/tools/__init__.py`, move `query_oscal_documentation` import and append outside the `if config.knowledge_base_id:` guard
    - _Requirements: 4.1_

  - [x] 5.4 Write unit tests for query_documentation refactor
    - Test `init_store()` sets module-level singleton
    - Test `query_local()` returns error when store not initialized
    - Test `query_local()` delegates to `search_documentation()` when store is set
    - Test unconditional tool registration (import `get_tool_list()`, verify `query_oscal_documentation` is present regardless of `knowledge_base_id`)
    - Test KB path used when `knowledge_base_id` set, local path when not set
    - Test KB failure falls back to local search
    - Test logging of search path selection
    - Place tests in `tests/tools/test_local_doc_search.py`
    - _Requirements: 3.2, 3.3, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 5.1_

- [x] 6. Startup wiring in main.py
  - [x] 6.1 Wire OscalStore into query_documentation at startup
    - In `src/mcp_server_for_oscal/main.py`, modify `_init_oscal_store()` to:
      - Add `from mcp_server_for_oscal.tools import query_documentation` import
      - Call `query_documentation.init_store(store)` alongside existing `init_store()` calls
      - Ensure `store.scan_directory()` is called on `oscal_docs/` directory (already done for OSCAL JSON; markdown files will now be picked up automatically)
    - _Requirements: 5.2, 5.3, 5.4_

  - [x] 6.2 Write unit tests for startup wiring
    - Test that `_init_oscal_store()` calls `query_documentation.init_store(store)`
    - Test that `oscal_docs/` directory is scanned
    - Test that if `_init_oscal_store()` fails, `query_documentation._store` remains `None`
    - Place tests in `tests/tools/test_local_doc_search.py`
    - _Requirements: 5.2, 5.3, 5.4_

- [x] 7. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- All new tests go in `tests/tools/test_local_doc_search.py` to avoid bloating the existing `test_oscal_store.py` (which is already ~3800 lines)
- The build script (`bin/build_oscal_db.py`) already scans `oscal_docs/` via `store.scan_directory()` — once `scan_directory()` handles `.md` files, markdown indexing in the bundled DB happens automatically with no build script changes needed

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "2.1"] },
    { "id": 1, "tasks": ["1.2", "2.2"] },
    { "id": 2, "tasks": ["1.3", "2.3", "2.4"] },
    { "id": 3, "tasks": ["4.1"] },
    { "id": 4, "tasks": ["4.2", "4.3", "4.4"] },
    { "id": 5, "tasks": ["5.1"] },
    { "id": 6, "tasks": ["5.2", "5.3"] },
    { "id": 7, "tasks": ["5.4", "6.1"] },
    { "id": 8, "tasks": ["6.2"] }
  ]
}
```
