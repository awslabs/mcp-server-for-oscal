# Requirements Document

## Introduction

The `query_oscal_documentation` tool currently has two code paths: (1) query AWS Bedrock Knowledge Base when `OSCAL_KB_ID` is set, and (2) a `query_local()` stub that returns "Not yet implemented". The tool is only registered when `config.knowledge_base_id` is set, making the local path unreachable in normal operation.

This feature replaces the `query_local()` stub with a working FTS5 full-text search over the bundled `oscal_docs/` documentation content (markdown files about OSCAL concepts, community resources, etc.), and makes the tool unconditionally available so users always have documentation search capability — with or without AWS credentials.

A key design consideration: the bundled `oscal_docs/` directory contains markdown reference documentation about OSCAL itself, which is conceptually different from OSCAL model instances (catalogs, SSPs, component definitions) already indexed in the `OscalStore`. The existing `OscalStore.text_search()` only indexes JSON OSCAL documents and their child elements via `scan_directory()`, which skips non-JSON files. A dedicated indexing and search path for documentation content is needed.

## Glossary

- **Documentation_Search_Tool**: The `query_oscal_documentation` MCP tool function that accepts a text query and returns relevant OSCAL documentation results.
- **OscalStore**: The SQLite-backed store (`oscal_store.py`) that manages OSCAL documents, child elements, and FTS5 full-text search indexes.
- **FTS_Index**: The SQLite FTS5 virtual table (`fts_index`) used for full-text search across indexed content.
- **Documentation_Content**: The bundled markdown and text files in the `oscal_docs/` directory that describe OSCAL concepts, architecture, community resources, and reference material — distinct from OSCAL model instance data.
- **OSCAL_Model_Content**: JSON OSCAL documents (catalogs, SSPs, profiles, etc.) and their child elements already indexed by `OscalStore.scan_directory()`.
- **Tool_Registry**: The `get_tool_list()` function in `tools/__init__.py` that determines which tools are registered with the MCP server.
- **Knowledge_Base_Path**: The existing code path that queries AWS Bedrock Knowledge Base when `OSCAL_KB_ID` is configured.
- **Local_Search_Path**: The new code path that performs local FTS5 search over Documentation_Content when no Knowledge_Base_Path is available.

## Requirements

### Requirement 1: Index Documentation Content into FTS

**User Story:** As a developer, I want the bundled `oscal_docs/` markdown files indexed into the OscalStore FTS index, so that their content is searchable via full-text search.

#### Acceptance Criteria

1. WHEN the OscalStore scans a directory containing markdown files (`.md`), THE OscalStore SHALL insert a row into the `documents` table for each markdown file with `model_type` set to `"documentation"`, a deterministic `uuid` derived from the file path, and `raw_json` containing the file's text content, and SHALL insert a corresponding row into the FTS_Index with `entity_type` set to `"documentation"`.
2. THE OscalStore SHALL derive the file title from the first markdown heading (any `#` level) found in the file content; IF the file contains no markdown heading, THEN THE OscalStore SHALL derive the title from the filename with the `.md` extension removed and hyphens/underscores replaced by spaces.
3. WHEN a markdown file has not changed (same SHA-256 content hash as the previously indexed version), THE OscalStore SHALL skip re-indexing that file. THE OscalStore SHALL store the content hash alongside the document record to support this comparison.
4. THE OscalStore SHALL store the full markdown body text in the FTS_Index `description` column so that full-text search matches against the content body and content snippets can be retrieved from search results.
5. WHEN the `build_oscal_db.py` script runs, THE build script SHALL index all markdown files from `oscal_docs/` into the bundled database alongside existing OSCAL model content.
6. IF a markdown file is empty (zero bytes) or cannot be read, THEN THE OscalStore SHALL skip that file and log a warning message.

### Requirement 2: Documentation-Scoped Full-Text Search

**User Story:** As a developer, I want to search only documentation content separately from OSCAL model content, so that documentation queries return relevant reference material without noise from model instance data.

#### Acceptance Criteria

1. THE OscalStore SHALL provide a method to perform full-text search scoped to documentation content only (entities with `entity_type` of `"documentation"`), accepting a query string, an offset integer defaulting to 0, and a limit integer defaulting to 10 (maximum 100).
2. WHEN a documentation search query is executed and matching results exist, THE OscalStore SHALL return results ordered by FTS5 rank score (lower rank first, per SQLite FTS5 default ranking).
3. WHEN a documentation search query is executed, THE OscalStore SHALL return each result as a dict containing the document title, a content snippet of up to 200 characters surrounding the matched text, and the source file path of the originating documentation file.
4. WHEN the search query text is empty or whitespace-only, THE OscalStore SHALL return a page response dict with an empty items list, total of 0, the provided offset and limit values, and hasMore set to false.
5. WHEN the search query contains invalid FTS5 syntax (causing a sqlite3.OperationalError on MATCH), THE OscalStore SHALL fall back to a case-insensitive LIKE-based search on the documentation title and content columns, returning results in the same page response format.
6. THE OscalStore documentation search SHALL return a page response dict containing: items (list of result dicts), total (integer count of all matching rows), offset (integer), limit (integer), and hasMore (boolean indicating whether additional results exist beyond the current page).

### Requirement 3: Replace query_local Stub with FTS Search

**User Story:** As a developer, I want the `query_local()` function to perform a real FTS5 search over documentation content, so that users get useful results when querying OSCAL documentation without AWS credentials.

#### Acceptance Criteria

1. WHEN `query_local()` is called with a non-empty query string, THE Documentation_Search_Tool SHALL call the OscalStore documentation-scoped search method with the query string and return the result dict unchanged.
2. THE Documentation_Search_Tool SHALL expose an `init_store()` function that accepts an OscalStore instance and stores it as a module-level singleton, following the same pattern used by `query_oscal_models.py`.
3. IF the OscalStore module-level singleton has not been initialized when `query_local()` is called, THEN THE Documentation_Search_Tool SHALL return a dict with an `"error"` key containing a message indicating that the OscalStore has not been initialized.
4. THE `query_local()` function SHALL return a dict with an `"items"` key containing a list of matched results, where each item includes a `"title"` string, a `"snippet"` string of matched content, and a `"source"` string of the source file path.
5. IF `query_local()` is called with an empty or whitespace-only query string, THEN THE Documentation_Search_Tool SHALL return a dict with an empty `"items"` list.

### Requirement 4: Unconditional Tool Registration

**User Story:** As a user, I want the `query_oscal_documentation` tool to always be available regardless of whether `OSCAL_KB_ID` is configured, so that I can search OSCAL documentation without needing AWS credentials.

#### Acceptance Criteria

1. THE Tool_Registry SHALL include `query_oscal_documentation` in the tool list regardless of whether `config.knowledge_base_id` is set.
2. WHEN `config.knowledge_base_id` is set and the user invokes `query_oscal_documentation`, THE Documentation_Search_Tool SHALL send the query to the configured Bedrock Knowledge Base and return the retrieval results.
3. WHEN `config.knowledge_base_id` is not set and the user invokes `query_oscal_documentation`, THE Documentation_Search_Tool SHALL execute a local FTS5 full-text search against the bundled OSCAL documentation database and return the matching results.
4. IF the Knowledge_Base_Path query fails due to a runtime error (e.g., network failure, invalid credentials, or service unavailability), THEN THE Documentation_Search_Tool SHALL fall back to the Local_Search_Path and return the local search results.
5. WHEN the user invokes `query_oscal_documentation`, THE Documentation_Search_Tool SHALL log an informational message indicating which search path (Knowledge_Base_Path or Local_Search_Path) is being used before executing the query.
6. IF the Local_Search_Path is invoked and the local FTS5 database is not available, THEN THE Documentation_Search_Tool SHALL return an error response indicating that no search backend is available.

### Requirement 5: Wire OscalStore into query_documentation Module

**User Story:** As a developer, I want the `query_documentation` module to receive the OscalStore singleton at startup, so that it can perform local documentation searches.

#### Acceptance Criteria

1. THE `query_documentation` module SHALL expose an `init_store()` function that accepts a single `OscalStore` argument and stores it in a module-level `_store` variable, following the same pattern used by `query_oscal_models.init_store()`.
2. WHEN `_init_oscal_store()` in `main.py` successfully creates and configures the OscalStore instance, THE server SHALL call `query_documentation.init_store(store)` alongside the existing `query_component_definition.init_store(store)` and `query_oscal_models.init_store(store)` calls, before `_setup_tools()` is invoked.
3. WHEN the OscalStore is initialized in `main.py`, THE server SHALL call `store.scan_directory()` on the bundled `oscal_docs/` directory (resolved relative to the package root, i.e. `Path(__file__).parent / "oscal_docs"`) so that any OSCAL JSON content in that directory is indexed and available for local search at runtime.
4. IF `_init_oscal_store()` raises an exception after `query_documentation.init_store(store)` has not yet been called, THEN THE `query_documentation` module SHALL keep `_store` as `None` and the `query_local()` function SHALL return an error dict indicating the store is unavailable.
5. IF `query_local()` is invoked and `_store` is not `None`, THEN THE `query_documentation` module SHALL delegate the search to the OscalStore instance instead of returning the current hard-coded "Not yet implemented" error.

### Requirement 6: Content-Hash Change Detection for All Indexed Files

**User Story:** As a security-conscious user, I want all indexed content (OSCAL documents and documentation) to use SHA-256 content hashes for change detection instead of file metadata (mtime/size), so that I have confidence that tampered files are detected and re-indexed.

#### Acceptance Criteria

1. THE OscalStore SHALL compute a SHA-256 hash of each file's content during `scan_directory()` and store it in the `documents` table alongside the existing metadata.
2. THE OscalStore `_file_unchanged()` method SHALL compare the stored SHA-256 hash against the current file's computed hash to determine whether re-indexing is needed, replacing the current mtime + file_size comparison.
3. THE OscalStore SHALL reuse the same SHA-256 hashing approach used by `verify_package_integrity()` in `utils.py` (binary-mode read, `hashlib.sha256`).
4. WHEN a file's content hash differs from the stored hash, THE OscalStore SHALL treat the file as changed and re-index it, even if the file's mtime and size are unchanged.
5. THE `documents` table schema SHALL include a `content_hash` TEXT column to store the SHA-256 hex digest.
6. WHEN migrating an existing database that lacks the `content_hash` column, THE OscalStore SHALL add the column and treat all existing rows as needing re-verification on the next scan.

### Requirement 7: Backward Compatibility of Bedrock Knowledge Base Path

**User Story:** As a user with AWS Bedrock configured, I want the existing Knowledge Base query behavior to remain unchanged, so that my current workflow is not disrupted.

#### Acceptance Criteria

1. WHEN `config.knowledge_base_id` is set and a query is received, THE Documentation_Search_Tool SHALL pass the query string and context to `query_kb()` and return the Bedrock `retrieve()` API response dict to the caller without modification.
2. THE Documentation_Search_Tool SHALL preserve the `query_kb()` function accepting a `query` string parameter and an optional `ctx` context parameter, and returning the Bedrock `retrieve()` API response dict.
3. WHEN `query_kb()` raises an exception, THE Documentation_Search_Tool SHALL log the exception, notify the context via `ctx.error()` if a context is provided, and re-raise the original exception to the caller.
