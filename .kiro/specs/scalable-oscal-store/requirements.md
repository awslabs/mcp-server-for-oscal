# Requirements Document

## Introduction

The MCP Server for OSCAL currently supports only Component Definition documents via a `ComponentDefinitionStore` that loads all data eagerly into memory at module import time. This approach does not scale to tens of thousands of OSCAL documents and does not support other OSCAL model types (catalogs, profiles, SSPs, assessment plans, assessment results, POA&Ms). This feature replaces the monolithic in-memory store with a scalable, multi-model OSCAL store backed by SQLite, supporting lazy loading, efficient indexing, text search, and a unified query interface across all OSCAL model types.

## Glossary

- **OSCAL_Store**: The new scalable storage layer that replaces `ComponentDefinitionStore`, backed by SQLite, supporting all OSCAL model types.
- **OSCAL_Model_Type**: One of the OSCAL document types: catalog, profile, component-definition, system-security-plan, assessment-plan, assessment-results, plan-of-action-and-milestones, mapping-collection. Represented by the existing `OSCALModelType` enum in `utils.py`.
- **Document**: A single top-level OSCAL JSON file (e.g., one Component Definition, one Catalog, one SSP). Each document has a UUID, a title extracted from its `metadata.title`, and a model type.
- **Index**: A SQLite table or index structure that enables efficient lookup of documents and their child elements by UUID, title, or type without loading full document content.
- **Child_Element**: A nested object within a document that is independently queryable (e.g., a Component within a Component Definition, a Control within a Catalog, a Control Implementation within an SSP).
- **Lazy_Loading**: The strategy of deferring full document parsing until a specific document or child element is requested, storing only metadata and index entries at scan time.
- **Page_Response**: The existing pagination envelope with keys `items`, `total`, `offset`, `limit`, `hasMore` returned by list operations.
- **Text_Search**: SQLite FTS5-based full-text search over document and child element titles, descriptions, and other textual fields.
- **Trestle_Model**: A Pydantic model from the `compliance-trestle` library (`trestle.oscal.*`) used for parsing, validating, and serializing OSCAL documents.
- **Bundled_Database**: A pre-built, fully indexed SQLite database shipped with the package containing all bundled OSCAL content (e.g., AWS component definitions). Generated at build time via a build script.
- **Database_Mode**: One of three operational modes for the SQLite database: bundled (read from package), persistent (user-configured path survives restarts), or ephemeral (temporary directory, rebuilt each run).

## Requirements

### Requirement 1: SQLite-Backed Storage Engine

**User Story:** As a server operator, I want the OSCAL store to use SQLite instead of in-memory dicts, so that the server can handle tens of thousands of documents without excessive memory consumption.

#### Acceptance Criteria

1. THE OSCAL_Store SHALL persist document metadata (UUID, title, model type, file path, file size in bytes) and raw JSON content in a SQLite database.
2. THE OSCAL_Store SHALL support three Database_Modes: (a) bundled — using a pre-built Bundled_Database shipped with the package, (b) persistent — using a user-configured file path that survives server restarts, (c) ephemeral — using a temporary directory that is rebuilt each run.
3. WHEN no `OSCAL_STORE_DB_PATH` is configured and a Bundled_Database exists in the package, THE OSCAL_Store SHALL copy the Bundled_Database to a temporary location and use it as the initial database, layering any user-provided documents on top.
4. WHEN `OSCAL_STORE_DB_PATH` is configured, THE OSCAL_Store SHALL use that path as a persistent database, creating it if it does not exist and reusing it across restarts.
5. WHEN no `OSCAL_STORE_DB_PATH` is configured and no Bundled_Database exists, THE OSCAL_Store SHALL create an ephemeral database in a temporary directory.
6. WHEN the OSCAL_Store is initialized, THE OSCAL_Store SHALL create all required tables and indexes if they do not already exist.
7. THE OSCAL_Store SHALL store child element metadata (UUID, title/name, element type, parent document UUID) in a separate table with a foreign key to the document table.
8. THE OSCAL_Store SHALL use SQLite indexes on UUID, title, and model type columns to support O(1) or O(log n) lookups.
9. IF a database write operation fails, THEN THE OSCAL_Store SHALL log the error and raise a descriptive exception without corrupting existing data.

### Requirement 2: Multi-Model OSCAL Support

**User Story:** As an AI agent user, I want to query catalogs, profiles, SSPs, assessment plans, assessment results, and POA&Ms in addition to component definitions, so that I can work with the full OSCAL lifecycle.

#### Acceptance Criteria

1. THE OSCAL_Store SHALL accept documents of all types defined in the OSCAL_Model_Type enum (catalog, profile, component-definition, system-security-plan, assessment-plan, assessment-results, plan-of-action-and-milestones, mapping-collection).
2. WHEN a document is ingested, THE OSCAL_Store SHALL detect the OSCAL model type from the root JSON key using the existing `ROOT_KEY_TO_MODEL_TYPE` mapping in `utils.py`.
3. WHEN a document is ingested, THE OSCAL_Store SHALL validate the document using the corresponding `trestle.oscal.*` Pydantic model before storing it.
4. IF a document fails validation, THEN THE OSCAL_Store SHALL skip the document, log a warning with the file path and error details, and continue processing remaining documents.
5. THE OSCAL_Store SHALL index child elements appropriate to each model type: components and capabilities for component-definitions, controls and groups for catalogs, imports and modifications for profiles, control-implementations for SSPs, mappings for mapping-collections, and relevant sub-elements for assessment and POA&M documents.
6. WHEN listing documents, THE OSCAL_Store SHALL support filtering by OSCAL_Model_Type so that users can list only catalogs, only SSPs, or any other single model type.

### Requirement 3: Lazy Loading and Deferred Parsing

**User Story:** As a server operator, I want the store to scan directories quickly at startup and defer full document parsing until query time, so that startup time remains fast even with tens of thousands of files.

#### Acceptance Criteria

1. WHEN the OSCAL_Store scans a directory at startup, THE OSCAL_Store SHALL extract only document metadata (file path, file size, root JSON key for model type detection) without fully parsing each document into a Trestle_Model.
2. WHEN a query requests the full content of a specific document or child element, THE OSCAL_Store SHALL parse the document from its stored raw JSON on demand.
3. THE OSCAL_Store SHALL cache parsed Trestle_Model instances using an LRU eviction policy with a configurable maximum cache size.
4. WHEN a document has been fully indexed (child elements extracted), THE OSCAL_Store SHALL record this in the database so that re-indexing is skipped on subsequent startups unless the file has changed.
5. THE OSCAL_Store SHALL detect file changes by comparing file modification timestamps and file sizes against stored values, and re-index only changed files.

### Requirement 4: Efficient List and Summary Operations

**User Story:** As an AI agent user, I want list operations to return results quickly without serializing every document, so that browsing large collections is responsive.

#### Acceptance Criteria

1. THE OSCAL_Store SHALL compute and store `sizeInBytes` for each document at ingestion time, eliminating per-call serialization.
2. WHEN a list operation is called, THE OSCAL_Store SHALL retrieve summary data (UUID, title, model type, child element count, file size) directly from SQLite without loading full document content.
3. THE OSCAL_Store SHALL support pagination on all list operations using the existing `paginate()` utility with `offset` and `limit` parameters.
4. WHEN listing child elements, THE OSCAL_Store SHALL include the parent document title and UUID in each summary item.

### Requirement 5: Unified Query Interface

**User Story:** As an AI agent user, I want a single query tool that works across all OSCAL model types with consistent parameters, so that I do not need to learn different tools for each model type.

#### Acceptance Criteria

1. THE OSCAL_Store SHALL provide a `query()` method that accepts an `oscal_model_type` parameter to scope queries to a specific OSCAL model type, or query across all types when the parameter is omitted.
2. THE OSCAL_Store SHALL support query types: `by_uuid`, `by_title`, `by_type`, and `all`, consistent with the existing query interface.
3. WHEN `query_type` is `by_uuid`, THE OSCAL_Store SHALL perform a direct index lookup returning results in O(log n) time or better.
4. WHEN `query_type` is `by_title`, THE OSCAL_Store SHALL perform a case-insensitive exact match first, then fall back to text search if no exact match is found.
5. WHEN `query_type` is `all` without a document filter, THE OSCAL_Store SHALL return paginated results rather than loading all documents into memory.
6. IF `query_value` is required but not provided, THEN THE OSCAL_Store SHALL raise a ValueError with a descriptive message.

### Requirement 6: Full-Text Search

**User Story:** As an AI agent user, I want to search across OSCAL documents by keywords in titles, descriptions, and other text fields, so that I can find relevant content without knowing exact UUIDs or titles.

#### Acceptance Criteria

1. THE OSCAL_Store SHALL maintain a SQLite FTS5 virtual table indexing document titles, descriptions, and child element titles and descriptions.
2. WHEN a text search query is submitted, THE OSCAL_Store SHALL return matching documents and child elements ranked by relevance.
3. THE OSCAL_Store SHALL support text search scoped to a specific OSCAL_Model_Type or across all types.
4. THE OSCAL_Store SHALL return text search results in the same Page_Response format used by list operations.

### Requirement 7: Backward-Compatible MCP Tool Interface

**User Story:** As an existing user of the MCP server, I want the existing tool names and parameter signatures to continue working unchanged, so that my workflows are not disrupted by the storage migration.

#### Acceptance Criteria

1. THE MCP server SHALL continue to expose the tools `query_component_definition`, `list_component_definitions`, `list_components`, `list_capabilities`, and `get_capability` with their existing parameter signatures and return formats.
2. WHEN an existing tool is called, THE MCP server SHALL delegate to the new OSCAL_Store and return results in the same format as the current implementation.
3. THE MCP server SHALL expose new tools for querying other OSCAL model types (e.g., `query_catalog`, `list_catalogs`, `query_ssp`, `list_ssps`) following the same parameter and return format conventions as the existing component definition tools.
4. THE OSCAL_Store SHALL support the existing `load_external_component_definition` functionality for loading documents from local zip files and remote URIs.

### Requirement 8: Configuration

**User Story:** As a server operator, I want to configure the store's behavior through environment variables, so that I can tune performance for my deployment size.

#### Acceptance Criteria

1. THE Config class SHALL support an `OSCAL_STORE_DB_PATH` environment variable to specify the SQLite database file path. WHEN set, the database SHALL be persistent across restarts. WHEN not set, the OSCAL_Store SHALL use the Bundled_Database if available, otherwise an ephemeral temporary directory.
2. THE Config class SHALL support an `OSCAL_STORE_CACHE_SIZE` environment variable to configure the LRU cache maximum number of parsed documents, defaulting to 100.
3. THE Config class SHALL support an `OSCAL_DOCUMENTS_DIR` environment variable to specify a general OSCAL documents directory (for non-component-definition models), defaulting to empty (disabled).
4. WHEN the `OSCAL_COMPONENT_DEFINITIONS_DIR` environment variable is set, THE OSCAL_Store SHALL continue to load component definitions from that directory for backward compatibility.

### Requirement 9: Startup and Initialization

**User Story:** As a server operator, I want the store to initialize reliably at startup and handle missing or empty directories gracefully, so that the server starts without errors in any deployment configuration.

#### Acceptance Criteria

1. WHEN the configured documents directory does not exist, THE OSCAL_Store SHALL log an informational message and start with an empty store.
2. WHEN the configured documents directory is empty, THE OSCAL_Store SHALL log an informational message and start with an empty store.
3. THE OSCAL_Store SHALL complete directory scanning (metadata extraction only) and be ready to serve queries before the MCP server begins accepting client connections.
4. IF the SQLite database file cannot be created or opened, THEN THE OSCAL_Store SHALL raise a descriptive RuntimeError during initialization.
5. WHEN the server starts with an existing persistent database and unchanged files, THE OSCAL_Store SHALL skip re-indexing and be ready to serve queries immediately.
6. WHEN the server starts with a Bundled_Database and no `OSCAL_STORE_DB_PATH` configured, THE OSCAL_Store SHALL copy the Bundled_Database to a temporary location, then scan for any additional user-provided documents and layer them on top.
7. WHEN the server starts with a Bundled_Database and `OSCAL_STORE_DB_PATH` is configured to a path that does not yet exist, THE OSCAL_Store SHALL copy the Bundled_Database to that path as the initial persistent database.

### Requirement 10: Pre-Built Bundled Database

**User Story:** As a package maintainer, I want a build script that generates a pre-built SQLite database from bundled OSCAL content, so that end users get instant startup with zero indexing cost for shipped content.

#### Acceptance Criteria

1. THE project SHALL include a build script (e.g., `bin/build_oscal_db.py` or a hatch script `hatch run build-db`) that scans the bundled content directories, fully indexes all documents and child elements, populates the FTS5 table, and writes the resulting SQLite database to a known location within the package (e.g., `src/mcp_server_for_oscal/oscal_store.db`).
2. THE build script SHALL be idempotent: running it multiple times with the same input content SHALL produce a database with identical logical content.
3. THE Bundled_Database SHALL be included in the package distribution (listed in `pyproject.toml` package data).
4. THE Bundled_Database SHALL have its SHA-256 hash recorded in the appropriate `hashes.json` manifest for integrity verification at startup, consistent with the existing integrity verification pattern.
5. IF the Bundled_Database fails integrity verification at startup, THEN THE OSCAL_Store SHALL log a warning and fall back to building an ephemeral database from the bundled JSON/zip files.
