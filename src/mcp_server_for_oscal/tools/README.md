# OSCAL MCP Server Tools

This package contains all tool implementations for the OSCAL MCP server. Each tool is implemented as a Python module with the `@tool` decorator from the `strands` library, making them automatically discoverable by the FastMCP server.

## Available Tools

| Tool | Description |
|------|-------------|
| `list_oscal_models` | List all 8 OSCAL model types with metadata (layer, status, descriptions) |
| `get_oscal_schema` | Retrieve JSON or XSD schema for any OSCAL model |
| `list_oscal_resources` | Browse curated OSCAL community resources, tools, and educational content |
| `validate_oscal_content` | Validate OSCAL JSON content through a 4-level pipeline (well-formedness, JSON Schema, Trestle, oscal-cli) |
| `validate_oscal_file` | Validate an OSCAL JSON file (local path or remote URI) through the same 4-level pipeline |
| `query_component_definition` | Query component definitions to find capabilities and components by UUID, title, or type |
| `list_component_definitions` | List all loaded component definitions with summary metadata |
| `list_components` | List all loaded components with summary metadata |
| `list_capabilities` | List all loaded capabilities with summary metadata |
| `get_capability` | Retrieve a single capability by UUID with full OSCAL representation |
| `query_oscal_documentation` | RAG-based documentation query (requires AWS Bedrock Knowledge Base; conditionally registered) |
| `about` | Server metadata including version and supported OSCAL version |
| **Catalog tools** | |
| `query_catalog` | Query OSCAL Catalog documents by UUID, title, type, or list all (paginated) |
| `list_catalogs` | List loaded OSCAL Catalogs with summary metadata (UUID, title, child count, size) |
| `list_catalog_controls` | List controls within OSCAL Catalog documents, optionally scoped by parent catalog UUID |
| `list_catalog_groups` | List control groups (families) within OSCAL Catalog documents, optionally scoped by parent catalog UUID |
| **SSP tools** | |
| `query_ssp` | Query OSCAL System Security Plan documents by UUID, title, type, or list all (paginated) |
| `list_ssps` | List loaded OSCAL System Security Plans with summary metadata |
| `list_ssp_control_implementations` | List control-implementation elements within OSCAL SSP documents |
| `list_ssp_system_components` | List system-component elements (servers, services, software) within OSCAL SSP documents |
| **Profile tools** | |
| `query_profile` | Query OSCAL Profile documents by UUID, title, type, or list all (paginated) |
| `list_profiles` | List loaded OSCAL Profiles with summary metadata |
| `list_profile_imports` | List import elements (catalog/profile references) within OSCAL Profile documents |
| `list_profile_modify` | List modify elements (control customisations) within OSCAL Profile documents |
| **Assessment Plan tools** | |
| `query_assessment_plan` | Query OSCAL Assessment Plan documents by UUID, title, type, or list all (paginated) |
| `list_assessment_plans` | List loaded OSCAL Assessment Plans with summary metadata |
| `list_assessment_plan_tasks` | List task elements within OSCAL Assessment Plan documents |
| `list_assessment_plan_activities` | List activity elements (assessment methods/procedures) within OSCAL Assessment Plan documents |
| **Assessment Results tools** | |
| `query_assessment_results` | Query OSCAL Assessment Results documents by UUID, title, type, or list all (paginated) |
| `list_assessment_results` | List loaded OSCAL Assessment Results with summary metadata |
| `list_assessment_results_results` | List result elements (assessment outcomes) within OSCAL Assessment Results documents |
| `list_assessment_results_findings` | List finding elements (control implementation determinations) within OSCAL Assessment Results documents |
| **POA&M tools** | |
| `query_poam` | Query OSCAL Plan of Action and Milestones (POA&M) documents by UUID, title, type, or list all (paginated) |
| `list_poams` | List loaded OSCAL Plans of Action and Milestones with summary metadata |
| `list_poam_items` | List POA&M item elements (security issues and remediation plans) within OSCAL POA&M documents |
| **Mapping Collection tools** | |
| `query_mapping_collection` | Query OSCAL Mapping Collection documents by UUID, title, type, or list all (paginated) |
| `list_mapping_collections` | List loaded OSCAL Mapping Collections with summary metadata |
| `list_mapping_collection_mappings` | List mapping elements (cross-framework control relationships) within OSCAL Mapping Collection documents |
| **Cross-cutting tools** | |
| `text_search_oscal` | Full-text search across all loaded OSCAL documents and child elements using SQLite FTS5, ranked by relevance |
| `get_child_element` | Retrieve a single child element by its identifier (UUID or token ID), with optional parent document scoping |

### 1. List OSCAL Models
**Tool**: `list_oscal_models`

Returns metadata about all available OSCAL model types including:
- Model descriptions and purposes
- OSCAL layer (Control, Implementation, Assessment)
- Formal and short names
- Release status (all currently GA)

Covers all 8 OSCAL models: Catalog, Profile, Mapping, Component Definition, System Security Plan, Assessment Plan, Assessment Results, and Plan of Action & Milestones.

**Parameters**: None

**Returns**: Dictionary mapping model names to their metadata

---

### 2. Get OSCAL Schema
**Tool**: `get_oscal_schema`

Retrieves JSON or XSD schemas for OSCAL models. OSCAL schemas are self-documenting, making this the primary tool for understanding model structure, properties, and requirements.

**Parameters**:
- `model_name` (str, default="complete"): Name of the OSCAL model (use `list_oscal_models` to get valid names)
- `schema_type` (str, default="json"): Either "json" or "xsd"

**Returns**: Schema as JSON string

**Note**: Returns the complete schema (all models) by default, which is large. Specify a model name for focused results.

---

### 3. List OSCAL Community Resources
**Tool**: `list_oscal_resources`

Provides access to a curated collection of OSCAL community resources from [Awesome OSCAL](https://github.com/oscal-club/awesome-oscal), including:
- OSCAL-compatible tools and software implementations
- Educational content, tutorials, and documentation
- Example OSCAL documents and templates
- Presentations, articles, and research papers
- Government and industry adoption examples
- Libraries and SDKs for OSCAL development
- Validation tools and utilities

**Parameters**: None (context injected automatically)

**Returns**: Complete markdown content with categorized resources

---

### 4. Query Component Definitions
**Tool**: `query_component_definition`

Queries OSCAL Component Definition documents to extract information about components (services, software, regions, etc.) and their control implementations.

**Parameters**:
- `component_definition_filter` (str, optional): UUID or title to limit search to specific Component Definition
- `query_type` (str, default="all"): One of "all", "by_uuid", "by_title", "by_type"
- `query_value` (str, optional): Value to search for (required for by_uuid, by_title, by_type queries)
- `return_format` (str, default="raw"): Format of returned data (currently only "raw" supported)

**Returns**: Dictionary with:
- `components`: List of matching components in OSCAL JSON format
- `total_count`: Number of components found
- `query_type`: Type of query executed
- `component_definitions_searched`: Number of Component Definitions searched
- `filtered_by`: Filter applied (if any)

**Features**:
- Loads Component Definitions from local directory (including zip files)
- Supports remote URI loading when `OSCAL_ALLOW_REMOTE_URIS=true`
- Maintains global indexes for fast lookups by UUID, title, and type
- Can search by component properties

---

### 5. List Component Definitions
**Tool**: `list_component_definitions`

Returns a summary list of all loaded Component Definitions.

**Parameters**: None (context injected automatically)

**Returns**: List of dictionaries containing:
- `uuid`: Component Definition UUID
- `title`: Component Definition title
- `componentCount`: Number of components defined
- `importedComponentDefinitionsCount`: Number of imported Component Definitions

---

### 6. List Components
**Tool**: `list_components`

Returns a summary list of all loaded Components across all Component Definitions.

**Parameters**: None (context injected automatically)

**Returns**: List of dictionaries containing:
- `uuid`: Component UUID
- `title`: Component title
- `parentComponentDefinitionTitle`: Title of parent Component Definition
- `parentComponentDefinitionUuid`: UUID of parent Component Definition

---

### 7. Query OSCAL Documentation
**Tool**: `query_oscal_documentation`

Queries authoritative OSCAL documentation using Amazon Bedrock Knowledge Base. Use this for questions about OSCAL concepts, best practices, and implementation guidance that cannot be answered by analyzing schemas alone.

**Parameters**:
- `query` (str): Question or search query about OSCAL

**Returns**: Results from knowledge base as Bedrock RetrieveResponseTypeDef object

**Requirements**:
- Requires `OSCAL_KB_ID` environment variable to be set
- Requires AWS credentials configured (via profile or environment)
- Optional: Set `OSCAL_AWS_PROFILE` to use specific AWS profile

**Note**: This tool is only registered when a Knowledge Base ID is configured. A local fallback implementation is planned for future releases.

---

### 8. Validate OSCAL Content
**Tool**: `validate_oscal_content`

Validates OSCAL JSON content through a multi-level pipeline:

| Level | What it checks | Implementation |
|-------|---------------|----------------|
| 1. Well-formedness | Valid JSON, is a dict | `json.loads()` |
| 2. JSON Schema | Conforms to NIST OSCAL schema | `jsonschema.Draft7Validator` with bundled schemas |
| 3. Trestle | Semantic checks via Pydantic models | `trestle.oscal.*` model instantiation |
| 4. oscal-cli | Full NIST validation | `subprocess.run()` if on PATH |

**Parameters**:
- `content` (str): OSCAL JSON content as a string
- `model_type` (str, optional): OSCAL model type (e.g. "catalog", "profile"). Auto-detected from root key if omitted.

**Returns**: Dictionary with:
- `valid`: Overall validity (true only if all non-skipped levels pass)
- `model_type`: Detected or provided model type
- `levels`: Per-level results with `valid`, `errors`, `warnings`, `skipped`, and `skip_reason`

**Key behaviors**:
- If Level 1 fails, Levels 2-4 are skipped
- If `oscal-cli` is not installed, Level 4 is gracefully skipped
- `mapping-collection` skips Level 3 (trestle does not support it)
- Errors capped at 20 per level

---

### 9. Validate OSCAL File
**Tool**: `validate_oscal_file`

Validates an OSCAL JSON file (local path or remote URI) through the same multi-level pipeline as `validate_oscal_content`.

**Parameters**:
- `file_uri` (str): Local file path or remote URI pointing to an OSCAL JSON file. Remote URIs require `OSCAL_ALLOW_REMOTE_URIS=true`.
- `model_type` (str, optional): OSCAL model type (e.g. "catalog", "profile"). Auto-detected from root key if omitted.

**Returns**: Same structured validation results as `validate_oscal_content`

**Key behaviors**:
- Supports local file paths and `file://` URIs
- Remote URIs (http/https) are blocked by default; enable with `OSCAL_ALLOW_REMOTE_URIS=true`
- Remote requests respect `OSCAL_REQUEST_TIMEOUT` (default 30s)
- Delegates to `validate_oscal_content` after reading the file

---

### 10. List Capabilities
**Tool**: `list_capabilities`

Returns a summary list of all capabilities across all loaded Component Definitions.

**Parameters**: None (context injected automatically)

**Returns**: List of dictionaries containing:
- `uuid`: Capability UUID
- `name`: Capability name
- `description`: Capability description
- `parentComponentDefinitionTitle`: Title of parent Component Definition
- `parentComponentDefinitionUuid`: UUID of parent Component Definition

---

### 11. Get Capability
**Tool**: `get_capability`

Retrieves a single capability by UUID with its full OSCAL representation.

**Parameters**:
- `uuid` (str): UUID of the capability. Use `list_capabilities` to discover UUIDs.

**Returns**: Dictionary with the full OSCAL capability object, or None if not found

---

### 12. About
**Tool**: `about`

Returns metadata about the MCP server itself.

**Parameters**: None

**Returns**: Dictionary containing:
- `version`: Server version
- `keywords`: Server keywords
- `oscal-version`: Supported OSCAL version (currently 1.2.1)

---

## Query & List Tools (OSCAL Store)

The OSCAL Store provides a SQLite-backed index of all loaded OSCAL documents and their child elements. Every OSCAL model type has a pair of tools:

- **`query_<model>`** — retrieve full document content, with filtering by UUID, title, or type
- **`list_<model>`** — return summary metadata (UUID, title, model type, child count, size)

Child element tools (`list_<model>_<element>`) list elements within a specific parent document type. Two cross-cutting tools — `text_search_oscal` and `get_child_element` — operate across all model types.

### Common Parameters for `query_*` Tools

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `query_type` | str | `"all"` | One of `"all"`, `"by_uuid"`, `"by_title"`, `"by_type"` |
| `query_value` | str | `None` | Value to search for (required for `by_uuid`, `by_title`, `by_type`) |
| `offset` | int | `0` | Zero-based pagination offset |
| `limit` | int | `10` | Maximum items to return, 1–100 |

### Common Parameters for `list_*` Tools

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `offset` | int | `0` | Zero-based pagination offset |
| `limit` | int | `10` | Maximum items to return, 1–100 |

### Common Return Format

All `query_*` and `list_*` tools return a paginated response dict:

| Key | Type | Description |
|-----|------|-------------|
| `items` | list | Page of result objects |
| `total` | int | Total number of matching items |
| `offset` | int | Current pagination offset |
| `limit` | int | Requested page size |
| `hasMore` | bool | Whether additional pages exist beyond the current page |

### Child Element List Tools

Tools like `list_catalog_controls`, `list_ssp_system_components`, `list_poam_items`, etc. list child elements within a specific parent document type. In addition to `offset` and `limit`, they accept:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `parent_doc_uuid` | str | `None` | UUID of the parent document to scope the listing. When omitted, child elements across all documents of that type are returned. |

Each returned item contains: `id`, `title`, `element_type`, `description`, `parentDocumentTitle`, `parentDocumentUuid`.

### `text_search_oscal`

Full-text search across all loaded OSCAL documents and child elements using SQLite FTS5. Results are ranked by relevance.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `query_text` | str | _(required)_ | The search text |
| `oscal_model_type` | str | `None` | Filter results to a specific OSCAL model type (e.g. `"catalog"`, `"system-security-plan"`). When omitted, all model types are searched. |
| `offset` | int | `0` | Zero-based pagination offset |
| `limit` | int | `10` | Maximum items to return, 1–100 |

Returns the standard paginated response. Each item contains: `entity_type`, `entity_id`, `title`, `description`, `model_type`.

### `get_child_element`

Retrieve a single child element by its identifier (UUID or token ID), with optional parent document scoping.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `element_id` | str | _(required)_ | UUID or token ID of the child element (e.g. `"ac-1"` for a catalog control, or a UUID for tasks, findings, etc.) |
| `parent_doc_uuid` | str | `None` | UUID of the parent document to narrow the search. Recommended for token-based IDs that may not be globally unique. |

Returns a dict with keys: `id`, `title`, `element_type`, `description`, `parentDocumentTitle`, `parentDocumentUuid`, `raw_json` — or `None` if not found. If `element_id` is ambiguous across documents and `parent_doc_uuid` is omitted, returns an error dict with `error: "ambiguous_element_id"` and a list of matching parent document UUIDs.

---

## Implementation Details

### Tool Registration
Tools are registered in `main.py` using the FastMCP framework. Tool functions are collected by `get_tool_list()` in `tools/__init__.py`, which gathers the original tools, query/list tools from `query_oscal_models.py`, and `query_oscal_documentation` (always included). The `about` tool is registered separately in `main.py` as an MCP-server-only tool.

### Dependencies
- **strands**: Provides the `@tool` decorator for tool definitions
- **FastMCP**: MCP server framework
- **compliance-trestle**: OSCAL Pydantic models and utilities
- **OscalStore**: SQLite-backed content indexing and full-text search (`oscal_store.py`)
- **boto3**: AWS SDK (for documentation queries)
- **requests**: HTTP client (for remote Component Definition loading)
- **jsonschema**: JSON Schema validation (transitive dependency)

### Utilities
The `utils.py` module provides shared functionality:
- `OSCALModelType`: Enum of OSCAL model types
- `schema_names`: Mapping of model names to schema file names
- `ROOT_KEY_TO_MODEL_TYPE`: Reverse mapping from JSON root keys to model types
- `load_oscal_json_schema()`: Load bundled OSCAL JSON schemas
- `try_notify_client_error()`: Helper for error notifications
- `verify_package_integrity()`: Package integrity verification

The `query_oscal_models.py` module provides the query/list tool implementations for all OSCAL model types, including per-model `query_*`/`list_*` pairs, child element list tools, `text_search_oscal`, and `get_child_element`.

### Configuration
Tools respect configuration from `config.py`, including:
- `component_definitions_dir`: Directory for Component Definitions
- `allow_remote_uris`: Enable/disable remote URI loading
- `request_timeout`: Timeout for remote requests
- `knowledge_base_id`: Bedrock Knowledge Base ID
- `aws_profile`: AWS profile for Bedrock queries
- `log_level`: Logging level
- `oscal_documents_dir`: Directory containing user OSCAL JSON files
- `oscal_store_db_path`: Path to persistent SQLite database
- `oscal_store_cache_size`: Maximum parsed documents in LRU cache
