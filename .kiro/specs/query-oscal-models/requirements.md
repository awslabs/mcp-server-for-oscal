# Requirements Document

## Introduction

This feature adds MCP tools to `query_oscal_models.py` that expose queries for the major child elements within each OSCAL model type. Currently the module provides document-level query/list tool pairs for each model type plus a cross-model `text_search_oscal` tool, but there is no way for AI agents to drill into the child elements of those documents (e.g. list all controls in a catalog, list all findings in assessment results, list all POA&M items).

The `OscalStore` already provides a `list_child_elements()` method that supports filtering by `parent_doc_uuid` and `element_type` with pagination. The `_extract_child_elements()` method already extracts the relevant child element types per model. This feature wires new `@tool()` functions to that existing store capability.

Component Definition child elements (components, capabilities) are excluded because they are already covered by `query_component_definition.py`.

## Glossary

- **Child_Element**: A major structural element nested inside an OSCAL document (e.g. a control inside a catalog, a finding inside assessment results). Stored in the `child_elements` SQLite table by `OscalStore`.
- **Element_ID**: The primary identifier of a child element. OSCAL uses two identifier schemes: (1) UUIDs (`UUIDDatatype`) for most elements — globally unique, machine-oriented; (2) Token IDs (`TokenDatatype`) for catalog controls and groups — human-readable (e.g. `ac-1`, `ac`), unique only within the containing document. The `child_elements.uuid` column stores whichever identifier the element uses.
- **Page_Response**: The standard paginated response envelope used by all tools: `{items, total, offset, limit, hasMore}`.
- **OscalStore**: The SQLite-backed singleton that indexes OSCAL documents and their child elements, providing `list_child_elements()`, `query()`, `list_documents()`, and `text_search()` methods.
- **Tool_Function**: A Python function decorated with `@tool()` from `strands`, registered in `get_tool_list()` and added to the MCP server via `mcp.add_tool()`.
- **Catalog**: An OSCAL model containing security controls and groups. Controls and groups use `id` (TokenDatatype) — human-readable identifiers like `ac-1` that are unique only within the containing catalog document.
- **SSP**: System Security Plan — an OSCAL model documenting how a system implements security controls. The `control-implementation` is a singleton (no identifier); `system-component` elements use UUIDs.
- **Profile**: An OSCAL model that selects and customizes controls from one or more catalogs. Imports are positional (index-based, no native identifier); modify is a singleton.
- **Assessment_Plan**: An OSCAL model defining how security controls will be assessed. Tasks and activities use UUIDs.
- **Assessment_Results**: An OSCAL model documenting the outcomes of control assessments, containing results and findings. Results and findings use UUIDs.
- **POAM**: Plan of Action and Milestones — an OSCAL model documenting remediation plans for identified security issues. POA&M items have an optional UUID; title and description are required.
- **Mapping_Collection**: An OSCAL model describing how one set of security controls relates to another. Mappings use UUIDs.

## Requirements

### Requirement 1: Catalog Child Element Tools

**User Story:** As an AI agent, I want to list controls and groups within a catalog document, so that I can drill into catalog structure without retrieving the full document.

#### Acceptance Criteria

1. WHEN a user calls `list_catalog_controls`, THE Tool_Function SHALL delegate to `OscalStore.list_child_elements()` with `element_type="control"` and return a Page_Response containing the matching child elements.
2. WHEN a user provides a `parent_doc_uuid` parameter to `list_catalog_controls`, THE Tool_Function SHALL pass that value to `OscalStore.list_child_elements()` to scope results to a single catalog document.
3. WHEN a user calls `list_catalog_groups`, THE Tool_Function SHALL delegate to `OscalStore.list_child_elements()` with `element_type="group"` and return a Page_Response containing the matching child elements.
4. WHEN a user provides a `parent_doc_uuid` parameter to `list_catalog_groups`, THE Tool_Function SHALL pass that value to `OscalStore.list_child_elements()` to scope results to a single catalog document.
5. WHEN no child elements of the requested type exist, THE Tool_Function SHALL return a Page_Response with `total` equal to 0 and `items` as an empty list.

### Requirement 2: SSP Child Element Tools

**User Story:** As an AI agent, I want to list control-implementation and system-component elements within an SSP document, so that I can inspect SSP internals.

#### Acceptance Criteria

1. WHEN a user calls `list_ssp_control_implementations`, THE Tool_Function SHALL delegate to `OscalStore.list_child_elements()` with `element_type="control-implementation"` and return a Page_Response.
2. WHEN a user calls `list_ssp_system_components`, THE Tool_Function SHALL delegate to `OscalStore.list_child_elements()` with `element_type="system-component"` and return a Page_Response.
3. WHEN a user provides a `parent_doc_uuid` parameter, THE Tool_Function SHALL pass that value to scope results to a single SSP document.
4. WHEN no child elements of the requested type exist, THE Tool_Function SHALL return a Page_Response with `total` equal to 0 and `items` as an empty list.

### Requirement 3: Profile Child Element Tools

**User Story:** As an AI agent, I want to list imports and modify elements within a profile document, so that I can understand which catalogs a profile references and what customizations it applies.

#### Acceptance Criteria

1. WHEN a user calls `list_profile_imports`, THE Tool_Function SHALL delegate to `OscalStore.list_child_elements()` with `element_type="import"` and return a Page_Response.
2. WHEN a user calls `list_profile_modify`, THE Tool_Function SHALL delegate to `OscalStore.list_child_elements()` with `element_type="modify"` and return a Page_Response.
3. WHEN a user provides a `parent_doc_uuid` parameter, THE Tool_Function SHALL pass that value to scope results to a single profile document.
4. WHEN no child elements of the requested type exist, THE Tool_Function SHALL return a Page_Response with `total` equal to 0 and `items` as an empty list.

### Requirement 4: Assessment Plan Child Element Tools

**User Story:** As an AI agent, I want to list tasks and activities within an assessment plan document, so that I can understand the planned assessment approach.

#### Acceptance Criteria

1. WHEN a user calls `list_assessment_plan_tasks`, THE Tool_Function SHALL delegate to `OscalStore.list_child_elements()` with `element_type="task"` and return a Page_Response.
2. WHEN a user calls `list_assessment_plan_activities`, THE Tool_Function SHALL delegate to `OscalStore.list_child_elements()` with `element_type="activity"` and return a Page_Response.
3. WHEN a user provides a `parent_doc_uuid` parameter, THE Tool_Function SHALL pass that value to scope results to a single assessment plan document.
4. WHEN no child elements of the requested type exist, THE Tool_Function SHALL return a Page_Response with `total` equal to 0 and `items` as an empty list.

### Requirement 5: Assessment Results Child Element Tools

**User Story:** As an AI agent, I want to list results and findings within an assessment results document, so that I can review assessment outcomes.

#### Acceptance Criteria

1. WHEN a user calls `list_assessment_results_results`, THE Tool_Function SHALL delegate to `OscalStore.list_child_elements()` with `element_type="result"` and return a Page_Response.
2. WHEN a user calls `list_assessment_results_findings`, THE Tool_Function SHALL delegate to `OscalStore.list_child_elements()` with `element_type="finding"` and return a Page_Response.
3. WHEN a user provides a `parent_doc_uuid` parameter, THE Tool_Function SHALL pass that value to scope results to a single assessment results document.
4. WHEN no child elements of the requested type exist, THE Tool_Function SHALL return a Page_Response with `total` equal to 0 and `items` as an empty list.

### Requirement 6: POA&M Child Element Tools

**User Story:** As an AI agent, I want to list POA&M items within a POA&M document, so that I can review remediation plans.

#### Acceptance Criteria

1. WHEN a user calls `list_poam_items`, THE Tool_Function SHALL delegate to `OscalStore.list_child_elements()` with `element_type="poam-item"` and return a Page_Response.
2. WHEN a user provides a `parent_doc_uuid` parameter, THE Tool_Function SHALL pass that value to scope results to a single POA&M document.
3. WHEN no child elements of the requested type exist, THE Tool_Function SHALL return a Page_Response with `total` equal to 0 and `items` as an empty list.

### Requirement 7: Mapping Collection Child Element Tools

**User Story:** As an AI agent, I want to list mappings within a mapping collection document, so that I can understand control relationships.

#### Acceptance Criteria

1. WHEN a user calls `list_mapping_collection_mappings`, THE Tool_Function SHALL delegate to `OscalStore.list_child_elements()` with `element_type="mapping"` and return a Page_Response.
2. WHEN a user provides a `parent_doc_uuid` parameter, THE Tool_Function SHALL pass that value to scope results to a single mapping collection document.
3. WHEN no child elements of the requested type exist, THE Tool_Function SHALL return a Page_Response with `total` equal to 0 and `items` as an empty list.

### Requirement 8: Tool Registration

**User Story:** As a server operator, I want all new child element tools to be registered in the MCP server, so that AI agents can discover and invoke them.

#### Acceptance Criteria

1. THE `get_tool_list()` function in `__init__.py` SHALL include all new child element Tool_Functions (both list and get tools) in the returned list.
2. WHEN the MCP server starts, THE server SHALL register all new child element Tool_Functions via `mcp.add_tool()` so they appear in the tool catalog.

### Requirement 9: Consistent Tool Interface

**User Story:** As an AI agent, I want all child element tools to follow the same interface conventions as existing tools, so that I can use them predictably.

#### Acceptance Criteria

1. THE Tool_Function for each child element tool SHALL accept `ctx: Context | None = None` as the first parameter.
2. THE Tool_Function for each child element tool SHALL accept `parent_doc_uuid: str | None = None` as an optional filter parameter.
3. THE Tool_Function for each child element tool SHALL accept `offset: int = 0` and `limit: int = 10` pagination parameters.
4. THE Tool_Function for each child element tool SHALL return a Page_Response dict with keys: `items`, `total`, `offset`, `limit`, `hasMore`.
5. THE Tool_Function for each child element tool SHALL include a docstring describing the element type, accepted parameters, and return format.
6. THE Tool_Function for each child element tool SHALL use the `_get_store()` helper to obtain the OscalStore singleton.

### Requirement 10: Child Element Item Format

**User Story:** As an AI agent, I want each child element item to include identifying metadata and parent context, so that I can correlate elements back to their source documents.

#### Acceptance Criteria

1. THE Page_Response items returned by each list child element tool SHALL include the keys: `id`, `title`, `element_type`, `description`, `parentDocumentTitle`, `parentDocumentUuid`.
2. THE `id` field SHALL contain the element's native OSCAL identifier — a UUID for elements that use `UUIDDatatype`, or a human-readable token (e.g. `ac-1`) for elements that use `TokenDatatype` (catalog controls and groups).
3. WHEN a child element has no description, THE Tool_Function SHALL return `null` for the `description` field rather than omitting the key.
4. THE `parentDocumentUuid` field SHALL always be present so that callers can disambiguate token-based IDs that are only unique within their containing document.

### Requirement 11: Get Child Element by ID

**User Story:** As an AI agent, I want to retrieve a single child element's full content by its identifier, so that I can inspect the complete OSCAL structure of a specific control, finding, task, or other element without fetching the entire parent document.

#### Acceptance Criteria

1. WHEN a user calls `get_child_element`, THE Tool_Function SHALL accept an `element_id: str` parameter (required) and a `parent_doc_uuid: str | None = None` parameter (optional).
2. WHEN `parent_doc_uuid` is provided, THE Tool_Function SHALL query the `child_elements` table using the composite key `(uuid, parent_doc_id)` to locate the element.
3. WHEN `parent_doc_uuid` is omitted and exactly one child element matches the given `element_id` across all documents, THE Tool_Function SHALL return that element.
4. WHEN `parent_doc_uuid` is omitted and multiple child elements match the given `element_id` across different documents, THE Tool_Function SHALL return an error indicating ambiguity and listing the matching parent document UUIDs so the caller can disambiguate.
5. THE returned dict SHALL include the keys: `id`, `title`, `element_type`, `description`, `parentDocumentTitle`, `parentDocumentUuid`, and `raw_json` containing the full serialized OSCAL element.
6. WHEN no child element matches the given `element_id` (and optional `parent_doc_uuid`), THE Tool_Function SHALL return `null`.
