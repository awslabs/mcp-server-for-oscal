# Requirements Document

## Introduction

The `query_component_definition` tool function currently returns all matching components without pagination. Its peer functions (e.g. `query_catalog`) already support `offset`/`limit` parameters and return a `Page_Response` dict. This feature adds the same offset/limit pagination to `query_component_definition`, covering both the OscalStore code path and the legacy `ComponentDefinitionStore` code path, and wrapping capability results in a `Page_Response` envelope for consistency.

## Glossary

- **Query_Tool**: The `query_component_definition` tool function in `query_component_definition.py`.
- **OscalStore_Path**: The code path taken when `_oscal_store is not None`, delegating to `_oscal_store_query_component_definition()`.
- **Legacy_Path**: The code path taken when `_oscal_store is None`, delegating directly to `ComponentDefinitionStore.query()`.
- **Page_Response**: A dictionary with keys `items`, `total`, `offset`, `limit`, `hasMore` — the standard paginated response envelope used by peer tools.
- **Capability_Response**: The response returned when a query matches a Capability (by title or UUID). Currently contains `capability`, `component_count`, `query_type`, `component_definitions_searched`, `filtered_by`.
- **Component_Response**: The response returned when the query falls through to component search. Currently contains `components`, `total_count`, `query_type`, `component_definitions_searched`, `filtered_by`.
- **Paginate_Helper**: The existing `paginate()` function in `utils.py` that slices a list and returns a `Page_Response` envelope.
- **Default_Limit**: The limit value applied when the caller does not supply an explicit `limit`. Set to 10.

## Requirements

### Requirement 1: Add offset/limit parameters to query_component_definition

**User Story:** As an AI assistant, I want to paginate component query results, so that large result sets do not overflow my context window.

#### Acceptance Criteria

1. WHEN `query_component_definition` is called, THE Query_Tool SHALL accept `offset: int = 0` and `limit: int = 10` parameters.
2. WHEN `query_component_definition` is called without `offset` or `limit` parameters, THE Query_Tool SHALL default `offset` to 0 and `limit` to Default_Limit.
3. THE Query_Tool SHALL thread `offset` and `limit` through to both the OscalStore_Path and the Legacy_Path.

### Requirement 2: Paginate component results in the Legacy_Path

**User Story:** As an AI assistant, I want paginated component results from the legacy store path, so that the response shape is consistent with peer tools.

#### Acceptance Criteria

1. WHEN the Legacy_Path returns a Component_Response, THE Query_Tool SHALL apply the Paginate_Helper to the `components` list.
2. THE paginated Component_Response SHALL include `offset`, `limit`, `total`, and `hasMore` metadata alongside the existing `query_type`, `component_definitions_searched`, and `filtered_by` fields.
3. THE `components` key SHALL contain only the paginated slice of components for the current page.
4. THE `total_count` key SHALL reflect the total number of matching components across all pages.

### Requirement 3: Paginate component results in the OscalStore_Path

**User Story:** As an AI assistant, I want paginated component results from the OscalStore path, so that both code paths return consistent paginated responses.

#### Acceptance Criteria

1. WHEN the OscalStore_Path falls back to `_store.query()` for component results, THE Query_Tool SHALL apply the Paginate_Helper to the `components` list in the response.
2. THE paginated response SHALL include `offset`, `limit`, `total`, and `hasMore` metadata alongside the existing response fields.
3. THE `components` key SHALL contain only the paginated slice of components for the current page.
4. THE `total_count` key SHALL reflect the total number of matching components across all pages.

### Requirement 4: Wrap capability results in Page_Response envelope

**User Story:** As an AI assistant, I want capability results wrapped in a consistent Page_Response envelope, so that all responses from `query_component_definition` share a predictable shape.

#### Acceptance Criteria

1. WHEN a Capability matches (by title or UUID), THE Query_Tool SHALL wrap the Capability_Response in a Page_Response-like envelope.
2. THE wrapped Capability_Response SHALL include `offset` set to 0, `limit` set to 1, `total` set to 1, and `hasMore` set to false.
3. THE wrapped Capability_Response SHALL preserve the existing `capability`, `component_count`, `query_type`, `component_definitions_searched`, and `filtered_by` fields.

### Requirement 5: Preserve existing error and edge-case behavior

**User Story:** As a developer, I want pagination to not alter existing error handling or edge-case behavior, so that backward compatibility is maintained for error paths.

#### Acceptance Criteria

1. WHEN `query_type` requires `query_value` and `query_value` is missing, THE Query_Tool SHALL raise a `ValueError` with a descriptive message (unchanged behavior).
2. WHEN no Component Definitions are loaded, THE Query_Tool SHALL raise a `ValueError` with the message "No Component Definitions loaded" (unchanged behavior).
3. WHEN `component_definition_filter` matches no definitions, THE Query_Tool SHALL return a response with `components` as an empty list and `total_count` of 0 (unchanged behavior), augmented with pagination metadata.
4. IF `offset` is negative, THEN THE Paginate_Helper SHALL raise a `ValueError`.
5. IF `limit` is less than 1 or greater than 100, THEN THE Paginate_Helper SHALL raise a `ValueError`.

### Requirement 6: Update docstring and tests

**User Story:** As a developer, I want the docstring and tests updated to reflect the new pagination parameters and response shape, so that the API is well-documented and verified.

#### Acceptance Criteria

1. THE Query_Tool docstring SHALL document the `offset` and `limit` parameters and the paginated response shape.
2. THE existing tests SHALL be updated to account for the new pagination metadata in component responses.
3. THE test suite SHALL include tests verifying default pagination parameters, explicit pagination parameters, and edge cases (empty results, capability wrapping).
