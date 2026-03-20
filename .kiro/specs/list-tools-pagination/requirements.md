# Requirements Document

## Introduction

The `list_component_definitions`, `list_components`, and `list_capabilities` MCP tools in the `query_component_definition.py` module currently return all results at once. When many OSCAL Component Definitions, Components, or Capabilities are loaded, the full result set can overflow an AI assistant's context window. This feature adds offset/limit pagination to these three tools so callers can request results in manageable pages while preserving backward compatibility for callers that omit pagination parameters.

## Glossary

- **Pagination_Engine**: The internal pagination logic within `ComponentDefinitionStore` that slices a full result list into pages based on `offset` and `limit` parameters.
- **List_Tool**: Any of the three MCP tool wrapper functions (`list_component_definitions`, `list_components`, `list_capabilities`) that delegate to the `ComponentDefinitionStore` singleton.
- **Page_Response**: A dictionary returned by a paginated List_Tool containing the result slice and pagination metadata (`total`, `offset`, `limit`, `hasMore`).
- **Store**: The `ComponentDefinitionStore` singleton instance that holds all indexed OSCAL data in memory.
- **Offset**: A zero-based integer indicating how many items to skip from the beginning of the full result list.
- **Limit**: A positive integer indicating the maximum number of items to return in a single page.
- **Default_Limit**: The limit value applied when the caller does not supply an explicit `limit`. Set to 10.

## Requirements

### Requirement 1: Paginated list_component_definitions

**User Story:** As an AI assistant, I want to request a page of Component Definition summaries, so that I can avoid overflowing my context window when many definitions are loaded.

#### Acceptance Criteria

1. WHEN `list_component_definitions` is called with `offset` and `limit` parameters, THE Pagination_Engine SHALL return at most `limit` items starting from position `offset` in the full result list.
2. WHEN `list_component_definitions` is called without `offset` or `limit` parameters, THE List_Tool SHALL default `offset` to 0 and `limit` to Default_Limit.
3. THE Page_Response SHALL include `total` (total number of Component Definitions), `offset` (the offset used), `limit` (the limit used), and `hasMore` (boolean indicating whether additional items exist beyond the current page).
4. WHEN `offset` is greater than or equal to the total number of Component Definitions, THE Pagination_Engine SHALL return an empty `items` list with `hasMore` set to false.
5. IF `offset` is negative, THEN THE Pagination_Engine SHALL raise a `ValueError` with a descriptive message.
6. IF `limit` is less than 1 or greater than 100, THEN THE Pagination_Engine SHALL raise a `ValueError` with a descriptive message.

### Requirement 2: Paginated list_components

**User Story:** As an AI assistant, I want to request a page of Component summaries, so that I can avoid overflowing my context window when many components are loaded.

#### Acceptance Criteria

1. WHEN `list_components` is called with `offset` and `limit` parameters, THE Pagination_Engine SHALL return at most `limit` items starting from position `offset` in the full result list.
2. WHEN `list_components` is called without `offset` or `limit` parameters, THE List_Tool SHALL default `offset` to 0 and `limit` to Default_Limit.
3. THE Page_Response SHALL include `total`, `offset`, `limit`, and `hasMore` with the same semantics as Requirement 1.
4. WHEN `offset` is greater than or equal to the total number of Components, THE Pagination_Engine SHALL return an empty `items` list with `hasMore` set to false.
5. IF `offset` is negative, THEN THE Pagination_Engine SHALL raise a `ValueError` with a descriptive message.
6. IF `limit` is less than 1 or greater than 100, THEN THE Pagination_Engine SHALL raise a `ValueError` with a descriptive message.

### Requirement 3: Paginated list_capabilities

**User Story:** As an AI assistant, I want to request a page of Capability summaries, so that I can avoid overflowing my context window when many capabilities are loaded.

#### Acceptance Criteria

1. WHEN `list_capabilities` is called with `offset` and `limit` parameters, THE Pagination_Engine SHALL return at most `limit` items starting from position `offset` in the full result list.
2. WHEN `list_capabilities` is called without `offset` or `limit` parameters, THE List_Tool SHALL default `offset` to 0 and `limit` to Default_Limit.
3. THE Page_Response SHALL include `total`, `offset`, `limit`, and `hasMore` with the same semantics as Requirement 1.
4. WHEN `offset` is greater than or equal to the total number of Capabilities, THE Pagination_Engine SHALL return an empty `items` list with `hasMore` set to false.
5. IF `offset` is negative, THEN THE Pagination_Engine SHALL raise a `ValueError` with a descriptive message.
6. IF `limit` is less than 1 or greater than 100, THEN THE Pagination_Engine SHALL raise a `ValueError` with a descriptive message.
7. WHEN no Capabilities are loaded, THE List_Tool SHALL return a Page_Response with an empty `items` list, `total` of 0, and `hasMore` set to false (no error raised, consistent with current behavior).

### Requirement 4: Shared pagination logic

**User Story:** As a developer, I want pagination logic centralized in a single reusable helper available to all tools in the project, so that any tool can paginate results consistently without duplicating logic.

#### Acceptance Criteria

1. THE Pagination_Engine SHALL be implemented as a standalone `paginate` function in `src/mcp_server_for_oscal/tools/utils.py`, reusable by any MCP tool in the project.
2. THE Pagination_Engine SHALL accept a list of items, an `offset`, and a `limit`, and SHALL return a Page_Response dictionary.
3. THE Pagination_Engine SHALL validate inputs: raise `ValueError` if `offset` is negative, or if `limit` is less than 1 or greater than 100.
4. FOR ALL valid inputs, slicing then concatenating all pages SHALL produce the same items in the same order as the original unsliced list (round-trip property).
5. FOR ALL valid `offset` and `limit` combinations, the number of items returned SHALL be less than or equal to `limit`.
6. FOR ALL valid `offset` and `limit` combinations, `hasMore` SHALL be true if and only if `offset + limit < total`.
7. THE implementation SHALL NOT depend on external pagination utilities (neither `mcp` SDK nor `strands-agents` provide a reusable offset/limit helper; the `mcp` SDK's pagination is cursor-based at the protocol layer, and Strands' `PaginatedList` is a return-type wrapper, not a slicing engine).

### Requirement 5: Page_Response structure

**User Story:** As an AI assistant, I want a consistent, predictable response shape from paginated list tools, so that I can reliably parse results and decide whether to fetch more pages.

#### Acceptance Criteria

1. THE Page_Response SHALL contain exactly these top-level keys: `items`, `total`, `offset`, `limit`, `hasMore`.
2. THE `items` key SHALL contain the list of summary dictionaries for the current page (same shape as the items returned by the current non-paginated tools).
3. THE `total` key SHALL contain the total count of all available items across all pages.
4. THE `hasMore` key SHALL be a boolean value.
5. THE `offset` and `limit` keys SHALL reflect the actual values used for the query (including defaults).
