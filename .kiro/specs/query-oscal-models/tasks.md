# Implementation Plan: Query OSCAL Models — Child Element Tools

## Overview

Add 13 new `@tool()` functions to `query_oscal_models.py` (12 list tools + 1 get tool), a new `OscalStore.get_child_element()` method, rename the `uuid` key to `id` in `list_child_elements()` response items, and register all tools in `__init__.py`.

## Tasks

- [x] 1. Update OscalStore and add get_child_element method
  - [x] 1.1 Rename `uuid` key to `id` in `OscalStore.list_child_elements()` response items
    - In `oscal_store.py`, change the item dict key from `"uuid"` to `"id"` in the `list_child_elements()` method where items are built from rows
    - Update the existing tests that assert on the `uuid` key to use `id` instead
    - _Requirements: 10.1, 10.2_

  - [x] 1.2 Add `OscalStore.get_child_element()` method
    - Add a new method `get_child_element(element_id, parent_doc_uuid=None)` to `OscalStore`
    - When `parent_doc_uuid` is provided, query using composite key `(uuid, parent_doc_id)` via JOIN on documents
    - When `parent_doc_uuid` is omitted, query by `uuid` alone — return the element if exactly one match, return ambiguity error dict if multiple matches
    - Ensure lazy indexing is triggered (same pattern as `list_child_elements`)
    - Return full element dict with keys: `id`, `title`, `element_type`, `description`, `parentDocumentTitle`, `parentDocumentUuid`, `raw_json`
    - Return `None` if no match found
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6_

  - [x] 1.3 Write unit tests for `get_child_element()` store method
    - Test get by UUID with parent_doc_uuid provided
    - Test get by token ID (e.g. `ac-1`) with parent_doc_uuid
    - Test get by token ID without parent — unique match returns element
    - Test get by token ID without parent — ambiguous match returns error dict with matching parent UUIDs
    - Test get with nonexistent element_id returns None
    - Test get with empty element_id returns None
    - _Requirements: 11.2, 11.3, 11.4, 11.5, 11.6_

- [x] 2. Implement the 12 list child element tool functions
  - [x] 2.1 Add catalog child element tools to `query_oscal_models.py`
    - Implement `list_catalog_controls` with `element_type="control"`
    - Implement `list_catalog_groups` with `element_type="group"`
    - Each tool: `@tool()` decorator, standard signature `(ctx, parent_doc_uuid, offset, limit)`, delegates to `_get_store().list_child_elements()`, includes docstring
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 9.1, 9.2, 9.3, 9.4, 9.5, 9.6_

  - [x] 2.2 Add SSP child element tools to `query_oscal_models.py`
    - Implement `list_ssp_control_implementations` with `element_type="control-implementation"`
    - Implement `list_ssp_system_components` with `element_type="system-component"`
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 9.1, 9.2, 9.3, 9.4, 9.5, 9.6_

  - [x] 2.3 Add profile child element tools to `query_oscal_models.py`
    - Implement `list_profile_imports` with `element_type="import"`
    - Implement `list_profile_modify` with `element_type="modify"`
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 9.1, 9.2, 9.3, 9.4, 9.5, 9.6_

  - [x] 2.4 Add assessment plan child element tools to `query_oscal_models.py`
    - Implement `list_assessment_plan_tasks` with `element_type="task"`
    - Implement `list_assessment_plan_activities` with `element_type="activity"`
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 9.1, 9.2, 9.3, 9.4, 9.5, 9.6_

  - [x] 2.5 Add assessment results child element tools to `query_oscal_models.py`
    - Implement `list_assessment_results_results` with `element_type="result"`
    - Implement `list_assessment_results_findings` with `element_type="finding"`
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 9.1, 9.2, 9.3, 9.4, 9.5, 9.6_

  - [x] 2.6 Add POA&M and mapping collection child element tools to `query_oscal_models.py`
    - Implement `list_poam_items` with `element_type="poam-item"`
    - Implement `list_mapping_collection_mappings` with `element_type="mapping"`
    - _Requirements: 6.1, 6.2, 6.3, 7.1, 7.2, 7.3, 9.1, 9.2, 9.3, 9.4, 9.5, 9.6_

- [x] 3. Implement the get_child_element tool function
  - [x] 3.1 Add `get_child_element` tool to `query_oscal_models.py`
    - Implement `get_child_element(ctx, element_id, parent_doc_uuid)` with `@tool()` decorator
    - Delegates to `_get_store().get_child_element(element_id, parent_doc_uuid)`
    - Docstring describes both identifier schemes (UUID vs token ID), ambiguity behavior, and return format
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 9.5, 9.6_

- [x] 4. Register all new tools in `__init__.py`
  - [x] 4.1 Update `get_tool_list()` in `tools/__init__.py`
    - Import all 12 list child element tools and `get_child_element` from `query_oscal_models`
    - Add all 13 new tool functions to the `tools` list
    - _Requirements: 8.1, 8.2_

- [x] 5. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 6. Write tests for child element tools
  - [x] 6.1 Write unit tests for list child element tools
    - Test each list tool against the `multi_type_store` fixture with real OSCAL data
    - Verify `list_catalog_controls` returns controls from the catalog with controls
    - Verify `list_catalog_groups` returns groups
    - Verify `list_poam_items` returns POA&M items
    - Verify empty results for tools with no matching data (e.g. `list_ssp_control_implementations` when no SSPs loaded)
    - Verify response items use `id` key (not `uuid`) and include all required keys
    - _Requirements: 1.1–1.5, 2.1–2.4, 3.1–3.4, 4.1–4.4, 5.1–5.4, 6.1–6.3, 7.1–7.3, 10.1, 10.2, 10.3, 10.4_

  - [x] 6.2 Write unit tests for `get_child_element` tool
    - Test get by UUID with parent_doc_uuid
    - Test get by token ID (`ac-1`) with parent_doc_uuid
    - Test get by token ID without parent — unique match
    - Test get by token ID without parent — ambiguous (two catalogs with same control ID)
    - Test get not found returns None
    - Test response includes `raw_json` key
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6_

  - [x] 6.3 Write unit test for tool registration
    - Verify `get_tool_list()` includes all 13 new tool functions
    - _Requirements: 8.1_

  - [x] 6.4 Write property test: correct delegation (Property 1)
    - **Property 1: Correct delegation (list tools)**
    - For each of the 12 list tools, mock `OscalStore.list_child_elements`, call the tool with random `(parent_doc_uuid, offset, limit)`, assert the mock was called with the correct fixed `element_type` and all params passed through unchanged
    - **Validates: Requirements 1.1–1.4, 2.1–2.3, 3.1–3.3, 4.1–4.3, 5.1–5.3, 6.1–6.2, 7.1–7.2**

  - [x] 6.5 Write property test: consistent interface signature (Property 2)
    - **Property 2: Consistent interface signature (list tools)**
    - Use `inspect.signature()` on each list tool to verify parameter names `(ctx, parent_doc_uuid, offset, limit)`, types, and defaults
    - **Validates: Requirements 9.1, 9.2, 9.3, 9.5**

  - [x] 6.6 Write property test: response format contract (Property 3)
    - **Property 3: Response format contract (list tools)**
    - Call each list tool against a real `OscalStore` with sample data, verify response dict has keys `{items, total, offset, limit, hasMore}` and each item has keys `{id, title, element_type, description, parentDocumentTitle, parentDocumentUuid}`
    - **Validates: Requirements 9.4, 10.1, 10.2, 10.3, 10.4**

  - [x] 6.7 Write property test: store dependency enforcement (Property 4)
    - **Property 4: Store dependency enforcement**
    - Set `_store = None`, call each tool (all 12 list tools + get_child_element), assert `RuntimeError` is raised
    - **Validates: Requirements 9.6**

  - [x] 6.8 Write property test: get tool unambiguous lookup (Property 5)
    - **Property 5: Get tool — unambiguous lookup**
    - Mock `OscalStore.get_child_element`, call `get_child_element` tool with random `(element_id, parent_doc_uuid)`, verify the mock was called with correct params
    - **Validates: Requirements 11.1, 11.2, 11.5, 11.6**

  - [x] 6.9 Write property test: get tool ambiguity detection (Property 6)
    - **Property 6: Get tool — ambiguity detection**
    - Create two catalog documents with overlapping token IDs (e.g. both have `ac-1`), call `get_child_element(element_id="ac-1")` without parent, verify error dict with `error: "ambiguous_element_id"` and both parent UUIDs listed
    - **Validates: Requirements 11.3, 11.4**

- [x] 7. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- The design uses Python — all code examples use Python 3.11+ with `@tool()` from strands and `Context` from `mcp.server.fastmcp.server`

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.2"] },
    { "id": 1, "tasks": ["1.3", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6"] },
    { "id": 2, "tasks": ["3.1"] },
    { "id": 3, "tasks": ["4.1"] },
    { "id": 4, "tasks": ["6.1", "6.2", "6.3", "6.4", "6.5", "6.6", "6.7", "6.8", "6.9"] }
  ]
}
```
