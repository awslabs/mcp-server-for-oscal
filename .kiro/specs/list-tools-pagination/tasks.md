# Implementation Plan: list-tools-pagination

## Overview

Add offset/limit pagination to the three list tools by implementing a standalone `paginate()` helper in `utils.py`, updating the `@tool()` wrappers to accept `offset`/`limit` and return a `Page_Response` dict, and updating existing tests to match the new return type.

## Tasks

- [x] 1. Implement the `paginate()` helper function
  - [x] 1.1 Add `paginate()` to `src/mcp_server_for_oscal/tools/utils.py`
    - Accept `items: list[dict]`, `offset: int = 0`, `limit: int = 10`
    - Validate: raise `ValueError` if `offset < 0`, `limit < 1`, or `limit > 100`
    - Slice `items[offset:offset+limit]` and return a dict with keys `items`, `total`, `offset`, `limit`, `hasMore`
    - `hasMore` is `True` iff `offset + limit < len(items)`
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 5.1, 5.2, 5.3, 5.4, 5.5_

  - [x] 1.2 Write property test: round-trip consistency (Property 1)
    - **Property 1: Pagination round-trip**
    - Iterate all pages by advancing offset by limit, concatenate `items` — must equal original list
    - **Validates: Requirements 4.4, 1.1, 2.1, 3.1, 5.2**
    - File: `tests/tools/test_paginate.py` (new), use `hypothesis` with `@settings(max_examples=100)`

  - [x] 1.3 Write property test: page size invariant (Property 2)
    - **Property 2: Page size invariant**
    - `len(result["items"]) <= limit` for all valid inputs
    - **Validates: Requirements 4.5, 1.1, 2.1, 3.1**

  - [x] 1.4 Write property test: hasMore correctness (Property 3)
    - **Property 3: hasMore correctness**
    - `hasMore` is `True` iff `offset + limit < total`
    - **Validates: Requirements 4.6, 1.3, 2.3, 3.3**

  - [x] 1.5 Write property test: response shape and metadata (Property 4)
    - **Property 4: Response shape and metadata**
    - Returned dict has exactly keys `items`, `total`, `offset`, `limit`, `hasMore`; `total == len(input)`; `offset` and `limit` echo inputs
    - **Validates: Requirements 5.1, 5.3, 5.5, 1.3, 2.3, 3.3**

  - [x] 1.6 Write property test: invalid inputs raise ValueError (Property 5)
    - **Property 5: Invalid inputs raise ValueError**
    - Negative offset or limit outside [1, 100] raises `ValueError`
    - **Validates: Requirements 4.3, 1.5, 1.6, 2.5, 2.6, 3.5, 3.6**

  - [x] 1.7 Write property test: beyond-end offset yields empty page (Property 6)
    - **Property 6: Beyond-end offset yields empty page**
    - When `offset >= len(items)`, `items` is `[]` and `hasMore` is `False`
    - **Validates: Requirements 1.4, 2.4, 3.4**

- [x] 2. Checkpoint — Verify `paginate()` and property tests
  - Ensure all tests pass, ask the user if questions arise.

- [x] 3. Update `@tool()` wrappers with pagination parameters
  - [x] 3.1 Update `list_component_definitions` wrapper in `src/mcp_server_for_oscal/tools/query_component_definition.py`
    - Add `offset: int = 0` and `limit: int = 10` parameters
    - Import `paginate` from `utils`
    - Call `_store.list_component_definitions(ctx)` then `return paginate(items, offset, limit)`
    - Update return type annotation from `list[dict]` to `dict`
    - Update docstring to document `offset`, `limit`, and the `Page_Response` return shape
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6_

  - [x] 3.2 Update `list_components` wrapper in `src/mcp_server_for_oscal/tools/query_component_definition.py`
    - Same changes as 3.1 but for `list_components`
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6_

  - [x] 3.3 Update `list_capabilities` wrapper in `src/mcp_server_for_oscal/tools/query_component_definition.py`
    - Same changes as 3.1 but for `list_capabilities`
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7_

- [x] 4. Update existing tests for new return type
  - [x] 4.1 Update `TestListMethods` in `tests/tools/test_query_component_definition.py`
    - `test_list_component_definitions`: assert result is a `dict` with `items` key; check `result["items"][0]["title"]`, `total`, `offset`, `limit`, `hasMore`
    - `test_list_component_definitions_empty`: unchanged (still raises `RuntimeError`)
    - `test_list_components`: same pattern — unwrap via `result["items"]`
    - `test_list_components_empty`: unchanged (still raises `RuntimeError`)
    - `test_list_capabilities_empty`: assert result is a `Page_Response` with `items=[], total=0, hasMore=False`
    - `test_list_capabilities_with_data`: unwrap via `result["items"]`
    - _Requirements: 1.1, 1.2, 1.3, 2.1, 2.2, 2.3, 3.1, 3.2, 3.3, 3.7, 5.1_

  - [x] 4.2 Add integration smoke tests for default pagination parameters
    - Verify each wrapper called without `offset`/`limit` returns `offset=0, limit=10` in the response
    - _Requirements: 1.2, 2.2, 3.2_

- [x] 5. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- The `ComponentDefinitionStore` list methods are not modified — they keep returning `list[dict]`
- All property tests target `paginate()` directly since all three tools delegate to it
- `hypothesis` is already in devtest dependencies
- Run tests with `hatch test` or `hatch run tests`
