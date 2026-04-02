# Implementation Plan: query-cdef-pagination

## Overview

Add offset/limit pagination to `query_component_definition()` and `_oscal_store_query_component_definition()`, applying `paginate()` to component results and wrapping capability results in a Page_Response envelope. Both code paths (OscalStore and legacy) are updated.

## Tasks

- [x] 1. Add `_paginate_component_response` helper and update `query_component_definition`
  - [x] 1.1 Add `_paginate_component_response()` private helper to `query_component_definition.py`
    - Import `paginate` from `utils` (if not already imported)
    - Accept `result: dict`, `offset: int`, `limit: int`
    - Apply `paginate()` to `result["components"]`, merge pagination metadata (`offset`, `limit`, `total_count`, `hasMore`) into the result dict
    - _Requirements: 2.1, 2.2, 2.3, 2.4_

  - [x] 1.2 Add `offset: int = 0` and `limit: int = 10` parameters to `query_component_definition()`
    - Update function signature
    - Update docstring to document `offset`, `limit`, and the paginated response shape
    - _Requirements: 1.1, 1.2, 6.1_

  - [x] 1.3 Apply pagination in the legacy path (`_oscal_store is None`)
    - After `_store.query()` returns, detect capability vs component response (check for `"capability"` key)
    - For component responses: call `_paginate_component_response(result, offset, limit)`
    - For capability responses: add `offset=0, limit=1, total=1, hasMore=False` to the result dict
    - _Requirements: 2.1, 4.1, 4.2, 4.3, 1.3_

  - [x] 1.4 Thread `offset`/`limit` to `_oscal_store_query_component_definition()` and apply pagination
    - Add `offset: int = 0` and `limit: int = 10` parameters to `_oscal_store_query_component_definition()`
    - Pass `offset` and `limit` from `query_component_definition()` call
    - For the capability match path: add `offset=0, limit=1, total=1, hasMore=False` to `cap_result`
    - For the `_store.query()` fallback: call `_paginate_component_response(result, offset, limit)`
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 4.1, 4.2, 4.3, 1.3_

- [x] 2. Checkpoint — Verify implementation compiles and existing tests still pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 3. Update existing tests and add new tests
  - [x] 3.1 Update `TestQueryComponentDefinitionTool` tests in `tests/tools/test_query_component_definition.py`
    - Update assertions in component-result tests to expect `offset`, `limit`, `total_count`, `hasMore` keys
    - Update assertions in capability-result tests (if any) to expect pagination envelope
    - Verify empty-result responses include pagination metadata
    - _Requirements: 6.2, 5.3, 2.2, 3.2_

  - [x] 3.2 Add pagination-specific tests for `query_component_definition`
    - Test default pagination (offset=0, limit=10) when called without explicit params
    - Test explicit offset/limit values produce correct slicing
    - Test capability response wrapping includes `offset=0, limit=1, total=1, hasMore=False`
    - Test empty results include pagination metadata
    - _Requirements: 1.2, 2.1, 4.1, 4.2, 5.3, 6.3_

  - [x] 3.3 Write property test for component pagination slice correctness
    - **Property 1: Component pagination slice correctness**
    - Mock `_store.query()` to return a component response with a generated list, call `query_component_definition()` with random valid offset/limit, verify `components == full_list[offset:offset+limit]` and `total_count == len(full_list)`
    - **Validates: Requirements 2.1, 2.2, 2.3, 2.4, 3.1, 3.2, 3.3, 3.4**

- [x] 4. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- The existing `paginate()` function in `utils.py` is reused — no modifications needed
- `ComponentDefinitionStore.query()` is not modified — pagination is applied at the tool wrapper layer
- The `_oscal_store_find_capability()` helper is not modified — pagination envelope is added after it returns
- Property tests for `paginate()` itself already exist in `tests/tools/test_paginate.py`
