# Implementation Plan: Parallel-Safe Tests

## Overview

Isolate shared mutable singleton state in `tests/tools/test_query_component_definition.py` so the full test suite passes under `pytest-xdist` parallel execution. The implementation adds an autouse `reset_store` fixture, fixes 5 tests that rely on implicit state, and enables `parallel = true` in `pyproject.toml`.

## Tasks

- [x] 1. Add the `reset_store` autouse fixture
  - [x] 1.1 Implement the `reset_store` fixture in `tests/tools/test_query_component_definition.py`
    - Add `import copy` and `from mcp_server_for_oscal.tools import query_component_definition as _qcd_module` at the top of the file
    - Define a module-level `@pytest.fixture(autouse=True)` named `reset_store` that:
      - Deep-copies all 10 `_store` attributes (`_cdefs_by_path`, `_cdefs_by_uuid`, `_cdefs_by_title`, `_components_by_uuid`, `_components_by_title`, `_components_to_cdef_by_uuid`, `_capabilities_by_uuid`, `_capabilities_by_name`, `_capabilities_to_cdef_by_uuid`, `_stats`)
      - Saves `_qcd_module._oscal_store`
      - Calls `_store._reset()` and sets `_qcd_module._oscal_store = None`
      - Yields
      - Restores all 10 `_store` attributes and `_qcd_module._oscal_store` after yield
    - Place the fixture at module level (outside any class) so it applies to all tests in the file
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 2.1, 2.2, 2.3, 2.4_

- [x] 2. Fix the 5 tests that rely on implicit store population
  - [x] 2.1 Fix `test_query_by_type_not_found` and `test_query_invalid_query_type`
    - Add `setup_component_defs_dir` as a fixture parameter to both test methods
    - This ensures `_store` is populated before the query runs, so `test_query_by_type_not_found` finds an empty result for "hardware" and `test_query_invalid_query_type` bypasses the "No Component Definitions loaded" guard to reach the invalid query_type error path
    - _Requirements: 3.1, 3.2, 3.6_

  - [x] 2.2 Fix `test_query_with_component_definition_filter_by_uuid`, `_by_title`, and `_not_found`
    - Add a `_load_component_definitions_from_directory()` call in each of the three test methods, after the config is patched and before `query_component_definition()` is called
    - _Requirements: 3.3, 3.4, 3.5_

- [x] 3. Checkpoint - Verify test isolation
  - Ensure all tests pass sequentially (`hatch test`), ask the user if questions arise.

- [x] 4. Enable parallel test execution
  - [x] 4.1 Uncomment `parallel = true` in `pyproject.toml`
    - Change `# parallel = true` to `parallel = true` in the `[tool.hatch.envs.hatch-test]` section
    - _Requirements: 4.1_

  - [x] 4.2 Write property test for store state save/reset/restore round-trip
    - **Property 1: Store state save/reset/restore round-trip**
    - Use Hypothesis to generate arbitrary `_store` state (random dicts for each of the 10 attributes), save via deep copy, call `_reset()`, restore, and assert equivalence to original
    - Add the test to `tests/tools/test_query_component_definition.py` or a dedicated property test section
    - Tag: `Feature: parallel-safe-tests, Property 1: Store state save/reset/restore round-trip`
    - **Validates: Requirements 1.1, 1.2, 1.4, 2.1, 2.2, 2.4**

- [x] 5. Final checkpoint - Verify parallel execution
  - Ensure all tests pass with parallel execution enabled (`hatch test --all`), ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- The `reset_store` fixture mirrors the existing `reset_oscal_store` pattern in `tests/test_properties.py`, extended to cover all 10 `_store` attributes
- No production code changes are needed — all changes are in the test layer and `pyproject.toml`

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["2.1", "2.2"] },
    { "id": 2, "tasks": ["4.1", "4.2"] }
  ]
}
```
