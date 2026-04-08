# Requirements Document

## Introduction

The project's test suite fails when `pytest-xdist` parallel execution is enabled (`parallel = true` in `[tool.hatch.envs.hatch-test]`). Five tests in `tests/tools/test_query_component_definition.py` fail because they depend on shared mutable module-level singletons (`_store` and `_oscal_store`) in `query_component_definition.py`. When tests run in parallel, non-deterministic ordering causes tests that call `_store._reset()` to clear state needed by other tests in the same worker. This feature isolates test state so all tests pass under parallel execution, then enables the `parallel = true` setting.

## Glossary

- **Test_Suite**: The full collection of pytest tests in the `tests/` directory
- **Store_Singleton**: The module-level `_store` instance of `ComponentDefinitionStore` in `query_component_definition.py`, shared across all tests
- **OscalStore_Singleton**: The module-level `_oscal_store` variable in `query_component_definition.py`, shared across all tests
- **Worker**: A `pytest-xdist` subprocess that runs a subset of tests in a single pytest session
- **Fixture**: A pytest fixture that provides setup and teardown logic for tests
- **Reset_Fixture**: An autouse pytest fixture that saves, clears, and restores singleton state around each test
- **Parallel_Mode**: The `parallel = true` setting in `[tool.hatch.envs.hatch-test]` in `pyproject.toml` that enables `pytest-xdist`
- **QCD_Module**: The `mcp_server_for_oscal.tools.query_component_definition` module

## Requirements

### Requirement 1: Isolate Store_Singleton State Between Tests

**User Story:** As a developer, I want each test to have isolated `_store` state, so that tests do not interfere with each other when run in parallel or in any order.

#### Acceptance Criteria

1. WHEN a test begins execution, THE Reset_Fixture SHALL save a deep copy of all Store_Singleton index dictionaries and stats, then call `_store._reset()` to clear Store_Singleton to its empty state (all index dictionaries empty, all stats counters set to zero)
2. WHEN a test completes execution (whether it passed, failed, or raised an error), THE Reset_Fixture SHALL restore all Store_Singleton index dictionaries and stats to the deep-copied values saved before the test began
3. THE Reset_Fixture SHALL be defined as a function-scoped autouse fixture that applies automatically to every test in `tests/tools/test_query_component_definition.py` without requiring explicit use in each test method
4. IF a test explicitly calls `_store._reset()` or modifies Store_Singleton state within its body, THEN THE Reset_Fixture SHALL still restore Store_Singleton to the pre-test state after that test completes

### Requirement 2: Isolate OscalStore_Singleton State Between Tests

**User Story:** As a developer, I want each test to have isolated `_oscal_store` state, so that the OscalStore singleton does not leak across tests when run in parallel.

#### Acceptance Criteria

1. WHEN a test begins execution, THE Reset_Fixture SHALL save the current value of OscalStore_Singleton and set OscalStore_Singleton to None on the QCD_Module
2. WHEN a test completes execution (whether it passed, failed, or raised an exception), THE Reset_Fixture SHALL restore OscalStore_Singleton on the QCD_Module to the saved value from before the test
3. THE Reset_Fixture SHALL apply automatically to every test in `tests/tools/test_query_component_definition.py` without requiring explicit use in each test method
4. IF a test or its fixture sets OscalStore_Singleton to a new value during execution, THEN THE Reset_Fixture SHALL still restore OscalStore_Singleton to the value saved before the test began

### Requirement 3: Fix Tests That Rely on Implicit Module-Level Store Population

**User Story:** As a developer, I want all five failing tests to explicitly set up the state they need, so that they pass regardless of test execution order.

#### Acceptance Criteria

1. WHEN `test_query_by_type_not_found` executes, THE Test_Suite SHALL set up a temporary directory containing at least one valid component definition JSON file, patch the config to reference that directory, and call `_load_component_definitions_from_directory()` to populate Store_Singleton before the query runs
2. WHEN `test_query_invalid_query_type` executes, THE Test_Suite SHALL set up a temporary directory containing at least one valid component definition JSON file, patch the config to reference that directory, and call `_load_component_definitions_from_directory()` to populate Store_Singleton before the query runs, so that the "No Component Definitions loaded" guard is bypassed and the invalid query_type error path is reached
3. WHEN `test_query_with_component_definition_filter_by_uuid` executes, THE Test_Suite SHALL call `_load_component_definitions_from_directory()` to populate Store_Singleton after the temporary directory is created and the config is patched to reference it
4. WHEN `test_query_with_component_definition_filter_by_title` executes, THE Test_Suite SHALL call `_load_component_definitions_from_directory()` to populate Store_Singleton after the temporary directory is created and the config is patched to reference it
5. WHEN `test_query_with_component_definition_filter_not_found` executes, THE Test_Suite SHALL call `_load_component_definitions_from_directory()` to populate Store_Singleton after the temporary directory is created and the config is patched to reference it
6. IF Store_Singleton is empty when `query_component_definition()` is called, THEN THE QCD_Module SHALL raise a `ValueError` with the message "No Component Definitions loaded" before evaluating the query_type, which means tests for specific error paths (such as invalid query_type) must populate Store_Singleton first to reach those paths

### Requirement 4: Enable Parallel Test Execution

**User Story:** As a developer, I want `parallel = true` enabled in the hatch test environment configuration, so that the test suite runs faster using `pytest-xdist`.

#### Acceptance Criteria

1. THE Parallel_Mode setting in `pyproject.toml` SHALL be set to `parallel = true` (not commented out) in the `[tool.hatch.envs.hatch-test]` section
2. WHEN the Test_Suite runs with Parallel_Mode enabled across all Python versions in the hatch-test matrix, THE Test_Suite SHALL complete with zero test failures and zero test errors
3. WHEN the Test_Suite runs with Parallel_Mode enabled, THE Test_Suite SHALL not skip any tests that were not already skipped when running without Parallel_Mode

### Requirement 5: Preserve Existing Test Behavior

**User Story:** As a developer, I want the test fixes to preserve all existing test assertions and behavior, so that no test coverage is lost.

#### Acceptance Criteria

1. WHEN the Test_Suite is run without Parallel_Mode (sequential execution), THE Test_Suite SHALL produce zero test failures and the same number of passed tests as before the changes
2. WHEN the Test_Suite is run with Parallel_Mode enabled, THE Test_Suite SHALL produce zero test failures and the same number of passed tests as when run sequentially
3. WHEN a test in `tests/tools/test_query_component_definition.py` already uses the `setup_component_defs_dir` fixture, THE Reset_Fixture SHALL not interfere with the fixture's setup of Store_Singleton, such that the test's assertions produce the same pass/fail results as before the Reset_Fixture was introduced
4. WHEN a test in `tests/tools/test_query_component_definition.py` explicitly calls `_store._reset()`, THE Reset_Fixture SHALL not prevent the test from controlling Store_Singleton state, such that the test's assertions produce the same pass/fail results as before the Reset_Fixture was introduced
5. IF the Reset_Fixture is applied to a test that does not reference Store_Singleton or OscalStore_Singleton, THEN THE Reset_Fixture SHALL have no observable effect on that test's execution or assertions
