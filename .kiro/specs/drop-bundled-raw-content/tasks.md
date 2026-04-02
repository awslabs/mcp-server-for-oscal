# Implementation Plan: Drop Bundled Raw Content

## Overview

Restructure the package to stop bundling `oscal_docs/` and `component_definitions/` inside the published wheel. Move these directories to a top-level `data/` directory (build-time only), remove startup scanning/integrity-verification of those directories, and update the build script, rehash script, and tests accordingly.

## Tasks

- [x] 1. Move raw content directories and update build configuration
  - [x] 1.1 Move `oscal_docs/` and `component_definitions/` to `data/`
    - Move `src/mcp_server_for_oscal/oscal_docs/` to `data/oscal_docs/`
    - Move `src/mcp_server_for_oscal/component_definitions/` to `data/component_definitions/`
    - Verify `data/` directory exists at repo root with both subdirectories
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

  - [x] 1.2 Update `pyproject.toml` rehash script
    - Remove the two `hatch run bin/update_hashes.py src/mcp_server_for_oscal/oscal_docs` and `git add src/mcp_server_for_oscal/oscal_docs/hashes.json` lines
    - Remove the two `hatch run bin/update_hashes.py src/mcp_server_for_oscal/component_definitions` and `git add src/mcp_server_for_oscal/component_definitions/hashes.json` lines
    - Keep the `oscal_schemas` rehash line and the package-level `hashes.json` staging line
    - _Requirements: 5.1, 5.2, 5.3, 5.4_

  - [x] 1.3 Update `bin/build_oscal_db.py` path constants
    - Change `COMPONENT_DEFS_DIR` from `PACKAGE_DIR / "component_definitions"` to `REPO_ROOT / "data" / "component_definitions"`
    - Change `OSCAL_DOCS_DIR` from `PACKAGE_DIR / "oscal_docs"` to `REPO_ROOT / "data" / "oscal_docs"`
    - _Requirements: 6.1, 6.2, 1.6_

- [x] 2. Remove redundant startup code
  - [x] 2.1 Remove `scan_directory` calls from `_init_oscal_store()` in `main.py`
    - Remove the `comp_defs_dir` scanning block (lines that scan `config.component_definitions_dir`)
    - Remove the `bundled_docs_dir` scanning block (lines that scan `oscal_docs/`)
    - Keep the user-configured `oscal_documents_dir` scanning block
    - Add a warning log if user-configured `oscal_documents_dir` is set but doesn't exist
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

  - [x] 2.2 Remove `verify_package_integrity` calls for `oscal_docs` and `component_definitions` from `main.py`
    - Remove `verify_package_integrity(my_dir.joinpath("oscal_docs"))` call
    - Remove the `component_defs_dir` conditional block and its `verify_package_integrity` call
    - Keep `verify_package_integrity(my_dir.joinpath("oscal_schemas"))` call
    - _Requirements: 4.1, 4.2, 4.5, 4.7, 4.8_

  - [x] 2.3 Remove `verify_package_integrity` calls for `oscal_docs` and `component_definitions` from `oscal_agent.py`
    - Remove `verify_package_integrity(my_dir.joinpath("oscal_docs"))` call
    - Remove the `component_defs_dir` conditional block and its `verify_package_integrity` call
    - Keep `verify_package_integrity(my_dir.joinpath("oscal_schemas"))` call
    - _Requirements: 4.3, 4.4, 4.6, 4.7, 4.8_

- [x] 3. Checkpoint - Verify core changes
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Update tests to reflect new package layout
  - [x] 4.1 Update `test_file_integrity_integration.py`
    - Change `test_successful_server_startup_with_valid_packages` to assert `mock_verify_integrity.call_count == 1` (only `oscal_schemas`)
    - Remove assertion for `docs_dir_checked` (oscal_docs)
    - Update `test_verification_of_both_oscal_directories` to verify only `oscal_schemas` is checked (call_count == 1)
    - Update `test_first_directory_failure_prevents_second_check` — failure on first (oscal_schemas) still causes exit code 2, call_count == 1
    - Remove `test_second_directory_failure_after_first_success` or update it since there is no second directory check
    - Update `test_integrity_check_order_and_path_resolution` to assert call_count == 1 and only `oscal_schemas` path
    - Update `test_server_continues_after_successful_integrity_checks` to assert call_count == 1
    - _Requirements: 8.1, 8.2, 8.3, 8.6_

  - [x] 4.2 Update `test_main.py`
    - Tests that mock `verify_package_integrity` should expect 1 call (for `oscal_schemas` only), not 2
    - Verify no test asserts `oscal_docs` or `component_definitions` integrity verification
    - _Requirements: 8.1, 8.2, 8.6_

  - [x] 4.3 Update `test_oscal_agent.py`
    - Update `test_exit_code_2_on_integrity_failure` — `verify_package_integrity` is called once for `oscal_schemas`
    - Update any tests that mock `verify_package_integrity` to expect 1 call instead of 2
    - _Requirements: 8.1, 8.2, 8.6_

  - [x] 4.4 Update `test_build_oscal_db.py`
    - Add a test that verifies `COMPONENT_DEFS_DIR` equals `REPO_ROOT / "data" / "component_definitions"`
    - Add a test that verifies `OSCAL_DOCS_DIR` equals `REPO_ROOT / "data" / "oscal_docs"`
    - Existing parameterized tests pass directory paths directly, so they continue to work
    - _Requirements: 8.5_

- [x] 5. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- No property-based testing needed — this feature involves file system restructuring and code path removal, not algorithmic logic
- `oscal_schemas/` and `oscal_store.db` remain bundled in the package and are unchanged
- The `config.component_definitions_dir` setting is left in place to avoid breaking users who have set `OSCAL_COMPONENT_DEFINITIONS_DIR`, but startup code no longer uses it for scanning bundled content
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "1.3", "2.1", "2.2", "2.3"] },
    { "id": 2, "tasks": ["4.1", "4.2", "4.3", "4.4"] }
  ]
}
```