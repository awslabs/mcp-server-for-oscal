# Implementation Plan

- [x] 1. Write bug condition exploration test
  - **Property 1: Bug Condition** - Nested Controls Are Extracted
  - **CRITICAL**: This test MUST FAIL on unfixed code — failure confirms the bug exists
  - **DO NOT attempt to fix the test or the code when it fails**
  - **NOTE**: This test encodes the expected behavior — it will validate the fix when it passes after implementation
  - **GOAL**: Surface counterexamples that demonstrate the bug exists
  - **Scoped PBT Approach**: Create a catalog with controls nested inside groups at one and two levels of nesting. Use Hypothesis to generate varying numbers of groups and controls within groups.
  - Test that `_extract_child_elements(CATALOG, parsed_model)` returns child dicts for every control inside every group, including nested groups
  - The bug condition from design: `isBugCondition(catalog)` returns true when any group has non-empty `controls` or nested `groups`
  - Expected behavior: every control at every nesting level appears in the result with `element_type="control"` and `uuid` matching the control's `id`
  - Concrete failing cases to include:
    - Catalog with `groups[0].controls = [ctrl_a]` — `ctrl_a` must appear in children
    - Catalog with `groups[0].groups[0].controls = [ctrl_b]` — `ctrl_b` must appear in children
    - Catalog with both top-level controls and group-nested controls — all must appear
  - Run test on UNFIXED code
  - **EXPECTED OUTCOME**: Test FAILS (this is correct — it proves the bug exists)
  - Document counterexamples found (e.g., "nested control 'CloudTrail.1' missing from extracted children")
  - Mark task complete when test is written, run, and failure is documented
  - _Requirements: 1.1, 1.2, 1.5_

- [x] 2. Write preservation property tests (BEFORE implementing fix)
  - **Property 2: Preservation** - Non-Nested and Non-Catalog Behavior Unchanged
  - **IMPORTANT**: Follow observation-first methodology
  - Observe: `_extract_child_elements(CATALOG, catalog_with_only_top_level_controls)` returns controls and groups on unfixed code
  - Observe: `_extract_child_elements(COMPONENT_DEFINITION, comp_def)` returns components and capabilities on unfixed code
  - Observe: `_extract_child_elements(CATALOG, empty_catalog)` returns `[]` on unfixed code
  - Write property-based tests with Hypothesis:
    - Generate catalogs with only top-level controls (no groups with nested controls) and verify extraction result matches expected structure
    - Generate component definitions and verify extraction is unchanged
    - Verify groups themselves continue to be extracted as `element_type="group"`
  - Verify tests pass on UNFIXED code
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [x] 3. Fix `_extract_child_elements()` to recursively extract controls from groups

  - [x] 3.1 Implement the recursive helper and call it from the CATALOG branch
    - Add a helper method (e.g., `_extract_controls_from_groups(self, groups, children)`) that:
      - Iterates each group's `controls` attribute and appends a child dict via `_child_dict()`
      - Recurses into each group's `groups` attribute for arbitrary nesting depth
    - Call this helper from the CATALOG branch of `_extract_child_elements()` after the existing group loop, passing `parsed_model.groups`
    - Do NOT change group extraction — groups are already extracted correctly at the top level
    - _Bug_Condition: isBugCondition(catalog) where any group has non-empty controls or nested groups_
    - _Expected_Behavior: all controls at every nesting level appear in children with element_type="control"_
    - _Preservation: top-level controls, groups, and all non-catalog model types unchanged_
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.2, 3.3_

  - [x] 3.2 Verify bug condition exploration test now passes
    - **Property 1: Expected Behavior** - Nested Controls Are Extracted
    - **IMPORTANT**: Re-run the SAME test from task 1 — do NOT write a new test
    - The test from task 1 encodes the expected behavior
    - When this test passes, it confirms the expected behavior is satisfied
    - Run bug condition exploration test from step 1
    - **EXPECTED OUTCOME**: Test PASSES (confirms bug is fixed)
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

  - [x] 3.3 Verify preservation tests still pass
    - **Property 2: Preservation** - Non-Nested and Non-Catalog Behavior Unchanged
    - **IMPORTANT**: Re-run the SAME tests from task 2 — do NOT write new tests
    - Run preservation property tests from step 2
    - **EXPECTED OUTCOME**: Tests PASS (confirms no regressions)
    - Confirm all tests still pass after fix (no regressions)

- [x] 4. Rebuild the bundled database
  - Run `hatch run python bin/build_oscal_db.py` to regenerate `src/mcp_server_for_oscal/oscal_store.db`
  - Verify the child element count increased (nested controls now indexed)
  - Verify `list_catalog_controls()` returns controls from catalogs that previously returned 0
  - _Requirements: 2.1, 2.2_

- [x] 5. Checkpoint — Ensure all tests pass
  - Run `hatch run tests` to execute the full test suite
  - Ensure all existing tests pass (no regressions)
  - Ensure the new exploration and preservation tests pass
  - Ask the user if questions arise
