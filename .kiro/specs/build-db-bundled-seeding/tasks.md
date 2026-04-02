# Implementation Plan

- [x] 1. Write bug condition exploration test
  - **Property 1: Bug Condition** — build_db bundled seeding contamination
  - **CRITICAL**: This test MUST FAIL on unfixed code — failure confirms the bug exists
  - **DO NOT attempt to fix the test or the code when it fails**
  - **NOTE**: This test encodes the expected behavior — it will validate the fix when it passes after implementation
  - **GOAL**: Surface counterexamples that demonstrate the bug exists
  - **Scoped PBT Approach**: Scope the property to the concrete failing case: `build_db()` with empty source directories while a valid bundled DB exists at `BUNDLED_DB_PATH`
  - In `tests/test_build_oscal_db.py`, write a Hypothesis property-based test that:
    - Uses `@given(st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=("L", "N"))))` to generate random DB filename suffixes
    - For each generated suffix, creates a temp directory with empty `component_definitions/` and `oscal_docs/` subdirectories
    - Calls `build_db(db_path=tmp/test_{suffix}.db, component_defs_dir=empty_comp_dir, oscal_docs_dir=empty_docs_dir)`
    - Asserts `stats["docs_indexed"] == 0` and `stats["children"] == 0`
  - This tests the bug condition from design: `isBugCondition(input)` where `db_path` does not exist, bundled DB is present, and caller intent is clean build
  - Run test on UNFIXED code — expect FAILURE (`docs_indexed == 232` instead of `0`)
  - Document counterexamples found (e.g., "build_db with empty dirs returns docs_indexed=232 because _resolve_persistent() seeds from bundled DB")
  - Mark task complete when test is written, run, and failure is documented
  - _Requirements: 1.1, 1.2, 2.1, 2.2_

- [x] 2. Write preservation property tests (BEFORE implementing fix)
  - **Property 2: Preservation** — Default OscalStore seeding behavior unchanged
  - **IMPORTANT**: Follow observation-first methodology
  - **Step 1 — Observe on UNFIXED code**:
    - Observe: `OscalStore(db_path=new_path)` where `new_path` does not exist and bundled DB is valid → seeds from bundled DB, document count > 0
    - Observe: `OscalStore(db_path=existing_path)` where file already exists → opens existing DB without re-seeding, `_db_mode == "persistent"`
    - Observe: `OscalStore()` with no explicit path and no bundled DB → creates ephemeral database, `_db_mode == "ephemeral"`
  - **Step 2 — Write property-based tests** in `tests/test_build_oscal_db.py`:
    - Property: for all generated `db_path` strings (non-existent paths), default `OscalStore(db_path=path)` with a valid bundled DB present seeds the database (document count matches bundled DB count). Use `unittest.mock.patch` on `BUNDLED_DB_PATH` if needed to control bundled DB presence.
    - Property: for all generated `db_path` strings pointing to an existing (pre-created empty) DB file, `OscalStore(db_path=path)` opens it without copying bundled content (`_db_mode == "persistent"`, document count == 0 since the DB was empty)
    - Property: `build_db()` with non-empty source directories scans and indexes only those documents (preservation of scanning behavior)
  - Verify all preservation tests PASS on UNFIXED code
  - Mark task complete when tests are written, run, and passing on unfixed code
  - _Requirements: 3.1, 3.2, 3.3, 3.4_

- [x] 3. Fix for build_db bundled seeding contamination

  - [x] 3.1 Add `seed_from_bundled` parameter to `OscalStore.__init__()`
    - In `src/mcp_server_for_oscal/tools/oscal_store.py`, add `seed_from_bundled: bool = True` parameter to `OscalStore.__init__()` signature
    - Store as `self._seed_from_bundled = seed_from_bundled` before the call to `self._resolve_db_path(db_path)`
    - _Bug_Condition: isBugCondition(input) where input.db_path IS NOT None AND NOT fileExists(input.db_path) AND fileExists(BUNDLED_DB_PATH) AND input.caller_intent == "clean_build"_
    - _Expected_Behavior: When seed_from_bundled=False, resulting database contains zero pre-existing documents_
    - _Preservation: When seed_from_bundled=True (default), _resolve_persistent() continues to copy bundled DB exactly as before_
    - _Requirements: 2.1, 2.2, 3.1, 3.2, 3.3_

  - [x] 3.2 Gate bundled DB copy in `_resolve_persistent()`
    - In `src/mcp_server_for_oscal/tools/oscal_store.py`, wrap the `if BUNDLED_DB_PATH.exists() and self._verify_bundled_db():` block inside `_resolve_persistent()` with an additional `if self._seed_from_bundled:` guard
    - When `self._seed_from_bundled` is `False`, skip the bundled DB copy and fall through to the "Create a new empty persistent DB" branch
    - _Bug_Condition: _resolve_persistent() unconditionally seeds from bundled DB when target path does not exist_
    - _Expected_Behavior: _resolve_persistent() only seeds from bundled DB when self._seed_from_bundled is True_
    - _Preservation: Default callers (seed_from_bundled=True) are completely unaffected_
    - _Requirements: 2.1, 3.1, 3.2_

  - [x] 3.3 Update `build_db()` to pass `seed_from_bundled=False`
    - In `bin/build_oscal_db.py`, change `OscalStore(db_path=str(db_path), cache_size=200)` to `OscalStore(db_path=str(db_path), cache_size=200, seed_from_bundled=False)`
    - _Bug_Condition: build_db() creates OscalStore without signaling clean-build intent_
    - _Expected_Behavior: build_db() produces a database containing only scanned documents, docs_indexed reflects only source directory contents_
    - _Preservation: All other OscalStore callers continue using default seed_from_bundled=True_
    - _Requirements: 2.1, 2.2, 2.3_

  - [x] 3.4 Verify bug condition exploration test now passes
    - **Property 1: Expected Behavior** — build_db bundled seeding contamination
    - **IMPORTANT**: Re-run the SAME test from task 1 — do NOT write a new test
    - The test from task 1 encodes the expected behavior (docs_indexed == 0 for empty dirs)
    - When this test passes, it confirms the expected behavior is satisfied
    - Run bug condition exploration test from step 1
    - **EXPECTED OUTCOME**: Test PASSES (confirms bug is fixed)
    - _Requirements: 2.1, 2.2_

  - [x] 3.5 Verify preservation tests still pass
    - **Property 2: Preservation** — Default OscalStore seeding behavior unchanged
    - **IMPORTANT**: Re-run the SAME tests from task 2 — do NOT write new tests
    - Run preservation property tests from step 2
    - **EXPECTED OUTCOME**: Tests PASS (confirms no regressions)
    - Confirm all preservation tests still pass after fix (no regressions)

- [x] 4. Checkpoint — Ensure all tests pass
  - Run `hatch run tests` to execute the full test suite (typing + pytest + coverage + bandit)
  - Verify `test_build_db_empty_directories` passes with `docs_indexed == 0` and `children == 0`
  - Verify all new property-based tests pass
  - Verify all existing tests pass (no regressions)
  - Ensure all tests pass, ask the user if questions arise
