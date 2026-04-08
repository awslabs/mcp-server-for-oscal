# Implementation Plan: Post-Copy DB Verification

## Overview

Extract shared hash-reading logic, add post-copy SHA-256 verification to both DB seeding paths, make verification failure fatal, and remove the brittle hardcoded-count test.

## Tasks

- [x] 1. Extract `_get_expected_db_hash()` and `_verify_file_hash()` static methods
  - [x] 1.1 Add `_get_expected_db_hash()` static method to `OscalStore`
    - Extract hashes.json parsing from `_verify_bundled_db()` into a new `@staticmethod` that returns `str | None`
    - Place it above `_verify_bundled_db()` in the class
    - _Requirements: 2.1_
  - [x] 1.2 Add `_verify_file_hash()` static method to `OscalStore`
    - Computes SHA-256 of a file, compares against expected hash
    - On mismatch: calls `file_path.unlink(missing_ok=True)` then raises `RuntimeError` with expected hash, actual hash, and file path in the message
    - _Requirements: 1.3, 1.4_
  - [x] 1.3 Refactor `_verify_bundled_db()` to use `_get_expected_db_hash()`
    - Replace inline hashes.json parsing with a call to `_get_expected_db_hash()`
    - Preserve existing return type (`bool`) and behavior (does NOT delete bundled DB on mismatch)
    - _Requirements: 2.2_

- [x] 2. Add post-copy verification to `_resolve_persistent()`
  - [x] 2.1 Add `_verify_file_hash()` call after `shutil.copy2` in `_resolve_persistent()`
    - Use try/else pattern: `shutil.copy2` in try, verification in else block
    - Get expected hash via `_get_expected_db_hash()`; if hash available, call `_verify_file_hash(p, expected_hash)`
    - `RuntimeError` from `_verify_file_hash` propagates up (fatal)
    - _Requirements: 1.1, 2.3_
  - [ ]* 2.2 Write property test for `_verify_file_hash()`
    - **Property 1: Hash mismatch raises RuntimeError and removes file**
    - **Validates: Requirements 1.3, 1.4**

- [x] 3. Add post-copy verification to `_copy_bundled_to_temp()`
  - [x] 3.1 Add `_verify_file_hash()` call after `shutil.copy2` in `_copy_bundled_to_temp()`
    - After successful copy, get expected hash and call `_verify_file_hash(dest, expected_hash)`
    - `RuntimeError` propagates up (fatal)
    - _Requirements: 1.2, 2.3_

- [x] 4. Remove brittle test and update docstring
  - [x] 4.1 Remove `test_new_path_with_bundled_db_seeds` from `TestPreservationDefaultSeeding`
    - Delete the entire method (including `@given` and `@settings` decorators)
    - _Requirements: 3.1_
  - [x] 4.2 Update `TestPreservationDefaultSeeding` class docstring
    - Remove reference to Requirement 3.1 from the `**Validates:**` line
    - _Requirements: 3.2_

- [x] 5. Checkpoint - Ensure all tests pass
  - Run `hatch run tests` to verify all remaining tests pass
  - Ensure all tests pass, ask the user if questions arise.
  - _Requirements: 3.3_

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- The `_verify_bundled_db()` method intentionally does NOT use `_verify_file_hash()` because it must not delete the bundled DB (a read-only package asset) and returns `bool` instead of raising
- Post-copy verification failure is fatal (`RuntimeError`) per user direction — without an intact DB, the server cannot serve customers correctly
