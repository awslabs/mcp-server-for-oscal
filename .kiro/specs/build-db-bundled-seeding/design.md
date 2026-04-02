# Build-DB Bundled Seeding Bugfix Design

## Overview

`build_db()` in `bin/build_oscal_db.py` is supposed to produce a fresh SQLite database containing only the documents scanned from source directories. Instead, when a valid bundled DB (`oscal_store.db`) ships with the package, the freshly-created `OscalStore` silently seeds from it — injecting 232 pre-existing documents into what should be an empty database.

The fix adds a `seed_from_bundled` boolean parameter to `OscalStore.__init__()` (default `True`) that `_resolve_persistent()` checks before copying the bundled DB. `build_db()` passes `seed_from_bundled=False`, while all runtime callers keep the default `True`, preserving existing behavior.

## Glossary

- **Bug_Condition (C)**: `OscalStore` is instantiated with an explicit `db_path` that does not yet exist, a valid bundled DB is present, and the caller intended a clean (unseeded) database — i.e., `seed_from_bundled=False` was not passed.
- **Property (P)**: When `seed_from_bundled=False`, the resulting database contains zero pre-existing documents; `docs_indexed` reflects only what was scanned from source directories.
- **Preservation**: When `seed_from_bundled=True` (the default), `_resolve_persistent()` continues to copy the bundled DB exactly as before. All runtime paths are unchanged.
- **`OscalStore`**: The class in `src/mcp_server_for_oscal/tools/oscal_store.py` that manages the SQLite-backed OSCAL document store.
- **`_resolve_persistent()`**: Method on `OscalStore` that decides whether to open an existing DB, seed from the bundled DB, or create a fresh empty DB when an explicit `db_path` is provided.
- **`build_db()`**: The function in `bin/build_oscal_db.py` that builds the bundled database by scanning source directories and indexing their contents.
- **`BUNDLED_DB_PATH`**: Module-level constant pointing to `src/mcp_server_for_oscal/oscal_store.db`.

## Bug Details

### Bug Condition

The bug manifests when `build_db()` deletes the target DB file and then creates `OscalStore(db_path=str(db_path))`. Since the file was just deleted, `_resolve_persistent()` sees a non-existent path, finds a valid bundled DB at `BUNDLED_DB_PATH`, and copies it to the target — contaminating the "fresh" build with 232 pre-existing documents.

**Formal Specification:**
```
FUNCTION isBugCondition(input)
  INPUT: input of type OscalStoreConstructorArgs
  OUTPUT: boolean

  RETURN input.db_path IS NOT None
         AND NOT fileExists(input.db_path)
         AND fileExists(BUNDLED_DB_PATH)
         AND verifyBundledDb() == True
         AND input.caller_intent == "clean_build"
END FUNCTION
```

### Examples

- `build_db(db_path=tmp/test.db, comp_dir=empty/, docs_dir=empty/)` → Expected: `docs_indexed=0`. Actual: `docs_indexed=232` because the bundled DB was copied in.
- `build_db(db_path=tmp/test.db, comp_dir=one_doc/, docs_dir=empty/)` → Expected: `docs_indexed=1`. Actual: `docs_indexed=233` (232 bundled + 1 scanned).
- Running `build_db()` twice (idempotency test) → Second run deletes DB, re-seeds from bundled, then scans. Counts may differ from first run if bundled content overlaps with scanned content.
- `OscalStore(db_path="/new/path.db")` at runtime (no `build_db`) → Should still seed from bundled DB. This is correct existing behavior and must not change.

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- `OscalStore(db_path=path)` where `path` already exists opens the existing persistent DB without modification
- `OscalStore(db_path=path)` where `path` does not exist and a valid bundled DB is present seeds from the bundled DB (default `seed_from_bundled=True`)
- `OscalStore()` with no explicit path and no bundled DB creates an ephemeral database
- `OscalStore()` with no explicit path and a valid bundled DB copies it to a temp directory
- `build_db()` with non-empty source directories scans and indexes all documents correctly
- `scan_directory()`, `_ensure_indexed()`, `close()`, and all query methods are unaffected

**Scope:**
All callers that do NOT pass `seed_from_bundled=False` should be completely unaffected by this fix. This includes:
- Runtime MCP server startup (uses default `seed_from_bundled=True`)
- Direct `OscalStore` instantiation in tests that rely on bundled seeding
- The `_resolve_auto()` path (no explicit `db_path`) — untouched by this change

## Hypothesized Root Cause

Based on the bug description, the root cause is:

1. **Missing intent signal in `OscalStore.__init__()`**: There is no way for a caller to say "I want a clean, empty database — do not seed from the bundled DB." The `_resolve_persistent()` method unconditionally copies the bundled DB when the target path does not exist and the bundled DB is valid.

2. **`build_db()` deletes the file but cannot prevent re-seeding**: `build_db()` correctly removes the old DB for idempotency (`os.remove(db_path)`), but the subsequent `OscalStore(db_path=str(db_path))` call triggers `_resolve_persistent()`, which sees a missing file and seeds from the bundled DB.

3. **No alternative code path**: `_resolve_persistent()` has exactly two branches for a missing file: (a) seed from bundled if valid, (b) create empty. There is no way to force branch (b) when a valid bundled DB exists.

## Correctness Properties

Property 1: Bug Condition — No bundled seeding when seed_from_bundled=False

_For any_ `OscalStore` instantiation where `seed_from_bundled=False` and `db_path` points to a non-existent file, the resulting database SHALL contain zero documents regardless of whether a valid bundled DB exists at `BUNDLED_DB_PATH`.

**Validates: Requirements 2.1, 2.2**

Property 2: Preservation — Default seeding behavior unchanged

_For any_ `OscalStore` instantiation where `seed_from_bundled` is not specified (defaults to `True`) and `db_path` points to a non-existent file and a valid bundled DB exists, the resulting database SHALL be seeded from the bundled DB, producing the same document count as the bundled DB contains.

**Validates: Requirements 3.1, 3.2, 3.3**

## Fix Implementation

### Changes Required

Assuming our root cause analysis is correct:

**File**: `src/mcp_server_for_oscal/tools/oscal_store.py`

**Function**: `OscalStore.__init__()`

**Specific Changes**:
1. **Add parameter**: Add `seed_from_bundled: bool = True` to `__init__()` signature.
2. **Store as instance attribute**: Set `self._seed_from_bundled = seed_from_bundled` before calling `_resolve_db_path()`.
3. **Gate seeding in `_resolve_persistent()`**: Wrap the `if BUNDLED_DB_PATH.exists() and self._verify_bundled_db():` block with an additional `if self._seed_from_bundled:` check. When `False`, fall through to the "Create a new empty persistent DB" branch.

**File**: `bin/build_oscal_db.py`

**Function**: `build_db()`

**Specific Changes**:
4. **Pass `seed_from_bundled=False`**: Change `OscalStore(db_path=str(db_path), cache_size=200)` to `OscalStore(db_path=str(db_path), cache_size=200, seed_from_bundled=False)`.

**File**: `tests/test_build_oscal_db.py`

**Specific Changes**:
5. **Verify existing test passes**: `test_build_db_empty_directories` should now pass with `docs_indexed=0` and `children=0`.

## Testing Strategy

### Validation Approach

The testing strategy follows a two-phase approach: first, surface counterexamples that demonstrate the bug on unfixed code, then verify the fix works correctly and preserves existing behavior.

### Exploratory Bug Condition Checking

**Goal**: Surface counterexamples that demonstrate the bug BEFORE implementing the fix. Confirm or refute the root cause analysis. If we refute, we will need to re-hypothesize.

**Test Plan**: Write a test that instantiates `OscalStore` with a non-existent `db_path` while a bundled DB is present, then counts documents. Run on UNFIXED code to observe the seeding behavior.

**Test Cases**:
1. **Empty directories test**: Call `build_db()` with empty source dirs, assert `docs_indexed == 0` (will fail on unfixed code with `docs_indexed == 232`)
2. **Direct OscalStore instantiation**: Create `OscalStore(db_path=new_path)` where `new_path` doesn't exist, count documents (will show 232 on unfixed code)
3. **Idempotency contamination**: Run `build_db()` twice with one source doc, compare counts (may show inconsistent counts on unfixed code)

**Expected Counterexamples**:
- `docs_indexed` is 232 (or 232 + N) instead of 0 (or N)
- Root cause confirmed: `_resolve_persistent()` unconditionally seeds from bundled DB

### Fix Checking

**Goal**: Verify that for all inputs where the bug condition holds, the fixed function produces the expected behavior.

**Pseudocode:**
```
FOR ALL input WHERE isBugCondition(input) DO
  store := OscalStore(db_path=input.db_path, seed_from_bundled=False)
  doc_count := store.count_documents()
  ASSERT doc_count == 0
  store.close()
END FOR
```

### Preservation Checking

**Goal**: Verify that for all inputs where the bug condition does NOT hold, the fixed function produces the same result as the original function.

**Pseudocode:**
```
FOR ALL input WHERE NOT isBugCondition(input) DO
  store_default := OscalStore(db_path=input.db_path)  # seed_from_bundled=True (default)
  ASSERT store_default behaves identically to original OscalStore
  store_default.close()
END FOR
```

**Testing Approach**: Property-based testing is recommended for preservation checking because:
- It generates many test cases automatically across the input domain
- It catches edge cases that manual unit tests might miss
- It provides strong guarantees that behavior is unchanged for all non-buggy inputs

**Test Plan**: Observe behavior on UNFIXED code first for default `OscalStore` instantiation, then write property-based tests capturing that behavior.

**Test Cases**:
1. **Default seeding preserved**: Instantiate `OscalStore(db_path=new_path)` (default `seed_from_bundled=True`) with a valid bundled DB present, verify documents are seeded
2. **Existing DB preserved**: Instantiate `OscalStore(db_path=existing_path)` where the file already exists, verify it opens without re-seeding
3. **Ephemeral mode preserved**: Instantiate `OscalStore()` with no path and no bundled DB, verify ephemeral mode
4. **scan_directory preserved**: After creating store with `seed_from_bundled=False`, call `scan_directory()` and verify documents are indexed correctly

### Unit Tests

- Test `OscalStore(db_path=new_path, seed_from_bundled=False)` produces empty DB
- Test `OscalStore(db_path=new_path, seed_from_bundled=True)` seeds from bundled DB (when present)
- Test `OscalStore(db_path=existing_path, seed_from_bundled=False)` opens existing DB unchanged
- Test `build_db()` with empty directories returns `docs_indexed=0`
- Test `build_db()` with one document returns `docs_indexed=1`

### Property-Based Tests

- Generate random `db_path` values (non-existent paths) and verify `seed_from_bundled=False` always produces zero documents
- Generate random `db_path` values and verify default `seed_from_bundled=True` preserves seeding behavior
- Generate random combinations of source directory contents and verify `build_db()` counts match only scanned documents

### Integration Tests

- Test full `build_db()` → `compute_sha256()` → `update_hashes_json()` pipeline with `seed_from_bundled=False`
- Test that `hatch run tests` passes with the fix applied (existing test suite)
- Test idempotency: run `build_db()` twice and verify identical stats
