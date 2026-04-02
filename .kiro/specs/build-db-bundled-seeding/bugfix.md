# Bugfix Requirements Document

## Introduction

The `build_db()` function in `bin/build_oscal_db.py` is intended to build a fresh OSCAL SQLite database by scanning source directories and indexing their contents. However, when a pre-packaged bundled database (`oscal_store.db`) is present in the package, `build_db()` inadvertently seeds from it instead of starting empty. This causes the test `test_build_db_empty_directories` to fail (`assert 232 == 0`) and breaks the release automation pipeline (`hatch run release`).

The root cause is that `build_db()` deletes the existing DB file, then creates an `OscalStore` with the same path. Since the file no longer exists, `OscalStore._resolve_persistent()` detects the bundled DB, verifies its integrity, and copies it to the target path — pre-populating the "fresh" database with 232 documents.

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN `build_db()` is called with a `db_path` that does not yet exist (or was just deleted) AND a valid bundled DB exists at `BUNDLED_DB_PATH` THEN the system seeds the new database from the bundled DB, resulting in a non-empty database containing pre-existing documents (e.g., 232 docs)

1.2 WHEN `build_db()` is called with empty source directories AND a valid bundled DB exists THEN the system returns `docs_indexed=232` (or the bundled count) instead of `docs_indexed=0`, causing `test_build_db_empty_directories` to fail

1.3 WHEN the release automation pipeline runs `hatch run release` AND the bundled DB is present THEN the pipeline fails because `test_build_db_empty_directories` fails with `assert 232 == 0`

### Expected Behavior (Correct)

2.1 WHEN `build_db()` is called THEN the system SHALL create a completely empty database regardless of whether a bundled DB exists, so that `docs_indexed` reflects only documents scanned from the provided source directories

2.2 WHEN `build_db()` is called with empty source directories THEN the system SHALL return `docs_indexed=0` and `children=0`

2.3 WHEN the release automation pipeline runs `hatch run release` THEN the system SHALL pass all tests including `test_build_db_empty_directories`

### Unchanged Behavior (Regression Prevention)

3.1 WHEN `OscalStore` is instantiated at runtime (without `build_db`) with a missing DB path AND a valid bundled DB exists THEN the system SHALL CONTINUE TO seed from the bundled DB as before

3.2 WHEN `OscalStore` is instantiated at runtime with an existing DB path THEN the system SHALL CONTINUE TO open the existing persistent DB without modification

3.3 WHEN `OscalStore` is instantiated at runtime with no explicit path and no bundled DB THEN the system SHALL CONTINUE TO create an ephemeral database

3.4 WHEN `build_db()` is called with non-empty source directories THEN the system SHALL CONTINUE TO scan and index all documents from those directories correctly
