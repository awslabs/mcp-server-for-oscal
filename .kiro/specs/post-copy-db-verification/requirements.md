# Requirements Document

## Introduction

Add post-copy SHA-256 hash verification to all OscalStore database seeding paths. Currently, the bundled DB integrity is verified before copying but not after. A corrupted copy results in a silently broken server. This feature ensures every copied DB file is verified against the expected hash from `hashes.json` before use, and raises a fatal error on mismatch. Additionally, the brittle `test_new_path_with_bundled_db_seeds` test with a hardcoded document count is removed since runtime verification supersedes it.

## Glossary

- **OscalStore**: The SQLite-backed store class in `oscal_store.py` that manages all OSCAL model types.
- **Bundled_DB**: The pre-built `oscal_store.db` file shipped with the package at `BUNDLED_DB_PATH`.
- **Hashes_Manifest**: The `hashes.json` file at `BUNDLED_HASHES_PATH` containing expected SHA-256 hashes for bundled files.
- **Post_Copy_Verification**: SHA-256 hash comparison of a copied file against the expected hash in the Hashes_Manifest.
- **Seeding**: The process of copying the Bundled_DB to a new path to initialize a persistent or temporary database.

## Requirements

### Requirement 1

**User Story:** As a server operator, I want the copied database file to be verified after copying, so that a corrupted copy is detected before the server uses it.

#### Acceptance Criteria

1. WHEN the OscalStore copies the Bundled_DB to a persistent path via `_resolve_persistent`, THE OscalStore SHALL compute the SHA-256 hash of the copied file and compare it against the expected hash from the Hashes_Manifest.
2. WHEN the OscalStore copies the Bundled_DB to a temporary path via `_copy_bundled_to_temp`, THE OscalStore SHALL compute the SHA-256 hash of the copied file and compare it against the expected hash from the Hashes_Manifest.
3. IF the Post_Copy_Verification fails (hash mismatch), THEN THE OscalStore SHALL raise a RuntimeError with a message containing the expected hash, the actual hash, and the destination path.
4. IF the Post_Copy_Verification fails, THEN THE OscalStore SHALL remove the corrupted copy before raising the error.

### Requirement 2

**User Story:** As a developer, I want hash-reading logic extracted into a shared helper, so that hashes.json parsing is not duplicated across methods.

#### Acceptance Criteria

1. THE OscalStore SHALL provide a private method that reads the expected hash for `oscal_store.db` from the Hashes_Manifest and returns the hash string.
2. THE `_verify_bundled_db` method SHALL use the shared hash-reading method instead of inline hashes.json parsing.
3. THE Post_Copy_Verification logic SHALL use the same shared hash-reading method.

### Requirement 3

**User Story:** As a developer, I want the brittle hardcoded-count test removed, so that the test suite does not break when bundled DB content changes.

#### Acceptance Criteria

1. WHEN the test suite is executed, THE test suite SHALL NOT contain the `test_new_path_with_bundled_db_seeds` test method.
2. THE `TestPreservationDefaultSeeding` class docstring SHALL remain accurate after the test removal.
3. THE remaining tests in `TestPreservationDefaultSeeding` SHALL continue to pass without modification.
