# Requirements Document

## Introduction

The published `mcp-server-for-oscal` package currently bundles raw `oscal_docs/` markdown files and `component_definitions/` zipped JSON files inside the package directory alongside the pre-built `oscal_store.db` SQLite database. Since the database already contains all indexed content from these directories (built at release time by `bin/build_oscal_db.py`), the raw files are redundant at runtime. This feature:

1. Moves the raw content directories (`oscal_docs/` and `component_definitions/`) from `src/mcp_server_for_oscal/` to a top-level `data/` directory in the repository, making them build-time-only inputs.
2. Excludes them from the published wheel so the package ships only the pre-built DB.
3. Preserves the `oscal_schemas/` directory inside the package (served directly by the `get_oscal_schema` tool at runtime).
4. Keeps the `oscal_store.db` inside the package structure (`src/mcp_server_for_oscal/oscal_store.db`) since it needs to be resolvable via `__file__`-relative paths after installation.

## Glossary

- **Package**: The published Python wheel/sdist for `mcp-server-for-oscal` installed by end users.
- **Bundled_DB**: The pre-built SQLite database file `oscal_store.db` shipped inside the package at `src/mcp_server_for_oscal/oscal_store.db`, containing all indexed OSCAL content.
- **Raw_Content_Directories**: The `oscal_docs/` and `component_definitions/` directories that contain source markdown and zipped JSON files. Currently at `src/mcp_server_for_oscal/`; to be moved to `data/` at the repository root.
- **Data_Directory**: The new top-level `data/` directory in the repository that holds Raw_Content_Directories as build-time-only inputs.
- **Build_Script**: The `bin/build_oscal_db.py` script that scans Raw_Content_Directories and produces the Bundled_DB at release time.
- **Startup_Code**: The `_init_oscal_store()` function in `main.py` and the integrity verification logic in `main()` and `oscal_agent.main()`.
- **Integrity_Verifier**: The `verify_package_integrity()` function in `tools/utils.py` that checks SHA-256 hashes of bundled files against `hashes.json` manifests.
- **Packaging_Config**: The `[tool.hatch.build]` section in `pyproject.toml` that controls which files are included in the published Package.
- **Rehash_Script**: The `hatch run rehash` command defined in `pyproject.toml` that regenerates `hashes.json` manifests for bundled content directories.

## Requirements

### Requirement 1: Move Raw Content to Top-Level Data Directory

**User Story:** As a developer, I want the raw content directories moved out of the package source tree into a top-level `data/` directory, so that build-time inputs are clearly separated from runtime package contents.

#### Acceptance Criteria

1. THE repository SHALL contain a top-level `data/` directory.
2. THE `oscal_docs/` directory SHALL be moved from `src/mcp_server_for_oscal/oscal_docs/` to `data/oscal_docs/`.
3. THE `component_definitions/` directory SHALL be moved from `src/mcp_server_for_oscal/component_definitions/` to `data/component_definitions/`.
4. THE `oscal_schemas/` directory SHALL remain at `src/mcp_server_for_oscal/oscal_schemas/` (it is served directly at runtime).
5. THE `oscal_store.db` file SHALL remain at `src/mcp_server_for_oscal/oscal_store.db` (it is resolved via `__file__`-relative paths at runtime).
6. ALL references to the old paths in the Build_Script, Rehash_Script, and documentation SHALL be updated to point to the new `data/` locations.

### Requirement 2: Exclude Raw Content Directories from Published Package

**User Story:** As a package maintainer, I want the `oscal_docs/` and `component_definitions/` directories excluded from the published wheel, so that the package size is reduced without losing functionality.

#### Acceptance Criteria

1. THE Packaging_Config SHALL exclude the `data/oscal_docs/` directory and all of its contents from the published wheel.
2. THE Packaging_Config SHALL exclude the `data/component_definitions/` directory and all of its contents from the published wheel.
3. THE Packaging_Config SHALL include the `oscal_schemas/` directory and all of its contents (schema files and `hashes.json` manifest) in the published wheel.
4. THE Packaging_Config SHALL include the `oscal_store.db` file in the published wheel.
5. THE Packaging_Config SHALL include the package-level `hashes.json` file in the published wheel.
6. THE Packaging_Config SHALL NOT exclude the `data/` directory from the sdist, so that source builds can produce the Bundled_DB.

### Requirement 3: Remove Redundant Raw Content Scanning from Startup

**User Story:** As a developer, I want the startup code to stop scanning raw content directories that no longer exist in the package, so that startup is clean and free of unnecessary file-system probes.

#### Acceptance Criteria

1. THE Startup_Code SHALL NOT call `scan_directory()` or `verify_package_integrity()` on the `component_definitions/` directory when initializing the OscalStore.
2. THE Startup_Code SHALL NOT call `scan_directory()` or `verify_package_integrity()` on the bundled `oscal_docs/` directory when initializing the OscalStore.
3. WHEN a user-configured `oscal_documents_dir` is provided, THE Startup_Code SHALL scan that external directory into the OscalStore.
4. IF a user-configured `oscal_documents_dir` is provided and the directory does not exist, THEN THE Startup_Code SHALL log a warning and continue startup without scanning that directory.
5. THE Startup_Code SHALL continue to initialize the OscalStore from the Bundled_DB.

### Requirement 4: Remove Raw Content Integrity Checks from Startup

**User Story:** As a developer, I want the startup integrity verification to stop checking directories that are no longer bundled, so that startup does not fail due to missing directories.

#### Acceptance Criteria

1. THE Startup_Code in `main.py` SHALL NOT call the Integrity_Verifier for the `oscal_docs/` directory.
2. THE Startup_Code in `main.py` SHALL NOT call the Integrity_Verifier for the `component_definitions/` directory.
3. THE Startup_Code in `oscal_agent.py` SHALL NOT call the Integrity_Verifier for the `oscal_docs/` directory.
4. THE Startup_Code in `oscal_agent.py` SHALL NOT call the Integrity_Verifier for the `component_definitions/` directory.
5. THE Startup_Code in `main.py` SHALL call the Integrity_Verifier for the `oscal_schemas/` directory.
6. THE Startup_Code in `oscal_agent.py` SHALL call the Integrity_Verifier for the `oscal_schemas/` directory.
7. IF the Integrity_Verifier raises a RuntimeError or KeyError for the `oscal_schemas/` directory, THEN THE Startup_Code SHALL exit with status code 2.
8. THE Startup_Code SHALL continue to verify the Bundled_DB integrity via the package-level `hashes.json` manifest located at `src/mcp_server_for_oscal/hashes.json`.

### Requirement 5: Update Rehash Script Configuration

**User Story:** As a package maintainer, I want the `rehash` script to stop regenerating hash manifests for directories that are no longer bundled, so that the build workflow stays consistent with the package contents.

#### Acceptance Criteria

1. THE Rehash_Script SHALL NOT regenerate or stage `hashes.json` for the `oscal_docs/` directory.
2. THE Rehash_Script SHALL NOT regenerate or stage `hashes.json` for the `component_definitions/` directory.
3. THE Rehash_Script SHALL continue to regenerate `hashes.json` for the `oscal_schemas/` directory and stage the result.
4. THE Rehash_Script SHALL continue to stage the package-level `hashes.json` that records the Bundled_DB hash.
5. WHEN the Rehash_Script is executed, THE Rehash_Script SHALL complete without error.

### Requirement 6: Preserve Build Script Functionality

**User Story:** As a package maintainer, I want the build script to continue reading raw content directories at build time, so that the Bundled_DB is correctly populated before publishing.

#### Acceptance Criteria

1. WHEN the Build_Script is executed, THE Build_Script SHALL scan the `data/component_definitions/` directory and index all discovered documents into the Bundled_DB.
2. WHEN the Build_Script is executed, THE Build_Script SHALL scan the `data/oscal_docs/` directory and index all discovered documents into the Bundled_DB.
3. IF the `data/component_definitions/` directory is absent at build time, THEN THE Build_Script SHALL skip that directory and log an informational message.
4. IF the `data/oscal_docs/` directory is absent at build time, THEN THE Build_Script SHALL skip that directory and log an informational message.
5. WHEN the Build_Script completes, THE Build_Script SHALL produce an `oscal_store.db` file that contains at least 1 indexed document and at least 1 child element.
6. WHEN the Build_Script completes, THE Build_Script SHALL compute the SHA-256 hash of the produced `oscal_store.db` and record it under the `file_hashes` key in the package-level `hashes.json`.

### Requirement 7: Graceful Startup Without Raw Content

**User Story:** As an end user, I want the server to start successfully from the Bundled_DB alone, so that the removal of raw content directories does not break my workflow.

#### Acceptance Criteria

1. WHEN the `oscal_docs/` directory is absent, THE Startup_Code SHALL start the server process without raising an exception and without exiting with a non-zero exit code.
2. WHEN the `component_definitions/` directory is absent, THE Startup_Code SHALL start the server process without raising an exception and without exiting with a non-zero exit code.
3. WHEN the Bundled_DB is present and passes integrity verification, THE Startup_Code SHALL initialize the OscalStore in bundled mode and log a message indicating bundled mode was selected.
4. IF the Bundled_DB is missing, THEN THE Startup_Code SHALL create an ephemeral database, log a message indicating ephemeral mode was selected, and start the server process without raising an exception.
5. IF the Bundled_DB fails integrity verification, THEN THE Startup_Code SHALL create an ephemeral database, log a warning indicating the integrity failure and ephemeral fallback, and start the server process without raising an exception.
6. WHEN both the `oscal_docs/` and `component_definitions/` directories are absent and the Bundled_DB is present and passes integrity verification, THE Startup_Code SHALL initialize the OscalStore in bundled mode and all store-backed tools SHALL return results from the Bundled_DB.

### Requirement 8: Update Tests to Reflect New Package Layout

**User Story:** As a developer, I want the test suite to pass with the new package layout, so that CI remains green after the raw content directories are removed from the runtime package.

#### Acceptance Criteria

1. THE test suite SHALL NOT contain assertions that verify the `oscal_docs/` directory via the Integrity_Verifier at startup.
2. THE test suite SHALL NOT contain assertions that verify the `component_definitions/` directory via the Integrity_Verifier at startup.
3. THE test suite SHALL include at least one test that invokes the Integrity_Verifier on the `oscal_schemas/` directory and asserts it passes for a valid package.
4. THE test suite SHALL include at least one test that verifies the Bundled_DB hash entry in the package-level `hashes.json` is checked during startup.
5. WHEN tests for the Build_Script are executed, THE test suite SHALL verify that the Build_Script accepts `component_definitions/` and `oscal_docs/` directory paths as inputs and produces a Bundled_DB containing indexed content from those directories.
6. THE startup integration tests SHALL assert that the Startup_Code calls the Integrity_Verifier only for the `oscal_schemas/` directory and the package-level `hashes.json`, and not for `oscal_docs/` or `component_definitions/`.
