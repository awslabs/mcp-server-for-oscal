# Requirements Document

## Introduction

Update all project README and documentation files to accurately reflect the v0.4.0 release of MCP Server for OSCAL. The release introduced ~30 new query/list tools via the OSCAL Store, agent session persistence, conversation management, pagination support, and structural changes (bundled content moved to `data/` directory, new files added). Documentation must be brought into alignment with the current codebase.

## Glossary

- **Tools_README**: The file `src/mcp_server_for_oscal/tools/README.md`
- **Main_README**: The file `README.md` at the project root
- **DEVELOPING_Doc**: The file `DEVELOPING.md` at the project root
- **Schemas_README**: The file `src/mcp_server_for_oscal/oscal_schemas/README.md`
- **POWER_Doc**: The file `conf/powers/oscal/POWER.md`
- **Query_Tools**: The ~30 new tools defined in `query_oscal_models.py` (query/list pairs for each OSCAL model type, child element list tools, `text_search_oscal`, `get_child_element`)
- **Original_Tools**: The 12 tools documented prior to v0.4.0
- **OSCAL_Store**: The SQLite-backed content indexing system in `oscal_store.py`

## Requirements

### Requirement 1

**User Story:** As a developer evaluating the MCP server, I want the tools README to list all available tools so that I can understand the full capabilities of the server.

#### Acceptance Criteria

1. THE Tools_README SHALL list all registered tools including both Original_Tools and Query_Tools in the Available Tools table
2. WHEN a Query_Tool is listed, THE Tools_README SHALL include the tool name and a brief description in the table
3. THE Tools_README SHALL document Query_Tools with a lighter treatment than Original_Tools: a shared description of common parameters (query_type, query_value, offset, limit, parent_doc_uuid) and return format (Page_Response), rather than per-tool detailed sections
4. THE Tools_README SHALL document `text_search_oscal` and `get_child_element` with their unique parameters since they differ from the standard query/list pattern
5. THE Tools_README SHALL update the Implementation Details section to reference new modules (`oscal_store.py`, `query_oscal_models.py`) and the OSCAL_Store dependency
6. THE Tools_README SHALL update the Configuration section to include OSCAL_Store environment variables (`OSCAL_DOCUMENTS_DIR`, `OSCAL_STORE_DB_PATH`, `OSCAL_STORE_CACHE_SIZE`)

### Requirement 2

**User Story:** As a user reading the POWER.md, I want the Available Tools table to reflect all current tools so that I can discover and use the full tool set.

#### Acceptance Criteria

1. THE POWER_Doc SHALL list all registered tools including Query_Tools in the Available Tools table
2. THE POWER_Doc SHALL add Key Tool Parameters entries for the common query/list tool parameters and for `text_search_oscal`
3. THE POWER_Doc SHALL add at least one Tool Usage Example demonstrating a Query_Tool (e.g. `query_catalog` or `text_search_oscal`)

### Requirement 3

**User Story:** As a developer setting up the project, I want DEVELOPING.md to accurately describe the project structure and environment variables so that I can navigate and configure the project correctly.

#### Acceptance Criteria

1. THE DEVELOPING_Doc SHALL update the Project Structure tree to reflect the current directory layout: `data/` directory at root containing `component_definitions/` and `oscal_docs/`, removal of those directories from under `src/mcp_server_for_oscal/`, and addition of new files (`oscal_store.py`, `query_oscal_models.py`, `oscal_store.db`, `hashes.json`, `server.json`)
2. THE DEVELOPING_Doc SHALL include `OSCAL_DOCUMENTS_DIR`, `OSCAL_STORE_DB_PATH`, and `OSCAL_STORE_CACHE_SIZE` in the Environment Variables table
3. THE DEVELOPING_Doc Project Structure tree SHALL remove `oscal_docs/` and `component_definitions/` entries from under `src/mcp_server_for_oscal/`

### Requirement 4

**User Story:** As a contributor, I want the OSCAL schemas README to state the correct OSCAL version so that I know which schema version is bundled.

#### Acceptance Criteria

1. THE Schemas_README SHALL state OSCAL version 1.2.1 instead of 1.2.0 in the description of how schema files are populated

### Requirement 5

**User Story:** As a user reading the main README, I want it to accurately reflect the current tool count and new capabilities so that I have a correct overview of the project.

#### Acceptance Criteria

1. WHEN the Main_README references tool count or tool capabilities, THE Main_README SHALL reflect the current total of approximately 42 tools rather than 12
2. THE Main_README SHALL remain accurate for sections already covering OSCAL Store, Session Persistence, and Conversation Management (verify no stale references)
