# Implementation Plan: Update READMEs for v0.4.0

## Overview

Update five documentation files to reflect the v0.4.0 release: expanded tool listings (~42 tools), OSCAL Store configuration, updated project structure, and corrected OSCAL schema version.

## Tasks

- [x] 1. Update `src/mcp_server_for_oscal/tools/README.md`
  - [x] 1.1 Expand the Available Tools table to include all ~42 tools (add rows for every tool from `query_oscal_models.py`: `query_catalog`, `list_catalogs`, `list_catalog_controls`, `list_catalog_groups`, `query_ssp`, `list_ssps`, `list_ssp_control_implementations`, `list_ssp_system_components`, `query_profile`, `list_profiles`, `list_profile_imports`, `list_profile_modify`, `query_assessment_plan`, `list_assessment_plans`, `list_assessment_plan_tasks`, `list_assessment_plan_activities`, `query_assessment_results`, `list_assessment_results`, `list_assessment_results_results`, `list_assessment_results_findings`, `query_poam`, `list_poams`, `list_poam_items`, `query_mapping_collection`, `list_mapping_collections`, `list_mapping_collection_mappings`, `text_search_oscal`, `get_child_element`)
    - _Requirements: 1.1, 1.2_
  - [x] 1.2 Add a new "Query & List Tools (OSCAL Store)" section after the existing per-tool docs describing the common pattern, shared parameters (`query_type`, `query_value`, `offset`, `limit`), return format (`Page_Response`), child element tools (`parent_doc_uuid`), and dedicated subsections for `text_search_oscal` and `get_child_element`
    - _Requirements: 1.3, 1.4_
  - [x] 1.3 Update the Implementation Details section to reference `oscal_store.py`, `query_oscal_models.py`, and the OscalStore dependency
    - _Requirements: 1.5_
  - [x] 1.4 Update the Configuration section to add `OSCAL_DOCUMENTS_DIR`, `OSCAL_STORE_DB_PATH`, `OSCAL_STORE_CACHE_SIZE`
    - _Requirements: 1.6_

- [x] 2. Update `conf/powers/oscal/POWER.md`
  - [x] 2.1 Expand the Available Tools table to include all ~30 new query/list tools with brief descriptions
    - _Requirements: 2.1_
  - [x] 2.2 Add Key Tool Parameters entries for common query/list parameters, `text_search_oscal`, and `get_child_element`
    - _Requirements: 2.2_
  - [x] 2.3 Add Tool Usage Examples for `query_catalog`, `list_catalogs`, and `text_search_oscal`
    - _Requirements: 2.3_

- [x] 3. Update `DEVELOPING.md`
  - [x] 3.1 Rewrite the Project Structure tree: add `data/` directory at root with `component_definitions/` and `oscal_docs/`, remove those from `src/mcp_server_for_oscal/`, add `oscal_store.py` and `query_oscal_models.py` to `tools/`, add `oscal_store.db` and `hashes.json` to package root, add `server.json` to project root
    - _Requirements: 3.1, 3.3_
  - [x] 3.2 Add `OSCAL_DOCUMENTS_DIR`, `OSCAL_STORE_DB_PATH`, and `OSCAL_STORE_CACHE_SIZE` to the Environment Variables table
    - _Requirements: 3.2_

- [x] 4. Update `src/mcp_server_for_oscal/oscal_schemas/README.md`
  - [x] 4.1 Change "OSCAL version 1.2.0" to "OSCAL version 1.2.1" in the "How Schema Files Are Populated" section
    - _Requirements: 4.1_

- [x] 5. Verify `README.md` accuracy
  - [x] 5.1 Review the main README for any stale tool count references or outdated information and correct them; verify OSCAL Store, Session Persistence, and Conversation Management sections are accurate
    - _Requirements: 5.1, 5.2_

- [x] 6. Final checkpoint
  - Ensure all documentation changes are consistent across files, ask the user if questions arise.

## Notes

- This is a documentation-only change — no code logic is modified
- No property-based tests are applicable for documentation updates
- The canonical tool list is defined in `src/mcp_server_for_oscal/tools/__init__.py` — use it as the source of truth for tool names
- Tool descriptions can be derived from the docstrings in `query_oscal_models.py`
