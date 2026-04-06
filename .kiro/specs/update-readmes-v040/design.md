# Design Document: Update READMEs for v0.4.0

## Overview

This is a documentation-only change. No code logic is modified. Five documentation files are updated to reflect the v0.4.0 release state of MCP Server for OSCAL.

## Architecture

No architectural changes. All work is editing existing Markdown files.

## Files to Modify

### 1. `src/mcp_server_for_oscal/tools/README.md`

**Available Tools table**: Expand from 12 rows to ~42 rows. New rows cover all tools from `query_oscal_models.py` plus the `about` tool already documented.

**New section — "Query & List Tools (OSCAL Store)"**: Add a shared section after the per-tool detailed docs (tool 12) that describes:
- The common pattern: every OSCAL model type has a `query_<model>` and `list_<model>` tool pair
- Common parameters: `query_type` (all/by_uuid/by_title/by_type), `query_value`, `offset`, `limit`
- Common return format: `Page_Response` dict with keys `items`, `total`, `offset`, `limit`, `hasMore`
- Child element list tools: `list_<model>_<element>` tools with `parent_doc_uuid` parameter
- Dedicated subsections for `text_search_oscal` (unique `query_text` and `oscal_model_type` params) and `get_child_element` (unique `element_id` and `parent_doc_uuid` params)

**Implementation Details section**: Add references to `oscal_store.py` and `query_oscal_models.py`.

**Configuration section**: Add `OSCAL_DOCUMENTS_DIR`, `OSCAL_STORE_DB_PATH`, `OSCAL_STORE_CACHE_SIZE`.

### 2. `conf/powers/oscal/POWER.md`

**Available Tools table**: Add all ~30 new tools with brief descriptions.

**Key Tool Parameters**: Add entries for:
- Common query/list parameters (`query_type`, `query_value`, `offset`, `limit`)
- `text_search_oscal` parameters (`query_text`, `oscal_model_type`)
- `get_child_element` parameters (`element_id`, `parent_doc_uuid`)

**Tool Usage Examples**: Add examples for `query_catalog`, `list_catalogs`, `text_search_oscal`.

### 3. `DEVELOPING.md`

**Project Structure tree**: 
- Add `data/` directory at root level with `component_definitions/` and `oscal_docs/` subdirectories
- Remove `oscal_docs/` and `component_definitions/` from under `src/mcp_server_for_oscal/`
- Add `oscal_store.py` and `query_oscal_models.py` to `tools/` listing
- Add `oscal_store.db` and `hashes.json` to `src/mcp_server_for_oscal/` listing
- Add `server.json` to root listing

**Environment Variables table**: Add three new rows for `OSCAL_DOCUMENTS_DIR`, `OSCAL_STORE_DB_PATH`, `OSCAL_STORE_CACHE_SIZE`.

### 4. `src/mcp_server_for_oscal/oscal_schemas/README.md`

**Single line change**: Replace "OSCAL version 1.2.0" with "OSCAL version 1.2.1" in the "How Schema Files Are Populated" section.

### 5. `README.md`

**Verify accuracy**: The main README already has sections for OSCAL Store, Session Persistence, Conversation Management. Verify these are accurate and update any stale tool count references. The Features section mentions "tools" generically without a count, so the main update is ensuring no stale references exist.

## Data Models

No data model changes.

## Error Handling

Not applicable — documentation only.

## Correctness Properties

All acceptance criteria are documentation content checks (EXAMPLE classification). No universal properties are applicable for documentation-only changes. Verification is done by manual review of the updated files.

No testable properties.
