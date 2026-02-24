# Implementation Plan: OSCAL MCP Server

## Overview

This implementation plan reflects the current state of the OSCAL MCP Server. All core functionality is implemented and passing tests (262 passed, 1 skipped). The remaining work is adding property-based tests using Hypothesis to validate the 29 correctness properties from the design document.

## Tasks

- [x] 1. Core project structure and configuration management
  - Config class with all 11 fields (bedrock_model_id, knowledge_base_id, aws_profile, aws_region, log_level, server_name, transport, allow_remote_uris, request_timeout, max_uri_depth, component_definitions_dir)
  - Environment variable loading via dotenv with sensible defaults
  - CLI argument parsing and override via update_from_args()
  - Transport validation via validate_transport()
  - Logging configuration for all components
  - _Requirements: 4.1-4.12, 6.1, 6.6, 7.1-7.7_

- [ ]* 1.1 Write property test for configuration override precedence
  - **Property 7: Configuration Override Precedence**
  - **Validates: Requirements 4.1, 4.6**

- [ ]* 1.2 Write property test for invalid transport rejection
  - **Property 8: Invalid Transport Rejection**
  - **Validates: Requirements 7.5**

- [ ]* 1.3 Write property test for log level configuration
  - **Property 9: Log Level Configuration**
  - **Validates: Requirements 6.1, 6.6**

- [x] 2. OSCAL model definitions and utilities
  - OSCALModelType enumeration in tools/utils.py
  - schema_names mapping for all model types
  - try_notify_client_error() and safe_log_mcp() helpers
  - verify_package_integrity() for SHA-256 hash verification
  - _Requirements: 2.3-2.5, 3.7, 18.1-18.8_

- [x] 3. Implement list_oscal_models tool
  - Tool function with @tool decorator returning all 8 OSCAL model types
  - Model metadata: description, layer, formalName, shortName, status
  - Unit tests passing
  - _Requirements: 2.1-2.5_

- [ ]* 3.1 Write property test for model metadata validity
  - **Property 3: Model Metadata Validity**
  - **Validates: Requirements 2.2, 2.4, 2.5**

- [x] 4. Implement get_oscal_schema tool
  - Schema retrieval with model name and schema type validation
  - Support for JSON and XSD formats
  - Model name aliasing (complete, ssp, poam, etc.)
  - open_schema_file() with path resolution relative to package
  - Unit tests passing
  - _Requirements: 3.1-3.8, 8.1-8.6_

- [ ]* 4.1 Write property test for schema format consistency
  - **Property 4: Schema Format Consistency**
  - **Validates: Requirements 3.1, 3.2, 3.3, 8.6**

- [ ]* 4.2 Write property test for invalid schema input error handling
  - **Property 5: Invalid Schema Input Error Handling**
  - **Validates: Requirements 3.5, 3.6**

- [ ]* 4.3 Write property test for schema file system consistency
  - **Property 6: Schema File System Consistency**
  - **Validates: Requirements 8.2, 8.3**

- [x] 5. Implement query_oscal_documentation tool
  - AWS Bedrock Knowledge Base integration via boto3
  - AWS profile-based session management
  - query_kb() and query_local() (placeholder) implementations
  - Conditional tool registration based on knowledge_base_id
  - Unit tests passing
  - _Requirements: 1.1-1.6_

- [ ]* 5.1 Write property test for documentation query passthrough
  - **Property 1: Documentation Query Passthrough**
  - **Validates: Requirements 1.1, 1.2**

- [ ]* 5.2 Write property test for AWS profile session creation
  - **Property 2: AWS Profile Session Creation**
  - **Validates: Requirements 1.5**

- [x] 6. Implement list_oscal_resources tool
  - Read and return awesome-oscal.md from oscal_docs directory
  - UTF-8 encoding with latin-1 fallback
  - Error handling for file not found, I/O errors, encoding issues
  - Unit tests passing
  - _Requirements: 9.1-9.7_

- [ ]* 6.1 Write property test for OSCAL resources content preservation
  - **Property 28: OSCAL Resources Content Preservation**
  - **Validates: Requirements 9.1, 9.3, 9.6**

- [x] 7. Implement ComponentDefinitionStore
  - Singleton class with 9 index dictionaries (cdefs by path/UUID/title, components by UUID/title, capabilities by UUID/name, parent tracking)
  - Case-insensitive title/name indexing
  - Stats tracking dictionary
  - _reset() method for clearing state
  - _index_components() for indexing cdefs and their children
  - _Requirements: 10.1-10.12_

- [ ]* 7.1 Write property test for component definition indexing completeness
  - **Property 12: Component Definition Indexing Completeness**
  - **Validates: Requirements 10.2, 10.3, 10.4**

- [ ]* 7.2 Write property test for parent relationship tracking
  - **Property 13: Parent Relationship Tracking**
  - **Validates: Requirements 10.5, 10.6**

- [ ]* 7.3 Write property test for directory reset on explicit path
  - **Property 14: Directory Reset on Explicit Path**
  - **Validates: Requirements 10.11**

- [ ]* 7.4 Write property test for loading statistics accuracy
  - **Property 15: Loading Statistics Accuracy**
  - **Validates: Requirements 10.12**

- [x] 8. Implement directory loading (JSON and zip)
  - load_from_directory() with recursive scanning
  - _process_zip_files() and _handle_zip_file() for zip archives
  - _process_json_files() using trestle ComponentDefinition.oscal_read()
  - Graceful error handling per-file (log and continue)
  - Module-level _store.load_from_directory() call at import time
  - Unit tests passing
  - _Requirements: 10.1, 10.7-10.10_

- [x] 9. Implement external URI loading
  - load_external_component_definition() for local zip and remote URIs
  - Remote URI gating via config.allow_remote_uris
  - HTTP fetching with configurable timeout
  - Error handling for timeout, network errors, JSON parse errors
  - Unit tests passing
  - _Requirements: 16.1-16.7_

- [ ]* 9.1 Write property test for external URI validation
  - **Property 25: External URI Validation**
  - **Validates: Requirements 16.2, 16.3**

- [ ]* 9.2 Write property test for remote component definition loading
  - **Property 26: Remote Component Definition Loading**
  - **Validates: Requirements 16.4**

- [x] 10. Implement query_component_definition tool
  - Thin MCP wrapper delegating to _store.query()
  - component_definition_filter parameter (UUID or title)
  - query_type: all, by_uuid, by_title, by_type
  - Capability-first query integration (checks capabilities before components)
  - Title fallback to prop value search via find_component_by_prop_value()
  - Type filtering via filter_components_by_type()
  - Raw-only return format
  - Unit tests passing
  - _Requirements: 11.1-11.12_

- [x] 10.1 Write property test for component definition filter scoping
  - **Property 16: Component Definition Filter Scoping**
  - **Validates: Requirements 11.2**

- [ ]* 10.2 Write property test for capability query integration
  - **Property 17: Capability Query Integration**
  - **Validates: Requirements 11.5, 11.6, 11.7**

- [ ]* 10.3 Write property test for title fallback to prop value search
  - **Property 18: Title Fallback to Prop Value Search**
  - **Validates: Requirements 11.8**

- [ ]* 10.4 Write property test for component type filtering accuracy
  - **Property 19: Component Type Filtering Accuracy**
  - **Validates: Requirements 11.9**

- [ ]* 10.5 Write property test for query response structure
  - **Property 20: Query Response Structure**
  - **Validates: Requirements 11.10**

- [ ]* 10.6 Write property test for invalid tool parameter rejection
  - **Property 11: Invalid Tool Parameter Rejection**
  - **Validates: Requirements 6.7, 11.4**

- [x] 11. Implement list_component_definitions tool
  - Thin MCP wrapper delegating to _store.list_component_definitions()
  - Returns uuid, title, componentCount, importedComponentDefinitionsCount, sizeInBytes
  - RuntimeError when no cdefs loaded
  - Unit tests passing
  - _Requirements: 12.1-12.3_

- [ ]* 11.1 Write property test for list component definitions completeness
  - **Property 21: List Component Definitions Completeness**
  - **Validates: Requirements 12.1, 12.2**

- [x] 12. Implement list_components tool
  - Thin MCP wrapper delegating to _store.list_components()
  - Returns uuid, title, parentComponentDefinitionTitle, parentComponentDefinitionUuid, sizeInBytes
  - RuntimeError when no components loaded
  - Unit tests passing
  - _Requirements: 13.1-13.3_

- [ ]* 12.1 Write property test for list components completeness
  - **Property 22: List Components Completeness**
  - **Validates: Requirements 13.1, 13.2**

- [x] 13. Implement list_capabilities tool
  - Thin MCP wrapper delegating to _store.list_capabilities()
  - Returns uuid, name, parentComponentDefinitionTitle, parentComponentDefinitionUuid, sizeInBytes
  - Returns empty list (no error) when no capabilities loaded
  - Unit tests passing
  - _Requirements: 14.1-14.3_

- [ ]* 13.1 Write property test for list capabilities completeness
  - **Property 23: List Capabilities Completeness**
  - **Validates: Requirements 14.1, 14.2**

- [x] 14. Implement get_capability tool
  - Direct dict lookup on _store._capabilities_by_uuid
  - Returns full Capability dict or None
  - Unit tests passing
  - _Requirements: 15.1-15.2_

- [ ]* 14.1 Write property test for get capability correctness
  - **Property 24: Get Capability Correctness**
  - **Validates: Requirements 15.1, 15.2**

- [x] 15. Implement about tool
  - Defined inline in _setup_tools() using @mcp.tool decorator
  - Returns version, keywords from package metadata, oscal-version "1.2.0"
  - Unit tests passing
  - _Requirements: 17.1-17.3_

- [x] 16. FastMCP server integration and tool registration
  - Module-level mcp = FastMCP(...) instance
  - _setup_tools() registers all tools, conditionally registers query_oscal_documentation
  - Server instructions describing OSCAL capabilities
  - Transport selection (stdio default, streamable-http)
  - Integrity verification at startup (oscal_schemas, oscal_docs, component_definitions)
  - Exit code 2 on integrity failure, exit code 1 on transport validation failure
  - Unit and integration tests passing
  - _Requirements: 5.1-5.9, 18.1-18.8_

- [ ]* 16.1 Write property test for error logging and client notification
  - **Property 10: Error Logging and Client Notification**
  - **Validates: Requirements 1.6, 6.2, 6.5, 6.7**

- [ ]* 16.2 Write property test for integrity verification
  - **Property 27: Integrity Verification**
  - **Validates: Requirements 18.5, 18.6, 18.7**

- [x] 17. Implement OSCAL Agent module
  - create_oscal_agent() in oscal_agent.py
  - Strands Agent with BedrockModel using configured profile/region
  - System prompt describing OSCAL expertise
  - load_tools_from_directory=True
  - _Requirements: 19.1-19.4_

- [ ]* 17.1 Write property test for agent profile and region configuration
  - **Property 29: Agent Profile and Region Configuration**
  - **Validates: Requirements 19.2**

- [x] 18. Comprehensive unit test suite
  - 262 tests passing, 1 skipped
  - Test files: test_config.py, test_file_integrity.py, test_file_integrity_integration.py, test_file_integrity_utils.py, test_integration.py, test_main.py, test_utils.py
  - Tool tests: test_get_schema.py, test_list_models.py, test_list_oscal_resources.py, test_query_component_definition.py, test_query_documentation.py
  - _Requirements: All_

- [ ] 19. Add Hypothesis dependency and configure property-based testing
  - Add hypothesis to devtest dependency group in pyproject.toml
  - Configure Hypothesis settings for minimum 100 iterations per test
  - Set up custom generators for OSCAL test data (ComponentDefinitions, Components, Capabilities, UUIDs)
  - _Requirements: All requirements covered by correctness properties_

- [ ] 20. Implement property-based tests for all 29 correctness properties
  - Implement Properties 1-29 from the design document as Hypothesis property tests
  - Tag each test with feature and property information
  - Mock external dependencies (AWS Bedrock, HTTP, file system)
  - Run with: `hatch test tests/test_properties.py`
  - _Requirements: All requirements covered by correctness properties_

## Notes

- Tasks marked with `*` are optional property-based tests that can be skipped for faster MVP
- All core implementation is complete - only property-based tests remain
- Run full test suite: `hatch test`
- Run type checking + tests + coverage: `hatch run devtest:tests`
- Run specific test: `hatch test <path/to/test::TestName>`
- Run type checking alone: `hatch run devtest:typing`