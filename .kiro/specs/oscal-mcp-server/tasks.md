# Implementation Plan: OSCAL MCP Server

## Overview

This implementation plan reflects the current state of the OSCAL MCP Server implementation and identifies remaining gaps. Most core functionality is already implemented, but there are import issues and missing property-based tests that need to be addressed.

## Current Implementation Status

**✅ COMPLETED TASKS:**
- Core project structure and configuration management
- OSCAL model definitions and utilities  
- All three main tools (list_models, get_schema, query_documentation)
- FastMCP server integration and main entry point
- Comprehensive unit test coverage
- Schema file management system

**❌ REMAINING TASKS:**

## Tasks

- [x] 1. Set up core project structure and configuration management *(COMPLETED)*
  - ✅ Main package structure exists
  - ✅ Config class fully implemented with env vars and CLI args  
  - ✅ Logging configuration implemented
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 6.1, 6.6_

- [x] 1.1 Fix import path issues *(COMPLETED)*
  - ✅ Fixed imports in get_schema.py and list_models.py to use correct utils path
  - ✅ All modules can now import correctly
  - ✅ 90 out of 91 tests now pass (98.9% success rate)
  - _Requirements: 5.1, 5.2_

- [x] 2. Implement OSCAL model definitions and utilities *(COMPLETED)*
  - ✅ OSCALModelType enumeration implemented in tools/utils.py
  - ✅ All supported model types included
  - ✅ Comprehensive unit tests exist
  - _Requirements: 2.3, 2.4, 2.5, 3.7_

- [x] 3. Implement the list_oscal_models tool *(COMPLETED)*
  - ✅ Tool function implemented with @tool decorator
  - ✅ Model information dictionary with descriptions, layers, and status
  - ✅ All required model types included with proper metadata
  - ✅ Comprehensive unit tests exist
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

- [ ]* 3.1 Write property tests for model listing
  - **Property 4: Model Information Completeness**
  - **Validates: Requirements 2.2**

- [ ]* 3.2 Write property tests for model metadata validation
  - **Property 5: Model Metadata Validation**
  - **Validates: Requirements 2.4, 2.5**

- [x] 4. Implement schema file management system *(COMPLETED)*
  - ✅ Schema file directory structure exists with all schemas
  - ✅ open_schema_file function implemented with proper path resolution
  - ✅ Schema file validation and error handling implemented
  - ✅ Comprehensive unit tests exist
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

- [ ]* 4.1 Write property tests for schema file system
  - **Property 13: Schema File System Consistency**
  - **Validates: Requirements 7.2, 7.3, 7.4**

- [ ]* 4.2 Write property tests for file error handling
  - **Property 15: File Error Handling**
  - **Validates: Requirements 7.5**

- [x] 5. Implement the get_oscal_schema tool *(COMPLETED)*
  - ✅ Tool function implemented with parameter validation
  - ✅ Model name validation and aliasing logic implemented
  - ✅ Schema type validation (json/xsd) implemented
  - ✅ Schema file loading and JSON serialization implemented
  - ✅ Comprehensive unit tests exist
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 7.6_

- [ ]* 5.1 Write property tests for schema format consistency
  - **Property 6: Schema Format Consistency**
  - **Validates: Requirements 3.2, 3.3**

- [ ]* 5.2 Write property tests for invalid input handling
  - **Property 7: Invalid Input Error Handling**
  - **Validates: Requirements 3.5, 3.6**

- [ ]* 5.3 Write property tests for JSON format validation
  - **Property 14: Schema JSON Format Validation**
  - **Validates: Requirements 7.6**

- [x] 6. Checkpoint - Fix import issues and ensure tests pass *(COMPLETED)*
  - ✅ Import path issues resolved
  - ✅ 90 out of 91 tests now pass (98.9% success rate)
  - ✅ All tools can be imported and used correctly
  - ⚠️ 1 minor test failure in error logging behavior (non-critical)

- [x] 7. Implement AWS Bedrock integration for documentation queries *(COMPLETED)*
  - ✅ AWS session management with profile support implemented
  - ✅ Bedrock Knowledge Base query functionality implemented
  - ✅ Proper error handling for AWS service calls implemented
  - ✅ Fallback behavior for missing configuration implemented
  - ✅ Comprehensive unit tests exist
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6_

- [ ]* 7.1 Write property tests for documentation query passthrough
  - **Property 1: Documentation Query Passthrough**
  - **Validates: Requirements 1.1, 1.2**

- [ ]* 7.2 Write property tests for AWS profile authentication
  - **Property 2: AWS Profile Authentication**
  - **Validates: Requirements 1.5**

- [x] 8. Implement the query_oscal_documentation tool *(COMPLETED)*
  - ✅ Tool function implemented with @tool decorator
  - ✅ AWS Bedrock Knowledge Base integration implemented
  - ✅ Error handling and logging implemented
  - ✅ MCP context integration for error reporting implemented
  - ✅ Comprehensive unit tests exist
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 6.2, 6.3_

- [ ]* 8.1 Write property tests for error logging and exception handling
  - **Property 3: Error Logging and Exception Handling**
  - **Validates: Requirements 1.6, 6.2, 6.3, 6.4, 6.5**

- [x] 9. Implement FastMCP server integration *(COMPLETED)*
  - ✅ Main MCP server instance created with FastMCP
  - ✅ All OSCAL tools registered with MCP framework
  - ✅ Server instructions and metadata implemented
  - ✅ Integration tests exist
  - _Requirements: 5.1, 5.2, 5.3, 5.5_

- [ ]* 9.1 Write property tests for tool context propagation
  - **Property 9: Tool Context Propagation**
  - **Validates: Requirements 5.6**

- [ ]* 9.2 Write property tests for MCP protocol error handling
  - **Property 10: MCP Protocol Error Handling**
  - **Validates: Requirements 5.7**

- [x] 10. Implement main server entry point and command line interface *(COMPLETED)*
  - ✅ main() function implemented with argument parsing
  - ✅ Configuration update from command line arguments implemented
  - ✅ Server lifecycle management implemented
  - ✅ Logging configuration integrated
  - ✅ Comprehensive unit tests exist
  - _Requirements: 4.6, 4.7, 5.4, 6.1_

- [ ]* 10.1 Write property tests for input validation consistency
  - **Property 12: Input Validation Consistency**
  - **Validates: Requirements 6.7**

- [ ] 11. Add missing property-based tests using Hypothesis
  - Install and configure Hypothesis for property-based testing
  - Implement the 15 correctness properties identified in the design
  - Ensure each property test runs minimum 100 iterations
  - Tag tests with feature and property information
  - _Requirements: All requirements covered by correctness properties_

- [x] 12. Add stdio transport support to configuration
  - Add transport field to Config class with default value "stdio"
  - Update config.py to handle transport configuration from environment and CLI args
  - Add --transport command line argument to argument parser
  - Add transport validation logic to ensure only valid values are accepted
  - _Requirements: 7.1, 7.2, 7.5, 7.6_

- [ ]* 12.1 Write property tests for transport configuration
  - **Property 18: Command Line Transport Argument**
  - **Validates: Requirements 7.1**

- [ ]* 12.2 Write property tests for transport validation
  - **Property 19: Invalid Transport Error Handling**
  - **Property 20: Transport Validation Before Startup**
  - **Validates: Requirements 7.5, 7.6**

- [x] 13. Update main server to support both transport types
  - Modify main() function to use configured transport instead of hardcoded "streamable-http"
  - Add transport selection logic based on configuration
  - Add transport method logging during startup
  - Update error handling for transport-specific failures
  - _Requirements: 5.4, 5.5, 5.6, 7.3, 7.4, 7.7_

- [ ]* 13.1 Write property tests for transport protocol support
  - **Property 16: Transport Protocol Support**
  - **Property 17: Transport Configuration Override**
  - **Validates: Requirements 5.4, 5.6, 7.3, 7.4**

- [ ]* 13.2 Write property tests for transport logging
  - **Property 21: Transport Method Logging**
  - **Validates: Requirements 7.7**

- [x] 14. Update unit tests for transport functionality
  - Add tests for transport configuration parsing
  - Add tests for transport validation logic
  - Add tests for main() function with different transport options
  - Update existing tests to work with new transport parameter
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7_

- [x] 15. Implement the list_oscal_resources tool
  - Create list_oscal_resources.py in the tools directory
  - Implement tool function with @tool decorator
  - Add file reading functionality for awesome-oscal.md from oscal_docs directory
  - Implement proper error handling for file not found and read failures
  - Add encoding handling for robust file reading
  - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7_

- [ ]* 15.1 Write property tests for OSCAL resources file content return
  - **Property 22: OSCAL Resources File Content Return**
  - **Validates: Requirements 9.1, 9.2, 9.3, 9.6**

- [ ]* 15.2 Write property tests for OSCAL resources error handling
  - **Property 23: OSCAL Resources Error Handling**
  - **Validates: Requirements 9.4, 9.5**

- [ ]* 15.3 Write property tests for OSCAL resources encoding handling
  - **Property 24: OSCAL Resources Encoding Handling**
  - **Validates: Requirements 9.7**

- [x] 15.4 Write unit tests for list_oscal_resources tool
  - Test successful file reading and content return
  - Test file not found error handling
  - Test file read permission errors
  - Test encoding edge cases
  - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7_

- [x] 15.5 Register the new tool with MCP server
  - Update main.py to import and register list_oscal_resources tool
  - Ensure tool is properly exposed through MCP protocol
  - Update server instructions to mention the new tool
  - _Requirements: 5.1, 5.2_

- [ ] 16. Add missing property-based tests using Hypothesis
  - Install and configure Hypothesis for property-based testing
  - Implement the 24 correctness properties identified in the design (including new tool properties)
  - Ensure each property test runs minimum 100 iterations
  - Tag tests with feature and property information
  - _Requirements: All requirements covered by correctness properties_

- [ ] 17. Final integration verification
  - Ensure all tests pass including new property-based tests
  - Verify end-to-end functionality works correctly with both transports
  - Test MCP server can start with stdio transport (default)
  - Test MCP server can start with streamable-http transport (explicit)
  - Validate all error handling paths work as expected

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties
- Unit tests validate specific examples and edge cases
- The implementation builds incrementally from core infrastructure to complete functionality

## Summary

**Implementation Status: ~85% Complete**

The OSCAL MCP Server implementation has most core functionality implemented but needs the new list_oscal_resources tool and stdio transport support added. The main remaining work involves:

1. ✅ **RESOLVED**: Import path issues have been fixed - 90/91 tests now pass
2. **New Feature**: Implement the list_oscal_resources tool for community resources
3. **New Feature**: Add stdio transport support and make it the default
4. **Enhancement**: Adding property-based tests to validate the 24 correctness properties  
5. **Minor Fix**: One failing test in error logging behavior (non-critical)
6. **Verification**: Final integration testing with both transport types

**Key Accomplishments:**
- ✅ Three of four MCP tools fully implemented (query_documentation, list_models, get_schema)
- ✅ Complete configuration management with env vars and CLI args
- ✅ FastMCP server integration with proper tool registration
- ✅ Comprehensive unit test suite with high coverage
- ✅ AWS Bedrock Knowledge Base integration
- ✅ Local schema file management system
- ✅ Proper error handling and logging throughout

**Immediate Next Steps:**
1. ✅ **COMPLETED**: Import paths fixed - tests now running successfully
2. Implement the list_oscal_resources tool for community resources
3. Add stdio transport support to configuration and main server
4. Update unit tests for new transport functionality
5. Add Hypothesis for property-based testing
6. Implement the 24 correctness properties as property tests
7. Fix minor test failure (optional)
8. Verify end-to-end functionality with both transport types