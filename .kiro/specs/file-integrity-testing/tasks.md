# Implementation Plan: File Integrity Testing

## Overview

This implementation plan creates comprehensive tests for the file integrity checking capabilities in the OSCAL MCP Server. The existing `verify_package_integrity` function provides critical security functionality but lacks proper test coverage. This plan will implement both unit tests for specific scenarios and property-based tests for comprehensive validation across many inputs.

## Tasks

- [x] 1. Set up test infrastructure and utilities
  - Create test utilities module for package creation and manipulation
  - Implement functions to create temporary test packages using bin/update_hashes.py
  - Add utilities for tampering with files, creating missing files, and adding orphaned files
  - Set up temporary directory management for isolated test execution
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6_

- [ ]* 1.1 Write property test for test utility reliability
  - **Property 1: Test Utility Consistency**
  - **Validates: Requirements 7.1, 7.6**

- [x] 2. Implement core file integrity unit tests
  - [x] 2.1 Create test_file_integrity.py with basic test structure
    - Set up test class with setUp/tearDown methods
    - Import necessary modules and create test fixtures
    - _Requirements: 1.1, 1.2, 1.3, 1.5_

  - [x] 2.2 Write unit tests for valid package scenarios
    - Test successful verification of valid packages
    - Test empty packages (only hashes.json)
    - Test single file packages
    - _Requirements: 3.5_

  - [ ]* 2.3 Write property test for valid package verification
    - **Property 3: Hash Verification Accuracy**
    - **Validates: Requirements 3.1, 3.3, 3.4, 3.5**

  - [x] 2.4 Write unit tests for hash manifest validation
    - Test parsing of valid JSON manifests
    - Test rejection of malformed JSON
    - Test rejection of manifests missing file_hashes section
    - Test rejection of invalid SHA-256 hash formats
    - _Requirements: 1.1, 1.2, 1.3, 1.5_

  - [ ]* 2.5 Write property test for manifest validation
    - **Property 1: Manifest Validation Consistency**
    - **Validates: Requirements 1.1, 1.2, 1.3, 1.5**

- [x] 3. Implement file existence and tampering tests
  - [x] 3.1 Write unit tests for missing file detection
    - Test detection of files listed in manifest but missing from directory
    - Test proper error messages with specific file identification
    - Test exact filename matching behavior
    - _Requirements: 2.1, 2.2, 2.4_

  - [ ]* 3.2 Write property test for file existence validation
    - **Property 2: File Existence Validation**
    - **Validates: Requirements 2.1, 2.2, 2.4**

  - [x] 3.3 Write unit tests for file tampering detection
    - Test detection of files with modified content
    - Test proper error messages showing expected vs actual hashes
    - Test binary file handling for hash computation
    - _Requirements: 3.1, 3.3, 3.4_

  - [x] 3.4 Write unit tests for orphaned file detection
    - Test detection of files not listed in hash manifest
    - Test exclusion of hashes.json file itself
    - Test filtering of non-regular files (directories, symlinks)
    - _Requirements: 4.1, 4.2, 4.3, 4.4_

  - [ ]* 3.5 Write property test for orphaned file detection
    - **Property 4: Orphaned File Detection**
    - **Validates: Requirements 4.1, 4.2, 4.3, 4.4**

- [x] 4. Implement error handling and edge case tests
  - [x] 4.1 Write unit tests for directory-level errors
    - Test behavior when package directory doesn't exist
    - Test behavior when hashes.json file is missing
    - Test permission denied errors for directory access
    - _Requirements: 2.5, 5.5, 5.6_

  - [x] 4.2 Write unit tests for I/O error handling
    - Test handling of file read permission errors
    - Test handling of disk I/O errors during file reading
    - Test proper error message formatting
    - _Requirements: 5.5, 5.6_

  - [ ]* 4.3 Write property test for error handling robustness
    - **Property 6: Error Handling Robustness**
    - **Validates: Requirements 5.5, 5.6**

- [x] 5. Implement logging verification tests
  - [x] 5.1 Write unit tests for logging behavior
    - Test logging of package directory at verification start
    - Test logging of successful completion with file count
    - Test logging of detailed error information before exceptions
    - Test debug logging of individual file hash results
    - _Requirements: 5.1, 5.2, 5.3, 5.4_

  - [ ]* 5.2 Write property test for comprehensive logging
    - **Property 5: Comprehensive Logging Behavior**
    - **Validates: Requirements 5.1, 5.2, 5.3, 5.4**

- [x] 6. Checkpoint - Ensure all unit tests pass
  - Run all unit tests and verify they pass
  - Check test coverage of verify_package_integrity function
  - Ensure all tests run in isolation without side effects
  - Ask the user if questions arise

- [x] 7. Implement server integration tests
  - [x] 7.1 Create test_file_integrity_integration.py
    - Set up integration test structure
    - Create mock server startup scenarios
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6_

  - [x] 7.2 Write integration tests for server startup behavior
    - Test successful server startup with valid packages
    - Test server exit with status code 2 on integrity failure
    - Test logging of integrity failures before server exit
    - Test verification of both oscal_schemas and oscal_docs directories
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6_

  - [ ]* 7.3 Write property test for server exit code consistency
    - **Property 7: Server Exit Code Consistency**
    - **Validates: Requirements 6.3, 6.5**

- [ ] 8. Add property-based testing with Hypothesis
  - [ ] 8.1 Install and configure Hypothesis for property-based testing
    - Add Hypothesis to test dependencies
    - Configure Hypothesis settings for minimum 100 iterations per test
    - Set up custom generators for test data
    - _Requirements: All requirements covered by correctness properties_

  - [ ] 8.2 Implement intelligent test data generators
    - Create generators for valid package structures
    - Create generators for various file types and sizes
    - Create generators for different tampering scenarios
    - Create generators for various error conditions
    - _Requirements: All requirements covered by correctness properties_

  - [ ] 8.3 Implement all property-based tests
    - Implement Property 1: Manifest Validation Consistency
    - Implement Property 2: File Existence Validation
    - Implement Property 3: Hash Verification Accuracy
    - Implement Property 4: Orphaned File Detection
    - Implement Property 5: Comprehensive Logging Behavior
    - Implement Property 6: Error Handling Robustness
    - Implement Property 7: Server Exit Code Consistency
    - Tag each test with feature and property information
    - _Requirements: All requirements covered by correctness properties_

- [ ] 9. Performance and stress testing
  - [ ] 9.1 Write performance tests for large packages
    - Test verification of packages with many files (100+)
    - Test verification of packages with large files (>1MB)
    - Test memory usage during verification
    - _Requirements: 3.1, 4.1_

  - [ ] 9.2 Write stress tests for edge cases
    - Test packages with very long filenames
    - Test packages with special characters in filenames
    - Test concurrent access scenarios
    - _Requirements: 2.4, 3.4, 4.4_

- [ ] 10. Final integration and validation
  - [ ] 10.1 Run complete test suite
    - Execute all unit tests and ensure 100% pass rate
    - Execute all property-based tests with minimum 100 iterations each
    - Verify test coverage meets requirements (100% line coverage of verify_package_integrity)
    - _Requirements: All requirements_

  - [ ] 10.2 Validate security scenarios
    - Test all attack vectors (tampering, missing files, orphaned files)
    - Verify proper error handling prevents information leakage
    - Confirm logging captures all security-relevant events
    - _Requirements: 3.3, 4.2, 5.3_

  - [ ] 10.3 Integration testing with existing test suite
    - Ensure new tests don't break existing functionality
    - Verify new tests integrate properly with existing test infrastructure
    - Update any existing tests that may be affected
    - _Requirements: All requirements_

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties using Hypothesis
- Unit tests validate specific examples and edge cases
- All tests must use the existing bin/update_hashes.py script for hash manifest generation
- Test data should use temporary directories to avoid affecting the actual package files
- Integration tests should mock server startup to avoid actually starting the server
- Property tests must run minimum 100 iterations to ensure thorough coverage

## Summary

This implementation plan provides comprehensive test coverage for the critical file integrity checking functionality in the OSCAL MCP Server. The dual approach of unit tests and property-based tests ensures both specific known scenarios work correctly and that the system behaves properly across the full range of possible inputs.

**Key Security Testing Areas:**
- **Tampering Detection**: Comprehensive testing of hash mismatch scenarios
- **Missing File Detection**: Validation of file existence checking
- **Orphaned File Detection**: Security testing for unexpected file additions
- **Error Handling**: Robust testing of all error conditions
- **Integration Security**: Server startup behavior with compromised packages

**Testing Strategy Benefits:**
- **High Confidence**: Property-based testing provides mathematical confidence in correctness
- **Comprehensive Coverage**: Both positive and negative test cases covered
- **Security Focus**: All attack vectors and security scenarios tested
- **Maintainability**: Clear test structure with good separation of concerns
- **Performance Validation**: Stress testing ensures scalability