# Design Document: File Integrity Testing

## Overview

This design document outlines the comprehensive testing strategy for the file integrity checking capabilities in the OSCAL MCP Server. The existing `verify_package_integrity` function provides critical security functionality by validating that bundled OSCAL schemas and documentation files haven't been tampered with using SHA-256 hashes. However, this security-critical feature currently lacks proper test coverage, creating a significant gap in our security assurance.

The design focuses on creating a robust test suite that validates all aspects of file integrity checking, including positive cases (valid files), negative cases (tampered, missing, or orphaned files), error conditions, and integration with server startup. The testing approach will use both unit tests for specific scenarios and property-based tests for comprehensive validation across many inputs.

## Architecture

The file integrity testing system will be built around the existing `verify_package_integrity` function in `src/mcp_server_for_oscal/tools/utils.py`. The testing architecture consists of several key components:

### Test Structure
```
tests/
├── test_file_integrity.py          # Main test file for integrity checking
├── test_file_integrity_integration.py  # Integration tests with server startup
└── fixtures/
    ├── test_package_valid/          # Valid test package with correct hashes
    ├── test_package_tampered/       # Package with modified files
    ├── test_package_missing/        # Package with missing files
    └── test_package_orphaned/       # Package with extra files
```

### Test Utilities Module
A dedicated test utilities module will provide helper functions for:
- Creating temporary test packages with hash manifests
- Modifying files to simulate tampering
- Generating valid and invalid hash manifests
- Setting up various error conditions

### Integration Points
The tests will validate integration with:
- Server startup process in `main.py` (lines 122-129)
- Logging system for security events
- Error handling and exception propagation
- Exit code behavior on integrity failures

## Components and Interfaces

### Core Function Under Test
```python
def verify_package_integrity(directory: Path) -> None:
    """Verify all files match captured state from build time"""
```

**Input:** `directory` - Path to package directory containing files and hashes.json
**Output:** None on success, raises RuntimeError on failure
**Side Effects:** Logs verification progress and results

### Test Utility Functions

#### Package Creation Utilities
```python
def create_test_package(temp_dir: Path, files: Dict[str, bytes]) -> Path:
    """Create a test package with files and corresponding hash manifest using bin/update_hashes.py"""

def generate_hash_manifest(directory: Path) -> None:
    """Generate hashes.json file using the existing bin/update_hashes.py script
    
    This will call: bin/update_hashes.py <directory> -o <directory>
    The script captures both git commit hash and SHA-256 hashes of all files
    """

def tamper_file(file_path: Path, modification: str = "append") -> None:
    """Modify a file to simulate tampering"""
```

#### Validation Utilities
```python
def assert_integrity_passes(directory: Path) -> None:
    """Assert that integrity verification passes for directory"""

def assert_integrity_fails(directory: Path, expected_error: str) -> None:
    """Assert that integrity verification fails with expected error"""
```

### Test Data Management

#### Valid Test Package Structure
```
test_package_valid/
├── hashes.json              # Valid hash manifest
├── schema1.json            # Valid OSCAL schema file
├── schema2.json            # Valid OSCAL schema file
└── documentation.md        # Valid documentation file
```

#### Hash Manifest Format
```json
{
  "commit": "'d99c872d59391ebc35e538b3d27dbd68de4472e5'",
  "file_hashes": {
    "schema1.json": "a1b2c3d4e5f6...",
    "schema2.json": "f6e5d4c3b2a1...",
    "documentation.md": "1a2b3c4d5e6f..."
  }
}
```

## Data Models

### Test Case Categories

#### Positive Test Cases
- **Valid Package**: All files present with correct hashes
- **Empty Package**: Package with no files (only hashes.json)
- **Single File Package**: Package with one file and correct hash
- **Large Package**: Package with many files to test performance

#### Negative Test Cases
- **Tampered File**: File content modified, hash mismatch
- **Missing File**: File listed in manifest but not present
- **Orphaned File**: File present but not in manifest
- **Malformed Manifest**: Invalid JSON or missing sections
- **Missing Manifest**: No hashes.json file present
- **Permission Errors**: Files with restricted access permissions

#### Error Condition Test Cases
- **I/O Errors**: Simulated disk read failures
- **Encoding Issues**: Files with unusual encodings
- **Large Files**: Memory and performance testing
- **Concurrent Access**: Multiple processes accessing files

### Test Data Structures

#### Test Package Configuration
```python
@dataclass
class TestPackageConfig:
    name: str
    files: Dict[str, bytes]  # filename -> content
    tampered_files: List[str] = field(default_factory=list)
    missing_files: List[str] = field(default_factory=list)
    orphaned_files: Dict[str, bytes] = field(default_factory=dict)
    malformed_manifest: bool = False
```

#### Test Scenario Definition
```python
@dataclass
class IntegrityTestScenario:
    description: str
    package_config: TestPackageConfig
    should_pass: bool
    expected_error_pattern: Optional[str] = None
    expected_log_messages: List[str] = field(default_factory=list)
```

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system-essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

Now I'll analyze the acceptance criteria to determine which ones are testable as properties:

### Converting EARS to Properties

Based on the prework analysis, I'll convert the testable acceptance criteria into universally quantified properties:

**Property 1: Manifest Validation Consistency**
*For any* package directory with a hash manifest file, the File_Integrity_Checker should successfully parse valid JSON manifests with proper file_hashes sections and reject invalid manifests (malformed JSON, missing sections, or invalid hash formats) with descriptive RuntimeError messages.
**Validates: Requirements 1.1, 1.2, 1.3, 1.5**

**Property 2: File Existence Validation**
*For any* package directory and hash manifest, the File_Integrity_Checker should verify that all files listed in the manifest exist using exact filename matching, and raise RuntimeError with specific file identification when files are missing.
**Validates: Requirements 2.1, 2.2, 2.4**

**Property 3: Hash Verification Accuracy**
*For any* set of files in a package directory, the File_Integrity_Checker should compute SHA-256 hashes in binary mode and raise RuntimeError with both expected and actual hashes when mismatches are detected, while completing successfully when all hashes match.
**Validates: Requirements 3.1, 3.3, 3.4, 3.5**

**Property 4: Orphaned File Detection**
*For any* package directory, the File_Integrity_Checker should identify all regular files (excluding the hash manifest itself and non-regular files) and raise RuntimeError identifying any files not listed in the hash manifest.
**Validates: Requirements 4.1, 4.2, 4.3, 4.4**

**Property 5: Comprehensive Logging Behavior**
*For any* integrity verification operation, the File_Integrity_Checker should log the package directory being verified at start, log success with file count on completion, log detailed error information before raising exceptions on failure, and log individual file results when debug logging is enabled.
**Validates: Requirements 5.1, 5.2, 5.3, 5.4**

**Property 6: Error Handling Robustness**
*For any* I/O or permission errors encountered during file operations, the File_Integrity_Checker should handle them gracefully and raise RuntimeError with descriptive error messages that clearly identify the nature of the problem.
**Validates: Requirements 5.5, 5.6**

**Property 7: Server Exit Code Consistency**
*For any* integrity verification failure during server startup, the MCP server should exit with status code 2 and log the failure details before terminating.
**Validates: Requirements 6.3, 6.5**

## Error Handling

The file integrity testing system must handle various error conditions gracefully:

### Expected Error Conditions
- **Malformed Hash Manifests**: Invalid JSON, missing sections, invalid hash formats
- **File System Errors**: Missing files, permission denied, I/O errors
- **Hash Mismatches**: Tampered files with different content
- **Orphaned Files**: Unexpected files in package directories
- **Directory Issues**: Missing package directories, permission problems

### Error Response Strategy
- **Fail Fast**: Stop verification immediately on first error
- **Descriptive Messages**: Include specific file names, expected vs actual hashes
- **Security Logging**: Log all integrity failures for security monitoring
- **Clean Exit**: Ensure server exits cleanly with appropriate status codes

### Exception Hierarchy
```python
# All integrity errors raise RuntimeError with descriptive messages
RuntimeError("File schema1.json missing from package.")
RuntimeError("File schema1.json has been modified; expected hash abc123 != def456")
RuntimeError("File orphan.txt exists but not in hash manifest.")
RuntimeError("Hash manifest is malformed JSON: Expecting ',' delimiter")
```

## Testing Strategy

The testing strategy employs a dual approach combining unit tests for specific scenarios and property-based tests for comprehensive coverage:

### Unit Testing Approach
Unit tests will focus on:
- **Specific Examples**: Known good and bad packages with predictable outcomes
- **Edge Cases**: Empty packages, single files, missing directories
- **Integration Points**: Server startup behavior, logging integration
- **Error Conditions**: Specific error scenarios with expected messages

### Property-Based Testing Approach
Property tests will focus on:
- **Universal Properties**: Behaviors that must hold across all inputs
- **Comprehensive Input Coverage**: Random generation of packages, files, and error conditions
- **Invariant Validation**: Properties that remain true regardless of input variation
- **Stress Testing**: Large numbers of files, various file sizes and types

### Test Configuration
- **Minimum 100 iterations** per property test to ensure thorough coverage
- **Hypothesis library** for Python property-based testing
- **Temporary directories** for isolated test execution
- **Mock logging** to verify logging behavior without side effects
- **Process isolation** for server startup tests

### Test Data Generation Strategy
Property tests will use intelligent generators that:
- **Create realistic packages** with valid OSCAL-like file structures
- **Generate valid hash manifests** with proper SHA-256 format
- **Simulate tampering** by modifying file contents systematically
- **Create various error conditions** including I/O errors and permission issues
- **Scale appropriately** from single files to large package structures

### Coverage Goals
- **100% line coverage** of `verify_package_integrity` function
- **All error paths tested** with both unit and property tests
- **Integration coverage** of server startup integrity checks
- **Performance validation** with large packages and many files
- **Security scenario coverage** including all attack vectors

The combination of unit and property-based tests ensures both specific known scenarios work correctly and that the system behaves properly across the full range of possible inputs, providing high confidence in the security-critical file integrity functionality.