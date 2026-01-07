# OSCAL MCP Server Test Suite

This directory contains a comprehensive functional test suite for the OSCAL MCP Server package, designed to work with the pytest framework.

## Overview

The test suite provides thorough coverage of all major components of the OSCAL MCP Server:

- **Configuration management** (`test_config.py`)
- **File integrity checking** (`test_file_integrity*.py`)
- **MCP tools** (`tools/test_*.py`)
- **Main application logic** (`test_main.py`)
- **Utility functions** (`test_utils.py`)
- **Integration testing** (`test_integration.py`)

## Test Structure

```
tests/
├── conftest.py                        # Pytest configuration and shared fixtures
├── test_config.py                     # Configuration module tests
├── test_file_integrity.py             # File integrity checking unit tests
├── test_file_integrity_integration.py # File integrity integration tests
├── test_file_integrity_utils.py       # File integrity test utilities
├── test_main.py                       # Main application tests
├── test_utils.py                      # Utility function tests
├── test_integration.py                # Integration tests
├── tools/                             # Tool-specific tests
│   ├── __init__.py
│   ├── test_get_schema.py
│   ├── test_list_models.py
│   ├── test_list_oscal_resources.py
│   └── test_query_documentation.py
└── README.md                         # This file
```

## Test Categories

### Unit Tests
- **Configuration Tests**: Environment variable loading, validation, argument parsing
- **File Integrity Tests**: Package integrity validation, hash verification, corruption detection
- **Tool Tests**: Individual MCP tool functionality with mocked dependencies
- **Utility Tests**: OSCAL model type enumerations and helper functions
- **Main Module Tests**: CLI argument parsing, logging setup, server initialization

### Integration Tests
- **MCP Server Integration**: Tool registration, schema validation, server setup
- **File Integrity Integration**: Server startup behavior with integrity checking
- **End-to-End Workflows**: Complete tool execution paths
- **Error Handling**: Cross-component error propagation and handling

## Key Features

### Comprehensive Mocking
- **AWS Services**: Mocked Bedrock client and session management
- **File System**: Mocked schema file operations
- **External Dependencies**: MCP context, logging

### Fixtures and Test Data
- **Sample Responses**: Realistic Bedrock knowledge base responses
- **Schema Examples**: Complete OSCAL JSON and XSD schema samples
- **Configuration Scenarios**: Various environment and argument combinations

### Test Markers
- `@pytest.mark.unit`: Unit tests (automatically applied)
- `@pytest.mark.integration`: Integration tests (automatically applied)
- `@pytest.mark.slow`: Long-running tests

## Running Tests

### Using Hatch (Recommended)
```bash
# Run full test suite with coverage and security scanning
hatch run tests

# Run only the test execution (without type checking and security scanning)
hatch test --all --cover

# Run tests for specific Python version
hatch test --python 3.11
hatch test --python 3.12
```

### Using Pytest Directly
```bash
# Run all tests
python -m pytest tests/

# Run with verbose output
python -m pytest tests/ -v

# Run specific test categories
python -m pytest tests/ -m unit
python -m pytest tests/ -m integration

# Run specific test files
python -m pytest tests/test_file_integrity.py
python -m pytest tests/tools/
```

### Coverage Analysis
```bash
# Run tests with coverage (using hatch)
hatch test --all --cover

# View coverage reports
# HTML: private/docs/coverage/index.html
# XML: private/docs/coverage/coverage.xml
```

### Security Scanning
```bash
# Run security analysis (using hatch)
hatch run bandito

# Run bandit directly
bandit -r src/mcp_server_for_oscal
bandit -s B101 -r tests  # Skip assert_used (B101) for tests
```

### Type Checking
```bash
# Run type checking (using hatch)
hatch run typing

# Run mypy directly
mypy --install-types --non-interactive src/mcp_server_for_oscal tests
```

## Test Statistics
Test artifacts are written to `private/docs`.

## Test Configuration
### Environment Variables
Tests automatically handle environment variable isolation using the `clean_environment` fixture. The following variables are managed:

- `BEDROCK_MODEL_ID`, `OSCAL_KB_ID`
- `AWS_PROFILE`, `AWS_REGION`
- `LOG_LEVEL`, `OSCAL_MCP_SERVER_NAME`

### Pytest Configuration
The test suite is configured via `pyproject.toml`:
- Test discovery: `testpaths = ["tests"]`
- Execution options: `--durations=5 --color=yes`
- Coverage tracking: Source package and branch coverage enabled
- Multi-environment testing: Python 3.11 and 3.12 via hatch matrix

### Async Test Support
The pytest-asyncio plugin handles async test execution.

### Test Data and Fixtures

### Shared Fixtures (`conftest.py`)
- `mock_context`: MCP context mock
- `mock_config`: Configuration object mock
- `sample_bedrock_response`: Realistic AWS Bedrock response
- `sample_json_schema`: Complete OSCAL JSON schema
- `sample_xsd_schema`: OSCAL XSD schema content
- `clean_environment`: Isolated environment variables

### File Integrity Test Utilities (`test_file_integrity_utils.py`)
- `TestPackageManager`: Context manager for creating and managing test packages
- Package creation utilities: `create_sample_oscal_files`, `create_binary_test_files`
- Integrity validation helpers: `assert_integrity_passes`, `assert_integrity_fails`
- Hash manifest utilities: `assert_hash_manifest_valid`

### Tool-Specific Fixtures
Each tool test module includes specialized fixtures for that tool's requirements.

## Mocking Strategy

### External Dependencies
- **AWS Boto3**: Session and client mocking with realistic responses
- **File System**: Schema file access mocking and temporary directory management
- **Logging**: Logger configuration and output capture
- **MCP Framework**: Context and server mocking

### File Integrity Testing
- **Package Creation**: Temporary test packages with controlled content
- **Hash Manipulation**: Controlled corruption of hash manifests and files
- **Server Integration**: Mocked server startup with integrity checking

### Error Simulation
Tests include comprehensive error scenarios:
- AWS service errors (credentials, permissions, resource not found)
- File system errors (missing files, permission issues, corruption)
- Configuration errors (missing required values, invalid formats)
- Network errors (connection failures, timeouts)
- Package integrity violations (missing files, hash mismatches, corrupted manifests)

## Test Patterns

### Tool Testing with Mocks
```python
@patch('module.Session')
def test_tool_success(mock_session, mock_context):
    """Test successful tool execution."""
    # Setup mocks
    mock_client = Mock()
    mock_session.return_value.client.return_value = mock_client
    
    # Execute and verify
    result = tool_function("input", mock_context)
    assert result == expected_result
```

### File Integrity Testing
```python
def test_integrity_with_corrupted_file():
    """Test integrity checking with file corruption."""
    with TestPackageManager() as manager:
        package_dir = manager.create_test_package()
        manager.corrupt_file(package_dir / "file.json")
        
        assert_integrity_fails(package_dir, "Hash mismatch")
```

## Error Handling Tests

### AWS Service Errors
```python
def test_aws_error_handling(mock_session, mock_context):
    """Test handling of AWS service errors."""
    mock_client.operation.side_effect = ClientError(error_response, 'Operation')
    
    with pytest.raises(Exception):
        tool_function("input", mock_context)
    
    mock_context.error.assert_called_once()
```

### Package Integrity Validation
```python
def test_package_integrity_failure():
    """Test handling of package integrity failures."""
    with TestPackageManager() as manager:
        corrupted_package = manager.create_corrupted_package()
        
        with pytest.raises(SystemExit):
            verify_package_integrity(corrupted_package)
```

## Best Practices

### Test Organization
- Group related tests in classes
- Use descriptive test names that explain the scenario
- Include both positive and negative test cases
- Test edge cases and error conditions

### Mocking Guidelines
- Mock at the boundary of your system (external dependencies)
- Use realistic mock data that matches actual service responses
- Verify mock interactions to ensure correct API usage
- Reset mocks between tests to avoid interference

### Fixture Usage
- Use shared fixtures for common setup
- Create specific fixtures for complex test data
- Leverage pytest's dependency injection for clean test code
- Use fixture scopes appropriately (function, class, module, session)

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure the package is installed in development mode
2. **Async Test Failures**: Verify pytest-asyncio is installed
3. **Mock Assertion Failures**: Check that mocks are properly reset between tests
4. **Environment Isolation**: Use the `clean_environment` fixture for configuration tests

### Debug Tips
- Use `pytest -s` to see print statements and logging output
- Use `pytest --pdb` to drop into debugger on failures
- Use `pytest -k pattern` to run specific tests matching a pattern
- Use `pytest --tb=long` for detailed tracebacks

## Contributing

When adding new tests:

1. Follow the existing test structure and naming conventions
2. Include both success and failure scenarios
3. Mock external dependencies appropriately
4. Add fixtures for reusable test data
5. Update this README if adding new test categories or patterns

## Dependencies

The test suite requires:
- `pytest`: Test framework
- `pytest-asyncio`: Async test support  
- `unittest.mock`: Mocking framework (built-in)
- `mypy`: Type checking
- `bandit`: Security scanning
- `boto3-stubs`: Type stubs for AWS SDK
- Package dependencies: `boto3`, `mcp`, `strands-agents`

All test dependencies are managed through the project's `pyproject.toml` configuration and hatch environments.
