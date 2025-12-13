# Requirements Document

## Introduction

This document specifies the requirements for an MCP (Model Context Protocol) server that provides AI assistants with tools to work with NIST's Open Security Controls Assessment Language (OSCAL). The server enables AI assistants to query OSCAL documentation, retrieve schemas, and understand OSCAL model structures to help with security compliance workflows.

## Glossary

- **OSCAL**: Open Security Controls Assessment Language - NIST's framework-agnostic, vendor-neutral, machine-readable schemas for security artifacts
- **MCP_Server**: A Model Context Protocol server that exposes tools to AI assistants
- **Bedrock_Knowledge_Base**: Amazon Bedrock service for storing and querying documentation
- **OSCAL_Schema**: JSON or XSD schema definitions for OSCAL model structures
- **OSCAL_Model**: Specific OSCAL document types (catalog, profile, component-definition, etc.)
- **FastMCP**: Python framework for building MCP servers
- **Strands_Agent**: Framework for creating AI agents with tool capabilities

## Requirements

### Requirement 1: OSCAL Documentation Query

**User Story:** As an AI assistant, I want to query authoritative OSCAL documentation, so that I can provide accurate answers about OSCAL concepts and implementation guidance.

#### Acceptance Criteria

1. WHEN a documentation query is received, THE MCP_Server SHALL query the Bedrock_Knowledge_Base with the provided text
2. WHEN the Bedrock_Knowledge_Base returns results, THE MCP_Server SHALL return the complete response including retrieval results and scores
3. WHEN the knowledge base ID is not configured, THE MCP_Server SHALL return an appropriate error message
4. WHEN AWS credentials are not available, THE MCP_Server SHALL handle the authentication error gracefully
5. IF an AWS profile is configured, THEN THE MCP_Server SHALL use that profile for authentication
6. WHEN query execution fails, THE MCP_Server SHALL log the error and raise an exception with descriptive information

### Requirement 2: OSCAL Model Listing

**User Story:** As an AI assistant, I want to list all available OSCAL model types with their descriptions, so that I can understand the different OSCAL models and their purposes.

#### Acceptance Criteria

1. WHEN a model listing request is received, THE MCP_Server SHALL return all supported OSCAL model types
2. FOR EACH model type, THE MCP_Server SHALL provide description, layer classification, and development status
3. THE MCP_Server SHALL include these model types: catalog, profile, mapping, component-definition, system-security-plan, assessment-plan, assessment-results, plan-of-action-and-milestones
4. THE MCP_Server SHALL classify models into Control, Implementation, or Assessment layers
5. THE MCP_Server SHALL indicate status as GA (Generally Available) or PROTOTYPE

### Requirement 3: OSCAL Schema Retrieval

**User Story:** As an AI assistant, I want to retrieve JSON or XSD schemas for specific OSCAL models, so that I can validate OSCAL documents or understand model structure.

#### Acceptance Criteria

1. WHEN a schema request is received with a valid model name, THE MCP_Server SHALL return the corresponding schema
2. WHEN schema_type is "json", THE MCP_Server SHALL return the JSON schema for the specified model
3. WHEN schema_type is "xsd", THE MCP_Server SHALL return the XSD schema for the specified model
4. WHEN model_name is "complete", THE MCP_Server SHALL return a comprehensive schema including all models
5. WHEN an invalid model name is provided, THE MCP_Server SHALL return an error referencing the list_models tool
6. WHEN an invalid schema type is provided, THE MCP_Server SHALL return an error specifying valid options
7. THE MCP_Server SHALL handle model name aliases (system-security-plan → ssp, plan-of-action-and-milestones → poam)
8. WHEN schema file cannot be found or opened, THE MCP_Server SHALL log the error and raise an exception

### Requirement 4: Server Configuration Management

**User Story:** As a system administrator, I want to configure the MCP server through environment variables and command line arguments, so that I can customize the server for different deployment environments.

#### Acceptance Criteria

1. THE MCP_Server SHALL load configuration from environment variables with sensible defaults
2. THE MCP_Server SHALL support AWS_PROFILE environment variable for AWS authentication
3. THE MCP_Server SHALL support OSCAL_KB_ID environment variable for knowledge base configuration
4. THE MCP_Server SHALL support BEDROCK_MODEL_ID environment variable for model selection
5. THE MCP_Server SHALL support LOG_LEVEL environment variable for logging configuration
6. WHEN command line arguments are provided, THE MCP_Server SHALL override environment variable values
7. THE MCP_Server SHALL support --aws-profile, --bedrock-model-id, --knowledge-base-id, and --log-level command line options
8. THE MCP_Server SHALL use "OSCAL MCP Server" as the default server name unless overridden

### Requirement 5: MCP Protocol Integration

**User Story:** As an AI assistant framework, I want to communicate with the OSCAL server using the Model Context Protocol, so that I can access OSCAL tools through standardized interfaces.

#### Acceptance Criteria

1. THE MCP_Server SHALL implement the FastMCP framework for MCP protocol compliance
2. THE MCP_Server SHALL register all OSCAL tools with the MCP framework
3. THE MCP_Server SHALL provide tool schemas that describe parameters and return types
4. THE MCP_Server SHALL support streamable-http transport for communication
5. THE MCP_Server SHALL include descriptive instructions about OSCAL and server capabilities
6. WHEN tools are invoked, THE MCP_Server SHALL pass context information including session parameters
7. THE MCP_Server SHALL handle MCP protocol errors and provide appropriate responses

### Requirement 6: Error Handling and Logging

**User Story:** As a system administrator, I want comprehensive error handling and logging, so that I can troubleshoot issues and monitor server operation.

#### Acceptance Criteria

1. THE MCP_Server SHALL configure logging for all components with configurable log levels
2. WHEN errors occur in tool execution, THE MCP_Server SHALL log detailed error information
3. WHEN AWS service calls fail, THE MCP_Server SHALL handle boto3 exceptions gracefully
4. WHEN file operations fail, THE MCP_Server SHALL provide descriptive error messages
5. THE MCP_Server SHALL use the MCP context to report errors and warnings to clients
6. THE MCP_Server SHALL support DEBUG, INFO, WARNING, and ERROR log levels
7. WHEN invalid parameters are provided, THE MCP_Server SHALL validate inputs and return clear error messages

### Requirement 7: Schema File Management

**User Story:** As a developer, I want the server to manage OSCAL schema files locally, so that schema retrieval is fast and reliable without external dependencies.

#### Acceptance Criteria

1. THE MCP_Server SHALL store OSCAL schemas in a local oscal_schemas directory
2. THE MCP_Server SHALL support both JSON and XSD schema formats for each model type
3. THE MCP_Server SHALL use consistent naming convention: oscal_{model}_schema.{type}
4. WHEN opening schema files, THE MCP_Server SHALL resolve paths relative to the package structure
5. THE MCP_Server SHALL handle file not found errors with descriptive messages
6. THE MCP_Server SHALL return schemas as properly formatted JSON strings