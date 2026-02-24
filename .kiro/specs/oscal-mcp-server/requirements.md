# Requirements Document

## Introduction

This document specifies the requirements for an MCP (Model Context Protocol) server that provides AI assistants with tools to work with NIST's Open Security Controls Assessment Language (OSCAL). The server enables AI assistants to query OSCAL documentation, retrieve schemas, list and query pre-loaded OSCAL Component Definitions (including their Components and Capabilities), and understand OSCAL model structures to help with security compliance workflows.

## Glossary

- **OSCAL**: Open Security Controls Assessment Language - NIST's framework-agnostic, vendor-neutral, machine-readable schemas for security artifacts
- **MCP_Server**: A Model Context Protocol server that exposes tools to AI assistants
- **Bedrock_Knowledge_Base**: Amazon Bedrock service for storing and querying documentation
- **OSCAL_Schema**: JSON or XSD schema definitions for OSCAL model structures
- **OSCAL_Model**: Specific OSCAL document types (catalog, profile, component-definition, etc.)
- **FastMCP**: Python framework for building MCP servers
- **Strands_Agent**: Framework for creating AI agents with tool capabilities
- **ComponentDefinitionStore**: Singleton class that loads, indexes, and queries OSCAL Component Definitions and their child Components and Capabilities
- **Component_Definition**: An OSCAL document that defines one or more Components and optionally Capabilities
- **Component**: A defined-component within a Component Definition, representing a service, software, policy, etc.
- **Capability**: A grouping of Components within a Component Definition that represents a logical capability
- **Trestle**: The compliance-trestle library used for OSCAL model parsing, validation, and serialization

## Requirements

### Requirement 1: OSCAL Documentation Query

**User Story:** As an AI assistant, I want to query authoritative OSCAL documentation, so that I can provide accurate answers about OSCAL concepts and implementation guidance.

#### Acceptance Criteria

1. WHEN a documentation query is received, THE MCP_Server SHALL query the Bedrock_Knowledge_Base with the provided text
2. WHEN the Bedrock_Knowledge_Base returns results, THE MCP_Server SHALL return the complete response including retrieval results and scores
3. WHEN the knowledge base ID is not configured, THE MCP_Server SHALL not register the query_oscal_documentation tool
4. WHEN AWS credentials are not available, THE MCP_Server SHALL handle the authentication error gracefully
5. IF an AWS profile is configured, THEN THE MCP_Server SHALL use that profile for authentication
6. WHEN query execution fails, THE MCP_Server SHALL log the error and raise an exception with descriptive information

### Requirement 2: OSCAL Model Listing

**User Story:** As an AI assistant, I want to list all available OSCAL model types with their descriptions, so that I can understand the different OSCAL models and their purposes.

#### Acceptance Criteria

1. WHEN a model listing request is received, THE MCP_Server SHALL return all supported OSCAL model types
2. FOR EACH model type, THE MCP_Server SHALL provide description, layer classification, and development status
3. THE MCP_Server SHALL include these model types: catalog, profile, mapping-collection, component-definition, system-security-plan, assessment-plan, assessment-results, plan-of-action-and-milestones
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
7. THE MCP_Server SHALL support --aws-profile, --bedrock-model-id, --knowledge-base-id, --log-level, and --transport command line options
8. THE MCP_Server SHALL use "OSCAL" as the default server name unless overridden via OSCAL_MCP_SERVER_NAME
9. THE MCP_Server SHALL support OSCAL_ALLOW_REMOTE_URIS environment variable to control remote URI loading (default false)
10. THE MCP_Server SHALL support OSCAL_REQUEST_TIMEOUT environment variable for HTTP request timeout (default 30 seconds)
11. THE MCP_Server SHALL support OSCAL_MAX_URI_DEPTH environment variable for maximum URI resolution depth (default 3)
12. THE MCP_Server SHALL support OSCAL_COMPONENT_DEFINITIONS_DIR environment variable for the component definitions directory (default "component_definitions")

### Requirement 5: MCP Protocol Integration

**User Story:** As an AI assistant framework, I want to communicate with the OSCAL server using the Model Context Protocol, so that I can access OSCAL tools through standardized interfaces.

#### Acceptance Criteria

1. THE MCP_Server SHALL implement the FastMCP framework for MCP protocol compliance
2. THE MCP_Server SHALL register all OSCAL tools with the MCP framework
3. THE MCP_Server SHALL provide tool schemas that describe parameters and return types
4. THE MCP_Server SHALL support both stdio and streamable-http transport protocols
5. THE MCP_Server SHALL use stdio transport as the default communication method
6. WHEN streamable-http transport is explicitly configured, THE MCP_Server SHALL use streamable-http instead of stdio
7. THE MCP_Server SHALL include descriptive instructions about OSCAL and server capabilities
8. WHEN tools are invoked, THE MCP_Server SHALL pass context information including session parameters
9. THE MCP_Server SHALL handle MCP protocol errors and provide appropriate responses

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

### Requirement 7: Transport Configuration

**User Story:** As a system administrator, I want to configure the MCP transport method, so that I can choose between stdio and HTTP-based communication based on my deployment needs.

#### Acceptance Criteria

1. THE MCP_Server SHALL accept a --transport command line argument to specify the transport type
2. WHEN --transport is not specified, THE MCP_Server SHALL default to stdio transport
3. WHEN --transport is set to "stdio", THE MCP_Server SHALL use standard input/output for communication
4. WHEN --transport is set to "streamable-http", THE MCP_Server SHALL use HTTP-based transport
5. WHEN an invalid transport type is specified, THE MCP_Server SHALL raise a ValueError with valid options
6. THE MCP_Server SHALL validate transport configuration before starting the server
7. THE MCP_Server SHALL log the selected transport method during startup

### Requirement 8: Schema File Management

**User Story:** As a developer, I want the server to manage OSCAL schema files locally, so that schema retrieval is fast and reliable without external dependencies.

#### Acceptance Criteria

1. THE MCP_Server SHALL store OSCAL schemas in a local oscal_schemas directory
2. THE MCP_Server SHALL support both JSON and XSD schema formats for each model type
3. THE MCP_Server SHALL use consistent naming convention: oscal_{model}_schema.{type}
4. WHEN opening schema files, THE MCP_Server SHALL resolve paths relative to the package structure
5. THE MCP_Server SHALL handle file not found errors with descriptive messages
6. THE MCP_Server SHALL return schemas as properly formatted JSON strings

### Requirement 9: OSCAL Community Resources Listing

**User Story:** As an AI assistant, I want to access a curated list of OSCAL community resources, so that I can provide users with comprehensive information about available OSCAL tools, content, and educational materials.

#### Acceptance Criteria

1. WHEN a list_oscal_resources request is received, THE MCP_Server SHALL return the contents of the awesome-oscal.md file
2. THE MCP_Server SHALL read the awesome-oscal.md file from the local oscal_docs directory
3. THE MCP_Server SHALL return the complete markdown content including all sections
4. WHEN the awesome-oscal.md file cannot be found, THE MCP_Server SHALL return an appropriate error message
5. WHEN file reading fails, THE MCP_Server SHALL log the error and raise an exception with descriptive information
6. THE MCP_Server SHALL preserve the original markdown formatting in the returned content
7. THE MCP_Server SHALL handle encoding issues gracefully when reading the file

### Requirement 10: Component Definition Loading and Indexing

**User Story:** As a user of an AI agent, I need the server to pre-load and index OSCAL Component Definitions at startup, so that queries against components are fast and do not require on-demand file loading.

#### Acceptance Criteria

1. WHEN the MCP_Server starts, THE ComponentDefinitionStore SHALL recursively load all Component Definition files from the configured component definitions directory
2. THE ComponentDefinitionStore SHALL index each loaded Component Definition by file path, UUID, and title (case-insensitive)
3. THE ComponentDefinitionStore SHALL index each Component within a loaded Component Definition by UUID and title (case-insensitive)
4. THE ComponentDefinitionStore SHALL index each Capability within a loaded Component Definition by UUID and name (case-insensitive)
5. THE ComponentDefinitionStore SHALL track parent relationships mapping each Component UUID to its parent Component Definition UUID
6. THE ComponentDefinitionStore SHALL track parent relationships mapping each Capability UUID to its parent Component Definition UUID
7. THE ComponentDefinitionStore SHALL support loading Component Definitions from JSON files
8. THE ComponentDefinitionStore SHALL support loading Component Definitions from zip archives containing JSON files
9. THE ComponentDefinitionStore SHALL use Trestle's ComponentDefinition model for parsing and validation
10. WHEN a Component Definition file cannot be parsed, THE ComponentDefinitionStore SHALL log the error and continue loading remaining files
11. WHEN an explicit directory path is provided to load_from_directory, THE ComponentDefinitionStore SHALL reset all previously loaded data before loading from the new directory
12. THE ComponentDefinitionStore SHALL maintain loading statistics including counts of loaded files, processed zip files, zip file contents, processed JSON files, indexed component definitions, indexed components, processed external files, and indexed capabilities

### Requirement 11: Component Definition Query Tool

**User Story:** As an AI assistant, I want to query loaded Component Definitions to extract component information, so that I can provide users with details about services, software, controls, and security features.

#### Acceptance Criteria

1. WHEN a query_component_definition request is received, THE MCP_Server SHALL query the pre-loaded ComponentDefinitionStore
2. THE query_component_definition tool SHALL accept an optional component_definition_filter parameter (UUID or title) to limit the search to a specific Component Definition
3. THE query_component_definition tool SHALL support query_type values: "all", "by_uuid", "by_title", "by_type"
4. WHEN query_type is "by_uuid", "by_title", or "by_type", THE query_component_definition tool SHALL require a query_value parameter
5. WHEN query_type is "by_title" and the query_value matches a Capability name, THE query_component_definition tool SHALL return the matching Capability
6. WHEN query_type is "by_uuid" and the query_value matches a Capability UUID, THE query_component_definition tool SHALL return the matching Capability
7. WHEN a Capability match is found and a component_definition_filter is provided, THE query_component_definition tool SHALL verify the Capability belongs to a matching Component Definition before returning the result
8. WHEN query_type is "by_title" and no exact Component title match is found, THE query_component_definition tool SHALL search for an exact match in the values of any props defined by the Component
9. THE query_component_definition tool SHALL support filtering components by type via query_type "by_type"
10. THE query_component_definition tool SHALL return a response containing: components list, total_count, query_type, component_definitions_searched count, and filtered_by value
11. WHEN no Component Definitions are loaded, THE query_component_definition tool SHALL raise a ValueError with a descriptive message
12. THE query_component_definition tool SHALL support only "raw" as the return_format value

### Requirement 12: List Component Definitions Tool

**User Story:** As an AI assistant, I want to list all loaded Component Definitions with summary information, so that I can help users understand what data is available and select specific definitions for deeper queries.

#### Acceptance Criteria

1. WHEN a list_component_definitions request is received, THE MCP_Server SHALL return summary information for every loaded Component Definition
2. FOR EACH Component Definition, THE MCP_Server SHALL return: uuid, title, componentCount, importedComponentDefinitionsCount, and sizeInBytes
3. WHEN no Component Definitions are loaded, THE MCP_Server SHALL notify the client of the error and raise a RuntimeError

### Requirement 13: List Components Tool

**User Story:** As an AI assistant, I want to list all loaded Components with summary information including their parent Component Definition, so that I can help users identify specific components for detailed queries.

#### Acceptance Criteria

1. WHEN a list_components request is received, THE MCP_Server SHALL return summary information for every loaded Component
2. FOR EACH Component, THE MCP_Server SHALL return: uuid, title, parentComponentDefinitionTitle, parentComponentDefinitionUuid, and sizeInBytes
3. WHEN no Components are loaded, THE MCP_Server SHALL notify the client of the error and raise a RuntimeError

### Requirement 14: List Capabilities Tool

**User Story:** As an AI assistant, I want to list all loaded Capabilities with summary information including their parent Component Definition, so that I can help users understand available capability groupings.

#### Acceptance Criteria

1. WHEN a list_capabilities request is received, THE MCP_Server SHALL return summary information for every loaded Capability
2. FOR EACH Capability, THE MCP_Server SHALL return: uuid, name, parentComponentDefinitionTitle, parentComponentDefinitionUuid, and sizeInBytes
3. WHEN no Capabilities are loaded, THE MCP_Server SHALL return an empty list without raising an error

### Requirement 15: Get Capability Tool

**User Story:** As an AI assistant, I want to retrieve a specific Capability by UUID, so that I can provide users with detailed information about a capability grouping and its incorporated components.

#### Acceptance Criteria

1. WHEN a get_capability request is received with a UUID, THE MCP_Server SHALL return the full Capability object as a dictionary
2. WHEN the provided UUID does not match any loaded Capability, THE MCP_Server SHALL return None

### Requirement 16: External Component Definition Loading

**User Story:** As a user, I want the server to load Component Definitions from external URIs, so that I can query component data from sources beyond the bundled directory.

#### Acceptance Criteria

1. WHEN a local file URI pointing to a zip archive is provided, THE ComponentDefinitionStore SHALL load and index the Component Definitions from the zip file
2. WHEN a local file URI pointing to a directory is provided, THE ComponentDefinitionStore SHALL raise a ValueError indicating the URI must point to a zip file or JSON component definition
3. WHEN a remote URI is provided and OSCAL_ALLOW_REMOTE_URIS is false, THE ComponentDefinitionStore SHALL raise a ValueError indicating remote URI loading is not enabled
4. WHEN a remote URI is provided and OSCAL_ALLOW_REMOTE_URIS is true, THE ComponentDefinitionStore SHALL fetch, parse, validate, and index the Component Definition
5. WHEN a remote fetch times out, THE ComponentDefinitionStore SHALL raise a ValueError with the timeout duration and source URI
6. WHEN a remote fetch fails due to network errors, THE ComponentDefinitionStore SHALL raise a ValueError with details about the failure
7. WHEN remote JSON cannot be parsed, THE ComponentDefinitionStore SHALL raise a ValueError with parsing error details

### Requirement 17: Server Metadata (About Tool)

**User Story:** As an AI assistant, I want to retrieve metadata about the MCP server itself, so that I can report the server version, supported OSCAL version, and other identifying information.

#### Acceptance Criteria

1. WHEN an about request is received, THE MCP_Server SHALL return a dictionary containing version, keywords, and oscal-version
2. THE MCP_Server SHALL read the version and keywords from the installed package metadata
3. THE MCP_Server SHALL report the supported OSCAL version (currently 1.2.0)

### Requirement 18: Bundled Content Integrity Verification

**User Story:** As a security-conscious operator, I want the server to verify the integrity of bundled schemas, documentation, and component definitions at startup, so that tampered files are detected before use.

#### Acceptance Criteria

1. WHEN the MCP_Server starts, THE MCP_Server SHALL verify the integrity of the oscal_schemas directory using SHA-256 hashes
2. WHEN the MCP_Server starts, THE MCP_Server SHALL verify the integrity of the oscal_docs directory using SHA-256 hashes
3. WHEN the component definitions directory exists, THE MCP_Server SHALL verify its integrity using SHA-256 hashes
4. THE MCP_Server SHALL read expected hashes from a hashes.json manifest file in each verified directory
5. WHEN any file's computed hash does not match the expected hash, THE MCP_Server SHALL raise a RuntimeError and exit
6. WHEN any file listed in the manifest is missing, THE MCP_Server SHALL raise a RuntimeError and exit
7. WHEN any file exists in the directory but is not listed in the manifest, THE MCP_Server SHALL raise a RuntimeError and exit
8. WHEN integrity verification fails, THE MCP_Server SHALL log that bundled context files may have been tampered with and exit with code 2

### Requirement 19: OSCAL Agent

**User Story:** As a developer, I want an OSCAL expert AI agent powered by Amazon Bedrock, so that I can interact with OSCAL knowledge through a conversational interface separate from the MCP server.

#### Acceptance Criteria

1. THE Strands_Agent module SHALL create an OSCAL expert agent using the configured Bedrock model
2. THE Strands_Agent module SHALL use the configured AWS profile and region for Bedrock authentication
3. THE Strands_Agent module SHALL provide a system prompt that describes OSCAL expertise and available tool capabilities
4. THE Strands_Agent module SHALL load tools from its directory for agent tool use
