# MCP Server for OSCAL

A Model Context Protocol (MCP) server that provides AI assistants with tools to work with NIST's Open Security Controls Assessment Language (OSCAL). This server enables AI assistants to query OSCAL documentation, retrieve schemas, and understand OSCAL model structures to help with security compliance workflows.

## What is OSCAL?

[OSCAL (Open Security Controls Assessment Language)](https://pages.nist.gov/OSCAL/) is a set of framework-agnostic, vendor-neutral, machine-readable schemas developed by NIST that describe common security artifacts like controls and assessments. OSCAL enables automation of security governance, risk, and compliance workflows.
## Features

This MCP server provides three main tools for working with OSCAL:

### 1. Query OSCAL Documentation
- **Tool**: `query_oscal_documentation`
- Query authoritative OSCAL documentation using Amazon Bedrock Knowledge Base
- Get answers to questions about OSCAL concepts, best practices, and implementation guidance

### 2. List OSCAL Models  
- **Tool**: `list_oscal_models`
- Retrieve all available OSCAL model types with descriptions, layers, and status
- Understand the different OSCAL models and their purposes

### 3. Get OSCAL Schemas
- **Tool**: `get_oscal_schema`  
- Retrieve JSON or XSD schemas for specific OSCAL models
- Validate OSCAL documents or understand model structure
- Supports all OSCAL model types: catalog, profile, component-definition, system-security-plan, assessment-plan, assessment-results, plan-of-action-and-milestones

## Installation

### Prerequisites

- Python 3.11 or higher
- AWS credentials configured (for Bedrock Knowledge Base integration)

### Using with AI Assistants

Once running, the MCP server exposes three tools that AI assistants can use:

1. **Query Documentation**: Ask questions about OSCAL concepts, implementation guidance, or best practices
2. **List Models**: Get information about available OSCAL model types and their purposes  
3. **Get Schema**: Retrieve the JSON or XSD schema for any OSCAL model to understand its structure

### Example Queries

Here are some example queries an AI assistant could make using this MCP server:

```bash
# Query OSCAL documentation
"What is the difference between a catalog and a profile in OSCAL?"
"How do I implement continuous monitoring with OSCAL?"

# List available models
"Show me all available OSCAL model types"

# Get schema information  
"Get the JSON schema for the system-security-plan model"
"Retrieve the XSD schema for assessment-results"
```

## Development
See [DEVELOPING](DEVELOPING.md) to get started.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the [Apache-2.0](LICENSE) License.
