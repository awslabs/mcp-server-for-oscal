# MCP Server for OSCAL

A Model Context Protocol (MCP) server that provides AI assistants (Claude, Cline, Kiro, Claude Code, etc.) with tools to work with NIST's Open Security Controls Assessment Language (OSCAL). Like many early adopters, we needed help implementing OSCAL proofs-of-concept to demonstrate value to business stakeholders. Perhaps due to limited availability of examples in the public domain, we found that most AI agents/LLMs alone produced inconsistent results related to OSCAL. The tools in this MCP server minimzed that problem for our use-case and we hope they do the same for you. 

## What is OSCAL?

[OSCAL (Open Security Controls Assessment Language)](https://pages.nist.gov/OSCAL/) is a set of framework-agnostic, vendor-neutral, machine-readable schemas developed by NIST that describe common security artifacts like controls and assessments. OSCAL enables automation of security governance, risk, and compliance workflows.
## Features

This MCP server provides these [tools](src/mcp_server_for_oscal/tools/) for working with OSCAL:

### 1. List OSCAL Models  
- **Tool**: `list_oscal_models`
- Retrieve all available OSCAL model types with descriptions, layers, and status
- Understand the different OSCAL models and their purposes

### 2. Get OSCAL Schemas
- **Tool**: `get_oscal_schema`  
- Retrieve JSON or XSD schemas for current GA release of individual OSCAL models. Because OSCAL schemas are self-documenting, this is equivalent to querying model documentation.
- Used to answer questions about the structure, properties, requirements of each OSCAL model

### 3. List OSCAL Community Resources
- **Tool**: `list_oscal_resources`
- Access a curated collection of OSCAL community resources from [Awesome OSCAL](https://github.com/oscal-club/awesome-oscal)
- Get information about available OSCAL tools, content, articles, presentations, and educational materials
- Includes resources from government agencies, security organizations, and the broader OSCAL community

### 4. Query OSCAL Documentation
- **Tool**: `query_oscal_documentation`
- Query authoritative OSCAL documentation using Amazon Bedrock Knowledge Base (KB). Note that this feature requires you to setup and maintain a Bedrock KB in your AWS account. In future, we hope to provide this as a service.
- Get answers to questions about OSCAL concepts, best practices, and implementation guidance.

## Installation

### Prerequisites

- Python 3.11 or higher

### Configuring IDEs and AI Tools

This MCP server communicates via stdio (standard input/output) and can be integrated with various IDEs and agentic tools that support the Model Context Protocol.

#### Configuration Format

Most MCP-compatible tools use a JSON configuration format. *Values in the `"env":` section are generally not needed*, but shown here as a how-to. Here's the basic structure:

```json
{
  "mcpServers": {
    "oscal": {
      "command": "uvx",
      "args": ["mcp-server-for-oscal@latest", "server"],
      "env": {
      }
    }
  }
}
```

#### IDE-Specific Configuration

**Kiro IDE**
Add to your `.kiro/settings/mcp.json`:

```json
{
  "mcpServers": {
    "oscal": {
      "command": "uvx",
      "args": ["mcp-server-for-oscal@latest", "server"],
      "env": {
        "AWS_PROFILE": "your-aws-profile"
      },
      "disabled": false,
      "autoApprove": ["query_oscal_documentation", "list_oscal_models"]
    }
  }
}
```

**Claude Desktop**
Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "oscal": {
      "command": "uvx",
      "args": ["mcp-server-for-oscal@latest", "server"]
    }
  }
}
```

**VS Code with MCP Extension**
Configure in your workspace settings or user settings:

```json
{
  "mcp.servers": [
    {
      "name": "oscal",
      "command": "uvx",
      "args": ["mcp-server-for-oscal@latest", "server"]
    }
  ]
}
```

#### Environment Variables
Generally, configuration should not be required. See the file [dotenv.example](dotenv.example) for available options. Note that a dotenv file is only needed in a development environment. For typical, runtime use of the MCP server, environment variables should be configured as described above.

## Development
See [DEVELOPING](DEVELOPING.md) to get started.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the [Apache-2.0](LICENSE) License.
