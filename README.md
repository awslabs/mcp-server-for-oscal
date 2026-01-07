<div align="center">

![Build Status](https://github.com/awslabs/mcp-server-for-oscal/workflows/CI/badge.svg)
![Version](https://img.shields.io/github/v/release/awslabs/mcp-server-for-oscal)
[![PyPI][pypi-badge]][pypi-url]
[![PyPI - Downloads](https://img.shields.io/pypi/dm/mcp-server-for-oscal)][pypi-url]
[![OSCAL](https://img.shields.io/badge/dynamic/regex?url=https%3A%2F%2Fraw.githubusercontent.com%2Fawslabs%2Fmcp-server-for-oscal%2Frefs%2Fheads%2Fmain%2Fbin%2Fupdate-oscal-schemas.sh&search=CURRENT_RELEASE_VERSION%3D%22(%5Cd.%5Cd.%5Cd)%22&replace=%241&label=OSCAL)][nist-oscal-url]
![GitHub License](https://img.shields.io/github/license/awslabs/mcp-server-for-oscal)
</div>

[pypi-badge]: https://img.shields.io/pypi/v/mcp-server-for-oscal.svg
[pypi-url]: https://pypi.org/project/mcp-server-for-oscal/
[oscal-badge]: https://img.shields.io/badge/OSCAL-1.2.0-blue
[nist-oscal-url]: https://pages.nist.gov/OSCAL/
# MCP Server for OSCAL
<strong>
Instant OSCAL expertise for your favorite AI agent
</strong>

A Model Context Protocol (MCP) server that provides AI assistants (Claude, Cline, Kiro, Claude Code, etc.) with tools to work with NIST's Open Security Controls Assessment Language (OSCAL). Like many early adopters, we needed help implementing OSCAL proofs-of-concept to demonstrate value to business stakeholders. Perhaps due to limited availability of examples in the public domain, we found that most AI agents/LLMs alone produced inconsistent results related to OSCAL. The tools in this MCP server minimzed that problem for our use-case and we hope they do the same for you. 

> [!TIP]
> To get started, see [Installation](#installation) below.

## What is OSCAL?

[OSCAL (Open Security Controls Assessment Language)][nist-oscal-url] is a set of framework-agnostic, vendor-neutral, machine-readable schemas developed by NIST that describe the full life cycle of GRC (governance, risk, compliance) artifacts, from controls to remediation plans. OSCAL enables automation of GRC workflows by replacing digital paper (spreadsheets, PDFs, etc.) with a standard-based structured data format.
## Features

This MCP server provides a set of [tools](src/mcp_server_for_oscal/tools/) for working with OSCAL. Together, the tools are meant to enable your preferred AI assitant to provide accurate, authoritative gudiance about OSCAL architecture, models, use-cases, requirements, and implementation.

## Examples
Examples below were created with kiro-cli, but should work with any AI assistant that supports MCP servers.

### Example 1: Learn about available OSCAL models
```
 % kiro-cli

> /tools trust get_oscal_schema list_oscal_models list_oscal_resources


Tools '@oscal/get_oscal_schema', '@oscal/list_oscal_models', '@oscal/list_oscal_resources' are now trusted. I will not ask for confirmation before running these tools.


> How many GA OSCAL models are there? 


> I'll check the available OSCAL models to find out how many are in GA (Generally Available) status.
Running tool list_oscal_models with the param (from mcp server: oscal)
 ⋮  {}
 - Completed in 0.1s

> There are 8 GA OSCAL models:

Control Layer (3):
- Catalog
- Profile  
- Mapping Collection

Implementation Layer (2):
- Component Definition
- System Security Plan (SSP)

Assessment Layer (3):
- Assessment Plan (SAP)
- Assessment Results (SAR)
- Plan of Action and Milestones (POA&M)

All of these models have "GA" (Generally Available) status, meaning they are stable and ready for production use.
 ▸ Time: 8s
```

### Example 2: OSCAL template generation
```
> generate a minimum, valid, OSCAL mapping in JSON for use as a template.

> I'll help you create a minimal, valid OSCAL mapping in JSON. Let me first check what OSCAL models are available to understand the structure.
Running tool list_oscal_models with the param (from mcp server: oscal)
 ⋮  {}
 - Completed in 0.1s

> Now let me get the schema for the mapping-collection model to understand its structure:
Running tool get_oscal_schema with the param (from mcp server: oscal)
 ⋮  {
 ⋮    "model_name": "mapping-collection",
 ⋮    "schema_type": "json"
 ⋮  }
 - Completed in 0.14s

> Based on the schema, I'll create a minimal, valid OSCAL mapping collection template. Here's the absolute minimum required structure:
I'll create the following file: ./oscal-mapping-template.json (using tool: write)
Purpose: Create minimal OSCAL mapping collection template

+     1: {
+     2:   "mapping-collection": {
+     3:     "uuid": "12345678-1234-4567-8901-123456789012",
+     4:     "metadata": {
+     5:       "title": "Sample Mapping Collection",
+     6:       "last-modified": "2026-01-06T20:46:28.034Z",
+     7:       "version": "1.0",
+     8:       "oscal-version": "1.2.0"
+     9:     },
+    10:     "provenance": {
+    11:       "method": "human",
+    12:       "matching-rationale": "semantic",
+    13:       "status": "draft",
+    14:       "mapping-description": "Sample mapping between two control frameworks"
+    15:     },
+    16:     "mappings": [
+    17:       {
+    18:         "uuid": "87654321-4321-7654-1098-210987654321",
+    19:         "source-resource": {
+    20:           "type": "catalog",
+    21:           "href": "https://example.com/source-catalog.json"
+    22:         },
+    23:         "target-resource": {
+    24:           "type": "catalog", 
+    25:           "href": "https://example.com/target-catalog.json"
+    26:         },
+    27:         "maps": [
+    28:           {
+    29:             "uuid": "11111111-2222-3333-4444-555555555555",
+    30:             "relationship": "equivalent",
+    31:             "sources": [
+    32:               {
+    33:                 "type": "control",
+    34:                 "id-ref": "ac-1"
+    35:               }
+    36:             ],
+    37:             "targets": [
+    38:               {
+    39:                 "type": "control",
+    40:                 "id-ref": "access-control-policy"
+    41:               }
+    42:             ]
+    43:           }
+    44:         ]
+    45:       }
+    46:     ]
+    47:   }
+    48: }

Creating: ./oscal-mapping-template.json
 - Completed in 0.8s

> I've created a minimal, valid OSCAL mapping collection template at ./oscal-mapping-template.json. This template includes:

Required elements:
- uuid: Unique identifier for the mapping collection
- metadata: Document metadata with title, last-modified timestamp, version, and OSCAL version
- provenance: Mapping methodology information including method, matching rationale, status, and description
- mappings: Array containing at least one mapping with:
  - uuid: Mapping identifier
  - source-resource and target-resource: References to the catalogs being mapped
  - maps: Array with mapping entries showing relationships between controls

Key features:
- Uses placeholder UUIDs (replace with actual UUIDs in production)
- Maps a source control "ac-1" to target control "access-control-policy" with "equivalent" relationship
- Includes minimal required fields only
- Valid JSON structure conforming to OSCAL 1.2.0 schema

You can customize this template by:
- Replacing placeholder UUIDs with real ones
- Updating the resource URLs to point to actual catalogs
- Adding more mapping entries in the maps array
- Modifying control IDs and relationships as needed
 ▸ Time: 21s

```

### Example 3: Discover open source OSCAL catalogs
```
> What are some open source OSCAL catalogs?

Running tool list_oscal_resources with the param (from mcp server: oscal)
 ⋮  {}
 - Completed in 0.51s

> Based on the OSCAL community resources, here are some notable open source OSCAL catalogs:

## Government/Official Catalogs

Australian Cyber Security Centre (ACSC)
- Information Security Manual (ISM) controls in OSCAL format
- Essential Eight Maturity Levels (ML1, ML2, ML3)
- Available at: https://www.cyber.gov.au/ism/oscal

CMS Acceptable Risk Safeguards (ARS)
- Tailored NIST SP 800-53 controls for Centers for Medicare and Medicaid Services
- Available at: https://github.com/CMSgov/ars-machine-readable

GovTech Singapore
- ICT&SS Policy catalog and profile for low-risk systems
- Available at: https://github.com/GovtechSG/tech-standards

## Industry/Standards Organizations

Center for Internet Security (CIS)
- CIS Critical Security Controls (formerly Top 18/20)
- Available at: https://github.com/CISecurity/CISControls_OSCAL/

Cloud Security Alliance (CSA)
- Cloud Controls Matrix v4 in OSCAL format
- Available at: https://cloudsecurityalliance.org/artifacts/ccm-machine-readable-bundle-json-yaml-oscal/

NIST SP 800-171 (Community)
- Maintained by Fathom5
- Available at: https://github.com/FATHOM5/oscal/tree/main/content/SP800-171/oscal-content

## Community Collections

CivicActions Component Definitions
- Cloud services, software, security and privacy controls
- Available at: https://github.com/CivicActions/oscal-component-definitions

RedHat OSCAL Content
- Component definitions: https://github.com/RedHatProductSecurity/oscal-component-definitions
- Custom profiles: https://github.com/RedHatProductSecurity/oscal-profiles

Brad Hards ISM Catalog
- Australian Government ISM controls (community version)
- Available at: https://github.com/bradh/ism-oscal

These catalogs provide ready-to-use OSCAL content for various compliance frameworks and can serve as templates or starting points for your own OSCAL implementations.
 ▸ Time: 15s
 ```


## Installation
Follow these instructions to setup the MCP server for use with your IDE or preferred AI tool. 

> [!NOTE] 
> To setup for development instead, see [DEVELOPING.md](DEVELOPING.md)

### Prerequisites

- `uv` package manager for Python ([Installation instructions](https://docs.astral.sh/uv/getting-started/installation/))
- Python 3.11 or higher ([`uv install python 3.12`](https://docs.astral.sh/uv/guides/install-python/)). The server may work with other versions of Python, but we only test 3.11 & 3.12 for now.

### Configuring IDEs and AI Tools

This MCP server communicates via stdio (standard input/output) and can be integrated with various IDEs and agentic tools that support the Model Context Protocol.

#### Configuration Format

Most MCP-compatible tools use a JSON configuration format described in the [FastMCP documentation](https://gofastmcp.com/integrations/mcp-json-configuration). Here's the basic structure:

```json
{
  "mcpServers": {
    "oscal": {
      "command": "uvx",
      "args": ["--from", "mcp-server-for-oscal@latest", "server"],
      "env": {
      }
    }
  }
}
```

 For typical, runtime use of the MCP server, additional configuration should not be required. If needed, runtime environment variables can be configured in the `"env": {}` object (shown above, empty) as described in the [FastMCP documentation](https://gofastmcp.com/integrations/mcp-json-configuration#env-optional). See the file [dotenv.example](dotenv.example) for available options. 

> [!Note]
> A dotenv file is only needed in a development environment. 

#### Kiro Configuration

See [Kiro's MCP documentation](https://kiro.dev/docs/mcp/configuration/) for additional options. Add to your `.kiro/settings/mcp.json`:

```json
{
  "mcpServers": {
    "oscal": {
      "command": "uvx",
      "args": ["--from", "mcp-server-for-oscal@latest", "server"],
      "env": {},
      "disabled": false,
      "autoApprove": [
        "get_oscal_schema",
        "list_oscal_resources",
        "list_oscal_models",
        "query_oscal_documentation"
      ]
    }
  }
}
```

#### Claude Desktop
Add to your `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "oscal": {
      "command": "uvx",
      "args": ["--from", "mcp-server-for-oscal@latest", "server"]
    }
  }
}
```

#### VS Code
Run the `MCP: Open User Configuration` command, which opens the mcp.json file in your user profile. You can then manually add the server configuration to the file. See the [VSCode/Copilot docs](https://code.visualstudio.com/docs/copilot/customization/mcp-servers#_add-an-mcp-server) for addtional options and details.

```json
{
  "servers": [
    "oscal": {
      "command": "uvx",
      "args": ["--from", "mcp-server-for-oscal@latest", "server"]
    }
  ]
}
```

## Development
See [DEVELOPING](DEVELOPING.md) to get started.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the [Apache-2.0](LICENSE) License.
