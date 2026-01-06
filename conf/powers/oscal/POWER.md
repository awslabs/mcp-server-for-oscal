---
name: "oscal"
displayName: "OSCAL (Open Security Controls Assessment Language)"
description: "AI assistant tools for working with NIST's Open Security Controls Assessment Language (OSCAL) - access schemas, models, documentation, and community resources for GRC automation."
keywords: ["oscal", "security", "compliance", "grc", "governance", "risk", "controls", "SSP", "POAM", "control catalog", "SAP", "SAR"]
author: "AWS Labs"
---

# OSCAL (Open Security Controls Assessment Language)

## Overview

This power provides AI assistants with comprehensive tools to work with NIST's Open Security Controls Assessment Language (OSCAL). OSCAL is a set of framework-agnostic, vendor-neutral, machine-readable schemas that describe the full life cycle of governance, risk, and compliance (GRC) artifacts, from controls to remediation plans.

The power enables AI assistants to provide accurate, authoritative guidance about OSCAL architecture, models, use cases, requirements, and implementation by accessing:
- All OSCAL model schemas and documentation
- Community resources and tools
- Structured data about OSCAL's three-layer architecture
- Real-time access to OSCAL specifications

This addresses the common challenge where AI assistants alone produce inconsistent results related to OSCAL due to limited availability of examples in the public domain.

## What is OSCAL?

OSCAL (Open Security Controls Assessment Language) is a set of framework-agnostic, vendor-neutral, machine-readable schemas developed by NIST that describe the full life cycle of GRC (governance, risk, compliance) artifacts, from controls to remediation plans. OSCAL enables automation of GRC workflows by replacing digital paper (spreadsheets, PDFs, etc.) with a standard-based structured data format.

### OSCAL's Three-Layer Architecture

**Control Layer (3 models):**
- **Catalog** - Collections of security controls (e.g., NIST 800-53, ISO 27001)
- **Profile** - Tailored selections of controls from catalogs
- **Mapping Collection** - Relationships between different control frameworks

**Implementation Layer (2 models):**
- **Component Definition** - How components implement security controls
- **System Security Plan (SSP)** - How a system implements required controls

**Assessment Layer (3 models):**
- **Assessment Plan (SAP)** - Plans for assessing control implementation
- **Assessment Results (SAR)** - Results of control assessments
- **Plan of Action and Milestones (POA&M)** - Remediation plans for findings

## Onboarding

### Prerequisites

- **uv package manager** for Python ([Installation instructions](https://docs.astral.sh/uv/getting-started/installation/))
- **Python 3.11 or higher** ([Install with uv](https://docs.astral.sh/uv/guides/install-python/))

### Installation

The OSCAL MCP server is distributed as a Python package and runs via `uvx` (no local installation required).

**Verify Prerequisites:**
```bash
# Check uv installation
uv --version

# Check Python version
python --version
```

### Configuration

Add the OSCAL MCP server to your AI assistant's MCP configuration:

**Kiro IDE** (`.kiro/settings/mcp.json`):
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

### Verification

After configuration, restart your AI assistant and verify the OSCAL tools are available:

```
> How many GA OSCAL models are there?
```

Expected response should list the 8 GA OSCAL models across the three layers.

## Common Workflows

### Workflow 1: Explore OSCAL Models and Architecture

**Goal:** Understand OSCAL's structure and available models

**Steps:**
1. **List all OSCAL models:**
   ```
   List all available OSCAL models with their status and descriptions
   ```

2. **Get detailed schema for a specific model:**
   ```
   Get the JSON schema for the OSCAL Catalog model
   ```

3. **Understand model relationships:**
   ```
   Explain how the OSCAL Profile model relates to the Catalog model
   ```


### Workflow 2: Schema Analysis and Validation

**Goal:** Understand OSCAL model structure for implementation

**Steps:**
1. **Get schema for target model:**
   ```
   Get the JSON schema for the System Security Plan model
   ```

2. **Analyze required fields:**
   ```
   What are the required fields for an OSCAL SSP?
   ```

3. **Understand data types and constraints:**
   ```
   Explain the structure of control implementations in an OSCAL SSP
   ```


### Workflow 3: Community Resources Discovery

**Goal:** Find OSCAL tools, content, and educational materials

**Steps:**
1. **Browse available resources:**
   ```
   Show me available OSCAL community resources
   ```

2. **Filter by category:**
   ```
   What OSCAL tools are available for validation?
   ```

3. **Find educational content:**
   ```
   Are there any OSCAL tutorials or presentations available?
   ```


## Troubleshooting

### MCP Server Connection Issues

**Problem:** OSCAL MCP server won't start or connect
**Symptoms:**
- Error: "Connection refused"
- Server not responding
- Tools not available in AI assistant

**Solutions:**
1. **Verify uv installation:**
   ```bash
   uv --version
   ```
   If not installed, follow [uv installation guide](https://docs.astral.sh/uv/getting-started/installation/)

2. **Test server manually:**
   ```bash
   uvx --from mcp-server-for-oscal@latest server
   ```

3. **Check Python version:**
   ```bash
   python --version
   ```
   Ensure Python 3.11 or higher is installed

4. **Restart AI assistant** after configuration changes

5. **Check MCP configuration syntax** - ensure JSON is valid

### Tool Execution Errors

**Error:** "Tool not found" or "Permission denied"
**Cause:** MCP server not properly registered or tools not trusted
**Solution:**
1. Verify MCP configuration is correct
2. For Kiro: Add tools to `autoApprove` list in configuration
3. Restart AI assistant
4. Try trusting tools manually: `/tools trust get_oscal_schema list_oscal_models`

**Error:** "Schema not found for model X"
**Cause:** Invalid model name provided to get_oscal_schema
**Solution:**
1. Use `list_oscal_models` to see valid model names
2. Use exact model names: catalog, profile, ssp, component-definition, etc.

### Package Installation Issues

**Problem:** uvx can't find or install mcp-server-for-oscal
**Cause:** Network issues or package not available
**Solution:**
1. Check internet connection
2. Try updating uv: `uv self update`
3. Clear uv cache: `uv cache clean`

## Best Practices

### Using OSCAL Tools Effectively

- **Start with list_oscal_models** to understand the full OSCAL architecture before diving into specific models
- **Use get_oscal_schema** to understand exact data structures when implementing OSCAL documents
- **Leverage community resources** via list_oscal_resources to find existing tools rather than building from scratch


---

**Package:** `mcp-server-for-oscal`
**MCP Server:** oscal
**GitHub:** https://github.com/awslabs/mcp-server-for-oscal