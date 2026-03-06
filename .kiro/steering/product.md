# Product Overview

MCP Server for OSCAL is a Model Context Protocol (MCP) server that gives AI assistants (Claude, Kiro, Claude Code, etc.) tools to work with NIST's Open Security Controls Assessment Language (OSCAL).

OSCAL is a set of framework-agnostic, vendor-neutral, machine-readable schemas from NIST that describe the full GRC (governance, risk, compliance) lifecycle — from controls to remediation plans. It replaces spreadsheets and PDFs with structured, automatable data.

## Purpose

Most LLMs produce inconsistent OSCAL output due to limited public examples. This MCP server solves that by providing tools that give AI agents accurate, authoritative OSCAL guidance covering architecture, models, use-cases, requirements, and implementation.

## Key Characteristics

- Runs locally with no external service dependencies by default (all OSCAL schemas and docs are bundled)
- Uses `stdio` transport by default; `streamable-http` is available but lacks auth
- Bundled content is integrity-verified at startup via SHA-256 hash manifests
- Published on PyPI as `mcp-server-for-oscal`
- Licensed under Apache-2.0

## Tools Provided

- `list_oscal_models` — list available OSCAL model types
- `get_oscal_schema` — retrieve JSON/XSD schemas for any OSCAL model
- `list_oscal_resources` — list bundled OSCAL resources
- `query_component_definition` — query AWS component definitions
- `list_component_definitions`, `list_components`, `list_capabilities`, `get_capability` — navigate component definition content
- `validate_oscal_content` / `validate_oscal_file` — validate OSCAL JSON against schemas using compliance-trestle
- `query_oscal_documentation` — RAG-based doc query (requires AWS Bedrock Knowledge Base, conditionally registered)
- `about` — server metadata
