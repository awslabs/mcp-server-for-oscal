# Project Structure

```
mcp-server-for-oscal/
├── src/mcp_server_for_oscal/       # Main package
│   ├── __init__.py
│   ├── __main__.py                 # Module entry point
│   ├── main.py                     # MCP server setup, CLI arg parsing, startup integrity checks
│   ├── config.py                   # Config class — loads env vars, CLI overrides, singleton `config`
│   ├── oscal_agent.py              # Strands agent integration
│   ├── tools/                      # MCP tool implementations (one tool per file)
│   │   ├── __init__.py
│   │   ├── utils.py                # Shared: OSCALModelType enum, schema loading, hash verification
│   │   ├── get_schema.py
│   │   ├── list_models.py
│   │   ├── list_oscal_resources.py
│   │   ├── query_component_definition.py
│   │   ├── query_documentation.py
│   │   └── validate_oscal_content.py
│   ├── oscal_schemas/              # Bundled OSCAL JSON & XSD schemas + hashes.json manifest
│   ├── oscal_docs/                 # Bundled OSCAL documentation + hashes.json manifest
│   └── component_definitions/      # Bundled AWS component definitions (zip) + hashes.json
├── tests/                          # Test suite (mirrors src structure)
│   ├── conftest.py                 # Shared fixtures, pytest markers (unit, integration, slow)
│   ├── fixtures/                   # JSON test fixtures (sample/invalid component definitions)
│   ├── test_*.py                   # Top-level tests (config, main, utils, integration, properties)
│   └── tools/                      # Per-tool test files (test_get_schema.py, etc.)
├── bin/                            # Utility scripts (update_hashes.py, update-oscal-schemas.sh)
├── conf/
│   ├── agentcore/                  # Dockerfile for Bedrock AgentCore deployment
│   └── powers/oscal/               # Kiro Power config (POWER.md, mcp.json)
├── private/docs/                   # Generated reports (coverage, bandit) — not committed
├── pyproject.toml                  # Project metadata, dependencies, hatch config, tool settings
├── _version.py                     # Auto-generated version file (hatch-vcs)
└── requirements.txt                # Pinned dependencies for reproducible builds
```

## Conventions

- Each MCP tool lives in its own file under `tools/`
- Tools are registered in `main.py::_setup_tools()` via `mcp.add_tool()`
- Bundled content directories each contain a `hashes.json` manifest for integrity verification at startup
- Tests use `pytest` markers: `unit`, `integration`, `slow`; async tests auto-detected and marked with `pytest.mark.asyncio`
- Test fixtures are JSON files in `tests/fixtures/`
- The `private/` directory holds generated artifacts and is gitignored
