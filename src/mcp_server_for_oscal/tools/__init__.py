"""
OSCAL MCP Server Tools

This package contains all the tool functions for the OSCAL MCP server.
"""

from collections.abc import Callable


def get_tool_list() -> list[Callable]:
    """Return the canonical list of OSCAL tool functions.

    Conditionally includes query_oscal_documentation when
    config.knowledge_base_id is set. Excludes the `about` tool
    (MCP-server-only).
    """
    from mcp_server_for_oscal.config import config
    from mcp_server_for_oscal.tools.get_schema import get_oscal_schema
    from mcp_server_for_oscal.tools.list_models import list_oscal_models
    from mcp_server_for_oscal.tools.list_oscal_resources import list_oscal_resources
    from mcp_server_for_oscal.tools.query_component_definition import (
        get_capability,
        list_capabilities,
        list_component_definitions,
        list_components,
        query_component_definition,
    )
    from mcp_server_for_oscal.tools.validate_oscal_content import (
        validate_oscal_content,
        validate_oscal_file,
    )

    tools: list[Callable] = [
        list_oscal_models,
        get_oscal_schema,
        list_oscal_resources,
        query_component_definition,
        list_component_definitions,
        list_components,
        list_capabilities,
        get_capability,
        validate_oscal_content,
        validate_oscal_file,
    ]

    if config.knowledge_base_id:
        from mcp_server_for_oscal.tools.query_documentation import (
            query_oscal_documentation,
        )

        tools.append(query_oscal_documentation)

    return tools
