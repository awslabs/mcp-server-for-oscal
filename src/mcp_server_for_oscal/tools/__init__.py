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
    from mcp_server_for_oscal.tools.query_oscal_models import (
        get_child_element,
        list_assessment_plan_activities,
        list_assessment_plan_tasks,
        list_assessment_plans,
        list_assessment_results,
        list_assessment_results_findings,
        list_assessment_results_results,
        list_catalog_controls,
        list_catalog_groups,
        list_catalogs,
        list_mapping_collection_mappings,
        list_mapping_collections,
        list_poam_items,
        list_poams,
        list_profile_imports,
        list_profile_modify,
        list_profiles,
        list_ssp_control_implementations,
        list_ssp_system_components,
        list_ssps,
        query_assessment_plan,
        query_assessment_results,
        query_catalog,
        query_mapping_collection,
        query_poam,
        query_profile,
        query_ssp,
        text_search_oscal,
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
        # New OSCAL model tools
        query_catalog,
        list_catalogs,
        query_ssp,
        list_ssps,
        query_profile,
        list_profiles,
        query_assessment_plan,
        list_assessment_plans,
        query_assessment_results,
        list_assessment_results,
        query_poam,
        list_poams,
        query_mapping_collection,
        list_mapping_collections,
        text_search_oscal,
        # Child element tools
        list_catalog_controls,
        list_catalog_groups,
        list_ssp_control_implementations,
        list_ssp_system_components,
        list_profile_imports,
        list_profile_modify,
        list_assessment_plan_tasks,
        list_assessment_plan_activities,
        list_assessment_results_results,
        list_assessment_results_findings,
        list_poam_items,
        list_mapping_collection_mappings,
        get_child_element,
    ]

    if config.knowledge_base_id:
        from mcp_server_for_oscal.tools.query_documentation import (
            query_oscal_documentation,
        )

        tools.append(query_oscal_documentation)

    return tools
