"""
Tests for the centralized tool registry in tools/__init__.py.

Covers unit tests (task 1.3) and property-based tests (task 1.2)
for the get_tool_list() function.

Feature: oscal-agent-production
"""

from unittest.mock import patch

from hypothesis import given, settings
from hypothesis import strategies as st

from mcp_server_for_oscal.config import config
from mcp_server_for_oscal.tools import get_tool_list

# All tools that should always be present (query_oscal_documentation is
# unconditionally registered regardless of knowledge_base_id config).
BASE_TOOL_NAMES = {
    "list_oscal_models",
    "get_oscal_schema",
    "list_oscal_resources",
    "query_component_definition",
    "list_component_definitions",
    "list_components",
    "list_capabilities",
    "get_capability",
    "validate_oscal_content",
    "validate_oscal_file",
    # New OSCAL model tools
    "query_catalog",
    "list_catalogs",
    "query_ssp",
    "list_ssps",
    "query_profile",
    "list_profiles",
    "query_assessment_plan",
    "list_assessment_plans",
    "query_assessment_results",
    "list_assessment_results",
    "query_poam",
    "list_poams",
    "query_mapping_collection",
    "list_mapping_collections",
    "text_search_oscal",
    # Child element tools
    "list_catalog_controls",
    "list_catalog_groups",
    "list_ssp_control_implementations",
    "list_ssp_system_components",
    "list_profile_imports",
    "list_profile_modify",
    "list_assessment_plan_tasks",
    "list_assessment_plan_activities",
    "list_assessment_results_results",
    "list_assessment_results_findings",
    "list_poam_items",
    "list_mapping_collection_mappings",
    "get_child_element",
    # Documentation tool (unconditionally registered)
    "query_oscal_documentation",
}


class TestGetToolListUnit:
    """Unit tests for get_tool_list() — task 1.3."""

    def test_returns_all_base_tools(self):
        """get_tool_list() returns all base tools including query_oscal_documentation."""
        tools = get_tool_list()
        tool_names = {t.__name__ for t in tools}
        assert BASE_TOOL_NAMES == tool_names

    def test_excludes_about(self):
        """get_tool_list() never includes the 'about' tool."""
        tools = get_tool_list()
        tool_names = {t.__name__ for t in tools}
        assert "about" not in tool_names

    def test_includes_query_oscal_documentation_when_kb_id_set(self):
        """get_tool_list() includes query_oscal_documentation when KB ID is set."""
        with patch.object(config, "knowledge_base_id", "my-kb-id"):
            tools = get_tool_list()
            tool_names = {t.__name__ for t in tools}
            assert "query_oscal_documentation" in tool_names

    def test_includes_query_oscal_documentation_when_kb_id_empty(self):
        """get_tool_list() includes query_oscal_documentation even when KB ID is empty."""
        with patch.object(config, "knowledge_base_id", ""):
            tools = get_tool_list()
            tool_names = {t.__name__ for t in tools}
            assert "query_oscal_documentation" in tool_names


class TestProperty1UnconditionalToolInclusion:
    """
    Property 1: Unconditional tool inclusion

    For any string value of knowledge_base_id (empty or non-empty),
    the tool list returned by get_tool_list() SHALL always contain
    query_oscal_documentation and all base tools.

    **Validates: Requirements 1.2, 1.3, 4.1**
    """

    @settings(max_examples=100)
    @given(kb_id=st.text(min_size=1, max_size=200).filter(lambda s: s.strip()))
    def test_non_empty_kb_id_includes_doc_tool(self, kb_id):
        """
        Feature: oscal-agent-production, Property 1: Unconditional tool inclusion

        When knowledge_base_id is a non-empty string, query_oscal_documentation
        must be present and all base tools must also be present.
        """
        with patch.object(config, "knowledge_base_id", kb_id):
            tools = get_tool_list()
            tool_names = {t.__name__ for t in tools}

            assert "query_oscal_documentation" in tool_names
            assert BASE_TOOL_NAMES.issubset(tool_names)

    @settings(max_examples=100)
    @given(kb_id=st.just(""))
    def test_empty_kb_id_still_includes_doc_tool(self, kb_id):
        """
        Feature: oscal-agent-production, Property 1: Unconditional tool inclusion

        When knowledge_base_id is empty, query_oscal_documentation must
        still be present, along with all base tools.
        """
        with patch.object(config, "knowledge_base_id", kb_id):
            tools = get_tool_list()
            tool_names = {t.__name__ for t in tools}

            assert "query_oscal_documentation" in tool_names
            assert BASE_TOOL_NAMES.issubset(tool_names)
