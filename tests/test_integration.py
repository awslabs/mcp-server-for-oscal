"""
Integration tests for the OSCAL MCP Server.
"""

import requests
from unittest.mock import AsyncMock, Mock, patch

import pytest
from mcp.server.fastmcp import FastMCP

from mcp_server_for_oscal.main import mcp
from mcp_server_for_oscal.tools.get_schema import get_oscal_schema
from mcp_server_for_oscal.tools.list_models import list_oscal_models
from mcp_server_for_oscal.tools.query_documentation import query_oscal_documentation
from mcp_server_for_oscal.tools.utils import OSCALModelType, schema_names


class TestIntegration:
    """Integration test cases for the OSCAL MCP Server."""

    def test_mcp_server_initialization(self):
        """Test that the MCP server is properly initialized."""
        # Verify MCP server is a FastMCP instance
        assert isinstance(mcp, FastMCP)

        # Verify server has the expected name
        assert mcp.name == "OSCAL"  # Default from config

        # Verify server has instructions
        assert mcp.instructions is not None
        assert "OSCAL" in mcp.instructions

    def test_mcp_server_tools_registration(self):
        """Test that all expected tools are registered with the MCP server."""
        # Get the registered tools
        tools = mcp._tool_manager._tools

        # Verify expected number of tools
        assert len(tools) >= 3, "Expected at least 3 tools to be registered"

        # Verify specific tools are registered by checking their names
        tool_names = [tool.name for tool in tools.values()]

        expected_tools = [
            "list_oscal_resources",
            "list_oscal_models",
            "get_oscal_schema",
        ]

        for expected_tool in expected_tools:
            assert expected_tool in tool_names, (
                f"Tool {expected_tool} not found in registered tools"
            )

    def test_mcp_server_tool_schemas(self):
        """Test that registered tools have proper schemas."""
        tools = mcp._tool_manager._tools

        for tool_name, tool in tools.items():
            # Verify tool has a schema
            assert hasattr(tool, "schema"), f"Tool {tool_name} missing schema"

            # Verify schema has required fields
            # schema = tool.model_json_schema()
            # assert 'name' in schema, f"Tool {tool_name} schema missing name"
            # assert 'description' in schema, f"Tool {tool_name} schema missing description"

            # # Verify name matches
            # assert schema['name'] == tool_name, f"Tool {tool_name} schema name mismatch"

            # # Verify description is not empty
            # assert schema['description'].strip(), f"Tool {tool_name} has empty description"

    @patch("mcp_server_for_oscal.tools.query_documentation.Session")
    @patch("mcp_server_for_oscal.tools.query_documentation.config")
    def test_query_documentation_tool_integration(
        self, mock_config, mock_session_class
    ):
        """Test integration of query_documentation tool."""
        # Setup mocks
        mock_config.aws_profile = None
        mock_config.knowledge_base_id = "test-kb-id"
        mock_config.log_level = "INFO"

        mock_session = Mock()
        mock_client = Mock()
        mock_response = {
            "retrievalResults": [
                {"content": {"text": "Test OSCAL content"}, "score": 0.9}
            ]
        }
        mock_client.retrieve.return_value = mock_response
        mock_session.client.return_value = mock_client
        mock_session_class.return_value = mock_session

        mock_context = Mock()

        # Execute tool
        result = query_oscal_documentation("What is OSCAL?", mock_context)

        # Verify result
        assert result == mock_response
        assert "retrievalResults" in result
        assert len(result["retrievalResults"]) > 0

    @patch("mcp_server_for_oscal.tools.get_schema.open_schema_file")
    @patch("mcp_server_for_oscal.tools.get_schema.json.load")
    def test_get_schema_tool_integration(self, mock_json_load, mock_open_schema_file):
        """Test integration of get_schema tool."""
        # Setup mocks
        mock_file = Mock()
        mock_open_schema_file.return_value = mock_file
        mock_schema = {"$schema": "test-schema", "type": "object"}
        mock_json_load.return_value = mock_schema

        mock_context = Mock()
        mock_context.session = Mock()
        mock_context.session.client_params = {}

        # Execute tool
        result = get_oscal_schema(
            mock_context, model_name="catalog", schema_type="json"
        )

        # Verify result
        import json

        parsed_result = json.loads(result)
        assert parsed_result == mock_schema
        assert "$schema" in parsed_result

    def test_list_models_tool_integration(self):
        """Test integration of list_models tool."""
        # Execute tool
        result = list_oscal_models()

        # Verify result structure
        assert isinstance(result, dict)
        assert len(result) > 0

        # Verify each model has expected structure
        for model_name, model_info in result.items():
            assert isinstance(model_info, dict)
            assert "description" in model_info
            assert "layer" in model_info
            assert "status" in model_info

            # Verify values are not empty
            assert model_info["description"].strip()
            assert model_info["layer"].strip()
            assert model_info["status"].strip()

    def test_mcp_server_instructions_content(self):
        """Test that MCP server instructions contain expected content."""
        instructions = mcp.instructions

        # Verify key content is present
        expected_content = [
            "OSCAL MCP server",
            "OSCAL",
            "Open Security Controls Assessment Language",
            "NIST",
            "security",
            "controls",
        ]

        for content in expected_content:
            assert content in instructions, (
                f"Expected content '{content}' not found in instructions"
            )

    @patch("mcp_server_for_oscal.main.config")
    def test_mcp_server_configuration_integration(self, mock_config):
        """Test that MCP server uses configuration properly."""
        # Test with custom server name
        mock_config.server_name = "Custom OSCAL Server"

        # Create new MCP instance with custom config
        from mcp_server_for_oscal.main import FastMCP

        custom_mcp = FastMCP(mock_config.server_name, instructions="Test instructions")

        # Verify custom name is used
        assert custom_mcp.name == "Custom OSCAL Server"

    def test_tool_function_signatures(self):
        """Test that tool functions have expected signatures."""
        import inspect

        # Test query_documentation signature
        sig = inspect.signature(query_oscal_documentation)
        params = list(sig.parameters.keys())
        assert "query" in params
        assert "ctx" in params

        # Test get_schema signature
        sig = inspect.signature(get_oscal_schema)
        params = list(sig.parameters.keys())
        assert "ctx" in params
        assert "model_name" in params
        assert "schema_type" in params

        # Test list_models signature
        sig = inspect.signature(list_oscal_models)
        # list_models takes no parameters
        assert len(sig.parameters) == 0

    def test_tool_decorators(self):
        """Test that tools have proper decorators."""

        # Check query_documentation has @tool decorator
        # This is indicated by the presence of certain attributes added by the decorator
        assert hasattr(query_oscal_documentation, "__wrapped__") or hasattr(
            query_oscal_documentation, "_tool_metadata"
        )

        # Check get_schema has @tool decorator
        assert hasattr(get_oscal_schema, "__wrapped__") or hasattr(
            get_oscal_schema, "_tool_metadata"
        )

        # Check list_models has @tool decorator
        assert hasattr(list_oscal_models, "__wrapped__") or hasattr(
            list_oscal_models, "_tool_metadata"
        )

    @patch("mcp_server_for_oscal.tools.query_documentation.Session")
    @patch("mcp_server_for_oscal.tools.query_documentation.config")
    def test_error_handling_integration(self, mock_config, mock_session_class):
        """Test error handling across integrated components."""
        # Setup mocks to simulate AWS error
        mock_config.aws_profile = None
        mock_config.knowledge_base_id = "invalid-kb-id"
        mock_config.log_level = "INFO"

        from botocore.exceptions import ClientError

        error_response = {
            "Error": {
                "Code": "ResourceNotFoundException",
                "Message": "Knowledge base not found",
            }
        }

        mock_session = Mock()
        mock_client = Mock()
        mock_client.retrieve.side_effect = ClientError(error_response, "Retrieve")
        mock_session.client.return_value = mock_client
        mock_session_class.return_value = mock_session

        mock_context = Mock()

        # Execute tool and verify error handling
        with pytest.raises(Exception):
            query_oscal_documentation("test query", mock_context)

        # Verify error was reported to context
        mock_context.error.assert_called_once()

    def test_mcp_server_transport_compatibility(self):
        """Test that MCP server is compatible with expected transports."""
        # Verify server can be configured for streamable-http transport
        # This is tested by checking that the server has the necessary methods
        assert hasattr(mcp, "run"), "MCP server missing run method"

        # The actual transport compatibility is tested in the main function tests
        # Here we just verify the server structure supports it

    # TODO: this may be a redundant test; compare to test_get_schema.test_get_schema_all_valid_models
    @patch("mcp_server_for_oscal.tools.get_schema.open_schema_file")
    def test_schema_file_integration(self, mock_open_schema_file):
        """Test integration with schema file system."""
        # Test that schema files are accessed correctly
        mock_file = Mock()
        mock_open_schema_file.return_value = mock_file

        with patch("mcp_server_for_oscal.tools.get_schema.json.load") as mock_json_load:
            mock_json_load.return_value = {"test": "schema"}

            mock_context = Mock()
            mock_context.session = Mock()
            mock_context.session.client_params = {}

            for model in OSCALModelType:
                mock_open_schema_file.reset_mock()

                get_oscal_schema(mock_context, model_name=model, schema_type="json")

                # Verify correct file was requested
                expected_filename = f"{schema_names.get(model)}.json"
                mock_open_schema_file.assert_called_with(expected_filename)

    def test_logging_integration(self):
        """Test that logging is properly integrated across components."""
        import logging

        # Verify loggers exist for key components
        config_logger = logging.getLogger("mcp_server_for_oscal.config")
        main_logger = logging.getLogger("mcp_server_for_oscal.main")
        tools_logger = logging.getLogger(
            "mcp_server_for_oscal.tools.query_documentation"
        )

        # Verify loggers are properly configured (they should exist)
        assert config_logger is not None
        assert main_logger is not None
        assert tools_logger is not None

    def test_module_imports(self):
        """Test that all modules can be imported without errors."""
        # Test main module imports
        from mcp_server_for_oscal import config, main

        # Test tool imports
        from mcp_server_for_oscal.tools import (
            get_schema,
            list_models,
            query_documentation,
            utils,
        )

        # Verify key components exist
        assert hasattr(main, "main")
        assert hasattr(main, "mcp")
        assert hasattr(config, "config")
        assert hasattr(query_documentation, "query_oscal_documentation")
        assert hasattr(get_schema, "get_oscal_schema")
        assert hasattr(list_models, "list_oscal_models")
        assert hasattr(utils, "OSCALModelType")


class TestComponentDefinitionQueryIntegration:
    """Integration tests for the query_component_definition tool."""

    @pytest.fixture
    def mock_context(self):
        """Create a mock MCP context for testing."""
        context = Mock()
        context.log = AsyncMock()
        context.session = Mock()
        context.session.client_params = {}
        return context

    @pytest.fixture
    def sample_component_def_path(self):
        """Return path to sample component definition fixture."""
        import os
        return os.path.join(os.path.dirname(__file__), "fixtures", "sample_component_definition.json")

    @pytest.fixture
    def multi_component_def_path(self):
        """Return path to multi-component definition fixture."""
        import os
        return os.path.join(os.path.dirname(__file__), "fixtures", "multi_component_definition.json")

    @pytest.fixture
    def invalid_component_def_path(self):
        """Return path to invalid component definition fixture."""
        import os
        return os.path.join(os.path.dirname(__file__), "fixtures", "invalid_component_definition.json")

    @pytest.fixture
    def malformed_component_def_path(self):
        """Return path to malformed component definition fixture."""
        import os
        return os.path.join(os.path.dirname(__file__), "fixtures", "malformed_component_definition.json")

    # Subtask 25.1: Test with sample OSCAL Component Definition files
    def test_load_sample_component_definition(self, mock_context, sample_component_def_path):
        """Test loading a basic sample component definition file."""
        from mcp_server_for_oscal.tools.query_component_definition import query_component_definition

        # Execute query to load the file
        result = query_component_definition(
            ctx=mock_context,
            source=sample_component_def_path,
            query_type="all",
            return_format="summary"
        )

        # Verify the file was loaded successfully
        assert result is not None
        assert "components" in result
        assert "total_count" in result
        assert result["total_count"] == 1
        assert result["source"] == sample_component_def_path

        # Verify component data
        component = result["components"][0]
        assert component["uuid"] == "b2c3d4e5-6789-4bcd-9efa-234567890123"
        assert component["title"] == "Sample Component"
        assert component["type"] == "software"

    def test_load_multi_component_definition(self, mock_context, multi_component_def_path):
        """Test loading a component definition with multiple components."""
        from mcp_server_for_oscal.tools.query_component_definition import query_component_definition

        # Execute query to load the file
        result = query_component_definition(
            ctx=mock_context,
            source=multi_component_def_path,
            query_type="all",
            return_format="summary"
        )

        # Verify multiple components were loaded
        assert result is not None
        assert result["total_count"] == 3
        assert len(result["components"]) == 3

        # Verify different component types are present
        component_types = {comp["type"] for comp in result["components"]}
        assert "software" in component_types
        assert "service" in component_types
        assert "hardware" in component_types

    # Subtask 25.2: Test all query modes (all, by_uuid, by_title, by_type)
    def test_query_mode_all(self, mock_context, multi_component_def_path):
        """Test query_type='all' returns all components."""
        from mcp_server_for_oscal.tools.query_component_definition import query_component_definition

        result = query_component_definition(
            ctx=mock_context,
            source=multi_component_def_path,
            query_type="all"
        )

        assert result["query_type"] == "all"
        assert result["total_count"] == 3

    def test_query_mode_by_uuid(self, mock_context, multi_component_def_path):
        """Test query_type='by_uuid' finds specific component by UUID."""
        from mcp_server_for_oscal.tools.query_component_definition import query_component_definition

        result = query_component_definition(
            ctx=mock_context,
            source=multi_component_def_path,
            query_type="by_uuid",
            query_value="c2222222-2222-4222-8222-222222222223"
        )

        assert result["query_type"] == "by_uuid"
        assert result["total_count"] == 1
        assert result["components"][0]["uuid"] == "c2222222-2222-4222-8222-222222222223"
        assert result["components"][0]["title"] == "API Gateway"

    def test_query_mode_by_title(self, mock_context, multi_component_def_path):
        """Test query_type='by_title' finds component by exact title match."""
        from mcp_server_for_oscal.tools.query_component_definition import query_component_definition

        result = query_component_definition(
            ctx=mock_context,
            source=multi_component_def_path,
            query_type="by_title",
            query_value="Database Service"
        )

        assert result["query_type"] == "by_title"
        assert result["total_count"] == 1
        assert result["components"][0]["title"] == "Database Service"
        assert result["components"][0]["type"] == "software"

    def test_query_mode_by_title_prop_fallback(self, mock_context, multi_component_def_path):
        """Test query_type='by_title' falls back to searching prop values."""
        from mcp_server_for_oscal.tools.query_component_definition import query_component_definition

        # Search for a value that exists in props but not in title
        result = query_component_definition(
            ctx=mock_context,
            source=multi_component_def_path,
            query_type="by_title",
            query_value="14.5"  # This is a prop value for Database Service
        )

        assert result["query_type"] == "by_title"
        assert result["total_count"] == 1
        assert result["components"][0]["title"] == "Database Service"

    def test_query_mode_by_type(self, mock_context, multi_component_def_path):
        """Test query_type='by_type' filters components by type."""
        from mcp_server_for_oscal.tools.query_component_definition import query_component_definition

        result = query_component_definition(
            ctx=mock_context,
            source=multi_component_def_path,
            query_type="by_type",
            query_value="software"
        )

        assert result["query_type"] == "by_type"
        assert result["total_count"] == 1
        assert all(comp["type"] == "software" for comp in result["components"])

    def test_query_mode_by_type_multiple_matches(self, mock_context, multi_component_def_path):
        """Test query_type='by_type' returns multiple components of same type."""
        from mcp_server_for_oscal.tools.query_component_definition import query_component_definition

        # First verify we have multiple service types by checking the fixture
        result_all = query_component_definition(
            ctx=mock_context,
            source=multi_component_def_path,
            query_type="all"
        )
        
        # Count how many of each type exist
        type_counts = {}
        for comp in result_all["components"]:
            comp_type = comp["type"]
            type_counts[comp_type] = type_counts.get(comp_type, 0) + 1

        # Test filtering by a type that exists
        for comp_type, expected_count in type_counts.items():
            result = query_component_definition(
                ctx=mock_context,
                source=multi_component_def_path,
                query_type="by_type",
                query_value=comp_type
            )
            assert result["total_count"] == expected_count
            assert all(comp["type"] == comp_type for comp in result["components"])

    # Subtask 25.3: Test summary vs raw return formats
    def test_return_format_summary(self, mock_context, multi_component_def_path):
        """Test return_format='summary' returns only key fields."""
        from mcp_server_for_oscal.tools.query_component_definition import query_component_definition

        result = query_component_definition(
            ctx=mock_context,
            source=multi_component_def_path,
            query_type="by_uuid",
            query_value="c1111111-1111-4111-8111-111111111111",
            return_format="summary"
        )

        component = result["components"][0]
        
        # Verify summary fields are present
        assert "uuid" in component
        assert "title" in component
        assert "description" in component
        assert "type" in component
        assert "purpose" in component

        # Summary should be a simplified dict, not the full Pydantic model
        assert isinstance(component, dict)

    def test_return_format_raw(self, mock_context, multi_component_def_path):
        """Test return_format='raw' returns complete component object."""
        from mcp_server_for_oscal.tools.query_component_definition import query_component_definition

        result = query_component_definition(
            ctx=mock_context,
            source=multi_component_def_path,
            query_type="by_uuid",
            query_value="c1111111-1111-4111-8111-111111111111",
            return_format="raw"
        )

        component = result["components"][0]
        
        # Verify raw format includes all fields
        assert "uuid" in component
        assert "title" in component
        assert "description" in component
        assert "type" in component
        assert "purpose" in component
        assert "props" in component
        assert "links" in component
        assert "control_implementations" in component

        # Raw format should include nested structures
        assert len(component["props"]) > 0
        assert len(component["links"]) > 0

    def test_return_format_comparison(self, mock_context, sample_component_def_path):
        """Test that raw format contains more data than summary format."""
        from mcp_server_for_oscal.tools.query_component_definition import query_component_definition

        # Get summary format
        summary_result = query_component_definition(
            ctx=mock_context,
            source=sample_component_def_path,
            query_type="all",
            return_format="summary"
        )

        # Get raw format
        raw_result = query_component_definition(
            ctx=mock_context,
            source=sample_component_def_path,
            query_type="all",
            return_format="raw"
        )

        # Both should return same number of components
        assert summary_result["total_count"] == raw_result["total_count"]

        # Raw format should have more keys than summary
        summary_keys = set(summary_result["components"][0].keys())
        raw_keys = set(raw_result["components"][0].keys())
        assert len(raw_keys) >= len(summary_keys)

    # Subtask 25.4: Test error conditions (invalid files, not found, network errors)
    def test_error_file_not_found(self, mock_context):
        """Test error handling when component definition file doesn't exist."""
        from mcp_server_for_oscal.tools.query_component_definition import query_component_definition

        with pytest.raises(Exception) as exc_info:
            query_component_definition(
                ctx=mock_context,
                source="/nonexistent/path/to/component.json",
                query_type="all"
            )

        # Verify error message is descriptive
        assert "not found" in str(exc_info.value).lower() or "no such file" in str(exc_info.value).lower()

    def test_error_malformed_json(self, mock_context, malformed_component_def_path):
        """Test error handling when component definition has malformed JSON."""
        from mcp_server_for_oscal.tools.query_component_definition import query_component_definition

        with pytest.raises(Exception) as exc_info:
            query_component_definition(
                ctx=mock_context,
                source=malformed_component_def_path,
                query_type="all"
            )

        # Verify error indicates parsing failure
        error_msg = str(exc_info.value).lower()
        assert "parse" in error_msg or "json" in error_msg or "invalid" in error_msg

    def test_error_invalid_schema(self, mock_context, invalid_component_def_path):
        """Test error handling when component definition fails schema validation."""
        from mcp_server_for_oscal.tools.query_component_definition import query_component_definition

        with pytest.raises(Exception) as exc_info:
            query_component_definition(
                ctx=mock_context,
                source=invalid_component_def_path,
                query_type="all"
            )

        # Verify error indicates validation failure
        error_msg = str(exc_info.value).lower()
        assert "validation" in error_msg or "invalid" in error_msg or "uuid" in error_msg

    def test_error_component_not_found_by_uuid(self, mock_context, sample_component_def_path):
        """Test error handling when querying for non-existent UUID."""
        from mcp_server_for_oscal.tools.query_component_definition import query_component_definition

        with pytest.raises(ValueError) as exc_info:
            query_component_definition(
                ctx=mock_context,
                source=sample_component_def_path,
                query_type="by_uuid",
                query_value="00000000-0000-0000-0000-000000000000"
            )

        # Verify error message indicates component not found
        assert "not found" in str(exc_info.value).lower()

    def test_error_component_not_found_by_title(self, mock_context, sample_component_def_path):
        """Test error handling when querying for non-existent title."""
        from mcp_server_for_oscal.tools.query_component_definition import query_component_definition

        with pytest.raises(ValueError) as exc_info:
            query_component_definition(
                ctx=mock_context,
                source=sample_component_def_path,
                query_type="by_title",
                query_value="Nonexistent Component Title"
            )

        # Verify error message indicates component not found
        assert "not found" in str(exc_info.value).lower()

    def test_error_missing_query_value(self, mock_context, sample_component_def_path):
        """Test error handling when query_value is missing for queries that require it."""
        from mcp_server_for_oscal.tools.query_component_definition import query_component_definition

        # Test with by_uuid
        with pytest.raises(ValueError) as exc_info:
            query_component_definition(
                ctx=mock_context,
                source=sample_component_def_path,
                query_type="by_uuid",
                query_value=None
            )
        assert "required" in str(exc_info.value).lower()

        # Test with by_title
        with pytest.raises(ValueError) as exc_info:
            query_component_definition(
                ctx=mock_context,
                source=sample_component_def_path,
                query_type="by_title",
                query_value=None
            )
        assert "required" in str(exc_info.value).lower()

        # Test with by_type
        with pytest.raises(ValueError) as exc_info:
            query_component_definition(
                ctx=mock_context,
                source=sample_component_def_path,
                query_type="by_type",
                query_value=None
            )
        assert "required" in str(exc_info.value).lower()

    @patch("mcp_server_for_oscal.tools.query_component_definition.config")
    @patch("mcp_server_for_oscal.tools.query_component_definition.requests.get")
    def test_error_network_timeout(self, mock_requests_get, mock_config, mock_context):
        """Test error handling when remote URI request times out."""
        from mcp_server_for_oscal.tools.query_component_definition import query_component_definition

        # Setup mocks
        mock_config.allow_remote_uris = True
        mock_config.request_timeout = 30
        mock_requests_get.side_effect = requests.Timeout("Connection timed out")

        with pytest.raises(Exception) as exc_info:
            query_component_definition(
                ctx=mock_context,
                source="https://example.com/component.json",
                query_type="all"
            )

        # Verify error indicates network/timeout issue
        error_msg = str(exc_info.value).lower()
        assert "timeout" in error_msg or "network" in error_msg or "connection" in error_msg

    @patch("mcp_server_for_oscal.tools.query_component_definition.config")
    def test_error_remote_uri_not_allowed(self, mock_config, mock_context):
        """Test error handling when remote URIs are not allowed by configuration."""
        from mcp_server_for_oscal.tools.query_component_definition import query_component_definition

        # Setup config to disallow remote URIs
        mock_config.allow_remote_uris = False

        with pytest.raises(Exception) as exc_info:
            query_component_definition(
                ctx=mock_context,
                source="https://example.com/component.json",
                query_type="all"
            )

        # Verify error indicates remote URIs are not allowed
        error_msg = str(exc_info.value).lower()
        assert "not allowed" in error_msg or "disabled" in error_msg or "remote" in error_msg

    def test_control_implementations_extraction(self, mock_context, multi_component_def_path):
        """Test that control implementations are properly extracted in raw format."""
        from mcp_server_for_oscal.tools.query_component_definition import query_component_definition

        result = query_component_definition(
            ctx=mock_context,
            source=multi_component_def_path,
            query_type="by_uuid",
            query_value="c1111111-1111-4111-8111-111111111111",
            return_format="raw"
        )

        component = result["components"][0]
        
        # Verify control implementations are present
        assert "control_implementations" in component
        assert len(component["control_implementations"]) > 0

        # Verify structure of control implementation
        ctrl_impl = component["control_implementations"][0]
        assert "uuid" in ctrl_impl
        assert "source" in ctrl_impl
        assert "description" in ctrl_impl
        assert "implemented_requirements" in ctrl_impl

        # Verify implemented requirements
        assert len(ctrl_impl["implemented_requirements"]) > 0
        req = ctrl_impl["implemented_requirements"][0]
        assert "uuid" in req
        assert "control_id" in req
        assert "description" in req

    def test_props_and_links_in_raw_format(self, mock_context, sample_component_def_path):
        """Test that props and links are included in raw format."""
        from mcp_server_for_oscal.tools.query_component_definition import query_component_definition

        result = query_component_definition(
            ctx=mock_context,
            source=sample_component_def_path,
            query_type="all",
            return_format="raw"
        )

        component = result["components"][0]
        
        # Verify props are present
        assert "props" in component
        assert len(component["props"]) > 0
        prop = component["props"][0]
        assert "name" in prop
        assert "value" in prop

        # Verify links are present
        assert "links" in component
        assert len(component["links"]) > 0
        link = component["links"][0]
        assert "href" in link
        assert "rel" in link
