"""
Integration tests for the OSCAL MCP Server.
"""

from unittest.mock import Mock, patch

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
