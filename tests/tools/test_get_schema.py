"""
Tests for the get_schema tool.
"""

import json
from unittest.mock import AsyncMock, Mock, mock_open, patch

import pytest

from mcp_server_for_oscal.tools.get_schema import get_oscal_schema, open_schema_file
from mcp_server_for_oscal.tools.utils import OSCALModelType, schema_names


class TestGetSchema:
    """Test cases for the get_oscal_schema tool."""

    @pytest.fixture
    def mock_context(self):
        """Create a mock MCP context."""
        context = AsyncMock()
        context.error = AsyncMock()
        context.session = AsyncMock()
        context.session.client_params = {}
        return context

    @pytest.fixture
    def sample_json_schema(self):
        """Create a sample JSON schema for testing."""
        return {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "OSCAL Complete Schema",
            "type": "object",
            "properties": {
                "catalog": {
                    "type": "object",
                    "properties": {
                        "uuid": {"type": "string"},
                        "metadata": {"type": "object"},
                    },
                }
            },
        }


    @patch("mcp_server_for_oscal.tools.get_schema.open_schema_file")
    @patch("mcp_server_for_oscal.tools.get_schema.json.load")
    def test_get_schema_success_default_params(
        self, mock_json_load, mock_open_schema_file, mock_context, sample_json_schema
    ):
        """Test successful schema retrieval with default parameters."""
        # Setup mocks
        mock_file = Mock()
        mock_open_schema_file.return_value = mock_file
        mock_json_load.return_value = sample_json_schema

        # Execute test
        result = get_oscal_schema(mock_context)

        # Verify results
        expected_json = json.dumps(sample_json_schema)
        assert result == expected_json
        mock_open_schema_file.assert_called_once_with("oscal_complete_schema.json")
        mock_json_load.assert_called_once_with(mock_file)


    @patch("mcp_server_for_oscal.tools.get_schema.open_schema_file")
    @patch("mcp_server_for_oscal.tools.get_schema.json.load")
    def test_get_schema_success_catalog_model(
        self, mock_json_load, mock_open_schema_file, mock_context, sample_json_schema
    ):
        """Test successful schema retrieval for catalog model."""
        # Setup mocks
        mock_file = Mock()
        mock_open_schema_file.return_value = mock_file
        mock_json_load.return_value = sample_json_schema

        # Execute test
        result = get_oscal_schema(
            mock_context, model_name="catalog", schema_type="json"
        )

        # Verify results
        expected_json = json.dumps(sample_json_schema)
        assert result == expected_json
        mock_open_schema_file.assert_called_once_with("oscal_catalog_schema.json")


    @patch("mcp_server_for_oscal.tools.get_schema.open_schema_file")
    @patch("mcp_server_for_oscal.tools.get_schema.json.load")
    def test_get_schema_success_ssp_model(
        self, mock_json_load, mock_open_schema_file, mock_context, sample_json_schema
    ):
        """Test successful schema retrieval for system-security-plan model (mapped to ssp)."""
        # Setup mocks
        mock_file = Mock()
        mock_open_schema_file.return_value = mock_file
        mock_json_load.return_value = sample_json_schema

        # Execute test
        result = get_oscal_schema(
            mock_context, model_name="system-security-plan", schema_type="json"
        )

        # Verify results
        expected_json = json.dumps(sample_json_schema)
        assert result == expected_json
        mock_open_schema_file.assert_called_once_with("oscal_ssp_schema.json")


    @patch("mcp_server_for_oscal.tools.get_schema.open_schema_file")
    @patch("mcp_server_for_oscal.tools.get_schema.json.load")
    def test_get_schema_success_poam_model(
        self, mock_json_load, mock_open_schema_file, mock_context, sample_json_schema
    ):
        """Test successful schema retrieval for plan-of-action-and-milestones model (mapped to poam)."""
        # Setup mocks
        mock_file = Mock()
        mock_open_schema_file.return_value = mock_file
        mock_json_load.return_value = sample_json_schema

        # Execute test
        result = get_oscal_schema(
            mock_context, model_name="plan-of-action-and-milestones", schema_type="json"
        )

        # Verify results
        expected_json = json.dumps(sample_json_schema)
        assert result == expected_json
        mock_open_schema_file.assert_called_once_with("oscal_poam_schema.json")


    @patch("mcp_server_for_oscal.tools.get_schema.open_schema_file")
    def test_get_schema_success_xsd_schema(self, mock_open_schema_file, mock_context):
        """Test successful XSD schema retrieval."""
        # Setup mocks
        mock_file = Mock()
        mock_open_schema_file.return_value = mock_file

        # Mock XSD content (as string, not JSON)
        xsd_content = '<?xml version="1.0" encoding="UTF-8"?><xs:schema>...</xs:schema>'

        with patch("mcp_server_for_oscal.tools.get_schema.json.load") as mock_json_load:
            mock_json_load.return_value = xsd_content

            # Execute test
            result = get_oscal_schema(
                mock_context, model_name="catalog", schema_type="xsd"
            )

            # Verify results
            expected_json = json.dumps(xsd_content)
            assert result == expected_json
            mock_open_schema_file.assert_called_once_with("oscal_catalog_schema.xsd")


    def test_get_schema_invalid_schema_type(self, mock_context):
        """Test error handling for invalid schema type."""
        # Execute test and verify exception
        with pytest.raises(ValueError, match="Invalid schema type: invalid"):
            get_oscal_schema(mock_context, model_name="catalog", schema_type="invalid")

        # Verify error context call
        mock_context.log.assert_called_once_with("error", "Invalid schema type: invalid.")


    def test_get_schema_invalid_model_name(self, mock_context):
        """Test error handling for invalid model name."""
        # Execute test and verify exception
        with pytest.raises(ValueError, match="Invalid model: invalid-model"):
            get_oscal_schema(
                mock_context, model_name="invalid-model", schema_type="json"
            )

        # Verify error context call
        mock_context.log.assert_called_once()
        error_call_args = mock_context.log.call_args[0][1]
        assert "Invalid model: invalid-model" in error_call_args
        assert (
            "Use the tool list_oscal_models to get valid model names" in error_call_args
        )


    @patch("mcp_server_for_oscal.tools.get_schema.open_schema_file")
    def test_get_schema_file_not_found(self, mock_open_schema_file, mock_context):
        """Test error handling when schema file is not found."""
        # Setup mocks
        mock_open_schema_file.side_effect = FileNotFoundError("File not found")

        # Execute test and verify exception
        with pytest.raises(Exception):
            get_oscal_schema(mock_context, model_name="catalog", schema_type="json")

        # Verify error handling
        mock_context.log.assert_called_once_with("error", "failed to open schema oscal_catalog_schema.json")


    @patch("mcp_server_for_oscal.tools.get_schema.open_schema_file")
    @patch("mcp_server_for_oscal.tools.get_schema.json.load")
    def test_get_schema_json_parse_error(
        self, mock_json_load, mock_open_schema_file, mock_context
    ):
        """Test error handling when JSON parsing fails."""
        # Setup mocks
        mock_file = Mock()
        mock_open_schema_file.return_value = mock_file
        mock_json_load.side_effect = json.JSONDecodeError("Invalid JSON", "doc", 0)

        # Execute test and verify exception
        with pytest.raises(Exception):
            get_oscal_schema(mock_context, model_name="catalog", schema_type="json")

        # Verify error handling
        # mock_context.error.assert_called_once()
        mock_context.log.assert_called_once()
        level = mock_context.log.call_args[0]
        assert "error" in level


    @patch("mcp_server_for_oscal.tools.get_schema.logger")
    def test_get_schema_logging(self, mock_logger, mock_context):
        """Test that appropriate logging occurs."""
        with patch(
            "mcp_server_for_oscal.tools.get_schema.open_schema_file"
        ) as mock_open_schema_file, patch(
            "mcp_server_for_oscal.tools.get_schema.json.load"
        ) as mock_json_load:
            mock_file = Mock()
            mock_open_schema_file.return_value = mock_file
            mock_json_load.return_value = {"test": "schema"}

            # Execute test
            get_oscal_schema(mock_context, model_name="catalog", schema_type="json")

            # Verify logging
            mock_logger.debug.assert_called_once()
            debug_call_args = mock_logger.debug.call_args[0]
            assert "get_oscal_model_schema" in debug_call_args[0]
            assert "catalog" in debug_call_args[1]
            assert "json" in debug_call_args[2]

    def test_open_schema_file_success(self):
        """Test successful schema file opening."""
        with patch(
            "builtins.open", mock_open(read_data='{"test": "data"}')
        ) as mock_file:
            result = open_schema_file("schema.json")

            # Verify file was opened correctly (the path will be a PosixPath object)
            assert mock_file.called
            call_args = mock_file.call_args[0][0]
            assert str(call_args).endswith("oscal_schemas/schema.json")
            assert result is not None

    def test_open_schema_file_with_path_cleaning(self):
        """Test schema file opening with path cleaning."""
        with patch(
            "builtins.open", mock_open(read_data='{"test": "data"}')
        ) as mock_file:
            # Test with various path prefixes that should be stripped
            test_files = [
                "./schema.json",
                ".\\schema.json",
                "/schema.json",
                "\\schema.json",
            ]

            for test_file in test_files:
                mock_file.reset_mock()
                open_schema_file(test_file)

                # Verify the file path ends with the cleaned filename
                call_args = mock_file.call_args[0][0]
                assert str(call_args).endswith("oscal_schemas/schema.json")

    def test_open_schema_file_not_found(self):
        """Test error handling when schema file is not found."""
        with patch("builtins.open", side_effect=FileNotFoundError("File not found")):
            with pytest.raises(FileNotFoundError):
                open_schema_file("nonexistent.json")


    @patch("mcp_server_for_oscal.tools.get_schema.open_schema_file")
    @patch("mcp_server_for_oscal.tools.get_schema.json.load")
    def test_get_schema_all_valid_models(
        self, mock_json_load, mock_open_schema_file, mock_context, sample_json_schema
    ):
        """Test schema retrieval for all valid OSCAL model types."""
        # Setup mocks
        mock_file = Mock()
        mock_open_schema_file.return_value = mock_file
        mock_json_load.return_value = sample_json_schema

        for model in OSCALModelType:
            # Reset mocks
            mock_open_schema_file.reset_mock()
            mock_json_load.reset_mock()

            # Execute test
            result = get_oscal_schema(
                mock_context, model_name=model, schema_type="json"
            )

            # Verify results
            expected_json = json.dumps(sample_json_schema)
            assert result == expected_json

            expected_filename = f"{schema_names.get(model)}.json"
            mock_open_schema_file.assert_called_once_with(expected_filename)
