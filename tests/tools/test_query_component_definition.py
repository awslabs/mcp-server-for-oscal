"""
Tests for the query_component_definition tool.
"""

import json
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest
import requests
from trestle.oscal.component import ComponentDefinition

from mcp_server_for_oscal.tools.query_component_definition import (
    load_component_definition,
    _load_local_component_definition,
    _load_remote_component_definition,
)


class TestLoadComponentDefinition:
    """Test cases for component definition loading functions."""

    @pytest.fixture
    def mock_context(self):
        """Create a mock MCP context."""
        context = AsyncMock()
        context.log = AsyncMock()
        context.session = AsyncMock()
        context.session.client_params = {}
        return context

    @pytest.fixture
    def sample_component_def_path(self):
        """Return path to sample component definition fixture."""
        return Path(__file__).parent.parent / "fixtures" / "sample_component_definition.json"

    @pytest.fixture
    def sample_component_def_data(self, sample_component_def_path):
        """Load sample component definition data."""
        with open(sample_component_def_path) as f:
            return json.load(f)

    def test_load_local_component_definition_success(self, mock_context, sample_component_def_path):
        """Test successful loading of a local component definition file."""
        # Execute test
        result = _load_local_component_definition(str(sample_component_def_path), mock_context)

        # Verify results
        assert isinstance(result, ComponentDefinition)
        assert result.uuid == "a1b2c3d4-5678-4abc-8def-123456789012"
        assert result.metadata.title == "Sample Component Definition"
        assert len(result.components) == 1
        assert result.components[0].uuid == "b2c3d4e5-6789-4bcd-9efa-234567890123"
        assert result.components[0].title == "Sample Component"

    def test_load_local_component_definition_file_not_found(self, mock_context):
        """Test error handling when component definition file is not found."""
        # Execute test and verify exception
        with pytest.raises(FileNotFoundError, match="Component Definition file not found"):
            _load_local_component_definition("/nonexistent/path/component.json", mock_context)

        # Verify error context call
        mock_context.log.assert_called_once()
        assert "error" in mock_context.log.call_args[0]

    def test_load_local_component_definition_not_a_file(self, mock_context, tmp_path):
        """Test error handling when source path is a directory, not a file."""
        # Create a directory instead of a file
        dir_path = tmp_path / "test_dir"
        dir_path.mkdir()

        # Execute test and verify exception
        with pytest.raises(ValueError, match="Source path is not a file"):
            _load_local_component_definition(str(dir_path), mock_context)

        # Verify error context call
        mock_context.log.assert_called_once()
        assert "error" in mock_context.log.call_args[0]

    def test_load_local_component_definition_invalid_json(self, mock_context, tmp_path):
        """Test error handling when component definition file contains invalid JSON."""
        # Create a file with invalid JSON
        invalid_file = tmp_path / "invalid.json"
        invalid_file.write_text("{ invalid json }")

        # Execute test and verify exception
        with pytest.raises(ValueError, match="Failed to parse Component Definition JSON"):
            _load_local_component_definition(str(invalid_file), mock_context)

        # Verify error context call
        mock_context.log.assert_called_once()
        assert "error" in mock_context.log.call_args[0]

    def test_load_local_component_definition_validation_failure(self, mock_context, tmp_path):
        """Test error handling when component definition fails schema validation."""
        # Create a file with JSON that doesn't match OSCAL schema
        invalid_comp_def = tmp_path / "invalid_comp_def.json"
        invalid_comp_def.write_text(json.dumps({
            "component-definition": {
                "uuid": "a1b2c3d4-5678-4abc-8def-123456789012",
                # Missing required 'metadata' field
            }
        }))

        # Execute test and verify exception
        with pytest.raises(ValueError, match="Failed to load or validate Component Definition"):
            _load_local_component_definition(str(invalid_comp_def), mock_context)

        # Verify error context call
        mock_context.log.assert_called_once()
        assert "error" in mock_context.log.call_args[0]

    @patch("mcp_server_for_oscal.tools.query_component_definition.config")
    @patch("mcp_server_for_oscal.tools.query_component_definition.requests.get")
    def test_load_remote_component_definition_success(
        self, mock_requests_get, mock_config, mock_context, sample_component_def_data
    ):
        """Test successful loading of a remote component definition."""
        # Setup mocks
        mock_config.allow_remote_uris = True
        mock_config.request_timeout = 30

        mock_response = Mock()
        mock_response.json.return_value = sample_component_def_data
        mock_response.raise_for_status = Mock()
        mock_requests_get.return_value = mock_response

        # Execute test
        result = _load_remote_component_definition("https://example.com/component.json", mock_context)

        # Verify results
        assert isinstance(result, ComponentDefinition)
        assert result.uuid == "a1b2c3d4-5678-4abc-8def-123456789012"
        assert result.metadata.title == "Sample Component Definition"
        mock_requests_get.assert_called_once_with("https://example.com/component.json", timeout=30)

    @patch("mcp_server_for_oscal.tools.query_component_definition.config")
    def test_load_remote_component_definition_not_allowed(self, mock_config, mock_context):
        """Test error handling when remote URIs are not allowed."""
        # Setup mocks
        mock_config.allow_remote_uris = False

        # Execute test and verify exception
        with pytest.raises(ValueError, match="Remote URI loading is not enabled"):
            _load_remote_component_definition("https://example.com/component.json", mock_context)

        # Verify error context call
        mock_context.log.assert_called_once()
        assert "error" in mock_context.log.call_args[0]

    @patch("mcp_server_for_oscal.tools.query_component_definition.config")
    @patch("mcp_server_for_oscal.tools.query_component_definition.requests.get")
    def test_load_remote_component_definition_timeout(
        self, mock_requests_get, mock_config, mock_context
    ):
        """Test error handling when remote request times out."""
        # Setup mocks
        mock_config.allow_remote_uris = True
        mock_config.request_timeout = 30
        mock_requests_get.side_effect = requests.Timeout("Request timed out")

        # Execute test and verify exception
        with pytest.raises(ValueError, match="Request timeout while fetching remote URI"):
            _load_remote_component_definition("https://example.com/component.json", mock_context)

        # Verify error context call
        mock_context.log.assert_called_once()
        assert "error" in mock_context.log.call_args[0]

    @patch("mcp_server_for_oscal.tools.query_component_definition.config")
    @patch("mcp_server_for_oscal.tools.query_component_definition.requests.get")
    def test_load_remote_component_definition_request_error(
        self, mock_requests_get, mock_config, mock_context
    ):
        """Test error handling when remote request fails."""
        # Setup mocks
        mock_config.allow_remote_uris = True
        mock_config.request_timeout = 30
        mock_requests_get.side_effect = requests.RequestException("Connection error")

        # Execute test and verify exception
        with pytest.raises(ValueError, match="Failed to fetch remote Component Definition"):
            _load_remote_component_definition("https://example.com/component.json", mock_context)

        # Verify error context call
        mock_context.log.assert_called_once()
        assert "error" in mock_context.log.call_args[0]

    @patch("mcp_server_for_oscal.tools.query_component_definition.config")
    @patch("mcp_server_for_oscal.tools.query_component_definition.requests.get")
    def test_load_remote_component_definition_invalid_json(
        self, mock_requests_get, mock_config, mock_context
    ):
        """Test error handling when remote response contains invalid JSON."""
        # Setup mocks
        mock_config.allow_remote_uris = True
        mock_config.request_timeout = 30

        mock_response = Mock()
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "doc", 0)
        mock_response.raise_for_status = Mock()
        mock_requests_get.return_value = mock_response

        # Execute test and verify exception
        with pytest.raises(ValueError, match="Failed to parse remote Component Definition JSON"):
            _load_remote_component_definition("https://example.com/component.json", mock_context)

        # Verify error context call
        mock_context.log.assert_called_once()
        assert "error" in mock_context.log.call_args[0]

    @patch("mcp_server_for_oscal.tools.query_component_definition.config")
    @patch("mcp_server_for_oscal.tools.query_component_definition.requests.get")
    def test_load_remote_component_definition_validation_failure(
        self, mock_requests_get, mock_config, mock_context
    ):
        """Test error handling when remote component definition fails validation."""
        # Setup mocks
        mock_config.allow_remote_uris = True
        mock_config.request_timeout = 30

        mock_response = Mock()
        mock_response.json.return_value = {
            "component-definition": {
                "uuid": "a1b2c3d4-5678-4abc-8def-123456789012",
                # Missing required 'metadata' field
            }
        }
        mock_response.raise_for_status = Mock()
        mock_requests_get.return_value = mock_response

        # Execute test and verify exception
        with pytest.raises(ValueError, match="Failed to load or validate remote Component Definition"):
            _load_remote_component_definition("https://example.com/component.json", mock_context)

        # Verify error context call
        mock_context.log.assert_called_once()
        assert "error" in mock_context.log.call_args[0]

    def test_load_component_definition_local_path(self, mock_context, sample_component_def_path):
        """Test that load_component_definition routes local paths correctly."""
        # Execute test
        result = load_component_definition(str(sample_component_def_path), mock_context)

        # Verify results
        assert isinstance(result, ComponentDefinition)
        assert result.uuid == "a1b2c3d4-5678-4abc-8def-123456789012"

    @patch("mcp_server_for_oscal.tools.query_component_definition._load_remote_component_definition")
    def test_load_component_definition_http_uri(
        self, mock_load_remote, mock_context, sample_component_def_data
    ):
        """Test that load_component_definition routes HTTP URIs correctly."""
        # Setup mocks
        mock_comp_def = ComponentDefinition(**sample_component_def_data["component-definition"])
        mock_load_remote.return_value = mock_comp_def

        # Execute test
        result = load_component_definition("http://example.com/component.json", mock_context)

        # Verify results
        assert isinstance(result, ComponentDefinition)
        mock_load_remote.assert_called_once_with("http://example.com/component.json", mock_context)

    @patch("mcp_server_for_oscal.tools.query_component_definition._load_remote_component_definition")
    def test_load_component_definition_https_uri(
        self, mock_load_remote, mock_context, sample_component_def_data
    ):
        """Test that load_component_definition routes HTTPS URIs correctly."""
        # Setup mocks
        mock_comp_def = ComponentDefinition(**sample_component_def_data["component-definition"])
        mock_load_remote.return_value = mock_comp_def

        # Execute test
        result = load_component_definition("https://example.com/component.json", mock_context)

        # Verify results
        assert isinstance(result, ComponentDefinition)
        mock_load_remote.assert_called_once_with("https://example.com/component.json", mock_context)
