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




class TestExtractComponentSummary:
    """Test cases for extract_component_summary function."""

    @pytest.fixture
    def sample_component_def_path(self):
        """Return path to sample component definition fixture."""
        return Path(__file__).parent.parent / "fixtures" / "sample_component_definition.json"

    def test_extract_summary_with_required_fields_only(self):
        """Test extracting summary from component with only required fields."""
        from trestle.oscal.component import DefinedComponent
        from mcp_server_for_oscal.tools.query_component_definition import extract_component_summary

        # Create a minimal component with only required fields
        component = DefinedComponent(
            uuid="c1d2e3f4-7890-4cde-9fab-345678901234",
            type="software",
            title="Test Component",
            description="A test component description",
            purpose="Testing summary extraction",
        )

        # Extract summary
        result = extract_component_summary(component)

        # Verify required fields
        assert result["uuid"] == "c1d2e3f4-7890-4cde-9fab-345678901234"
        assert result["title"] == "Test Component"
        assert result["description"] == "A test component description"
        assert result["type"] == "software"
        assert result["purpose"] == "Testing summary extraction"
        
        # Verify optional fields are not present
        assert "responsible_roles" not in result
        assert "protocols" not in result

    def test_extract_summary_with_responsible_roles(self):
        """Test extracting summary from component with responsible roles."""
        from trestle.oscal.component import DefinedComponent
        from trestle.oscal.common import ResponsibleRole
        from mcp_server_for_oscal.tools.query_component_definition import extract_component_summary

        # Create component with responsible roles
        component = DefinedComponent(
            uuid="c1d2e3f4-7890-4cde-9fab-345678901234",
            type="service",
            title="Test Service Component",
            description="A service component with roles",
            purpose="Testing role extraction",
            responsible_roles=[
                ResponsibleRole(role_id="admin"),
                ResponsibleRole(role_id="developer"),
            ],
        )

        # Extract summary
        result = extract_component_summary(component)

        # Verify required fields
        assert result["uuid"] == "c1d2e3f4-7890-4cde-9fab-345678901234"
        assert result["title"] == "Test Service Component"
        assert result["type"] == "service"
        
        # Verify responsible roles are included
        assert "responsible_roles" in result
        assert result["responsible_roles"] == ["admin", "developer"]

    def test_extract_summary_with_protocols(self):
        """Test extracting summary from component with protocols."""
        from trestle.oscal.component import DefinedComponent
        from trestle.oscal.common import Protocol
        from mcp_server_for_oscal.tools.query_component_definition import extract_component_summary

        # Create component with protocols
        component = DefinedComponent(
            uuid="c1d2e3f4-7890-4cde-9fab-345678901234",
            type="software",
            title="Test Protocol Component",
            description="A component with protocols",
            purpose="Testing protocol extraction",
            protocols=[
                Protocol(uuid="d2e3f4a5-8901-4def-9abc-456789012345", name="HTTPS"),
                Protocol(uuid="e3f4a5b6-9012-4efa-9bcd-567890123456", name="SSH"),
            ],
        )

        # Extract summary
        result = extract_component_summary(component)

        # Verify required fields
        assert result["uuid"] == "c1d2e3f4-7890-4cde-9fab-345678901234"
        assert result["title"] == "Test Protocol Component"
        
        # Verify protocols are included
        assert "protocols" in result
        assert result["protocols"] == [
            "d2e3f4a5-8901-4def-9abc-456789012345",
            "e3f4a5b6-9012-4efa-9bcd-567890123456",
        ]

    def test_extract_summary_with_all_optional_fields(self):
        """Test extracting summary from component with all optional fields."""
        from trestle.oscal.component import DefinedComponent
        from trestle.oscal.common import ResponsibleRole, Protocol
        from mcp_server_for_oscal.tools.query_component_definition import extract_component_summary

        # Create component with all optional fields
        component = DefinedComponent(
            uuid="c1d2e3f4-7890-4cde-9fab-345678901234",
            type="hardware",
            title="Complete Component",
            description="A component with all fields",
            purpose="Testing complete extraction",
            responsible_roles=[
                ResponsibleRole(role_id="security-officer"),
            ],
            protocols=[
                Protocol(uuid="d2e3f4a5-8901-4def-9abc-456789012345", name="TLS"),
            ],
        )

        # Extract summary
        result = extract_component_summary(component)

        # Verify all fields are present
        assert result["uuid"] == "c1d2e3f4-7890-4cde-9fab-345678901234"
        assert result["title"] == "Complete Component"
        assert result["description"] == "A component with all fields"
        assert result["type"] == "hardware"
        assert result["purpose"] == "Testing complete extraction"
        assert result["responsible_roles"] == ["security-officer"]
        assert result["protocols"] == ["d2e3f4a5-8901-4def-9abc-456789012345"]

    def test_extract_summary_from_loaded_component(self, sample_component_def_path):
        """Test extracting summary from a component loaded from fixture file."""
        from mcp_server_for_oscal.tools.query_component_definition import (
            extract_component_summary,
            _load_local_component_definition,
        )
        from unittest.mock import AsyncMock

        # Load component definition from fixture
        mock_context = AsyncMock()
        comp_def = _load_local_component_definition(str(sample_component_def_path), mock_context)
        
        # Extract summary from first component
        component = comp_def.components[0]
        result = extract_component_summary(component)

        # Verify the summary matches the fixture data
        assert result["uuid"] == "b2c3d4e5-6789-4bcd-9efa-234567890123"
        assert result["title"] == "Sample Component"
        assert result["description"] == "A sample component for testing"
        assert result["type"] == "software"
        assert result["purpose"] == "Testing component definition loading"



class TestComponentQuerying:
    """Test cases for component querying and filtering functions."""

    @pytest.fixture
    def sample_components(self):
        """Create sample components for testing."""
        from trestle.oscal.component import DefinedComponent
        from trestle.oscal.common import Property

        components = [
            DefinedComponent(
                uuid="a1b2c3d4-5678-4abc-8def-111111111111",
                type="software",
                title="Component One",
                description="First test component",
                purpose="Testing",
                props=[
                    Property(name="version", value="1.0.0"),
                    Property(name="vendor", value="ACME Corp"),
                ],
            ),
            DefinedComponent(
                uuid="b2c3d4e5-6789-4bcd-9efa-222222222222",
                type="hardware",
                title="Component Two",
                description="Second test component",
                purpose="Testing",
                props=[
                    Property(name="version", value="2.0.0"),
                    Property(name="model", value="XYZ-123"),
                ],
            ),
            DefinedComponent(
                uuid="c3d4e5f6-7890-4cde-9fab-333333333333",
                type="software",
                title="Component Three",
                description="Third test component",
                purpose="Testing",
            ),
        ]
        return components

    def test_find_component_by_uuid_found(self, sample_components):
        """Test finding a component by UUID when it exists."""
        from mcp_server_for_oscal.tools.query_component_definition import find_component_by_uuid

        result = find_component_by_uuid(sample_components, "b2c3d4e5-6789-4bcd-9efa-222222222222")

        assert result is not None
        assert str(result.uuid) == "b2c3d4e5-6789-4bcd-9efa-222222222222"
        assert result.title == "Component Two"

    def test_find_component_by_uuid_not_found(self, sample_components):
        """Test finding a component by UUID when it doesn't exist."""
        from mcp_server_for_oscal.tools.query_component_definition import find_component_by_uuid

        result = find_component_by_uuid(sample_components, "99999999-9999-9999-9999-999999999999")

        assert result is None

    def test_find_component_by_uuid_empty_list(self):
        """Test finding a component by UUID in an empty list."""
        from mcp_server_for_oscal.tools.query_component_definition import find_component_by_uuid

        result = find_component_by_uuid([], "a1b2c3d4-5678-4abc-8def-111111111111")

        assert result is None

    def test_find_component_by_title_found(self, sample_components):
        """Test finding a component by title when it exists."""
        from mcp_server_for_oscal.tools.query_component_definition import find_component_by_title

        result = find_component_by_title(sample_components, "Component One")

        assert result is not None
        assert result.title == "Component One"
        assert str(result.uuid) == "a1b2c3d4-5678-4abc-8def-111111111111"

    def test_find_component_by_title_not_found(self, sample_components):
        """Test finding a component by title when it doesn't exist."""
        from mcp_server_for_oscal.tools.query_component_definition import find_component_by_title

        result = find_component_by_title(sample_components, "Nonexistent Component")

        assert result is None

    def test_find_component_by_title_case_sensitive(self, sample_components):
        """Test that title search is case-sensitive."""
        from mcp_server_for_oscal.tools.query_component_definition import find_component_by_title

        result = find_component_by_title(sample_components, "component one")

        assert result is None

    def test_find_component_by_prop_value_found(self, sample_components):
        """Test finding a component by prop value when it exists."""
        from mcp_server_for_oscal.tools.query_component_definition import find_component_by_prop_value

        result = find_component_by_prop_value(sample_components, "ACME Corp")

        assert result is not None
        assert result.title == "Component One"

    def test_find_component_by_prop_value_version(self, sample_components):
        """Test finding a component by version prop value."""
        from mcp_server_for_oscal.tools.query_component_definition import find_component_by_prop_value

        result = find_component_by_prop_value(sample_components, "2.0.0")

        assert result is not None
        assert result.title == "Component Two"

    def test_find_component_by_prop_value_not_found(self, sample_components):
        """Test finding a component by prop value when it doesn't exist."""
        from mcp_server_for_oscal.tools.query_component_definition import find_component_by_prop_value

        result = find_component_by_prop_value(sample_components, "nonexistent-value")

        assert result is None

    def test_find_component_by_prop_value_no_props(self, sample_components):
        """Test finding a component by prop value when component has no props."""
        from mcp_server_for_oscal.tools.query_component_definition import find_component_by_prop_value

        # Component Three has no props, so searching for any value should not match it
        result = find_component_by_prop_value([sample_components[2]], "any-value")

        assert result is None

    def test_filter_components_by_type_software(self, sample_components):
        """Test filtering components by software type."""
        from mcp_server_for_oscal.tools.query_component_definition import filter_components_by_type

        result = filter_components_by_type(sample_components, "software")

        assert len(result) == 2
        assert all(comp.type == "software" for comp in result)
        assert result[0].title == "Component One"
        assert result[1].title == "Component Three"

    def test_filter_components_by_type_hardware(self, sample_components):
        """Test filtering components by hardware type."""
        from mcp_server_for_oscal.tools.query_component_definition import filter_components_by_type

        result = filter_components_by_type(sample_components, "hardware")

        assert len(result) == 1
        assert result[0].type == "hardware"
        assert result[0].title == "Component Two"

    def test_filter_components_by_type_no_matches(self, sample_components):
        """Test filtering components by type with no matches."""
        from mcp_server_for_oscal.tools.query_component_definition import filter_components_by_type

        result = filter_components_by_type(sample_components, "service")

        assert len(result) == 0

    def test_filter_components_by_type_empty_list(self):
        """Test filtering an empty component list."""
        from mcp_server_for_oscal.tools.query_component_definition import filter_components_by_type

        result = filter_components_by_type([], "software")

        assert len(result) == 0
