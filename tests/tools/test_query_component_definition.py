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


class TestResolveLinksAndProps:
    """Test cases for resolve_links_and_props function."""

    @pytest.fixture
    def mock_context(self):
        """Create a mock MCP context."""
        context = AsyncMock()
        context.log = AsyncMock()
        context.session = AsyncMock()
        context.session.client_params = {}
        return context

    def test_resolve_props_basic(self, mock_context):
            """Test resolving basic props from a component."""
            from trestle.oscal.component import DefinedComponent
            from trestle.oscal.common import Property
            from mcp_server_for_oscal.tools.query_component_definition import resolve_links_and_props

            # Create component with props
            component = DefinedComponent(
                uuid="c1d2e3f4-7890-4cde-9fab-345678901234",
                type="software",
                title="Test Component",
                description="Test description",
                purpose="Testing",
                props=[
                    Property(name="version", value="1.0.0"),
                    Property(name="vendor", value="ACME Corp"),
                ],
            )

            # Resolve props
            result = resolve_links_and_props(component, mock_context, resolve_uris=False)

            # Verify props
            assert "props" in result
            assert len(result["props"]) == 2
            assert result["props"][0]["name"] == "version"
            assert result["props"][0]["value"] == "1.0.0"
            assert result["props"][1]["name"] == "vendor"
            assert result["props"][1]["value"] == "ACME Corp"

    def test_resolve_props_with_optional_fields(self, mock_context):
        """Test resolving props with optional fields like ns, class, and remarks."""
        from trestle.oscal.component import DefinedComponent
        from trestle.oscal.common import Property
        from mcp_server_for_oscal.tools.query_component_definition import resolve_links_and_props

        # Create component with props including optional fields
        component = DefinedComponent(
            uuid="c1d2e3f4-7890-4cde-9fab-345678901235",
            type="software",
            title="Test Component",
            description="Test description",
            purpose="Testing",
            props=[
                Property(
                    name="version",
                    value="1.0.0",
                    ns="http://example.com/ns",
                    class_="metadata",
                    remarks="Version information",
                ),
            ],
        )

        # Resolve props
        result = resolve_links_and_props(component, mock_context, resolve_uris=False)

        # Verify props with optional fields
        assert len(result["props"]) == 1
        prop = result["props"][0]
        assert prop["name"] == "version"
        assert prop["value"] == "1.0.0"
        assert prop["ns"] == "http://example.com/ns"
        assert prop["class"] == "metadata"
        assert prop["remarks"] == "Version information"

    def test_resolve_links_basic(self, mock_context):
        """Test resolving basic links from a component."""
        from trestle.oscal.component import DefinedComponent
        from trestle.oscal.common import Link
        from mcp_server_for_oscal.tools.query_component_definition import resolve_links_and_props

        # Create component with links
        component = DefinedComponent(
            uuid="c1d2e3f4-7890-4cde-9fab-345678901236",
            type="software",
            title="Test Component",
            description="Test description",
            purpose="Testing",
            links=[
                Link(href="https://example.com/docs", rel="documentation"),
                Link(href="https://example.com/source", rel="source"),
            ],
        )

        # Resolve links
        result = resolve_links_and_props(component, mock_context, resolve_uris=False)

        # Verify links
        assert "links" in result
        assert len(result["links"]) == 2
        assert result["links"][0]["href"] == "https://example.com/docs"
        assert result["links"][0]["rel"] == "documentation"
        assert result["links"][1]["href"] == "https://example.com/source"
        assert result["links"][1]["rel"] == "source"

    def test_resolve_links_with_text(self, mock_context):
        """Test resolving links with optional text field."""
        from trestle.oscal.component import DefinedComponent
        from trestle.oscal.common import Link
        from mcp_server_for_oscal.tools.query_component_definition import resolve_links_and_props

        # Create component with links including text
        component = DefinedComponent(
            uuid="c1d2e3f4-7890-4cde-9fab-345678901237",
            type="software",
            title="Test Component",
            description="Test description",
            purpose="Testing",
            links=[
                Link(href="https://example.com/docs", rel="documentation", text="Documentation Site"),
            ],
        )

        # Resolve links
        result = resolve_links_and_props(component, mock_context, resolve_uris=False)

        # Verify link with text
        assert len(result["links"]) == 1
        link = result["links"][0]
        assert link["href"] == "https://example.com/docs"
        assert link["rel"] == "documentation"
        assert link["text"] == "Documentation Site"

    def test_resolve_component_without_props_or_links(self, mock_context):
        """Test resolving a component with no props or links."""
        from trestle.oscal.component import DefinedComponent
        from mcp_server_for_oscal.tools.query_component_definition import resolve_links_and_props

        # Create component without props or links
        component = DefinedComponent(
            uuid="c1d2e3f4-7890-4cde-9fab-345678901238",
            type="software",
            title="Test Component",
            description="Test description",
            purpose="Testing",
        )

        # Resolve
        result = resolve_links_and_props(component, mock_context, resolve_uris=False)

        # Verify empty lists
        assert result["props"] == []
        assert result["links"] == []

    def test_resolve_props_and_links_together(self, mock_context):
        """Test resolving both props and links from the same component."""
        from trestle.oscal.component import DefinedComponent
        from trestle.oscal.common import Property, Link
        from mcp_server_for_oscal.tools.query_component_definition import resolve_links_and_props

        # Create component with both props and links
        component = DefinedComponent(
            uuid="c1d2e3f4-7890-4cde-9fab-345678901239",
            type="software",
            title="Test Component",
            description="Test description",
            purpose="Testing",
            props=[
                Property(name="version", value="1.0.0"),
            ],
            links=[
                Link(href="https://example.com/docs", rel="documentation"),
            ],
        )

        # Resolve
        result = resolve_links_and_props(component, mock_context, resolve_uris=False)

        # Verify both props and links
        assert len(result["props"]) == 1
        assert result["props"][0]["name"] == "version"
        assert len(result["links"]) == 1
        assert result["links"][0]["href"] == "https://example.com/docs"


class TestResolveURIReference:
    """Test cases for _resolve_uri_reference function."""

    @pytest.fixture
    def mock_context(self):
        """Create a mock MCP context."""
        context = AsyncMock()
        context.log = AsyncMock()
        context.session = AsyncMock()
        context.session.client_params = {}
        return context

    @patch("mcp_server_for_oscal.tools.query_component_definition.config")
    @patch("mcp_server_for_oscal.tools.query_component_definition.requests.get")
    def test_resolve_remote_uri_json(self, mock_requests_get, mock_config, mock_context):
        """Test resolving a remote URI that returns JSON."""
        from mcp_server_for_oscal.tools.query_component_definition import _resolve_uri_reference

        # Setup mocks
        mock_config.allow_remote_uris = True
        mock_config.request_timeout = 30
        mock_config.max_uri_depth = 3

        mock_response = Mock()
        mock_response.json.return_value = {"key": "value"}
        mock_response.raise_for_status = Mock()
        mock_requests_get.return_value = mock_response

        # Resolve URI
        result = _resolve_uri_reference("https://example.com/data.json", mock_context, set(), 0)

        # Verify result
        assert result is not None
        assert result["uri"] == "https://example.com/data.json"
        assert result["content"] == {"key": "value"}
        assert result["content_type"] == "json"
        assert result["depth"] == 0
        mock_requests_get.assert_called_once_with("https://example.com/data.json", timeout=30)

    @patch("mcp_server_for_oscal.tools.query_component_definition.config")
    @patch("mcp_server_for_oscal.tools.query_component_definition.requests.get")
    def test_resolve_remote_uri_text(self, mock_requests_get, mock_config, mock_context):
        """Test resolving a remote URI that returns text."""
        from mcp_server_for_oscal.tools.query_component_definition import _resolve_uri_reference

        # Setup mocks
        mock_config.allow_remote_uris = True
        mock_config.request_timeout = 30
        mock_config.max_uri_depth = 3

        mock_response = Mock()
        mock_response.json.side_effect = json.JSONDecodeError("msg", "doc", 0)
        mock_response.text = "Plain text content"
        mock_response.raise_for_status = Mock()
        mock_requests_get.return_value = mock_response

        # Resolve URI
        result = _resolve_uri_reference("https://example.com/data.txt", mock_context, set(), 0)

        # Verify result
        assert result is not None
        assert result["uri"] == "https://example.com/data.txt"
        assert result["content"] == "Plain text content"
        assert result["content_type"] == "text"
        assert result["depth"] == 0

    @patch("mcp_server_for_oscal.tools.query_component_definition.config")
    def test_resolve_uri_remote_not_allowed(self, mock_config, mock_context):
        """Test that remote URI resolution fails when not allowed."""
        from mcp_server_for_oscal.tools.query_component_definition import _resolve_uri_reference

        # Setup mocks
        mock_config.allow_remote_uris = False
        mock_config.max_uri_depth = 3

        # Resolve URI
        result = _resolve_uri_reference("https://example.com/data.json", mock_context, set(), 0)

        # Verify error result
        assert result is not None
        assert "error" in result
        assert "not enabled" in result["error"]
        assert result["uri"] == "https://example.com/data.json"

    @patch("mcp_server_for_oscal.tools.query_component_definition.config")
    def test_resolve_uri_max_depth_exceeded(self, mock_config, mock_context):
        """Test that URI resolution stops at max depth."""
        from mcp_server_for_oscal.tools.query_component_definition import _resolve_uri_reference

        # Setup mocks
        mock_config.max_uri_depth = 2

        # Resolve URI at max depth
        result = _resolve_uri_reference("https://example.com/data.json", mock_context, set(), 2)

        # Verify error result
        assert result is not None
        assert "error" in result
        assert "Maximum URI resolution depth" in result["error"]
        assert result["uri"] == "https://example.com/data.json"

    @patch("mcp_server_for_oscal.tools.query_component_definition.config")
    def test_resolve_uri_circular_reference(self, mock_config, mock_context):
        """Test that circular references are detected."""
        from mcp_server_for_oscal.tools.query_component_definition import _resolve_uri_reference

        # Setup mocks
        mock_config.max_uri_depth = 3

        # Create visited set with the URI already in it
        visited = {"https://example.com/data.json"}

        # Resolve URI
        result = _resolve_uri_reference("https://example.com/data.json", mock_context, visited, 0)

        # Verify error result
        assert result is not None
        assert "error" in result
        assert "Circular reference" in result["error"]
        assert result["uri"] == "https://example.com/data.json"

    @patch("mcp_server_for_oscal.tools.query_component_definition.config")
    @patch("mcp_server_for_oscal.tools.query_component_definition.requests.get")
    def test_resolve_uri_network_error(self, mock_requests_get, mock_config, mock_context):
        """Test handling of network errors during URI resolution."""
        from mcp_server_for_oscal.tools.query_component_definition import _resolve_uri_reference

        # Setup mocks
        mock_config.allow_remote_uris = True
        mock_config.request_timeout = 30
        mock_config.max_uri_depth = 3

        mock_requests_get.side_effect = requests.RequestException("Network error")

        # Resolve URI
        result = _resolve_uri_reference("https://example.com/data.json", mock_context, set(), 0)

        # Verify error result
        assert result is not None
        assert "error" in result
        assert "Failed to fetch URI" in result["error"]
        assert result["uri"] == "https://example.com/data.json"

    @patch("mcp_server_for_oscal.tools.query_component_definition.config")
    def test_resolve_local_uri_json(self, mock_config, mock_context, tmp_path):
        """Test resolving a local file URI with JSON content."""
        from mcp_server_for_oscal.tools.query_component_definition import _resolve_uri_reference

        # Setup mocks
        mock_config.max_uri_depth = 3

        # Create a temporary JSON file
        json_file = tmp_path / "data.json"
        json_file.write_text('{"key": "value"}')

        # Resolve URI
        result = _resolve_uri_reference(str(json_file), mock_context, set(), 0)

        # Verify result
        assert result is not None
        assert result["uri"] == str(json_file)
        assert result["content"] == {"key": "value"}
        assert result["content_type"] == "json"
        assert result["depth"] == 0

    @patch("mcp_server_for_oscal.tools.query_component_definition.config")
    def test_resolve_local_uri_text(self, mock_config, mock_context, tmp_path):
        """Test resolving a local file URI with text content."""
        from mcp_server_for_oscal.tools.query_component_definition import _resolve_uri_reference

        # Setup mocks
        mock_config.max_uri_depth = 3

        # Create a temporary text file
        text_file = tmp_path / "data.txt"
        text_file.write_text("Plain text content")

        # Resolve URI
        result = _resolve_uri_reference(str(text_file), mock_context, set(), 0)

        # Verify result
        assert result is not None
        assert result["uri"] == str(text_file)
        assert result["content"] == "Plain text content"
        assert result["content_type"] == "text"
        assert result["depth"] == 0

    @patch("mcp_server_for_oscal.tools.query_component_definition.config")
    def test_resolve_local_uri_not_found(self, mock_config, mock_context):
        """Test handling of local file not found."""
        from mcp_server_for_oscal.tools.query_component_definition import _resolve_uri_reference

        # Setup mocks
        mock_config.max_uri_depth = 3

        # Resolve non-existent file
        result = _resolve_uri_reference("/nonexistent/file.json", mock_context, set(), 0)

        # Verify error result
        assert result is not None
        assert "error" in result
        assert "File not found" in result["error"]
        assert result["uri"] == "/nonexistent/file.json"
