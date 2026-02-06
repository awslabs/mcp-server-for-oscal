"""
Tests for the query_component_definition tool.
"""

import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from trestle.oscal.component import ComponentDefinition

from mcp_server_for_oscal.tools.query_component_definition import (
    load_component_definitions_from_directory,
    query_component_definition,
)


class TestLoadComponentDefinitionsFromDirectory:
    """Test cases for load_component_definitions_from_directory function."""

    @pytest.fixture
    def sample_component_def_data(self):
        """Load sample component definition data."""
        sample_path = (
            Path(__file__).parent.parent
            / "fixtures"
            / "sample_component_definition.json"
        )
        with open(sample_path) as f:
            return json.load(f)

    def test_load_from_directory_success(self, tmp_path, sample_component_def_data):
        """Test successfully loading component definitions from a directory."""
        comp_defs_dir = tmp_path / "component_definitions"
        comp_defs_dir.mkdir()

        # Create first component definition file
        comp_def_1 = comp_defs_dir / "comp_def_1.json"
        with open(comp_def_1, "w") as f:
            json.dump(sample_component_def_data, f)

        # Create second component definition file in subdirectory
        subdir = comp_defs_dir / "vendor_a"
        subdir.mkdir()
        comp_def_2 = subdir / "comp_def_2.json"
        with open(comp_def_2, "w") as f:
            json.dump(sample_component_def_data, f)

        # Load component definitions
        result = load_component_definitions_from_directory(comp_defs_dir)

        # Verify results
        assert len(result) == 2
        assert "comp_def_1.json" in result
        assert "vendor_a/comp_def_2.json" in result
        assert all(isinstance(cd, ComponentDefinition) for cd in result.values())

    def test_load_from_directory_nonexistent(self, tmp_path):
        """Test loading from a nonexistent directory."""
        nonexistent_dir = tmp_path / "nonexistent"
        result = load_component_definitions_from_directory(nonexistent_dir)
        assert result == {}

    def test_load_from_directory_not_a_directory(self, tmp_path):
        """Test loading when path is not a directory."""
        file_path = tmp_path / "not_a_dir.txt"
        file_path.write_text("test")
        result = load_component_definitions_from_directory(file_path)
        assert result == {}

    def test_load_from_directory_with_invalid_files(
        self, tmp_path, sample_component_def_data
    ):
        """Test loading from directory with mix of valid and invalid files."""
        comp_defs_dir = tmp_path / "component_definitions"
        comp_defs_dir.mkdir()

        # Create valid component definition file
        valid_file = comp_defs_dir / "valid.json"
        with open(valid_file, "w") as f:
            json.dump(sample_component_def_data, f)

        # Create invalid JSON file
        invalid_json = comp_defs_dir / "invalid.json"
        invalid_json.write_text("{ invalid json }")

        # Create non-component-definition JSON file
        other_json = comp_defs_dir / "other.json"
        with open(other_json, "w") as f:
            json.dump({"some": "data"}, f)

        # Load component definitions
        result = load_component_definitions_from_directory(comp_defs_dir)

        # Verify only valid component definition is loaded
        assert len(result) == 1
        assert "valid.json" in result

    def test_load_from_directory_empty(self, tmp_path):
        """Test loading from an empty directory."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        result = load_component_definitions_from_directory(empty_dir)
        assert result == {}

    def test_load_from_directory_no_json_files(self, tmp_path):
        """Test loading from directory with no JSON files."""
        comp_defs_dir = tmp_path / "component_definitions"
        comp_defs_dir.mkdir()

        # Create non-JSON files
        (comp_defs_dir / "readme.txt").write_text("test")
        (comp_defs_dir / "data.xml").write_text("<xml/>")

        result = load_component_definitions_from_directory(comp_defs_dir)
        assert result == {}


class TestQueryComponentDefinitionTool:
    """Test cases for the main query_component_definition tool function."""

    @pytest.fixture
    def mock_context(self):
        """Create a mock MCP context."""
        context = AsyncMock()
        context.log = AsyncMock()
        context.session = AsyncMock()
        context.session.client_params = {}
        return context

    @pytest.fixture
    def sample_component_def_data(self):
        """Load sample component definition data."""
        sample_path = (
            Path(__file__).parent.parent
            / "fixtures"
            / "sample_component_definition.json"
        )
        with open(sample_path) as f:
            return json.load(f)

    @pytest.fixture
    def setup_component_defs_dir(
        self, tmp_path, sample_component_def_data, monkeypatch
    ):
        """Set up a temporary component definitions directory with test data."""
        comp_defs_dir = tmp_path / "component_definitions"
        comp_defs_dir.mkdir()

        # Create sample component definition file
        comp_def_file = comp_defs_dir / "sample.json"
        with open(comp_def_file, "w") as f:
            json.dump(sample_component_def_data, f)

        # Patch the config to use our test directory
        from mcp_server_for_oscal import config as config_module

        monkeypatch.setattr(
            config_module.config, "component_definitions_dir", str(comp_defs_dir)
        )

        return comp_defs_dir

    def test_query_all_components_raw_format(self, mock_context, setup_component_defs_dir):
        """Test querying all components with raw format (default)."""
        result = query_component_definition(
            ctx=mock_context,
            component_definition_filter=None,
            query_type="all",
            return_format="raw",
        )

        # Verify response structure
        assert "components" in result
        assert "total_count" in result
        assert "query_type" in result
        assert "component_definitions_searched" in result
        assert "filtered_by" in result

        # Verify query metadata
        assert result["query_type"] == "all"
        assert result["component_definitions_searched"] == 1
        assert result["filtered_by"] is None
        assert result["total_count"] == 1

        # Verify component has full OSCAL structure (raw format)
        component = result["components"][0]
        assert "uuid" in component
        assert "title" in component
        assert component["uuid"] == "b2c3d4e5-6789-4bcd-9efa-234567890123"
        assert component["title"] == "Sample Component"

    def test_query_by_uuid_success(self, mock_context, setup_component_defs_dir):
        """Test querying component by UUID successfully."""
        result = query_component_definition(
            ctx=mock_context,
            component_definition_filter=None,
            query_type="by_uuid",
            query_value="b2c3d4e5-6789-4bcd-9efa-234567890123",
            return_format="raw",
        )

        assert result["total_count"] == 1
        assert result["query_type"] == "by_uuid"
        assert result["components"][0]["uuid"] == "b2c3d4e5-6789-4bcd-9efa-234567890123"

    def test_query_by_uuid_not_found(self, mock_context, setup_component_defs_dir):
        """Test querying component by UUID that doesn't exist."""
        with pytest.raises(ValueError, match="not found"):
            query_component_definition(
                ctx=mock_context,
                component_definition_filter=None,
                query_type="by_uuid",
                query_value="00000000-0000-0000-0000-000000000000",
                return_format="raw",
            )

    def test_query_by_title_success(self, mock_context, setup_component_defs_dir):
        """Test querying component by title successfully."""
        result = query_component_definition(
            ctx=mock_context,
            component_definition_filter=None,
            query_type="by_title",
            query_value="Sample Component",
            return_format="raw",
        )

        assert result["total_count"] == 1
        assert result["query_type"] == "by_title"
        assert result["components"][0]["title"] == "Sample Component"

    def test_query_by_title_not_found(self, mock_context, setup_component_defs_dir):
        """Test querying component by title that doesn't exist."""
        with pytest.raises(ValueError, match="not found"):
            query_component_definition(
                ctx=mock_context,
                component_definition_filter=None,
                query_type="by_title",
                query_value="Nonexistent Component",
                return_format="raw",
            )

    def test_query_by_type_success(self, mock_context, setup_component_defs_dir):
        """Test querying components by type successfully."""
        result = query_component_definition(
            ctx=mock_context,
            component_definition_filter=None,
            query_type="by_type",
            query_value="software",
            return_format="raw",
        )

        assert result["total_count"] == 1
        assert result["query_type"] == "by_type"
        assert result["components"][0]["type"] == "software"

    def test_query_by_type_not_found(self, mock_context):
        """Test querying components by type that doesn't exist."""
        with pytest.raises(ValueError, match="found"):
            query_component_definition(
                ctx=mock_context,
                component_definition_filter=None,
                query_type="by_type",
                query_value="hardware",
                return_format="raw",
            )

    def test_query_missing_query_value(self, mock_context):
        """Test that query_value is required for specific query types."""
        with pytest.raises(ValueError, match="query_value is required"):
            query_component_definition(
                ctx=mock_context,
                component_definition_filter=None,
                query_type="by_uuid",
                query_value=None,
                return_format="raw",
            )

    def test_query_invalid_query_type(self, mock_context):
        """Test that invalid query_type raises error."""
        with pytest.raises(ValueError, match="Invalid query_type"):
            query_component_definition(
                ctx=mock_context,
                component_definition_filter=None,
                query_type="invalid_type",  # type: ignore
                return_format="raw",
            )

    def test_query_with_component_definition_filter_by_uuid(
        self, mock_context, tmp_path, sample_component_def_data, monkeypatch
    ):
        """Test filtering to a specific component definition by UUID."""
        comp_defs_dir = tmp_path / "component_definitions"
        comp_defs_dir.mkdir()

        # Create component definition file
        comp_def_file = comp_defs_dir / "sample.json"
        with open(comp_def_file, "w") as f:
            json.dump(sample_component_def_data, f)

        # Patch the config
        from mcp_server_for_oscal import config as config_module

        monkeypatch.setattr(
            config_module.config, "component_definitions_dir", str(comp_defs_dir)
        )

        # Query with component definition filter
        result = query_component_definition(
            ctx=mock_context,
            component_definition_filter="a1b2c3d4-5678-4abc-8def-123456789012",
            query_type="all",
            return_format="raw",
        )

        assert result["component_definitions_searched"] == 1
        assert result["filtered_by"] == "a1b2c3d4-5678-4abc-8def-123456789012"

    def test_query_with_component_definition_filter_by_title(
        self, mock_context, tmp_path, sample_component_def_data, monkeypatch
    ):
        """Test filtering to a specific component definition by title."""
        comp_defs_dir = tmp_path / "component_definitions"
        comp_defs_dir.mkdir()

        # Create component definition file
        comp_def_file = comp_defs_dir / "sample.json"
        with open(comp_def_file, "w") as f:
            json.dump(sample_component_def_data, f)

        # Patch the config
        from mcp_server_for_oscal import config as config_module

        monkeypatch.setattr(
            config_module.config, "component_definitions_dir", str(comp_defs_dir)
        )

        # Query with component definition filter
        result = query_component_definition(
            ctx=mock_context,
            component_definition_filter="Sample Component Definition",
            query_type="all",
            return_format="raw",
        )

        assert result["component_definitions_searched"] == 1
        assert result["filtered_by"] == "Sample Component Definition"

    def test_query_with_component_definition_filter_not_found(
        self, mock_context, tmp_path, sample_component_def_data, monkeypatch
    ):
        """Test error when component definition filter doesn't match any definitions."""
        comp_defs_dir = tmp_path / "component_definitions"
        comp_defs_dir.mkdir()

        # Create component definition file
        comp_def_file = comp_defs_dir / "sample.json"
        with open(comp_def_file, "w") as f:
            json.dump(sample_component_def_data, f)

        # Patch the config
        from mcp_server_for_oscal import config as config_module

        monkeypatch.setattr(
            config_module.config, "component_definitions_dir", str(comp_defs_dir)
        )

        # Query with non-matching filter
        with pytest.raises(ValueError, match="No Component Definition found"):
            query_component_definition(
                ctx=mock_context,
                component_definition_filter="Nonexistent Definition",
                query_type="all",
                return_format="raw",
            )

    def test_query_empty_directory(self, mock_context, tmp_path, monkeypatch):
        """Test error when component definitions directory is empty."""
        comp_defs_dir = tmp_path / "component_definitions"
        comp_defs_dir.mkdir()

        # Patch the config
        from mcp_server_for_oscal import config as config_module

        monkeypatch.setattr(
            config_module.config, "component_definitions_dir", str(comp_defs_dir)
        )

        monkeypatch.setattr("mcp_server_for_oscal.tools.query_component_definition._cdefs_by_path", {})
        monkeypatch.setattr("mcp_server_for_oscal.tools.query_component_definition._cdefs_by_uuid", {})
        monkeypatch.setattr("mcp_server_for_oscal.tools.query_component_definition._cdefs_by_title", {})
        monkeypatch.setattr("mcp_server_for_oscal.tools.query_component_definition._components_by_uuid", {})
        monkeypatch.setattr("mcp_server_for_oscal.tools.query_component_definition._components_by_title", {})

        # Query should fail with no component definitions
        with pytest.raises(ValueError, match="No Component Definitions found"):
            query_component_definition(
                ctx=mock_context,
                component_definition_filter=None,
                query_type="all",
                return_format="raw",
            )
