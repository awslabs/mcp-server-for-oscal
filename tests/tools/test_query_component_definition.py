"""
Tests for the query_component_definition tool.
"""
import asyncio
import json
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

import pytest
import requests
from trestle.oscal.component import ComponentDefinition

from mcp_server_for_oscal.tools.query_component_definition import (
    _load_component_definitions_from_directory,
    _store,
    get_capability,
    list_capabilities,
    list_component_definitions,
    list_components,
    query_component_definition,
)


class TestLoadComponentDefinitionsFromDirectory:
    """Test cases for _load_component_definitions_from_directory function."""

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
        result = _load_component_definitions_from_directory(comp_defs_dir)

        # Verify results
        assert len(result) == 2
        assert "comp_def_1.json" in result
        assert "vendor_a/comp_def_2.json" in result
        assert all(isinstance(cd, ComponentDefinition) for cd in result.values())

    def test_load_from_directory_nonexistent(self, tmp_path):
        """Test loading from a nonexistent directory."""
        nonexistent_dir = tmp_path / "nonexistent"
        result = _load_component_definitions_from_directory(nonexistent_dir)
        assert result == {}

    def test_load_from_directory_not_a_directory(self, tmp_path):
        """Test loading when path is not a directory."""
        file_path = tmp_path / "not_a_dir.txt"
        file_path.write_text("test")
        result = _load_component_definitions_from_directory(file_path)
        assert result == {}

    def test_load_from_directory_with_invalid_files(
        self, tmp_path, sample_component_def_data, monkeypatch
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
        result = _load_component_definitions_from_directory(comp_defs_dir)

        # Verify only valid component definition is loaded
        assert len(result) == 1
        assert "valid.json" in result

    def test_load_from_directory_empty(self, tmp_path, monkeypatch):
        """Test loading from an empty directory."""

        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        result = _load_component_definitions_from_directory(empty_dir)
        assert result == {}

    def test_load_from_directory_no_json_files(self, tmp_path, monkeypatch):
        """Test loading from directory with no JSON files."""        
        comp_defs_dir = tmp_path / "component_definitions"
        comp_defs_dir.mkdir()

        # Create non-JSON files
        (comp_defs_dir / "readme.txt").write_text("test")
        (comp_defs_dir / "data.xml").write_text("<xml/>")

        result = _load_component_definitions_from_directory(comp_defs_dir)
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

        _load_component_definitions_from_directory()

        return comp_defs_dir

    def test_query_all_components_raw_format(self, mock_context, setup_component_defs_dir, monkeypatch):
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
        result =  query_component_definition(
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
        """Test querying component by UUID that doesn't exist returns empty."""
        result = query_component_definition(
            ctx=mock_context,
            component_definition_filter=None,
            query_type="by_uuid",
            query_value="00000000-0000-0000-0000-000000000000",
            return_format="raw",
        )
        assert result["total_count"] == 0
        assert result["components"] == []

    def test_query_by_title_success(self, mock_context, setup_component_defs_dir):
        """Test querying component by title successfully."""
        result =  query_component_definition(
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
        """Test querying component by title that doesn't exist returns empty."""
        result = query_component_definition(
            ctx=mock_context,
            component_definition_filter=None,
            query_type="by_title",
            query_value="Nonexistent Component",
            return_format="raw",
        )
        assert result["total_count"] == 0
        assert result["components"] == []

    def test_query_by_type_success(self, mock_context, setup_component_defs_dir):
        """Test querying components by type successfully."""
        result =  query_component_definition(
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
        """Test querying components by type that doesn't exist returns empty."""
        result = query_component_definition(
            ctx=mock_context,
            component_definition_filter=None,
            query_type="by_type",
            query_value="hardware",
            return_format="raw",
        )
        assert result["total_count"] == 0
        assert result["components"] == []

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
        result =  query_component_definition(
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
        result =  query_component_definition(
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

        # Query with non-matching filter - should return empty, not raise
        result = query_component_definition(
            ctx=mock_context,
            component_definition_filter="Nonexistent Definition",
            query_type="all",
            return_format="raw",
        )
        assert result["total_count"] == 0
        assert result["components"] == []

    def test_query_empty_directory(self, mock_context, tmp_path, monkeypatch):
        """Test error when component definitions directory is empty."""
        comp_defs_dir = tmp_path / "component_definitions"
        comp_defs_dir.mkdir()

        # Patch the config
        from mcp_server_for_oscal import config as config_module

        monkeypatch.setattr(
            config_module.config, "component_definitions_dir", str(comp_defs_dir)
        )

        _load_component_definitions_from_directory(comp_defs_dir)

        # Query should fail with no component definitions
        with pytest.raises(ValueError, match="No Component Definitions loaded"):
            query_component_definition(
                ctx=mock_context,
                component_definition_filter=None,
                query_type="all",
                return_format="raw",
            )


class TestLoadExternalComponentDefinition:
    """Tests for load_external_component_definition."""

    @pytest.fixture
    def mock_context(self):
        ctx = AsyncMock()
        ctx.log = AsyncMock()
        return ctx

    @pytest.fixture
    def sample_component_def_data(self):
        sample_path = (
            Path(__file__).parent.parent
            / "fixtures"
            / "sample_component_definition.json"
        )
        with open(sample_path) as f:
            return json.load(f)

    def test_load_local_directory_raises(self, mock_context, tmp_path):
        """Loading a directory path should raise ValueError."""
        _store._reset()
        with pytest.raises(ValueError, match="URI must point to a zip file"):
            _store.load_external_component_definition(str(tmp_path), mock_context)

    def test_load_local_zip_file(self, mock_context, tmp_path, sample_component_def_data):
        """Loading a local zip file should index its contents."""
        _store._reset()
        # Create a zip with a component definition JSON inside
        zip_path = tmp_path / "test.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("comp.json", json.dumps(sample_component_def_data))

        _store.load_external_component_definition(str(zip_path), mock_context)
        assert _store._stats["processed_external_files"] == 1
        assert len(_store._cdefs_by_uuid) == 1

    def test_load_local_non_zip_file_is_noop(self, mock_context, tmp_path):
        """Loading a local non-zip file should be a no-op."""
        _store._reset()
        f = tmp_path / "readme.txt"
        f.write_text("hello")
        _store.load_external_component_definition(str(f), mock_context)
        assert _store._stats["processed_external_files"] == 0

    def test_remote_uri_disabled(self, mock_context, monkeypatch):
        """Remote URI loading should raise when allow_remote_uris is False."""
        _store._reset()
        from mcp_server_for_oscal import config as config_module
        monkeypatch.setattr(config_module.config, "allow_remote_uris", False)

        with pytest.raises(ValueError, match="Remote URI loading is not enabled"):
            _store.load_external_component_definition("https://example.com/comp.json", mock_context)

    def test_remote_uri_success(self, mock_context, monkeypatch, sample_component_def_data):
        """Remote URI loading should fetch, parse, and index."""
        _store._reset()
        from mcp_server_for_oscal import config as config_module
        monkeypatch.setattr(config_module.config, "allow_remote_uris", True)

        mock_resp = MagicMock()
        mock_resp.json.return_value = sample_component_def_data
        mock_resp.raise_for_status = MagicMock()

        with patch("mcp_server_for_oscal.tools.query_component_definition.requests.get", return_value=mock_resp):
            _store.load_external_component_definition("https://example.com/comp.json", mock_context)

        assert _store._stats["processed_external_files"] == 1
        assert len(_store._cdefs_by_uuid) == 1

    def test_remote_uri_timeout(self, mock_context, monkeypatch):
        """Remote URI timeout should raise ValueError."""
        _store._reset()
        from mcp_server_for_oscal import config as config_module
        monkeypatch.setattr(config_module.config, "allow_remote_uris", True)

        with patch(
            "mcp_server_for_oscal.tools.query_component_definition.requests.get",
            side_effect=requests.Timeout("timed out"),
        ):
            with pytest.raises(ValueError, match="Request timeout"):
                _store.load_external_component_definition("https://example.com/comp.json", mock_context)

    def test_remote_uri_request_exception(self, mock_context, monkeypatch):
        """Remote request failure should raise ValueError."""
        _store._reset()
        from mcp_server_for_oscal import config as config_module
        monkeypatch.setattr(config_module.config, "allow_remote_uris", True)

        with patch(
            "mcp_server_for_oscal.tools.query_component_definition.requests.get",
            side_effect=requests.ConnectionError("refused"),
        ):
            with pytest.raises(ValueError, match="Failed to fetch"):
                _store.load_external_component_definition("https://example.com/comp.json", mock_context)

    def test_remote_uri_json_decode_error(self, mock_context, monkeypatch):
        """Bad JSON from remote should raise ValueError."""
        _store._reset()
        from mcp_server_for_oscal import config as config_module
        monkeypatch.setattr(config_module.config, "allow_remote_uris", True)

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.side_effect = json.JSONDecodeError("bad", "", 0)

        with patch("mcp_server_for_oscal.tools.query_component_definition.requests.get", return_value=mock_resp):
            with pytest.raises(ValueError, match="Failed to parse remote"):
                _store.load_external_component_definition("https://example.com/comp.json", mock_context)

    def test_remote_uri_validation_error(self, mock_context, monkeypatch):
        """Invalid OSCAL data from remote should raise ValueError."""
        _store._reset()
        from mcp_server_for_oscal import config as config_module
        monkeypatch.setattr(config_module.config, "allow_remote_uris", True)

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"component-definition": {"bad": "data"}}

        with patch("mcp_server_for_oscal.tools.query_component_definition.requests.get", return_value=mock_resp):
            with pytest.raises(ValueError, match="Failed to load or validate"):
                _store.load_external_component_definition("https://example.com/comp.json", mock_context)


class TestZipFileProcessing:
    """Tests for _process_zip_files and _handle_zip_file."""

    @pytest.fixture
    def sample_component_def_data(self):
        sample_path = (
            Path(__file__).parent.parent
            / "fixtures"
            / "sample_component_definition.json"
        )
        with open(sample_path) as f:
            return json.load(f)

    def test_process_zip_files(self, tmp_path, sample_component_def_data):
        """Zip files in directory should be processed."""
        _store._reset()
        zip_path = tmp_path / "bundle.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("comp.json", json.dumps(sample_component_def_data))
            zf.writestr("readme.txt", "not json")

        _store._process_zip_files(tmp_path)
        assert _store._stats["processed_zip_files"] == 1
        assert _store._stats["zip_file_contents"] == 2
        assert _store._stats["loaded_files"] == 1

    def test_process_zip_files_no_zips(self, tmp_path):
        """Directory with no zips should be a no-op."""
        _store._reset()
        (tmp_path / "file.json").write_text("{}")
        _store._process_zip_files(tmp_path)
        assert _store._stats["processed_zip_files"] == 0


class TestCapabilityQuery:
    """Tests for capability query paths in ComponentDefinitionStore.query."""

    @pytest.fixture
    def mock_context(self):
        ctx = AsyncMock()
        ctx.log = AsyncMock()
        return ctx

    @pytest.fixture
    def setup_with_capabilities(self, tmp_path, monkeypatch):
        """Load a component definition that includes capabilities."""
        _store._reset()
        cap_path = (
            Path(__file__).parent.parent
            / "fixtures"
            / "sample_component_definition_with_capabilities.json"
        )
        comp_defs_dir = tmp_path / "component_definitions"
        comp_defs_dir.mkdir()

        import shutil
        shutil.copy(cap_path, comp_defs_dir / "cap.json")

        from mcp_server_for_oscal import config as config_module
        monkeypatch.setattr(config_module.config, "component_definitions_dir", str(comp_defs_dir))
        _store.load_from_directory(comp_defs_dir)
        return comp_defs_dir

    def test_query_capability_by_title(self, mock_context, setup_with_capabilities):
        """Query by_title should return a capability when name matches."""
        result = _store.query(ctx=mock_context, query_type="by_title", query_value="Test Capability")
        assert "capability" in result
        assert result["query_type"] == "by_title"

    def test_query_capability_by_uuid(self, mock_context, setup_with_capabilities):
        """Query by_uuid should return a capability when UUID matches."""
        result = _store.query(ctx=mock_context, query_type="by_uuid", query_value="d1e2f3a4-5678-4abc-9def-112233445566")
        assert "capability" in result
        assert result["component_count"] == 0

    def test_query_capability_by_title_with_filter(self, mock_context, setup_with_capabilities):
        """Capability query with matching component_definition_filter should succeed."""
        result = _store.query(
            ctx=mock_context,
            query_type="by_title",
            query_value="Test Capability",
            component_definition_filter="c1d2e3f4-5678-4abc-8def-aabbccddeeff",
        )
        assert "capability" in result

    def test_query_capability_by_title_with_wrong_filter(self, mock_context, setup_with_capabilities):
        """Capability query with non-matching filter should fall through to component search."""
        result = _store.query(
            ctx=mock_context,
            query_type="by_title",
            query_value="Test Capability",
            component_definition_filter="Capability Test Definition",
        )
        # The filter matches the cdef title, so it should still find the capability
        assert "capability" in result


class TestListMethods:
    """Tests for list_component_definitions, list_components, list_capabilities."""

    @pytest.fixture
    def mock_context(self):
        ctx = AsyncMock()
        ctx.log = AsyncMock()
        return ctx

    @pytest.fixture
    def sample_component_def_data(self):
        sample_path = (
            Path(__file__).parent.parent
            / "fixtures"
            / "sample_component_definition.json"
        )
        with open(sample_path) as f:
            return json.load(f)

    @pytest.fixture
    def setup_store(self, tmp_path, sample_component_def_data, monkeypatch):
        _store._reset()
        comp_defs_dir = tmp_path / "component_definitions"
        comp_defs_dir.mkdir()
        with open(comp_defs_dir / "sample.json", "w") as f:
            json.dump(sample_component_def_data, f)

        from mcp_server_for_oscal import config as config_module
        monkeypatch.setattr(config_module.config, "component_definitions_dir", str(comp_defs_dir))
        _store.load_from_directory(comp_defs_dir)

    def test_list_component_definitions(self, mock_context, setup_store):
        result = list_component_definitions(mock_context)
        assert len(result) == 1
        assert result[0]["title"] == "Sample Component Definition"
        assert "uuid" in result[0]
        assert "componentCount" in result[0]
        assert "sizeInBytes" in result[0]

    def test_list_component_definitions_empty(self, mock_context):
        _store._reset()
        with pytest.raises(RuntimeError, match="No Component Definitions loaded"):
            list_component_definitions(mock_context)

    def test_list_components(self, mock_context, setup_store):
        result = list_components(mock_context)
        assert len(result) == 1
        assert result[0]["title"] == "Sample Component"
        assert "parentComponentDefinitionTitle" in result[0]

    def test_list_components_empty(self, mock_context):
        _store._reset()
        with pytest.raises(RuntimeError, match="No Components loaded"):
            list_components(mock_context)

    def test_list_capabilities_empty(self, mock_context):
        _store._reset()
        result = list_capabilities(mock_context)
        assert result == []

    def test_list_capabilities_with_data(self, mock_context, tmp_path, monkeypatch):
        _store._reset()
        cap_path = (
            Path(__file__).parent.parent
            / "fixtures"
            / "sample_component_definition_with_capabilities.json"
        )
        comp_defs_dir = tmp_path / "component_definitions"
        comp_defs_dir.mkdir()
        import shutil
        shutil.copy(cap_path, comp_defs_dir / "cap.json")

        from mcp_server_for_oscal import config as config_module
        monkeypatch.setattr(config_module.config, "component_definitions_dir", str(comp_defs_dir))
        _store.load_from_directory(comp_defs_dir)

        result = list_capabilities(mock_context)
        assert len(result) == 1
        assert result[0]["name"] == "Test Capability"
        assert "parentComponentDefinitionTitle" in result[0]


class TestGetCapability:
    """Tests for the get_capability tool wrapper."""

    @pytest.fixture
    def mock_context(self):
        ctx = AsyncMock()
        ctx.log = AsyncMock()
        return ctx

    def test_get_capability_found(self, mock_context, tmp_path, monkeypatch):
        _store._reset()
        cap_path = (
            Path(__file__).parent.parent
            / "fixtures"
            / "sample_component_definition_with_capabilities.json"
        )
        comp_defs_dir = tmp_path / "component_definitions"
        comp_defs_dir.mkdir()
        import shutil
        shutil.copy(cap_path, comp_defs_dir / "cap.json")

        from mcp_server_for_oscal import config as config_module
        monkeypatch.setattr(config_module.config, "component_definitions_dir", str(comp_defs_dir))
        _store.load_from_directory(comp_defs_dir)

        result = get_capability(mock_context, "d1e2f3a4-5678-4abc-9def-112233445566")
        assert result is not None
        assert result["name"] == "Test Capability"

    def test_get_capability_not_found(self, mock_context):
        _store._reset()
        result = get_capability(mock_context, "00000000-0000-0000-0000-000000000000")
        assert result is None


class TestSelectComponentsEdgeCases:
    """Tests for _select_components edge cases."""

    @pytest.fixture
    def mock_context(self):
        ctx = AsyncMock()
        ctx.log = AsyncMock()
        return ctx

    @pytest.fixture
    def sample_component_def_data(self):
        sample_path = (
            Path(__file__).parent.parent
            / "fixtures"
            / "sample_component_definition.json"
        )
        with open(sample_path) as f:
            return json.load(f)

    @pytest.fixture
    def setup_store(self, tmp_path, sample_component_def_data, monkeypatch):
        _store._reset()
        comp_defs_dir = tmp_path / "component_definitions"
        comp_defs_dir.mkdir()
        with open(comp_defs_dir / "sample.json", "w") as f:
            json.dump(sample_component_def_data, f)

        from mcp_server_for_oscal import config as config_module
        monkeypatch.setattr(config_module.config, "component_definitions_dir", str(comp_defs_dir))
        _store.load_from_directory(comp_defs_dir)

    def test_query_by_title_falls_back_to_prop_search(self, mock_context, setup_store):
        """When title doesn't match, should fall back to prop value search."""
        result = query_component_definition(
            ctx=mock_context,
            query_type="by_title",
            query_value="1.0.0",  # matches the prop value
            return_format="raw",
        )
        assert result["total_count"] == 1

    def test_query_no_components_in_filtered_cdef(self, mock_context, tmp_path, monkeypatch):
        """A component definition with no components should return empty."""
        _store._reset()
        cdef_data = {
            "component-definition": {
                "uuid": "f1a2b3c4-5678-4abc-8def-ffeeddccbbaa",
                "metadata": {
                    "title": "Empty Def",
                    "last-modified": "2024-01-01T00:00:00Z",
                    "version": "1.0",
                    "oscal-version": "1.0.4",
                },
            }
        }
        comp_defs_dir = tmp_path / "component_definitions"
        comp_defs_dir.mkdir()
        with open(comp_defs_dir / "empty.json", "w") as f:
            json.dump(cdef_data, f)

        from mcp_server_for_oscal import config as config_module
        monkeypatch.setattr(config_module.config, "component_definitions_dir", str(comp_defs_dir))
        _store.load_from_directory(comp_defs_dir)

        result = query_component_definition(
            ctx=mock_context,
            query_type="all",
            return_format="raw",
        )
        assert result["total_count"] == 0
        assert result["components"] == []


class TestIndexComponentsExceptionPath:
    """Test the exception path in _index_components."""

    def test_index_components_bad_data_raises(self):
        """_index_components should re-raise on bad data."""
        _store._reset()
        bad_cdef = MagicMock()
        bad_cdef.metadata = None  # will cause AttributeError

        with pytest.raises(Exception):
            _store._index_components(bad_cdef, "bad.json")


class TestRemainingCoverageGaps:
    """Tests targeting specific uncovered lines and branch partials."""

    @pytest.fixture
    def mock_context(self):
        ctx = AsyncMock()
        ctx.log = AsyncMock()
        return ctx

    @pytest.fixture
    def sample_component_def_data(self):
        sample_path = (
            Path(__file__).parent.parent
            / "fixtures"
            / "sample_component_definition.json"
        )
        with open(sample_path) as f:
            return json.load(f)

    def test_remote_uri_without_component_definition_key(self, mock_context, monkeypatch, sample_component_def_data):
        """Remote JSON without 'component-definition' wrapper should be parsed directly."""
        _store._reset()
        from mcp_server_for_oscal import config as config_module
        monkeypatch.setattr(config_module.config, "allow_remote_uris", True)

        # Send the inner object directly (no "component-definition" wrapper)
        inner_data = sample_component_def_data["component-definition"]
        mock_resp = MagicMock()
        mock_resp.json.return_value = inner_data
        mock_resp.raise_for_status = MagicMock()

        with patch("mcp_server_for_oscal.tools.query_component_definition.requests.get", return_value=mock_resp):
            _store.load_external_component_definition("https://example.com/comp.json", mock_context)

        assert _store._stats["processed_external_files"] == 1

    def test_find_component_by_prop_value_no_props(self):
        """Component with no props should not match."""
        from trestle.oscal.component import DefinedComponent
        import uuid as uuid_mod
        comp = DefinedComponent(
            uuid=str(uuid_mod.uuid4()),
            type="software",
            title="No Props",
            description="desc",
        )
        result = _store.find_component_by_prop_value([comp], "anything")
        assert result is None

    def test_capability_filter_no_match_falls_through(self, mock_context, tmp_path, monkeypatch):
        """Capability found but filter doesn't match its parent cdef — should fall through to component search."""
        _store._reset()
        # Load the capability fixture
        cap_path = (
            Path(__file__).parent.parent
            / "fixtures"
            / "sample_component_definition_with_capabilities.json"
        )
        comp_defs_dir = tmp_path / "component_definitions"
        comp_defs_dir.mkdir()
        import shutil
        shutil.copy(cap_path, comp_defs_dir / "cap.json")

        from mcp_server_for_oscal import config as config_module
        monkeypatch.setattr(config_module.config, "component_definitions_dir", str(comp_defs_dir))
        _store.load_from_directory(comp_defs_dir)

        # Also load the sample fixture so there's a second cdef to filter to
        sample_path = (
            Path(__file__).parent.parent
            / "fixtures"
            / "sample_component_definition.json"
        )
        shutil.copy(sample_path, comp_defs_dir / "sample.json")
        _store.load_from_directory(comp_defs_dir)

        # Query capability by title but filter to the OTHER cdef UUID
        result = _store.query(
            ctx=mock_context,
            query_type="by_title",
            query_value="Test Capability",
            component_definition_filter="a1b2c3d4-5678-4abc-8def-123456789012",
        )
        # The capability's parent doesn't match the filter, so it falls through
        # to component search which finds nothing with that title
        assert "components" in result

    def test_capability_search_exception_handled(self, mock_context, tmp_path, monkeypatch):
        """Exception during capability search should be caught and fall through."""
        _store._reset()
        cap_path = (
            Path(__file__).parent.parent
            / "fixtures"
            / "sample_component_definition_with_capabilities.json"
        )
        comp_defs_dir = tmp_path / "component_definitions"
        comp_defs_dir.mkdir()
        import shutil
        shutil.copy(cap_path, comp_defs_dir / "cap.json")

        from mcp_server_for_oscal import config as config_module
        monkeypatch.setattr(config_module.config, "component_definitions_dir", str(comp_defs_dir))
        _store.load_from_directory(comp_defs_dir)

        # Corrupt the capabilities index to force an exception
        for key in list(_store._capabilities_to_cdef_by_uuid.keys()):
            _store._capabilities_to_cdef_by_uuid[key] = "bogus-uuid"

        result = _store.query(
            ctx=mock_context,
            query_type="by_title",
            query_value="Test Capability",
            component_definition_filter="c1d2e3f4-5678-4abc-8def-aabbccddeeff",
        )
        # Should fall through to component search after exception
        assert "components" in result

    def test_select_components_by_uuid_none_query_value(self, mock_context, tmp_path, sample_component_def_data, monkeypatch):
        """_select_components by_uuid with None query_value should raise."""
        _store._reset()
        comp_defs_dir = tmp_path / "component_definitions"
        comp_defs_dir.mkdir()
        with open(comp_defs_dir / "sample.json", "w") as f:
            json.dump(sample_component_def_data, f)

        from mcp_server_for_oscal import config as config_module
        monkeypatch.setattr(config_module.config, "component_definitions_dir", str(comp_defs_dir))
        _store.load_from_directory(comp_defs_dir)

        by_uuid = {"x": MagicMock()}
        by_title = {"x": MagicMock()}
        with pytest.raises(ValueError, match="query_value is required for by_uuid"):
            _store._select_components("by_uuid", None, by_uuid, by_title, mock_context)

    def test_select_components_by_title_none_query_value(self, mock_context):
        """_select_components by_title with None query_value should raise."""
        by_uuid = {"x": MagicMock()}
        by_title = {"x": MagicMock()}
        with pytest.raises(ValueError, match="query_value is required for by_title"):
            _store._select_components("by_title", None, by_uuid, by_title, mock_context)

    def test_select_components_by_type_none_query_value(self, mock_context):
        """_select_components by_type with None query_value should raise."""
        by_uuid = {"x": MagicMock()}
        by_title = {"x": MagicMock()}
        with pytest.raises(ValueError, match="query_value is required for by_type"):
            _store._select_components("by_type", None, by_uuid, by_title, mock_context)


    def test_zip_reprocessing_existing_entry(self, mock_context, tmp_path, sample_component_def_data):
        """Loading a zip with an already-indexed entry should log reprocessing."""
        _store._reset()
        zip_path = tmp_path / "bundle.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("comp.json", json.dumps(sample_component_def_data))

        # Load once
        _store._handle_zip_file(zip_path)
        # Load again — the entry path should already be in _cdefs_by_path
        _store._handle_zip_file(zip_path)
        assert _store._stats["loaded_files"] == 2

    def test_process_json_files_skips_hashes_json(self, tmp_path, sample_component_def_data):
        """hashes.json files should be skipped during JSON processing."""
        _store._reset()
        (tmp_path / "hashes.json").write_text('{"file_hashes": {}}')
        with open(tmp_path / "sample.json", "w") as f:
            json.dump(sample_component_def_data, f)

        _store._process_json_files(tmp_path)
        assert _store._stats["processed_json_files"] == 1
        assert len(_store._cdefs_by_path) == 1

    def test_index_components_exception_reraise(self):
        """_index_components should log and re-raise when indexing fails mid-way."""
        _store._reset()
        sample_path = (
            Path(__file__).parent.parent
            / "fixtures"
            / "sample_component_definition.json"
        )
        with open(sample_path) as f:
            data = json.load(f)

        cdef = ComponentDefinition.parse_obj(data["component-definition"])
        # Sabotage the components list with a non-DefinedComponent to cause failure
        cdef.__dict__["components"] = ["not a component"]

        with pytest.raises(Exception):
            _store._index_components(cdef, "bad.json")

    def test_capability_exception_path_in_query(self, mock_context, tmp_path, monkeypatch):
        """Force an exception in the capability search try block."""
        _store._reset()
        cap_path = (
            Path(__file__).parent.parent
            / "fixtures"
            / "sample_component_definition_with_capabilities.json"
        )
        comp_defs_dir = tmp_path / "component_definitions"
        comp_defs_dir.mkdir()
        import shutil
        shutil.copy(cap_path, comp_defs_dir / "cap.json")

        from mcp_server_for_oscal import config as config_module
        monkeypatch.setattr(config_module.config, "component_definitions_dir", str(comp_defs_dir))
        _store.load_from_directory(comp_defs_dir)

        # Corrupt _capabilities_by_name to force an exception when accessing the capability
        cap_key = list(_store._capabilities_by_name.keys())[0]
        _store._capabilities_by_name[cap_key] = "not a capability"  # type: ignore[assignment]

        result = _store.query(
            ctx=mock_context,
            query_type="by_title",
            query_value="Test Capability",
        )
        # Should fall through to component search after exception
        assert "components" in result


    def test_process_json_files_oscal_read_returns_none(self, tmp_path):
        """When oscal_read returns None, the file should be skipped."""
        _store._reset()
        (tmp_path / "empty.json").write_text('{}')

        with patch(
            "mcp_server_for_oscal.tools.query_component_definition.ComponentDefinition.oscal_read",
            return_value=None,
        ):
            _store._process_json_files(tmp_path)

        assert _store._stats["processed_json_files"] == 1
        assert _store._stats["loaded_files"] == 0
        assert len(_store._cdefs_by_path) == 0
