"""
Tests for server.json metadata file structure and content.

Validates requirements 1.1–1.6 and 6.1–6.3 from the MCP Registry Publishing spec.
"""

import json
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SERVER_JSON_PATH = PROJECT_ROOT / "server.json"


@pytest.fixture
def server_data():
    """Load and parse server.json."""
    text = SERVER_JSON_PATH.read_text(encoding="utf-8")
    return json.loads(text)


class TestServerJsonExists:
    """Req 1.6: server.json exists and is valid JSON."""

    def test_server_json_file_exists(self):
        assert SERVER_JSON_PATH.is_file(), "server.json must exist in project root"

    def test_server_json_is_valid_json(self):
        text = SERVER_JSON_PATH.read_text(encoding="utf-8")
        data = json.loads(text)
        assert isinstance(data, dict)


class TestServerJsonSchema:
    """Req 1.1: $schema field points to the MCP Registry schema."""

    def test_schema_field_value(self, server_data):
        assert server_data["$schema"] == (
            "https://static.modelcontextprotocol.io/schemas/"
            "2025-12-11/server.schema.json"
        )


class TestServerJsonName:
    """Req 1.2: name field equals the expected Server_Name."""

    def test_name_field_value(self, server_data):
        assert (
            server_data["name"]
            == "io.github.awslabs/mcp-server-for-oscal"
        )


class TestServerJsonDescriptiveFields:
    """Req 1.3: title, description, and version are non-empty strings."""

    def test_title_is_non_empty_string(self, server_data):
        assert isinstance(server_data["title"], str)
        assert len(server_data["title"]) > 0

    def test_description_is_non_empty_string(self, server_data):
        assert isinstance(server_data["description"], str)
        assert len(server_data["description"]) > 0

    def test_version_is_non_empty_string(self, server_data):
        assert isinstance(server_data["version"], str)
        assert len(server_data["version"]) > 0


class TestServerJsonRepository:
    """Req 1.4: repository object has correct url and source."""

    def test_repository_url(self, server_data):
        repo = server_data["repository"]
        assert repo["url"] == "https://github.com/awslabs/mcp-server-for-oscal"

    def test_repository_source(self, server_data):
        repo = server_data["repository"]
        assert repo["source"] == "github"


class TestServerJsonPackages:
    """Req 1.5: packages array has a PyPI entry with stdio transport."""

    def test_packages_is_non_empty_array(self, server_data):
        assert isinstance(server_data["packages"], list)
        assert len(server_data["packages"]) >= 1

    def test_pypi_package_entry_exists(self, server_data):
        pypi_entries = [
            p for p in server_data["packages"]
            if p.get("registryType") == "pypi"
        ]
        assert len(pypi_entries) >= 1

    def test_pypi_package_identifier(self, server_data):
        pypi_entry = next(
            p for p in server_data["packages"]
            if p.get("registryType") == "pypi"
        )
        assert pypi_entry["identifier"] == "mcp-server-for-oscal"

    def test_pypi_package_has_stdio_transport(self, server_data):
        pypi_entry = next(
            p for p in server_data["packages"]
            if p.get("registryType") == "pypi"
        )
        transport = pypi_entry["transport"]
        assert transport["type"] == "stdio"


class TestServerJsonEnvironmentVariables:
    """Req 6.1–6.3: environment variables are documented with required fields."""

    EXPECTED_ENV_VARS = [
        "BEDROCK_MODEL_ID",
        "OSCAL_KB_ID",
        "AWS_PROFILE",
        "AWS_REGION",
        "LOG_LEVEL",
    ]

    def _get_env_vars(self, server_data):
        pypi_entry = next(
            p for p in server_data["packages"]
            if p.get("registryType") == "pypi"
        )
        return pypi_entry["environmentVariables"]

    def test_all_expected_env_vars_documented(self, server_data):
        env_vars = self._get_env_vars(server_data)
        names = [ev["name"] for ev in env_vars]
        for expected in self.EXPECTED_ENV_VARS:
            assert expected in names, f"{expected} not documented"

    def test_env_vars_have_name_field(self, server_data):
        for ev in self._get_env_vars(server_data):
            assert isinstance(ev["name"], str)
            assert len(ev["name"]) > 0

    def test_env_vars_have_description_field(self, server_data):
        for ev in self._get_env_vars(server_data):
            assert isinstance(ev["description"], str)
            assert len(ev["description"]) > 0

    def test_env_vars_have_required_field(self, server_data):
        for ev in self._get_env_vars(server_data):
            assert isinstance(ev["required"], bool)
