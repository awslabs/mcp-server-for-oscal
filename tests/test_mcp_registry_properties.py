"""
Property-based tests for MCP Registry Publishing correctness properties.

Uses Hypothesis to verify universal properties across generated inputs
for the MCP Registry metadata and version synchronization logic.

Feature: mcp-registry-publishing
"""

import json
import re
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SERVER_JSON_PATH = PROJECT_ROOT / "server.json"
README_PATH = PROJECT_ROOT / "README.md"

MCP_NAME_PATTERN = re.compile(r"<!--\s*mcp-name:\s*(.+?)\s*-->")


def _load_server_json() -> dict:
    """Load and parse server.json from the project root."""
    return json.loads(SERVER_JSON_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

@st.composite
def semver_string(draw):
    """Generate a valid semantic version string (major.minor.patch)."""
    major = draw(st.integers(min_value=0, max_value=999))
    minor = draw(st.integers(min_value=0, max_value=999))
    patch = draw(st.integers(min_value=0, max_value=999))
    return f"{major}.{minor}.{patch}"


def _apply_version_update(server_data: dict, version: str) -> dict:
    """
    Apply the same version update logic used in the release workflow.

    Mirrors the jq command:
        jq --arg v "$VERSION" '.version = $v | .packages[].version = $v'
    """
    updated = json.loads(json.dumps(server_data))  # deep copy
    updated["version"] = version
    for package in updated.get("packages", []):
        package["version"] = version
    return updated


# ---------------------------------------------------------------------------
# Property 1: Version Update Consistency
# ---------------------------------------------------------------------------


class TestProperty1VersionUpdateConsistency:
    """
    Property 1: Version Update Consistency

    For any valid semantic version string, after applying the version
    update logic to server.json, the top-level `version` field and every
    `version` field inside each `packages` entry must all equal the input
    version string.

    **Validates: Requirements 3.1, 3.2**
    """

    @settings(max_examples=100)
    @given(version=semver_string())
    def test_all_version_fields_match_after_update(self, version):
        """
        Feature: mcp-registry-publishing, Property 1: Version Update Consistency

        After applying a version update with any valid semver string,
        all version fields in server.json must equal the input version.
        """
        server_data = _load_server_json()
        updated = _apply_version_update(server_data, version)

        # Top-level version must match
        assert updated["version"] == version, (
            f"Top-level version '{updated['version']}' != '{version}'"
        )

        # Every package version must match
        for i, package in enumerate(updated["packages"]):
            assert package["version"] == version, (
                f"packages[{i}].version '{package['version']}' != '{version}'"
            )


# ---------------------------------------------------------------------------
# Property 2: Environment Variable Entry Completeness
# ---------------------------------------------------------------------------


class TestProperty2EnvironmentVariableEntryCompleteness:
    """
    Property 2: Environment Variable Entry Completeness

    For any entry in the environmentVariables array of server.json,
    the entry must have a non-empty name string, a non-empty description
    string, and a required field that is a boolean value.

    **Validates: Requirements 6.1, 6.3**
    """

    @settings(max_examples=100)
    @given(data=st.data())
    def test_env_var_entry_has_required_fields(self, data):
        """
        Feature: mcp-registry-publishing, Property 2: Environment Variable Entry Completeness

        Every environment variable entry must have a non-empty name,
        non-empty description, and a boolean required field.
        """
        server_data = _load_server_json()
        pypi_entry = next(
            p for p in server_data["packages"]
            if p.get("registryType") == "pypi"
        )
        env_vars = pypi_entry["environmentVariables"]
        assert len(env_vars) > 0, "environmentVariables must not be empty"

        entry = data.draw(st.sampled_from(env_vars))

        # name must be a non-empty string
        assert isinstance(entry["name"], str), (
            f"name must be a string, got {type(entry['name'])}"
        )
        assert len(entry["name"]) > 0, "name must not be empty"

        # description must be a non-empty string
        assert isinstance(entry["description"], str), (
            f"description must be a string, got {type(entry['description'])}"
        )
        assert len(entry["description"]) > 0, "description must not be empty"

        # required must be a boolean
        assert isinstance(entry["required"], bool), (
            f"required must be a bool, got {type(entry['required'])}"
        )


# ---------------------------------------------------------------------------
# Property 3: Cross-File Name Consistency
# ---------------------------------------------------------------------------


def _extract_mcp_name_from_readme(content: str) -> str | None:
    """Extract the mcp-name value from an HTML comment in README content."""
    match = MCP_NAME_PATTERN.search(content)
    return match.group(1) if match else None


@st.composite
def mcp_name_string(draw):
    """Generate a valid MCP server name string."""
    name = draw(
        st.text(
            min_size=1,
            max_size=80,
            alphabet=st.characters(
                whitelist_categories=("L", "N", "P"),
            ),
        ).filter(lambda t: t.strip() and "-->" not in t)
    )
    return name


class TestProperty3CrossFileNameConsistency:
    """
    Property 3: Cross-File Name Consistency

    The server name extracted from the <!-- mcp-name: ... --> HTML comment
    in README.md must exactly equal the name field in server.json.

    **Validates: Requirements 2.2**
    """

    @settings(max_examples=100)
    @given(name=mcp_name_string())
    def test_extraction_logic_roundtrips_with_generated_names(self, name):
        """
        Feature: mcp-registry-publishing, Property 3: Cross-File Name Consistency

        For any generated name, embedding it in an HTML comment and
        extracting it must yield the original name.
        """
        comment = f"<!-- mcp-name: {name} -->"
        extracted = _extract_mcp_name_from_readme(comment)
        assert extracted == name, (
            f"Extracted name '{extracted}' != generated name '{name}'"
        )

    def test_actual_readme_and_server_json_names_match(self):
        """
        Feature: mcp-registry-publishing, Property 3: Cross-File Name Consistency

        The actual mcp-name in README.md must match the name in server.json.
        """
        server_data = _load_server_json()
        readme_content = README_PATH.read_text(encoding="utf-8")

        readme_name = _extract_mcp_name_from_readme(readme_content)
        assert readme_name is not None, (
            "README.md must contain an <!-- mcp-name: ... --> comment"
        )
        assert readme_name == server_data["name"], (
            f"README mcp-name '{readme_name}' != "
            f"server.json name '{server_data['name']}'"
        )
