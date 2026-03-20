"""
Tests for README.md PyPI ownership verification tag.

Validates requirement 2.1 from the MCP Registry Publishing spec.
"""

import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
README_PATH = PROJECT_ROOT / "README.md"

EXPECTED_MCP_NAME = "io.github.awslabs/mcp-server-for-oscal"
MCP_NAME_PATTERN = re.compile(r"<!--\s*mcp-name:\s*(.+?)\s*-->")


@pytest.fixture
def readme_content():
    """Load README.md content."""
    return README_PATH.read_text(encoding="utf-8")


class TestReadmeVerificationTag:
    """Req 2.1: README.md contains the PyPI verification HTML comment."""

    def test_readme_contains_mcp_name_comment(self, readme_content):
        match = MCP_NAME_PATTERN.search(readme_content)
        assert match is not None, (
            "README.md must contain an <!-- mcp-name: ... --> HTML comment"
        )

    def test_mcp_name_matches_expected_value(self, readme_content):
        match = MCP_NAME_PATTERN.search(readme_content)
        assert match is not None
        assert match.group(1) == EXPECTED_MCP_NAME, (
            f"Expected mcp-name '{EXPECTED_MCP_NAME}', "
            f"got '{match.group(1)}'"
        )
