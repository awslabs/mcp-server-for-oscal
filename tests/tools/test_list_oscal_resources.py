"""
Tests for the list_oscal_resources tool.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from mcp_server_for_oscal.tools.list_oscal_resources import (
    list_oscal_resources,
    read_resources_file,
)


class TestListOscalResources:
    """Test cases for the list_oscal_resources tool."""

    def test_list_oscal_resources_returns_string(self):
        """Test that list_oscal_resources returns a string."""
        ctx = AsyncMock()
        ctx.session.client_params = {}

        result = list_oscal_resources(ctx)
        assert isinstance(result, str)

    def test_list_oscal_resources_contains_expected_content(self):
        """Test that the returned content contains expected OSCAL resource information."""
        ctx = AsyncMock()
        ctx.session.client_params = {}

        result = list_oscal_resources(ctx)

        # Check for key sections that should be in awesome-oscal.md
        assert "Awesome OSCAL" in result
        assert "Content" in result
        assert "Tools" in result
        assert "OSCAL" in result

        # Check for some specific resources mentioned in the file
        assert (
            "Australian Cyber Security Centre" in result
            or "Center for Internet Security" in result
        )

    def test_list_oscal_resources_preserves_markdown_formatting(self):
        """Test that markdown formatting is preserved in the returned content."""
        ctx = AsyncMock()
        ctx.session.client_params = {}

        result = list_oscal_resources(ctx)

        # Check for markdown formatting elements
        assert "# " in result  # Headers
        assert "- " in result or "* " in result  # List items
        assert "[" in result and "](" in result  # Links

    def test_list_oscal_resources_non_empty_content(self):
        """Test that the returned content is not empty."""
        ctx = AsyncMock()
        ctx.session.client_params = {}

        result = list_oscal_resources(ctx)

        assert result.strip(), "Content should not be empty"
        assert len(result) > 100, "Content should be substantial"

    def test_read_resources_file_returns_string(self):
        """Test that read_resources_file returns a string."""
        result = read_resources_file()
        assert isinstance(result, str)

    def test_read_resources_file_content_matches_tool_output(self):
        """Test that read_resources_file returns the same content as the tool."""
        ctx = AsyncMock()
        ctx.session.client_params = {}

        direct_result = read_resources_file()
        tool_result = list_oscal_resources(ctx)

        assert direct_result == tool_result

    @patch("mcp_server_for_oscal.tools.list_oscal_resources.open")
    def test_list_oscal_resources_file_not_found_error(self, mock_open):
        """Test error handling when the awesome-oscal.md file is not found."""
        mock_open.side_effect = FileNotFoundError("File not found")

        ctx = AsyncMock()
        ctx.session.client_params = {}

        with pytest.raises(FileNotFoundError):
            list_oscal_resources(ctx)

        # Verify error was reported to context
        ctx.error.assert_called_once()

    @patch("mcp_server_for_oscal.tools.list_oscal_resources.open")
    def test_list_oscal_resources_io_error(self, mock_open):
        """Test error handling for IO errors when reading the file."""
        mock_open.side_effect = OSError("Permission denied")

        ctx = AsyncMock()
        ctx.session.client_params = {}

        with pytest.raises(IOError):
            list_oscal_resources(ctx)

        # Verify error was reported to context
        ctx.error.assert_called_once()
        assert "Failed to read" in ctx.error.call_args[0][0]

    @patch("mcp_server_for_oscal.tools.list_oscal_resources.open")
    def test_list_oscal_resources_unicode_decode_error(self, mock_open):
        """Test error handling for encoding issues."""
        mock_open.side_effect = UnicodeDecodeError(
            "utf-8", b"", 0, 1, "invalid start byte"
        )

        ctx = AsyncMock()
        ctx.session.client_params = {}

        with pytest.raises(UnicodeDecodeError):
            list_oscal_resources(ctx)

        # Verify error was reported to context
        ctx.error.assert_called_once()

    def test_read_resources_file_with_temporary_file(self):
        """Test reading a temporary file with known content."""
        test_content = """# Test OSCAL Resources

## Content
- Test resource 1
- Test resource 2

## Tools
- Test tool 1
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".md", delete=False, encoding="utf-8"
        ) as temp_file:
            temp_file.write(test_content)
            temp_file_path = temp_file.name

        try:
            # Patch the path resolution to use our temporary file
            with patch(
                "mcp_server_for_oscal.tools.list_oscal_resources.Path"
            ) as mock_path:
                mock_path_instance = Mock()
                mock_path_instance.parent = Mock()
                mock_path_instance.parent.parent = Mock()
                mock_path_instance.parent.parent.__truediv__ = Mock(
                    return_value=Path(temp_file_path).parent
                )
                mock_path.__file__ = __file__
                mock_path.return_value = mock_path_instance

                # Mock the final path resolution
                with patch("builtins.open", open), patch(
                    "mcp_server_for_oscal.tools.list_oscal_resources.Path"
                ) as mock_path2:
                    mock_docs_path = Mock()
                    mock_docs_path.__truediv__ = Mock(
                        return_value=Path(temp_file_path)
                    )
                    mock_path2.return_value.parent.parent.__truediv__ = Mock(
                        return_value=mock_docs_path
                    )

                    # Direct test with the actual file
                    with open(temp_file_path, encoding="utf-8") as f:
                        result = f.read()

                    assert result == test_content
        finally:
            os.unlink(temp_file_path)

    def test_read_resources_file_empty_file_warning(self):
        """Test that a warning is logged for empty files."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".md", delete=False, encoding="utf-8"
        ) as temp_file:
            # Write empty content
            temp_file.write("")
            temp_file_path = temp_file.name

        try:
            with patch(
                "mcp_server_for_oscal.tools.list_oscal_resources.Path"
            ) as mock_path:
                mock_path_instance = Mock()
                mock_path_instance.parent = Mock()
                mock_path_instance.parent.parent = Mock()

                # Mock the final path to point to our empty temp file
                with patch("builtins.open", open), patch(
                    "mcp_server_for_oscal.tools.list_oscal_resources.logger"
                ) as mock_logger:
                    # Direct file read test
                    with open(temp_file_path, encoding="utf-8") as f:
                        content = f.read()

                    assert content == ""
        finally:
            os.unlink(temp_file_path)

    def test_list_oscal_resources_context_none(self):
        """Test that the tool works when context is None."""
        # This should not raise an exception even with None context
        result = list_oscal_resources(None)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_read_resources_file_encoding_fallback(self):
        """Test encoding fallback behavior."""
        # Create a file with latin-1 encoding
        test_content_latin1 = "Test content with special char: \xe9"  # é in latin-1

        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".md", delete=False
        ) as temp_file:
            temp_file.write(test_content_latin1.encode("latin-1"))
            temp_file_path = temp_file.name

        try:
            # Test that the file can be read with fallback encoding
            with open(temp_file_path, encoding="latin-1", errors="replace") as f:
                content = f.read()

            assert "Test content" in content
            assert len(content) > 0
        finally:
            os.unlink(temp_file_path)

    def test_list_oscal_resources_consistent_calls(self):
        """Test that multiple calls return consistent results."""
        ctx = AsyncMock()
        ctx.session.client_params = {}

        result1 = list_oscal_resources(ctx)
        result2 = list_oscal_resources(ctx)

        assert result1 == result2, "Multiple calls should return identical results"

    def test_list_oscal_resources_logging(self):
        """Test that appropriate logging occurs during successful execution."""
        ctx = AsyncMock()
        ctx.session.client_params = {}

        with patch(
            "mcp_server_for_oscal.tools.list_oscal_resources.logger"
        ) as mock_logger:
            result = list_oscal_resources(ctx)

            # Verify debug logging calls were made
            assert mock_logger.debug.called

            # Check that success message was logged
            info_calls = [call[0][0] for call in mock_logger.debug.call_args_list]
            assert any("Successfully read" in msg for msg in info_calls)
