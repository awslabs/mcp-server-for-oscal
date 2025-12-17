"""
Tests for the main module.
"""

from unittest.mock import Mock, patch

import pytest

from mcp_server_for_oscal.main import main


class TestMain:
    """Test cases for the main function and module."""

    @pytest.fixture
    def mock_config(self):
        """Create a mock configuration object."""
        config = Mock()
        config.aws_profile = "default"
        config.log_level = "INFO"
        return config

    @pytest.fixture
    def mock_mcp(self):
        """Create a mock MCP server."""
        mcp = Mock()
        mcp.run = Mock()
        return mcp

    @patch("mcp_server_for_oscal.main.mcp")
    @patch("mcp_server_for_oscal.main.config")
    @patch("mcp_server_for_oscal.main.logging.basicConfig")
    @patch("sys.argv", ["main.py"])
    def test_main_default_arguments(self, mock_logging_config, mock_config, mock_mcp):
        """Test main function with default arguments."""
        # Setup mocks
        mock_config.aws_profile = "default"
        mock_config.log_level = "INFO"
        mock_config.transport = "stdio"

        # Execute test
        main()

        # Verify configuration update was called with None values (defaults)
        mock_config.update_from_args.assert_called_once_with(
            bedrock_model_id=None,
            knowledge_base_id=None,
            log_level="INFO",
            transport="stdio",
        )

        # Verify transport validation was called
        mock_config.validate_transport.assert_called_once()

        # Verify logging configuration
        mock_logging_config.assert_called_once_with(level="INFO")

        # Verify MCP server was started with configured transport
        mock_mcp.run.assert_called_once_with(transport="stdio")

    @patch("mcp_server_for_oscal.main.mcp")
    @patch("mcp_server_for_oscal.main.config")
    @patch("mcp_server_for_oscal.main.logging.basicConfig")
    @patch(
        "sys.argv",
        [
            "main.py",
            "--aws-profile",
            "test-profile",
            "--log-level",
            "DEBUG",
            "--bedrock-model-id",
            "test-model",
            "--knowledge-base-id",
            "test-kb",
        ],
    )
    def test_main_with_arguments(self, mock_logging_config, mock_config, mock_mcp):
        """Test main function with command line arguments."""
        # Setup mocks
        mock_config.aws_profile = "test-profile"
        mock_config.log_level = "DEBUG"
        mock_config.transport = "stdio"

        # Execute test
        main()

        # Verify configuration update was called with provided values
        mock_config.update_from_args.assert_called_once_with(
            bedrock_model_id="test-model",
            knowledge_base_id="test-kb",
            log_level="DEBUG",
            transport="stdio",
        )

        # Verify transport validation was called
        mock_config.validate_transport.assert_called_once()

        # Verify logging configuration
        mock_logging_config.assert_called_once_with(level="DEBUG")

        # Verify MCP server was started with configured transport
        mock_mcp.run.assert_called_once_with(transport="stdio")

    @patch("mcp_server_for_oscal.main.mcp")
    @patch("mcp_server_for_oscal.main.config")
    @patch("mcp_server_for_oscal.main.logging.basicConfig")
    @patch("mcp_server_for_oscal.main.logger")
    @patch("sys.argv", ["main.py"])
    def test_main_mcp_server_error(
        self, mock_logger, mock_logging_config, mock_config, mock_mcp
    ):
        """Test main function when MCP server fails to start."""
        # Setup mocks
        mock_config.aws_profile = "default"
        mock_config.log_level = "INFO"
        mock_config.transport = "stdio"

        # Make MCP server fail
        mock_mcp.run.side_effect = Exception("Server failed to start")

        # Execute test and verify exception is raised
        with pytest.raises(Exception, match="Server failed to start"):
            main()

        # Verify error was logged with transport info
        mock_logger.exception.assert_called_once()
        error_call_args = mock_logger.exception.call_args[0][0]
        assert "Error running MCP server" in error_call_args

    @patch("mcp_server_for_oscal.main.logging.getLogger")
    @patch("mcp_server_for_oscal.main.mcp")
    @patch("mcp_server_for_oscal.main.config")
    @patch("mcp_server_for_oscal.main.logging.basicConfig")
    @patch("sys.argv", ["main.py", "--log-level", "DEBUG"])
    def test_main_logger_configuration(
        self, mock_logging_config, mock_config, mock_mcp, mock_get_logger
    ):
        """Test that all loggers are configured with the specified log level."""
        # Setup mocks
        mock_config.aws_profile = "default"
        mock_config.log_level = "DEBUG"
        mock_config.transport = "stdio"

        mock_strands_logger = Mock()
        mock_mcp_logger = Mock()
        mock_main_logger = Mock()

        def get_logger_side_effect(name):
            if name == "strands":
                return mock_strands_logger
            if name == "mcp":
                return mock_mcp_logger
            if name == "mcp_server_for_oscal.main":
                return mock_main_logger
            return Mock()

        mock_get_logger.side_effect = get_logger_side_effect

        # Execute test
        main()

        # Verify all loggers were configured
        mock_strands_logger.setLevel.assert_called_once_with("DEBUG")
        mock_mcp_logger.setLevel.assert_called_once_with("DEBUG")
        mock_main_logger.setLevel.assert_called_once_with("DEBUG")

    @patch("mcp_server_for_oscal.main.argparse.ArgumentParser")
    @patch("mcp_server_for_oscal.main.mcp")
    @patch("mcp_server_for_oscal.main.config")
    @patch("mcp_server_for_oscal.main.logging.basicConfig")
    def test_main_argument_parser_setup(
        self, mock_logging_config, mock_config, mock_mcp, mock_parser_class
    ):
        """Test that argument parser is set up correctly."""
        # Setup mocks
        mock_parser = Mock()
        mock_args = Mock()
        mock_args.aws_profile = "test-profile"
        mock_args.log_level = "INFO"
        mock_args.bedrock_model_id = None
        mock_args.knowledge_base_id = None
        mock_args.transport = "stdio"

        mock_parser.parse_args.return_value = mock_args
        mock_parser_class.return_value = mock_parser

        mock_config.aws_profile = "test-profile"
        mock_config.log_level = "INFO"
        mock_config.transport = "stdio"

        # Execute test
        main()

        # Verify parser was created with correct description
        mock_parser_class.assert_called_once_with(description="OSCAL MCP Server")

        # Verify all expected arguments were added
        add_argument_calls = mock_parser.add_argument.call_args_list
        argument_names = [call[0][0] for call in add_argument_calls]

        expected_arguments = [
            "--aws-profile",
            "--log-level",
            "--bedrock-model-id",
            "--knowledge-base-id",
            "--transport",
        ]

        for expected_arg in expected_arguments:
            assert expected_arg in argument_names, f"Argument {expected_arg} not found"

    @patch("sys.argv", ["main.py", "--help"])
    def test_main_help_argument(self):
        """Test that help argument works (will cause SystemExit)."""
        with pytest.raises(SystemExit):
            main()

    @patch("mcp_server_for_oscal.main.mcp")
    @patch("mcp_server_for_oscal.main.config")
    @patch("mcp_server_for_oscal.main.logging.basicConfig")
    @patch("sys.argv", ["main.py", "--log-level", "INVALID"])
    def test_main_with_invalid_log_level(
        self, mock_logging_config, mock_config, mock_mcp
    ):
        """Test main function with invalid log level (should still work)."""
        # Setup mocks
        mock_config.aws_profile = "default"
        mock_config.log_level = "INVALID"
        mock_config.transport = "stdio"

        # Execute test (should not raise exception)
        main()

        # Verify configuration was updated with invalid log level
        mock_config.update_from_args.assert_called_once_with(
            bedrock_model_id=None,
            knowledge_base_id=None,
            log_level="INVALID",
            transport="stdio",
        )

        # Verify logging was configured with invalid level
        mock_logging_config.assert_called_once_with(level="INVALID")

    @patch("mcp_server_for_oscal.main.mcp")
    @patch("mcp_server_for_oscal.main.config")
    @patch("mcp_server_for_oscal.main.logging.basicConfig")
    @patch("sys.argv", ["main.py", "--transport", "streamable-http"])
    def test_main_with_streamable_http_transport(
        self, mock_logging_config, mock_config, mock_mcp
    ):
        """Test main function with streamable-http transport."""
        # Setup mocks
        mock_config.aws_profile = "default"
        mock_config.log_level = "INFO"
        mock_config.transport = "streamable-http"

        # Execute test
        main()

        # Verify configuration update was called with streamable-http transport
        mock_config.update_from_args.assert_called_once_with(
            bedrock_model_id=None,
            knowledge_base_id=None,
            log_level="INFO",
            transport="streamable-http",
        )

        # Verify transport validation was called
        mock_config.validate_transport.assert_called_once()

        # Verify MCP server was started with streamable-http transport
        mock_mcp.run.assert_called_once_with(transport="streamable-http")

    @patch("mcp_server_for_oscal.main.mcp")
    @patch("mcp_server_for_oscal.main.config")
    @patch("mcp_server_for_oscal.main.logging.basicConfig")
    @patch("mcp_server_for_oscal.main.logger")
    @patch("sys.argv", ["main.py", "--transport", "invalid-transport"])
    def test_main_with_invalid_transport(
        self, mock_logger, mock_logging_config, mock_config, mock_mcp
    ):
        """Test main function with invalid transport type."""
        # Setup mocks
        mock_config.aws_profile = "default"
        mock_config.log_level = "INFO"
        mock_config.transport = "invalid-transport"

        # Make validate_transport raise ValueError
        mock_config.validate_transport.side_effect = ValueError(
            "Invalid transport type: invalid-transport. "
            "Valid options are: stdio, streamable-http"
        )

        # Execute test and verify SystemExit is raised
        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1

        # Verify error was logged
        mock_logger.error.assert_called_once()
        error_call_args = mock_logger.error.call_args[0]
        assert "Transport configuration error" in error_call_args[0]

    @patch("mcp_server_for_oscal.main.mcp")
    @patch("mcp_server_for_oscal.main.config")
    @patch("mcp_server_for_oscal.main.logging.basicConfig")
    @patch("mcp_server_for_oscal.main.logger")
    @patch("sys.argv", ["main.py"])
    def test_main_logs_transport_on_startup(
        self, mock_logger, mock_logging_config, mock_config, mock_mcp
    ):
        """Test that transport method is logged during startup."""
        # Setup mocks
        mock_config.aws_profile = "default"
        mock_config.log_level = "INFO"
        mock_config.transport = "stdio"

        # Execute test
        main()

        # Verify transport was logged during startup
        mock_logger.info.assert_called()
        info_calls = [call[0] for call in mock_logger.info.call_args_list]
        transport_logged = any("transport" in str(call).lower() for call in info_calls)
        assert transport_logged, "Transport method should be logged during startup"

    @patch("mcp_server_for_oscal.main.mcp")
    @patch("mcp_server_for_oscal.main.config")
    @patch("mcp_server_for_oscal.main.logging.basicConfig")
    @patch("sys.argv", ["main.py", "--transport", ""])
    def test_main_with_empty_transport(
        self, mock_logging_config, mock_config, mock_mcp
    ):
        """Test main function with empty transport string."""
        # Setup mocks
        mock_config.aws_profile = "default"
        mock_config.log_level = "INFO"
        mock_config.transport = ""

        # Make validate_transport raise ValueError for empty string
        mock_config.validate_transport.side_effect = ValueError(
            "Invalid transport type: . Valid options are: stdio, streamable-http"
        )

        # Execute test and verify SystemExit is raised
        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1

        # Verify configuration was updated with empty transport
        mock_config.update_from_args.assert_called_once_with(
            bedrock_model_id=None,
            knowledge_base_id=None,
            log_level="INFO",
            transport="",
        )

    @patch("mcp_server_for_oscal.main.mcp")
    @patch("mcp_server_for_oscal.main.config")
    @patch("mcp_server_for_oscal.main.logging.basicConfig")
    @patch("mcp_server_for_oscal.main.logger")
    @patch("sys.argv", ["main.py", "--transport", "STDIO"])
    def test_main_with_uppercase_transport(
        self, mock_logger, mock_logging_config, mock_config, mock_mcp
    ):
        """Test main function with uppercase transport (should fail validation)."""
        # Setup mocks
        mock_config.aws_profile = "default"
        mock_config.log_level = "INFO"
        mock_config.transport = "STDIO"

        # Make validate_transport raise ValueError for uppercase
        mock_config.validate_transport.side_effect = ValueError(
            "Invalid transport type: STDIO. Valid options are: stdio, streamable-http"
        )

        # Execute test and verify SystemExit is raised
        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1

        # Verify error was logged
        mock_logger.error.assert_called_once()
        error_call_args = mock_logger.error.call_args[0]
        assert "Transport configuration error" in error_call_args[0]

    @patch("mcp_server_for_oscal.main.mcp")
    @patch("mcp_server_for_oscal.main.config")
    @patch("mcp_server_for_oscal.main.logging.basicConfig")
    @patch("mcp_server_for_oscal.main.logger")
    @patch("sys.argv", ["main.py"])
    def test_main_logs_specific_transport_method(
        self, mock_logger, mock_logging_config, mock_config, mock_mcp
    ):
        """Test that the specific transport method is logged with correct format."""
        # Setup mocks
        mock_config.aws_profile = "default"
        mock_config.log_level = "INFO"
        mock_config.transport = "streamable-http"

        # Execute test
        main()

        # Verify specific transport was logged
        mock_logger.info.assert_called()
        info_calls = mock_logger.info.call_args_list

        # Look for the specific log message about transport
        transport_log_found = False
        for call in info_calls:
            if (
                len(call[0]) >= 2
                and "Starting MCP Server `%s` with transport:" in call[0][0]
            ):
                assert call[0][2] == "streamable-http"
                transport_log_found = True
                break

        assert transport_log_found, (
            "Specific transport method should be logged during startup"
        )
