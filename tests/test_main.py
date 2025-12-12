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

    @patch('mcp_server_for_oscal.main.mcp')
    @patch('mcp_server_for_oscal.main.config')
    @patch('mcp_server_for_oscal.main.logging.basicConfig')
    @patch('sys.argv', ['main.py'])
    def test_main_default_arguments(self, mock_logging_config, mock_config, mock_mcp):
        """Test main function with default arguments."""
        # Setup mocks
        mock_config.aws_profile = "default"
        mock_config.log_level = "INFO"

        # Execute test
        main()

        # Verify configuration update was called with None values (defaults)
        mock_config.update_from_args.assert_called_once_with(
            bedrock_model_id=None,
            knowledge_base_id=None,
            log_level="INFO"
        )

        # Verify logging configuration
        mock_logging_config.assert_called_once_with(level="INFO")

        # Verify MCP server was started
        mock_mcp.run.assert_called_once_with(transport="streamable-http")

    @patch('mcp_server_for_oscal.main.mcp')
    @patch('mcp_server_for_oscal.main.config')
    @patch('mcp_server_for_oscal.main.logging.basicConfig')
    @patch('sys.argv', [
        'main.py',
        '--aws-profile', 'test-profile',
        '--log-level', 'DEBUG',
        '--bedrock-model-id', 'test-model',
        '--knowledge-base-id', 'test-kb'
    ])
    def test_main_with_arguments(self, mock_logging_config, mock_config, mock_mcp):
        """Test main function with command line arguments."""
        # Setup mocks
        mock_config.aws_profile = "test-profile"
        mock_config.log_level = "DEBUG"

        # Execute test
        main()

        # Verify configuration update was called with provided values
        mock_config.update_from_args.assert_called_once_with(
            bedrock_model_id="test-model",
            knowledge_base_id="test-kb",
            log_level="DEBUG"
        )

        # Verify logging configuration
        mock_logging_config.assert_called_once_with(level="DEBUG")

        # Verify MCP server was started
        mock_mcp.run.assert_called_once_with(transport="streamable-http")


    @patch('mcp_server_for_oscal.main.mcp')
    @patch('mcp_server_for_oscal.main.config')
    @patch('mcp_server_for_oscal.main.logging.basicConfig')
    @patch('mcp_server_for_oscal.main.logger')
    @patch('sys.argv', ['main.py'])
    def test_main_mcp_server_error(self, mock_logger, mock_logging_config, mock_config, mock_mcp):
        """Test main function when MCP server fails to start."""
        # Setup mocks
        mock_config.aws_profile = "default"
        mock_config.log_level = "INFO"

        # Make MCP server fail
        mock_mcp.run.side_effect = Exception("Server failed to start")

        # Execute test and verify exception is raised
        with pytest.raises(Exception, match="Server failed to start"):
            main()

        # Verify error was logged
        mock_logger.error.assert_called_once()
        error_call_args = mock_logger.error.call_args[0][0]
        assert "Error running MCP server" in error_call_args

    @patch('mcp_server_for_oscal.main.logging.getLogger')
    @patch('mcp_server_for_oscal.main.mcp')
    @patch('mcp_server_for_oscal.main.config')
    @patch('mcp_server_for_oscal.main.logging.basicConfig')
    @patch('sys.argv', ['main.py', '--log-level', 'DEBUG'])
    def test_main_logger_configuration(self, mock_logging_config, mock_config, mock_mcp, mock_get_logger):
        """Test that all loggers are configured with the specified log level."""
        # Setup mocks
        mock_config.aws_profile = "default"
        mock_config.log_level = "DEBUG"

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

    @patch('mcp_server_for_oscal.main.argparse.ArgumentParser')
    @patch('mcp_server_for_oscal.main.mcp')
    @patch('mcp_server_for_oscal.main.config')
    @patch('mcp_server_for_oscal.main.logging.basicConfig')
    def test_main_argument_parser_setup(self, mock_logging_config, mock_config, mock_mcp, mock_parser_class):
        """Test that argument parser is set up correctly."""
        # Setup mocks
        mock_parser = Mock()
        mock_args = Mock()
        mock_args.aws_profile = "test-profile"
        mock_args.log_level = "INFO"
        mock_args.bedrock_model_id = None
        mock_args.knowledge_base_id = None

        mock_parser.parse_args.return_value = mock_args
        mock_parser_class.return_value = mock_parser

        mock_config.aws_profile = "test-profile"
        mock_config.log_level = "INFO"

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
            "--knowledge-base-id"
        ]

        for expected_arg in expected_arguments:
            assert expected_arg in argument_names, f"Argument {expected_arg} not found"

    @patch('sys.argv', ['main.py', '--help'])
    def test_main_help_argument(self):
        """Test that help argument works (will cause SystemExit)."""
        with pytest.raises(SystemExit):
            main()

    @patch('mcp_server_for_oscal.main.mcp')
    @patch('mcp_server_for_oscal.main.config')
    @patch('mcp_server_for_oscal.main.logging.basicConfig')
    @patch('sys.argv', ['main.py', '--log-level', 'INVALID'])
    def test_main_with_invalid_log_level(self, mock_logging_config, mock_config, mock_mcp):
        """Test main function with invalid log level (should still work)."""
        # Setup mocks
        mock_config.aws_profile = "default"
        mock_config.log_level = "INVALID"

        # Execute test (should not raise exception)
        main()

        # Verify configuration was updated with invalid log level
        mock_config.update_from_args.assert_called_once_with(
            bedrock_model_id=None,
            knowledge_base_id=None,
            log_level="INVALID"
        )

        # Verify logging was configured with invalid level
        mock_logging_config.assert_called_once_with(level="INVALID")
