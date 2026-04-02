"""
Integration tests for file integrity checking with server startup behavior.

This module tests the integration between file integrity checking and server startup,
ensuring that the server properly validates package integrity during initialization
and exits with appropriate status codes when integrity failures occur.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from tests.test_file_integrity_utils import (
    TestPackageManager,
    create_sample_oscal_files,
)


class TestFileIntegrityIntegration:
    """Integration test cases for file integrity checking with server startup."""

    def setup_method(self):
        """Set up test fixtures for each test method."""
        self.test_manager = TestPackageManager()
        self.test_manager.__enter__()

    def teardown_method(self):
        """Clean up test fixtures after each test method."""
        self.test_manager.__exit__(None, None, None)

    @patch("mcp_server_for_oscal.main.verify_package_integrity")
    @patch("mcp_server_for_oscal.main.mcp")
    @patch("mcp_server_for_oscal.main.config")
    @patch("mcp_server_for_oscal.main.logging.basicConfig")
    @patch("sys.argv", ["main.py"])
    def test_successful_server_startup_with_valid_packages(
        self, mock_logging_config, mock_config, mock_mcp, mock_verify_integrity
    ):
        """Test successful server startup when oscal_schemas passes integrity check.

        Requirements: 8.1, 8.2, 8.6
        """
        # Setup mocks
        mock_config.aws_profile = "default"
        mock_config.log_level = "INFO"
        mock_config.transport = "stdio"
        mock_verify_integrity.return_value = None  # Success (no exception)

        # Import and run main
        from mcp_server_for_oscal.main import main

        # Execute test
        main()

        # Verify integrity was checked only for oscal_schemas
        assert mock_verify_integrity.call_count == 1

        # Get the call arguments to verify correct directory was checked
        call_args = [call[0][0] for call in mock_verify_integrity.call_args_list]

        # Verify only oscal_schemas directory was checked
        schema_dir_checked = any("oscal_schemas" in str(arg) for arg in call_args)
        assert schema_dir_checked, "oscal_schemas directory should be verified"

        # Verify transport validation was called
        mock_config.validate_transport.assert_called_once()

        # Verify MCP server was started (integrity checks passed)
        mock_mcp.run.assert_called_once_with(transport="stdio")

    @patch("mcp_server_for_oscal.main.verify_package_integrity")
    @patch("mcp_server_for_oscal.main.mcp")
    @patch("mcp_server_for_oscal.main.config")
    @patch("mcp_server_for_oscal.main.logging.basicConfig")
    @patch("mcp_server_for_oscal.main.logger")
    @patch("sys.argv", ["main.py"])
    def test_server_exit_with_status_code_2_on_integrity_failure(
        self,
        mock_logger,
        mock_logging_config,
        mock_config,
        mock_mcp,
        mock_verify_integrity,
    ):
        """Test server exits with status code 2 when integrity verification fails.

        Requirements: 6.3, 6.5
        """
        # Setup mocks
        mock_config.aws_profile = "default"
        mock_config.log_level = "INFO"
        mock_config.transport = "stdio"

        # Make integrity verification fail
        mock_verify_integrity.side_effect = RuntimeError(
            "File schema1.json has been modified"
        )

        # Import main function
        from mcp_server_for_oscal.main import main

        # Execute test and verify SystemExit with code 2 is raised
        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 2

        # Verify integrity verification was attempted
        mock_verify_integrity.assert_called()

        # Verify error was logged before exit
        mock_logger.exception.assert_called_once()
        error_call_args = mock_logger.exception.call_args[0][0]
        assert "Bundled context files may have been tampered with" in error_call_args

        # Verify MCP server was NOT started (integrity check failed)
        mock_mcp.run.assert_not_called()

    @patch("mcp_server_for_oscal.main.verify_package_integrity")
    @patch("mcp_server_for_oscal.main.mcp")
    @patch("mcp_server_for_oscal.main.config")
    @patch("mcp_server_for_oscal.main.logging.basicConfig")
    @patch("mcp_server_for_oscal.main.logger")
    @patch("sys.argv", ["main.py"])
    def test_logging_of_integrity_failures_before_server_exit(
        self,
        mock_logger,
        mock_logging_config,
        mock_config,
        mock_mcp,
        mock_verify_integrity,
    ):
        """Test that integrity failures are logged with details before server exit.

        Requirements: 6.5
        """
        # Setup mocks
        mock_config.aws_profile = "default"
        mock_config.log_level = "INFO"
        mock_config.transport = "stdio"

        # Make integrity verification fail with specific error
        integrity_error = RuntimeError("File catalog.json missing from package.")
        mock_verify_integrity.side_effect = integrity_error

        # Import main function
        from mcp_server_for_oscal.main import main

        # Execute test and verify SystemExit with code 2 is raised
        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 2

        # Verify detailed error was logged before exit
        mock_logger.exception.assert_called_once_with(
            "Bundled context files may have been tampered with; exiting."
        )

        # Verify MCP server was NOT started
        mock_mcp.run.assert_not_called()

    @patch("mcp_server_for_oscal.main.verify_package_integrity")
    @patch("mcp_server_for_oscal.main.mcp")
    @patch("mcp_server_for_oscal.main.config")
    @patch("mcp_server_for_oscal.main.logging.basicConfig")
    @patch("sys.argv", ["main.py"])
    def test_verification_of_oscal_schemas_directory_only(
        self, mock_logging_config, mock_config, mock_mcp, mock_verify_integrity
    ):
        """Test that only the oscal_schemas directory is verified at startup.

        Requirements: 8.1, 8.2, 8.6
        """
        # Setup mocks
        mock_config.aws_profile = "default"
        mock_config.log_level = "INFO"
        mock_config.transport = "stdio"
        mock_verify_integrity.return_value = None  # Success

        # Import main function
        from mcp_server_for_oscal.main import main

        # Execute test
        main()

        # Verify integrity was checked exactly once (only oscal_schemas)
        assert mock_verify_integrity.call_count == 1

        # Get the call arguments to verify correct directory was checked
        call_args = [call[0][0] for call in mock_verify_integrity.call_args_list]

        # Convert Path objects to strings for easier checking
        call_paths = [str(arg) for arg in call_args]

        # Verify only oscal_schemas was checked
        schema_dir_checked = any("oscal_schemas" in path for path in call_paths)
        assert schema_dir_checked, (
            f"oscal_schemas directory should be verified. Actual calls: {call_paths}"
        )

    @patch("mcp_server_for_oscal.main.verify_package_integrity")
    @patch("mcp_server_for_oscal.main.mcp")
    @patch("mcp_server_for_oscal.main.config")
    @patch("mcp_server_for_oscal.main.logging.basicConfig")
    @patch("sys.argv", ["main.py"])
    def test_oscal_schemas_failure_causes_exit_code_2(
        self, mock_logging_config, mock_config, mock_mcp, mock_verify_integrity
    ):
        """Test that failure in oscal_schemas integrity check causes exit code 2.

        Requirements: 8.1, 8.3
        """
        # Setup mocks
        mock_config.aws_profile = "default"
        mock_config.log_level = "INFO"
        mock_config.transport = "stdio"

        # Make integrity check fail
        mock_verify_integrity.side_effect = RuntimeError(
            "oscal_schemas integrity failure"
        )

        # Import main function
        from mcp_server_for_oscal.main import main

        # Execute test and verify SystemExit with code 2 is raised
        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 2

        # Verify integrity was checked only once (for oscal_schemas)
        assert mock_verify_integrity.call_count == 1

        # Verify MCP server was NOT started
        mock_mcp.run.assert_not_called()

    @patch("mcp_server_for_oscal.main.verify_package_integrity")
    @patch("mcp_server_for_oscal.main.mcp")
    @patch("mcp_server_for_oscal.main.config")
    @patch("mcp_server_for_oscal.main.logging.basicConfig")
    @patch("mcp_server_for_oscal.main.logger")
    @patch("sys.argv", ["main.py"])
    def test_integrity_check_path_resolution_for_oscal_schemas(
        self,
        mock_logger,
        mock_logging_config,
        mock_config,
        mock_mcp,
        mock_verify_integrity,
    ):
        """Test that integrity check uses proper path resolution for oscal_schemas.

        Requirements: 8.1, 8.6
        """
        # Setup mocks
        mock_config.aws_profile = "default"
        mock_config.log_level = "INFO"
        mock_config.transport = "stdio"
        mock_verify_integrity.return_value = None  # Success

        # Import main function
        from mcp_server_for_oscal.main import main

        # Execute test
        main()

        # Verify integrity was checked once (only oscal_schemas)
        assert mock_verify_integrity.call_count == 1

        # Get the call argument to verify path resolution
        call_arg = mock_verify_integrity.call_args_list[0][0][0]

        # Verify path is resolved relative to main.py location
        assert isinstance(call_arg, Path), (
            f"Expected Path object, got {type(call_arg)}"
        )
        path_str = str(call_arg)
        assert call_arg.is_absolute(), f"Path should be absolute: {path_str}"

        # Verify only oscal_schemas path
        assert "oscal_schemas" in path_str, (
            f"oscal_schemas directory should be verified. Call: {path_str}"
        )

    @patch("mcp_server_for_oscal.main.verify_package_integrity")
    @patch("mcp_server_for_oscal.main.mcp")
    @patch("mcp_server_for_oscal.main.config")
    @patch("mcp_server_for_oscal.main.logging.basicConfig")
    @patch("mcp_server_for_oscal.main.logger")
    @patch("sys.argv", ["main.py"])
    def test_server_continues_after_successful_integrity_checks(
        self,
        mock_logger,
        mock_logging_config,
        mock_config,
        mock_mcp,
        mock_verify_integrity,
    ):
        """Test that server continues normal initialization after successful integrity checks.

        Requirements: 8.1, 8.6
        """
        # Setup mocks
        mock_config.aws_profile = "default"
        mock_config.log_level = "INFO"
        mock_config.transport = "stdio"
        mock_verify_integrity.return_value = None  # Success

        # Import main function
        from mcp_server_for_oscal.main import main

        # Execute test
        main()

        # Verify integrity check completed successfully (only oscal_schemas)
        assert mock_verify_integrity.call_count == 1

        # Verify transport validation was called (part of normal initialization)
        mock_config.validate_transport.assert_called_once()

        # Verify server startup logging occurred
        mock_logger.info.assert_called()
        info_calls = [call[0] for call in mock_logger.info.call_args_list]
        startup_logged = any("Starting MCP Server" in str(call) for call in info_calls)
        assert startup_logged, "Server startup should be logged"

        # Verify MCP server was started (normal initialization continued)
        mock_mcp.run.assert_called_once_with(transport="stdio")

    def test_integration_with_real_verify_function_valid_package(self):
        """Test integration with real verify_package_integrity function using valid package.

        This test uses the actual verify_package_integrity function with a real test package
        to ensure integration works correctly.

        Requirements: 6.1, 6.2, 6.4
        """
        # Create a valid test package
        test_files = create_sample_oscal_files()
        package_dir = self.test_manager.create_test_package(
            "valid_integration_test", test_files
        )

        # Import the real function
        from mcp_server_for_oscal.tools.utils import verify_package_integrity

        # Verify that the function works with our test package
        try:
            verify_package_integrity(package_dir)
        except Exception as e:
            pytest.fail(
                f"verify_package_integrity should pass for valid package, but got: {e}"
            )

    def test_integration_with_real_verify_function_tampered_package(self):
        """Test integration with real verify_package_integrity function using tampered package.

        This test uses the actual verify_package_integrity function with a tampered test package
        to ensure integration detects integrity failures correctly.

        Requirements: 6.3, 6.5
        """
        # Create a test package and tamper with it
        test_files = create_sample_oscal_files()
        package_dir = self.test_manager.create_test_package(
            "tampered_integration_test", test_files
        )

        # Tamper with one of the files
        self.test_manager.tamper_file(package_dir, "catalog.json", "append")

        # Import the real function
        from mcp_server_for_oscal.tools.utils import verify_package_integrity

        # Verify that the function detects the tampering
        with pytest.raises(RuntimeError) as exc_info:
            verify_package_integrity(package_dir)

        error_message = str(exc_info.value)
        assert "catalog.json has been modified" in error_message
        assert "expected hash" in error_message
