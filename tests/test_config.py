"""
Tests for the configuration module.
"""

import os
from unittest.mock import patch

from mcp_server_for_oscal.config import Config


class TestConfig:
    """Test cases for the Config class."""

    def test_config_initialization_with_defaults(self):
        """Test that config initializes with default values when env vars are not set."""
        with patch.dict(os.environ, {"PYTHON_DOTENV_DISABLED": "1"}, clear=True):
            config = Config()

            assert (
                config.bedrock_model_id == "us.anthropic.claude-sonnet-4-20250514-v1:0"
            )
            assert config.knowledge_base_id == ""
            assert config.aws_profile is None
            assert config.aws_region is None
            assert config.log_level == "INFO"
            assert config.server_name == "OSCAL"
            assert config.transport == "stdio"

    def test_config_initialization_with_env_vars(self):
        """Test that config loads values from environment variables."""
        env_vars = {
            "BEDROCK_MODEL_ID": "custom-model-id",
            "OSCAL_KB_ID": "test-kb-id",
            "AWS_PROFILE": "test-profile",
            "AWS_REGION": "us-west-2",
            "LOG_LEVEL": "DEBUG",
            "OSCAL_MCP_SERVER_NAME": "Custom OSCAL Server",
            "PYTHON_DOTENV_DISABLED": "1",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            config = Config()

            assert config.bedrock_model_id == "custom-model-id"
            assert config.knowledge_base_id == "test-kb-id"
            assert config.aws_profile == "test-profile"
            assert config.aws_region == "us-west-2"
            assert config.log_level == "DEBUG"
            assert config.server_name == "Custom OSCAL Server"
            assert config.transport == "stdio"  # Default since not in env_vars

    def test_update_from_args_all_params(self):
        """Test updating configuration from command line arguments."""
        config = Config()

        config.update_from_args(
            bedrock_model_id="new-model-id",
            knowledge_base_id="new-kb-id",
            log_level="WARNING",
        )

        assert config.bedrock_model_id == "new-model-id"
        assert config.knowledge_base_id == "new-kb-id"
        assert config.log_level == "WARNING"

    def test_update_from_args_partial_params(self):
        """Test updating configuration with only some parameters."""
        config = Config()
        original_model_id = config.bedrock_model_id
        original_kb_id = config.knowledge_base_id

        config.update_from_args(log_level="ERROR")

        assert config.bedrock_model_id == original_model_id
        assert config.knowledge_base_id == original_kb_id
        assert config.log_level == "ERROR"

    def test_update_from_args_none_values(self):
        """Test that None values don't override existing config."""
        config = Config()
        original_model_id = config.bedrock_model_id
        original_kb_id = config.knowledge_base_id
        original_log_level = config.log_level

        config.update_from_args(
            bedrock_model_id=None, knowledge_base_id=None, log_level=None
        )

        assert config.bedrock_model_id == original_model_id
        assert config.knowledge_base_id == original_kb_id
        assert config.log_level == original_log_level

    @patch("mcp_server_for_oscal.config.load_dotenv")
    def test_dotenv_loading(self, mock_load_dotenv):
        """Test that dotenv is loaded during initialization."""
        Config()
        mock_load_dotenv.assert_called_once()

    def test_transport_default_value(self):
        """Test that transport defaults to stdio."""
        with patch.dict(os.environ, {"PYTHON_DOTENV_DISABLED": "1"}, clear=True):
            config = Config()
            assert config.transport == "stdio"

    def test_transport_from_env_var(self):
        """Test that transport can be set via environment variable."""
        env_vars = {
            "OSCAL_MCP_TRANSPORT": "streamable-http",
            "PYTHON_DOTENV_DISABLED": "1",
        }
        with patch.dict(os.environ, env_vars, clear=True):
            config = Config()
            assert config.transport == "streamable-http"

    def test_update_from_args_with_transport(self):
        """Test updating transport from command line arguments."""
        config = Config()
        config.update_from_args(transport="streamable-http")
        assert config.transport == "streamable-http"

    def test_validate_transport_stdio(self):
        """Test that stdio transport passes validation."""
        config = Config()
        config.transport = "stdio"
        config.validate_transport()  # Should not raise

    def test_validate_transport_streamable_http(self):
        """Test that streamable-http transport passes validation."""
        config = Config()
        config.transport = "streamable-http"
        config.validate_transport()  # Should not raise

    def test_validate_transport_invalid(self):
        """Test that invalid transport raises ValueError."""
        config = Config()
        config.transport = "invalid-transport"

        try:
            config.validate_transport()
            assert False, "Expected ValueError to be raised"
        except ValueError as e:
            assert "Invalid transport type: invalid-transport" in str(e)
            assert "Valid options are: stdio, streamable-http" in str(e)

    def test_validate_transport_case_sensitive(self):
        """Test that transport validation is case sensitive."""
        config = Config()
        config.transport = "STDIO"

        try:
            config.validate_transport()
            assert False, "Expected ValueError to be raised for uppercase transport"
        except ValueError as e:
            assert "Invalid transport type: STDIO" in str(e)
            assert "Valid options are: stdio, streamable-http" in str(e)

    def test_validate_transport_empty_string(self):
        """Test that empty string transport raises ValueError."""
        config = Config()
        config.transport = ""

        try:
            config.validate_transport()
            assert False, "Expected ValueError to be raised for empty transport"
        except ValueError as e:
            assert "Invalid transport type: " in str(e)
            assert "Valid options are: stdio, streamable-http" in str(e)

    def test_validate_transport_none(self):
        """Test that None transport raises error."""
        config = Config()
        config.transport = None

        try:
            config.validate_transport()
            assert False, "Expected error to be raised for None transport"
        except (ValueError, TypeError):
            # Either ValueError or TypeError is acceptable for None
            pass

    def test_update_from_args_empty_string_transport(self):
        """Test updating transport with empty string (should not update)."""
        config = Config()
        original_transport = config.transport

        config.update_from_args(transport="")
        assert (
            config.transport == original_transport
        )  # Should NOT update with empty string

        # Original transport should still be valid
        config.validate_transport()  # Should not raise


# ---------------------------------------------------------------------------
# Task 2.3: Unit tests for agent config defaults
# ---------------------------------------------------------------------------


class TestAgentConfigDefaults:
    """Unit tests for agent-specific config attributes — task 2.3."""

    def test_agent_max_tokens_default(self):
        """agent_max_tokens defaults to 4096."""
        with patch.dict(os.environ, {"PYTHON_DOTENV_DISABLED": "1"}, clear=True):
            cfg = Config()
            assert cfg.agent_max_tokens == 4096

    def test_agent_max_retry_attempts_default(self):
        """agent_max_retry_attempts defaults to 4."""
        with patch.dict(os.environ, {"PYTHON_DOTENV_DISABLED": "1"}, clear=True):
            cfg = Config()
            assert cfg.agent_max_retry_attempts == 4

    def test_agent_retry_initial_delay_default(self):
        """agent_retry_initial_delay defaults to 2."""
        with patch.dict(os.environ, {"PYTHON_DOTENV_DISABLED": "1"}, clear=True):
            cfg = Config()
            assert cfg.agent_retry_initial_delay == 2

    def test_agent_retry_max_delay_default(self):
        """agent_retry_max_delay defaults to 60."""
        with patch.dict(os.environ, {"PYTHON_DOTENV_DISABLED": "1"}, clear=True):
            cfg = Config()
            assert cfg.agent_retry_max_delay == 60


# ---------------------------------------------------------------------------
# Task 2.2: Property test for agent config env var parsing
# ---------------------------------------------------------------------------

from hypothesis import given, settings
from hypothesis import strategies as st


class TestProperty3AgentConfigEnvVarParsing:
    """
    Property 3: Agent config environment variable parsing

    For any valid positive integer string set as the value of an agent
    configuration environment variable, the corresponding Config attribute
    SHALL equal that integer value after construction.

    **Validates: Requirements 4.3, 5.3**
    """

    @settings(max_examples=100)
    @given(
        max_tokens=st.integers(min_value=1, max_value=10000),
        max_retry=st.integers(min_value=1, max_value=10000),
        initial_delay=st.integers(min_value=1, max_value=10000),
        max_delay=st.integers(min_value=1, max_value=10000),
    )
    def test_agent_env_vars_parsed_correctly(
        self, max_tokens, max_retry, initial_delay, max_delay
    ):
        """
        Feature: oscal-agent-production, Property 3: Agent config env var parsing

        Setting agent env vars to random positive integers and constructing
        Config must yield matching attribute values.
        """
        env = {
            "OSCAL_AGENT_MAX_TOKENS": str(max_tokens),
            "OSCAL_AGENT_MAX_RETRY_ATTEMPTS": str(max_retry),
            "OSCAL_AGENT_RETRY_INITIAL_DELAY": str(initial_delay),
            "OSCAL_AGENT_RETRY_MAX_DELAY": str(max_delay),
            "PYTHON_DOTENV_DISABLED": "1",
        }
        with patch.dict(os.environ, env, clear=True):
            cfg = Config()
            assert cfg.agent_max_tokens == max_tokens
            assert cfg.agent_max_retry_attempts == max_retry
            assert cfg.agent_retry_initial_delay == initial_delay
            assert cfg.agent_retry_max_delay == max_delay
