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
        with patch.dict(os.environ, {"PYTHON_DOTENV_DISABLED":"1"}, clear=True):
            config = Config()

            assert config.bedrock_model_id == "us.anthropic.claude-sonnet-4-20250514-v1:0"
            assert config.knowledge_base_id == ""
            assert config.aws_profile is None
            assert config.aws_region is None
            assert config.log_level == "INFO"
            assert config.server_name == "OSCAL MCP Server"

    def test_config_initialization_with_env_vars(self):
        """Test that config loads values from environment variables."""
        env_vars = {
            "BEDROCK_MODEL_ID": "custom-model-id",
            "OSCAL_KB_ID": "test-kb-id",
            "AWS_PROFILE": "test-profile",
            "AWS_REGION": "us-west-2",
            "LOG_LEVEL": "DEBUG",
            "OSCAL_MCP_SERVER_NAME": "Custom OSCAL Server",
            "PYTHON_DOTENV_DISABLED":"1"
        }

        with patch.dict(os.environ, env_vars, clear=True):
            config = Config()

            assert config.bedrock_model_id == "custom-model-id"
            assert config.knowledge_base_id == "test-kb-id"
            assert config.aws_profile == "test-profile"
            assert config.aws_region == "us-west-2"
            assert config.log_level == "DEBUG"
            assert config.server_name == "Custom OSCAL Server"

    def test_update_from_args_all_params(self):
        """Test updating configuration from command line arguments."""
        config = Config()

        config.update_from_args(
            bedrock_model_id="new-model-id",
            knowledge_base_id="new-kb-id",
            log_level="WARNING"
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
            bedrock_model_id=None,
            knowledge_base_id=None,
            log_level=None
        )

        assert config.bedrock_model_id == original_model_id
        assert config.knowledge_base_id == original_kb_id
        assert config.log_level == original_log_level


    @patch('mcp_server_for_oscal.config.load_dotenv')
    def test_dotenv_loading(self, mock_load_dotenv):
        """Test that dotenv is loaded during initialization."""
        Config()
        mock_load_dotenv.assert_called_once()
