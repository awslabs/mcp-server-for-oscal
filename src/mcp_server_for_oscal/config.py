"""
Configuration module for OSCAL MCP Server.

This module handles loading configuration from environment variables with sensible defaults.
"""

import os

from dotenv import load_dotenv


class Config:
    """Configuration class that loads settings from environment variables."""

    def __init__(self) -> None:
        load_dotenv()
        """Initialize configuration from environment variables."""

        # Bedrock configuration (can be overridden by command line args)
        self.bedrock_model_id: str = os.getenv(
            "BEDROCK_MODEL_ID",
            "us.anthropic.claude-sonnet-4-20250514-v1:0"
        )

        # Knowledge base configuration (can be overridden by command line args)
        self.knowledge_base_id: str = os.getenv("OSCAL_KB_ID", "")

        # AWS configuration
        self.aws_profile: str | None = os.getenv("AWS_PROFILE")
        self.aws_region: str | None = os.getenv("AWS_REGION")

        # Logging configuration
        self.log_level: str = os.getenv("LOG_LEVEL", "INFO")

        # Server configuration
        self.server_name: str = os.getenv("OSCAL_MCP_SERVER_NAME", "OSCAL MCP Server")

    def update_from_args(self, bedrock_model_id: str | None = None, knowledge_base_id: str | None = None, log_level: str | None = None) -> None:
        """Update configuration with command line arguments."""
        if bedrock_model_id:
            self.bedrock_model_id = bedrock_model_id
        if knowledge_base_id:
            self.knowledge_base_id = knowledge_base_id
        if log_level:
            self.log_level = log_level


# Global configuration instance
config = Config()
