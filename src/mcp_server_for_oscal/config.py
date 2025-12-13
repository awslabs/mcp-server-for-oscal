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
            "BEDROCK_MODEL_ID", "us.anthropic.claude-sonnet-4-20250514-v1:0"
        )

        # Knowledge base configuration (can be overridden by command line args)
        self.knowledge_base_id: str = os.getenv("OSCAL_KB_ID", "")

        # AWS configuration
        self.aws_profile: str | None = os.getenv("AWS_PROFILE")
        self.aws_region: str | None = os.getenv("AWS_REGION")

        # Logging configuration
        self.log_level: str = os.getenv("LOG_LEVEL", "INFO")

        # Server configuration
        self.server_name: str = os.getenv("OSCAL_MCP_SERVER_NAME", "OSCAL")

        # Transport configuration
        self.transport: str = os.getenv("OSCAL_MCP_TRANSPORT", "stdio")

    def update_from_args(
        self,
        bedrock_model_id: str | None = None,
        knowledge_base_id: str | None = None,
        log_level: str | None = None,
        transport: str | None = None,
    ) -> None:
        """Update configuration with command line arguments."""
        if bedrock_model_id:
            self.bedrock_model_id = bedrock_model_id
        if knowledge_base_id:
            self.knowledge_base_id = knowledge_base_id
        if log_level:
            self.log_level = log_level
        if transport:
            self.transport = transport

    def validate_transport(self) -> None:
        """Validate that the configured transport is supported.

        Raises:
            ValueError: If transport is not one of the valid options.
        """
        valid_transports = ["stdio", "streamable-http"]
        if self.transport not in valid_transports:
            raise ValueError(
                f"Invalid transport type: {self.transport}. "
                f"Valid options are: {', '.join(valid_transports)}"
            )


# Global configuration instance
config = Config()
