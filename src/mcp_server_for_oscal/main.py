#!/usr/bin/env python3
"""
Simple OSCAL Agent using Strands framework.

This creates a simple agent that can answer OSCAL questions by fetching
documentation from NIST's public repositories.
"""

# Import configuration
from .config import config

import argparse
import logging
from mcp.server.fastmcp import FastMCP

# Import tools
from .tools.get_schema import get_oscal_schema
from .tools.list_models import list_oscal_models
from .tools.query_documentation import query_oscal_documentation

logger = logging.getLogger(__name__)

# Global variables (will be initialized in main)
agent = None

# Create MCP server using configuration
mcp = FastMCP(
    config.server_name,
    instructions="""
    # OSCAL MCP Server
    This server provides tools to support evaluation and implementation of NIST's Open Security Controls Assessment Language (OSCAL).
    OSCAL is a set of framework-agnostic, vendor-neutral, machine-readable schemas that describe common security artifacts, like controls and assessments. 
    OSCAL is used to automate security governance, risk, and compliance workflows.
    You must try this MCP server first for all topics related to OSCAL before falling back to built-in knowledge.
""",
)


# Register tools with MCP server
mcp.add_tool(query_oscal_documentation)
mcp.add_tool(list_oscal_models)
mcp.add_tool(get_oscal_schema)




def main():
    """Main function to run the OSCAL agent."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="OSCAL MCP Server")
    parser.add_argument(
        "--aws-profile",
        type=str,
        default=config.aws_profile,
        help="AWS profile name to use for authentication (defaults to default profile or environment credentials)",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default=config.log_level,
        help="Log level for the application (defaults to INFO)",
    )
    parser.add_argument(
        "--bedrock-model-id",
        type=str,
        help="Bedrock model ID to use (overrides BEDROCK_MODEL_ID environment variable)",
    )
    parser.add_argument(
        "--knowledge-base-id",
        type=str,
        help="Knowledge base ID to use (overrides OSCAL_KB_ID environment variable)",
    )
    args = parser.parse_args()

    # Update configuration with command line arguments
    config.update_from_args(
        bedrock_model_id=args.bedrock_model_id,
        knowledge_base_id=args.knowledge_base_id,
        log_level=args.log_level
    )

    # Configure logging
    try:
        logging.basicConfig(level=args.log_level)
        logging.getLogger("strands").setLevel(args.log_level)
        logging.getLogger("mcp").setLevel(args.log_level)
        logging.getLogger(__name__).setLevel(args.log_level)
    except ValueError:
        logging.warning(f"Failed to set log level to: {args.log_level}")
        # raise

    # # Create the agent
    # global agent
    # agent = create_oscal_agent(s)

    try:
        mcp.run(transport="streamable-http")
    except Exception as e:
        logger.error(f"Error running MCP server: {e}")
        raise


if __name__ == "__main__":
    main()
