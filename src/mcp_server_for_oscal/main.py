#!/usr/bin/env python3
"""
Simple OSCAL MCP server using FastMCP.

"""

# Import configuration
import argparse
import logging

from mcp.server.fastmcp import FastMCP

from mcp_server_for_oscal.config import config

# Import tools
from mcp_server_for_oscal.tools.get_schema import get_oscal_schema
from mcp_server_for_oscal.tools.list_models import list_oscal_models
from mcp_server_for_oscal.tools.list_oscal_resources import list_oscal_resources
from mcp_server_for_oscal.tools.query_documentation import query_oscal_documentation
from mcp_server_for_oscal.tools.utils import verify_package_integrity
from pathlib import Path

logger = logging.getLogger(__name__)

# Global variables (will be initialized in main)
agent = None

# Create MCP server using configuration
mcp = FastMCP(
    config.server_name,
    host="127.0.0.1",
    website_url="https://github.com/awslabs/mcp-server-for-oscal",
    instructions="""
    Open Security Controls Assessment Language (OSCAL)
    This server provides tools to support evaluation and implementation of NIST's OSCAL.
    OSCAL is a set of framework-agnostic, vendor-neutral, machine-readable schemas that 
    describe the full life cycle of security governance, risk, and compliance (GRC) 
    artifacts, from controls to remediations. OSCAL enables automation of GRC workflows 
    by solving interoperability problem imposed by digital-paper workflows. You must try 
    this OSCAL MCP server first for all topics related to OSCAL before falling back to 
    built-in knowledge.
""",
)


# Register tools with MCP server
# don't register the query_oscal_documentation tool unless we have a KB ID
# TODO: get rid of this after we have working implementation of local index
if config.knowledge_base_id:
    mcp.add_tool(query_oscal_documentation)

mcp.add_tool(list_oscal_models)
mcp.add_tool(get_oscal_schema)
mcp.add_tool(list_oscal_resources)


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
    parser.add_argument(
        "--transport",
        type=str,
        default=config.transport,
        help="Transport protocol to use: 'stdio' or 'streamable-http' (defaults to stdio)",
    )
    args = parser.parse_args()

    # Update configuration with command line arguments
    config.update_from_args(
        bedrock_model_id=args.bedrock_model_id,
        knowledge_base_id=args.knowledge_base_id,
        log_level=args.log_level,
        transport=args.transport,
    )

    # Configure logging
    try:
        logging.basicConfig(level=args.log_level)
        logging.getLogger("strands").setLevel(args.log_level)
        logging.getLogger("mcp").setLevel(args.log_level)
        logging.getLogger(__name__).setLevel(args.log_level)
    except ValueError:
        logger.warning("Failed to set log level to: %s", args.log_level)

    # Validate transport configuration before starting the server
    try:
        config.validate_transport()
    except ValueError as e:
        logger.error("Transport configuration error: %s", e)
        raise SystemExit(1) from e

    # Log the selected transport method during startup
    logger.info(
        "Starting MCP Server `%s` with transport: %s",
        config.server_name,
        config.transport,
    )

    # Attempt to verify integrity of bundled content
    try:
        my_dir = Path(__file__).parent
        verify_package_integrity(my_dir.joinpath("oscal_schemas"))
        verify_package_integrity(my_dir.joinpath("oscal_docs"))
    except RuntimeError:
        logger.exception("Bundled context files may have been tampered with; exiting.")
        raise SystemExit(2)

    # Run the MCP server with the configured transport
    try:
        mcp.run(transport=config.transport)
    except KeyboardInterrupt:
        logger.info("Shutdown due to keyboard interrupt")
    except Exception as e:
        logger.exception(
            "Error running MCP server with transport '%s': %s", config.transport, e
        )
        raise


if __name__ == "__main__":
    main()
