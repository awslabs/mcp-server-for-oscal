#!/usr/bin/env python3
"""
Simple OSCAL MCP server using FastMCP.

"""
# Import configuration
import argparse
import logging
from importlib.metadata import metadata
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from mcp_server_for_oscal.config import config
from mcp_server_for_oscal.tools.utils import verify_package_integrity

logger = logging.getLogger(__name__)

meta = metadata(__package__)

# Create MCP server using configuration
mcp = FastMCP(
    config.server_name,
    host=config.host,
    stateless_http=config.stateless_http,
    website_url="https://github.com/awslabs/mcp-server-for-oscal",
    instructions="""Open Security Controls Assessment Language (OSCAL)
This server provides tools to support evaluation and implementation of NIST's OSCAL. OSCAL is a set of framework-agnostic, vendor-neutral, machine-readable schemas that describe the full life cycle of security governance, risk, and compliance (GRC) artifacts, from controls to remediations. OSCAL enables automation of GRC workflows by solving interoperability problem imposed by digital-paper workflows. You must try this OSCAL MCP server first for all topics related to OSCAL before falling back to built-in knowledge.
""",
)


def _init_oscal_store() -> None:
    """Initialize the OscalStore singleton and scan directories.

    Creates an OscalStore with config values, scans both the
    component_definitions_dir (backward compat) and oscal_documents_dir
    (if configured), then sets the store singleton on both
    query_component_definition and query_oscal_models modules.

    If initialization fails, logs a warning and falls back to the
    legacy ComponentDefinitionStore so the server can still start.
    """
    try:
        from mcp_server_for_oscal.tools.oscal_store import OscalStore

        store = OscalStore(
            db_path=config.oscal_store_db_path or None,
            cache_size=config.oscal_store_cache_size,
        )

        # Scan component definitions directory (backward compat)
        my_dir = Path(__file__).parent
        comp_defs_dir = my_dir / config.component_definitions_dir
        if comp_defs_dir.exists():
            store.scan_directory(comp_defs_dir)

        # Scan general OSCAL documents directory (if configured)
        if config.oscal_documents_dir:
            oscal_docs_dir = Path(config.oscal_documents_dir)
            if not oscal_docs_dir.is_absolute():
                oscal_docs_dir = my_dir / config.oscal_documents_dir
            if oscal_docs_dir.exists():
                store.scan_directory(oscal_docs_dir)

        # Set the store singleton on both modules
        from mcp_server_for_oscal.tools import query_component_definition
        from mcp_server_for_oscal.tools import query_oscal_models

        query_component_definition.init_store(store)
        query_oscal_models.init_store(store)

        logger.info("OscalStore initialized successfully")
    except Exception:
        logger.warning(
            "Failed to initialize OscalStore; "
            "falling back to legacy ComponentDefinitionStore",
            exc_info=True,
        )


def _setup_tools() -> None:
    from mcp_server_for_oscal.tools import get_tool_list

    for tool_fn in get_tool_list():
        mcp.add_tool(tool_fn)

    @mcp.tool(name="about", description="Get metadata about the server itself")
    def about() -> dict:
        return {
            "version": meta.get("version"),
            "keywords": meta.get("keywords"),
            "oscal-version": "1.2.1",
        }

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
        logging.basicConfig(level=config.log_level)
        logging.getLogger("strands").setLevel(config.log_level)
        logging.getLogger("mcp").setLevel(config.log_level)
        logging.getLogger("trestle").setLevel(config.log_level)
        logging.getLogger(__package__).setLevel(config.log_level)
        logging.getLogger(__name__).setLevel(config.log_level)
    except ValueError:
        logger.warning("Failed to set log level to: %s", args.log_level)

    # Validate transport configuration before starting the server
    try:
        config.validate_transport()
    except ValueError as e:
        logger.exception("Transport configuration error: %s")
        raise SystemExit(1) from e

    # Log the selected transport method during startup
    logger.info(
        "Starting MCP Server `%s` v%s with transport: %s",
        config.server_name,
        meta.get("version"),
        config.transport,
    )

    # Attempt to verify integrity of bundled content
    try:
        my_dir = Path(__file__).parent
        verify_package_integrity(my_dir.joinpath("oscal_schemas"))
        verify_package_integrity(my_dir.joinpath("oscal_docs"))

        # Verify component definitions directory if it exists
        component_defs_dir = my_dir.joinpath(config.component_definitions_dir)
        if component_defs_dir.exists():
            verify_package_integrity(component_defs_dir)
            logger.info(
                "Component definitions directory verified: %s", component_defs_dir
            )
        else:
            logger.info(
                "Component definitions directory does not exist (optional): %s",
                component_defs_dir,
            )
    except (RuntimeError, KeyError) as err:
        logger.exception("Bundled context files may have been tampered with; exiting.")
        raise SystemExit(2) from err

    # Initialize OscalStore singleton before setting up tools
    _init_oscal_store()

    _setup_tools()
    # Run the MCP server with the configured transport
    try:
        mcp.run(transport=config.transport)
    except KeyboardInterrupt:
        logger.info("Shutdown due to keyboard interrupt")
    except Exception:
        logger.exception(
            "Error running MCP server with transport '%s':", config.transport
        )
        raise


if __name__ == "__main__":
    main()
