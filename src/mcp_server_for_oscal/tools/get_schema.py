"""
Tool for retrieving OSCAL schemas.
"""

import json
import logging
from pathlib import Path
from typing import Any
import asyncio
from mcp.server.fastmcp.server import Context
from strands import tool

from mcp_server_for_oscal.tools.utils import OSCALModelType

logger = logging.getLogger(__name__)


@tool
def get_oscal_schema(
    ctx: Context, model_name: str = "complete", schema_type: str = "json"
) -> str:
    """
    A tool that returns the schema for specified OSCAL model. Try this tool first for any questions about the structure of OSCAL models.
    By default we return a JSON schema, but `schema_type` parameter can change that behavior.

    Args:
        ctx: MCP server context (should be injected automatically by MCP server)
        model_name: The name of the OSCAL model. If no value is provided, then we return a "complete" schema including all models, which is large.
        schema_type: If `json` (default) then return the JSON schema for the specified model. Otherwise, return its XSD (XML) schema.

    Returns:
        str: The requested schema as JSON string
    """
    logger.debug(
        "get_oscal_model_schema(model_name: %s, syntax: %s, session client params: %s)",
        model_name,
        schema_type,
        ctx.session.client_params,
    )

    if schema_type not in ["json", "xsd"]:
        msg = f"Invalid schema type: {schema_type}."
        if ctx is not None:
            try:
                loop = asyncio.get_running_loop()
                # Already in async context - can't use asyncio.run()
                loop.run_until_complete(ctx.error(msg))
            except RuntimeError:
                # Not in async context - safe to use asyncio.run()
                asyncio.run(ctx.error(msg))
        raise ValueError(msg)

    if (
        model_name not in OSCALModelType.__members__.values()
        and model_name != "complete"
    ):
        msg = f"Invalid model: {model_name}. Use the tool list_oscal_models to get valid model names."
        if ctx is not None:
            try:
                loop = asyncio.get_running_loop()
                # Already in async context - can't use asyncio.run()
                loop.run_until_complete(ctx.error(msg))
            except RuntimeError:
                # Not in async context - safe to use asyncio.run()
                asyncio.run(ctx.error(msg))
        raise ValueError(msg)

    model_name = model_name.replace(OSCALModelType.SYSTEM_SECURITY_PLAN, "ssp")
    model_name = model_name.replace(
        OSCALModelType.PLAN_OF_ACTION_AND_MILESTONES, "poam"
    )
    model_name = model_name.replace(OSCALModelType.MAPPING, "mapping")

    schema_file_name = f"oscal_{model_name}_schema.{schema_type}"

    try:
        schema = json.load(open_schema_file(schema_file_name))
    except Exception:
        msg = f"failed to open schema {schema_file_name}"
        logger.exception(msg)
        if ctx is not None:
            try:
                loop = asyncio.get_running_loop()
                # Already in async context - can't use asyncio.run()
                loop.run_until_complete(ctx.error(msg))
            except RuntimeError:
                # Not in async context - safe to use asyncio.run()
                asyncio.run(ctx.error(msg))
        raise

    return json.dumps(schema)


def open_schema_file(file_name: str) -> Any:
    """Open a schema file from the OSCAL schemas directory."""
    # Get the directory of this file and navigate to oscal_schemas relative to it
    current_file_dir = Path(__file__).parent
    schema_path = current_file_dir.parent / "oscal_schemas"

    try:
        schema_file_path = schema_path / file_name.lstrip("./\\")
        return open(schema_file_path)
    except Exception:
        msg = f"failed to open file {file_name}"
        logger.exception(msg)
        raise
