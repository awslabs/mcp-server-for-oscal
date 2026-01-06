"""
Tool for retrieving OSCAL schemas.
"""

import json
import logging
from pathlib import Path
from typing import Any

from mcp.server.fastmcp.server import Context
from strands import tool

from mcp_server_for_oscal.tools.utils import (
    OSCALModelType,
    schema_names,
    try_notify_client_error,
)

logger = logging.getLogger(__name__)


@tool
def get_oscal_schema(
    ctx: Context, model_name: str = "complete", schema_type: str = "json"
) -> str:
    """
    A tool that returns the schema for specified OSCAL model. Try this tool first for any questions about the structure of OSCAL models.
    By default we return a JSON schema, but `schema_type` parameter can change that behavior. You can use the list_models tool to get
    a list of valid model names.

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
        try_notify_client_error(msg, ctx)
        raise ValueError(msg)

    if (
        model_name not in OSCALModelType.__members__.values()
        and model_name != "complete"
    ):
        msg = f"Invalid model: {model_name}. Use the tool list_oscal_models to get valid model names."
        try_notify_client_error(msg, ctx)
        raise ValueError(msg)

    schema_file_name = f"{schema_names.get(model_name)}.{schema_type}"

    try:
        schema = json.load(open_schema_file(schema_file_name))
    except Exception:
        msg = f"failed to open schema {schema_file_name}"
        logger.exception(msg)
        try_notify_client_error(msg, ctx)
        raise

    return json.dumps(schema)


def open_schema_file(file_name: str) -> Any:
    """Open a schema file from the OSCAL schemas directory."""
    # Get the directory of this file and navigate to oscal_schemas relative to it
    current_file_dir = Path(__file__).parent
    schema_path = current_file_dir.parent.joinpath("oscal_schemas")

    try:
        return open(schema_path.joinpath(file_name.lstrip("./\\")))
    except Exception:
        msg = f"failed to open file {file_name}"
        logger.exception(msg)
        raise
