"""
Tool for querying OSCAL Component Definition documents.
"""

import json
import logging
from pathlib import Path
from typing import Any

import requests
from mcp.server.fastmcp.server import Context
from trestle.oscal.component import ComponentDefinition

from mcp_server_for_oscal.config import config
from mcp_server_for_oscal.tools.utils import try_notify_client_error

logger = logging.getLogger(__name__)


def load_component_definition(source: str, ctx: Context) -> ComponentDefinition:
    """
    Load and validate an OSCAL Component Definition from a local file path or remote URI.
    
    Uses compliance-trestle's load_validate_model_path for automatic validation
    via Pydantic models. Remote URI loading is only supported when explicitly
    configured via allow_remote_uris setting.
    
    Args:
        source: Local file path or remote URI to the Component Definition JSON file
        ctx: MCP server context for error reporting
        
    Returns:
        ComponentDefinition: Validated Pydantic model instance
        
    Raises:
        FileNotFoundError: If the source file does not exist
        ValueError: If the file cannot be parsed, fails validation, or remote URIs are not allowed
        requests.RequestException: If remote URI fetching fails
    """
    logger.debug("Loading component definition from: %s", source)
    
    # Check if source is a remote URI
    is_remote = source.startswith("http://") or source.startswith("https://")
    
    if is_remote:
        return _load_remote_component_definition(source, ctx)
    else:
        return _load_local_component_definition(source, ctx)


def _load_local_component_definition(source: str, ctx: Context) -> ComponentDefinition:
    """
    Load and validate an OSCAL Component Definition from a local file path.
    
    Args:
        source: Local file path to the Component Definition JSON file
        ctx: MCP server context for error reporting
        
    Returns:
        ComponentDefinition: Validated Pydantic model instance
        
    Raises:
        FileNotFoundError: If the source file does not exist
        ValueError: If the file cannot be parsed or fails validation
    """
    source_path = Path(source)
    
    # Check if file exists
    if not source_path.exists():
        msg = f"Component Definition file not found: {source}"
        logger.error(msg)
        try_notify_client_error(msg, ctx)
        raise FileNotFoundError(msg)
    
    # Check if it's a file (not a directory)
    if not source_path.is_file():
        msg = f"Source path is not a file: {source}"
        logger.error(msg)
        try_notify_client_error(msg, ctx)
        raise ValueError(msg)
    
    try:
        # Load and parse the JSON file
        with open(source_path) as f:
            data = json.load(f)
        
        # Validate and instantiate ComponentDefinition using Pydantic
        # The data should have a 'component-definition' key at the root
        if "component-definition" in data:
            component_def = ComponentDefinition(**data["component-definition"])
        else:
            # Try direct instantiation if the root is already the component definition
            component_def = ComponentDefinition(**data)
        
        logger.info("Successfully loaded and validated component definition from: %s", source)
        return component_def
        
    except json.JSONDecodeError as e:
        msg = f"Failed to parse Component Definition JSON: {e}"
        logger.exception(msg)
        try_notify_client_error(msg, ctx)
        raise ValueError(msg) from e
        
    except Exception as e:
        msg = f"Failed to load or validate Component Definition: {e}"
        logger.exception(msg)
        try_notify_client_error(msg, ctx)
        raise ValueError(msg) from e


def _load_remote_component_definition(source: str, ctx: Context) -> ComponentDefinition:
    """
    Load and validate an OSCAL Component Definition from a remote URI.
    
    Only works when allow_remote_uris is configured to True. Fetches the JSON
    content via HTTP and validates it using compliance-trestle.
    
    Args:
        source: Remote URI to the Component Definition JSON file
        ctx: MCP server context for error reporting
        
    Returns:
        ComponentDefinition: Validated Pydantic model instance
        
    Raises:
        ValueError: If remote URIs are not allowed or validation fails
        requests.RequestException: If HTTP request fails
    """
    # Check if remote URIs are allowed
    if not config.allow_remote_uris:
        msg = (
            f"Remote URI loading is not enabled. "
            f"Set OSCAL_ALLOW_REMOTE_URIS=true to enable. Source: {source}"
        )
        logger.error(msg)
        try_notify_client_error(msg, ctx)
        raise ValueError(msg)
    
    logger.info("Fetching remote Component Definition from: %s", source)
    
    try:
        # Fetch the remote content with timeout
        response = requests.get(source, timeout=config.request_timeout)
        response.raise_for_status()
        
        # Parse JSON content
        data = response.json()
        
        # Validate and instantiate ComponentDefinition using Pydantic
        # The data should have a 'component-definition' key at the root
        if "component-definition" in data:
            component_def = ComponentDefinition(**data["component-definition"])
        else:
            # Try direct instantiation if the root is already the component definition
            component_def = ComponentDefinition(**data)
        
        logger.info("Successfully loaded and validated remote component definition from: %s", source)
        return component_def
        
    except requests.Timeout as e:
        msg = f"Request timeout while fetching remote URI (timeout={config.request_timeout}s): {source}"
        logger.exception(msg)
        try_notify_client_error(msg, ctx)
        raise ValueError(msg) from e
        
    except requests.RequestException as e:
        msg = f"Failed to fetch remote Component Definition: {e}"
        logger.exception(msg)
        try_notify_client_error(msg, ctx)
        raise ValueError(msg) from e
        
    except json.JSONDecodeError as e:
        msg = f"Failed to parse remote Component Definition JSON: {e}"
        logger.exception(msg)
        try_notify_client_error(msg, ctx)
        raise ValueError(msg) from e
        
    except Exception as e:
        msg = f"Failed to load or validate remote Component Definition: {e}"
        logger.exception(msg)
        try_notify_client_error(msg, ctx)
        raise ValueError(msg) from e
