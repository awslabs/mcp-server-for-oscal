"""
Tool for listing OSCAL community resources.
"""

import logging
from pathlib import Path
from typing import Any

from mcp.server.fastmcp.server import Context
from strands import tool

logger = logging.getLogger(__name__)


@tool
def list_oscal_resources(ctx: Context) -> str:
    """
    List OSCAL community resources from the awesome-oscal.md file.

    This tool returns the complete contents of the awesome-oscal.md file which contains
    a curated collection of OSCAL community resources including content, tools, articles,
    presentations, and other resources for increasing OSCAL adoption.

    Args:
        ctx: MCP server context (should be injected automatically by MCP server)

    Returns:
        str: The complete markdown content of the awesome-oscal.md file

    Raises:
        FileNotFoundError: If the awesome-oscal.md file cannot be found
        IOError: If there are issues reading the file
        UnicodeDecodeError: If there are encoding issues with the file
    """
    logger.debug(
        "list_oscal_resources() called with session client params: %s",
        ctx.session.client_params if ctx else None,
    )

    try:
        content = read_resources_file()
        logger.info("Successfully read OSCAL resources file")
        return content
    except FileNotFoundError as e:
        msg = f"OSCAL resources file not found: {e}"
        logger.error(msg)
        if ctx is not None:
            ctx.error(msg)
        raise
    except (IOError, OSError) as e:
        msg = f"Failed to read OSCAL resources file: {e}"
        logger.error(msg)
        if ctx is not None:
            ctx.error(msg)
        raise
    except UnicodeDecodeError as e:
        msg = f"Encoding error reading OSCAL resources file: {e}"
        logger.error(msg)
        if ctx is not None:
            ctx.error(msg)
        raise
    except Exception as e:
        msg = f"Unexpected error reading OSCAL resources file: {e}"
        logger.exception(msg)
        if ctx is not None:
            ctx.error(msg)
        raise


def read_resources_file() -> str:
    """
    Read the awesome-oscal.md file from the oscal_docs directory.

    Returns:
        str: The complete content of the awesome-oscal.md file

    Raises:
        FileNotFoundError: If the awesome-oscal.md file cannot be found
        IOError: If there are issues reading the file
        UnicodeDecodeError: If there are encoding issues with the file
    """
    # Get the directory of this file and navigate to oscal_docs relative to it
    current_file_dir = Path(__file__).parent
    docs_path = current_file_dir.parent / "oscal_docs"
    resources_file_path = docs_path / "awesome-oscal.md"

    logger.debug("Reading OSCAL resources from: %s", resources_file_path)

    try:
        # Read with explicit UTF-8 encoding and error handling
        with open(resources_file_path, "r", encoding="utf-8", errors="strict") as file:
            content = file.read()

        if not content.strip():
            logger.warning("OSCAL resources file is empty")

        return content
    except FileNotFoundError:
        logger.error("OSCAL resources file not found at: %s", resources_file_path)
        raise
    except UnicodeDecodeError as e:
        logger.error("Encoding error reading file %s: %s", resources_file_path, e)
        # Try with different encoding as fallback
        try:
            with open(
                resources_file_path, "r", encoding="latin-1", errors="replace"
            ) as file:
                content = file.read()
            logger.warning("Successfully read file with latin-1 encoding fallback")
            return content
        except Exception as fallback_error:
            logger.error("Fallback encoding also failed: %s", fallback_error)
            raise e  # Raise the original UnicodeDecodeError
    except (IOError, OSError) as e:
        logger.error("IO error reading file %s: %s", resources_file_path, e)
        raise
