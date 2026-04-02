"""
Tool for listing OSCAL community resources.
"""

import logging
from pathlib import Path

from mcp.server.fastmcp.server import Context
from strands import tool

from mcp_server_for_oscal.tools.oscal_store import OscalStore
from mcp_server_for_oscal.tools.utils import try_notify_client_error

logger = logging.getLogger(__name__)

# Module-level singleton — initialised lazily by ``init_store()``.
_store: OscalStore | None = None


def init_store(store: OscalStore) -> None:
    """Set the module-level OscalStore singleton.

    Called during server startup after the store has been
    initialised and directories have been scanned.
    """
    global _store  # noqa: PLW0603
    _store = store


@tool
def list_oscal_resources(ctx: Context | None = None) -> str:
    """
    Retrieve a comprehensive directory of OSCAL community resources and tools.

    This tool provides access to a curated collection of OSCAL (Open Security Controls Assessment Language)
    community resources that can help users:

    - Find OSCAL-compatible tools and software implementations
    - Discover educational content, tutorials, and documentation
    - Access example OSCAL documents and templates
    - Locate presentations, articles, and research papers about OSCAL
    - Identify government and industry adoption examples
    - Find libraries and SDKs for OSCAL development
    - Access validation tools and utilities

    The returned content is structured markdown that categorizes resources by type (tools, content,
    presentations, etc.) making it easy to find specific types of OSCAL resources based on user needs.

    Use this tool when users ask about:
    - "What OSCAL tools are available?"
    - "How can I learn more about OSCAL?"
    - "Are there examples of OSCAL implementations?"
    - "What resources exist for OSCAL development?"
    - "Who is using OSCAL in production?"

    Args:
        ctx: MCP server context (should be injected automatically by MCP server)

    Returns:
        str: Complete markdown content containing categorized OSCAL community resources,
             tools, documentation, examples, and educational materials

    Raises:
        FileNotFoundError: If the awesome-oscal.md content cannot be found
        IOError: If there are issues reading the content
    """
    logger.debug(
        "list_oscal_resources() called with session client params: %s",
        ctx.session.client_params if ctx else None,
    )

    try:
        content = read_resources_file()
        logger.debug("Successfully read OSCAL resources file")
        return content
    except Exception:
        msg = "Failed to read OSCAL resources file."
        logger.exception(msg)
        try_notify_client_error(msg, ctx)
        raise


def _read_from_store() -> str | None:
    """Try to read awesome-oscal content from the bundled OscalStore DB.

    Returns the content string, or None if the store is not initialised
    or the document is not found.
    """
    if _store is None:
        return None

    try:
        row = _store._conn.execute(
            "SELECT raw_json FROM documents "
            "WHERE model_type = 'documentation' "
            "AND file_path LIKE '%awesome-oscal.md'",
        ).fetchone()
        if row and row["raw_json"]:
            return row["raw_json"]
    except Exception:
        logger.debug("Failed to read awesome-oscal from OscalStore", exc_info=True)

    return None


def read_resources_file() -> str:
    """
    Read the awesome-oscal.md content.

    First attempts to read from the bundled OscalStore database (runtime
    path). Falls back to reading the file from the ``oscal_docs/``
    directory relative to this package (development path).

    Returns:
        str: The complete content of the awesome-oscal.md file

    Raises:
        FileNotFoundError: If the awesome-oscal.md content cannot be found
        IOError: If there are issues reading the file
        UnicodeDecodeError: If there are encoding issues with the file
    """
    # Primary path: read from the bundled DB
    content = _read_from_store()
    if content is not None:
        logger.debug("Read OSCAL resources from bundled OscalStore DB")
        if not content.strip():
            logger.warning("OSCAL resources content from DB is empty")
        return content

    # Fallback: read from filesystem (development / build-time)
    current_file_dir = Path(__file__).parent
    # Try repo-root data/ directory first (post-move location)
    repo_root = current_file_dir.parent.parent.parent
    resources_file_path = repo_root / "data" / "oscal_docs" / "awesome-oscal.md"
    if not resources_file_path.exists():
        # Legacy path (pre-move, inside package)
        resources_file_path = current_file_dir.parent / "oscal_docs" / "awesome-oscal.md"

    logger.debug("Reading OSCAL resources from: %s", resources_file_path)

    try:
        # Read with explicit UTF-8 encoding and error handling
        with open(resources_file_path, encoding="utf-8", errors="strict") as file:
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
                resources_file_path, encoding="latin-1", errors="replace"
            ) as file:
                content = file.read()
            logger.warning("Successfully read file with latin-1 encoding fallback")
            return content
        except Exception as fallback_error:
            logger.error("Fallback encoding also failed: %s", fallback_error)
            raise e  # Raise the original UnicodeDecodeError
    except OSError as e:
        logger.error("IO error reading file %s: %s", resources_file_path, e)
        raise
