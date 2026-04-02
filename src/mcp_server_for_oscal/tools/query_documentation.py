"""
Tool for querying OSCAL documentation from Amazon Bedrock Knowledge Base.
"""

import json
import logging
from typing import Any

from boto3 import Session
from mcp.server.fastmcp.server import Context
from strands import tool

from mcp_server_for_oscal.config import config
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


def _get_store() -> OscalStore:
    """Return the module-level store, raising if not yet initialised."""
    if _store is None:
        raise RuntimeError(
            "OscalStore has not been initialised. "
            "Call init_store() during server startup."
        )
    return _store


@tool
def query_oscal_documentation(query: str, ctx: Context | None = None) -> Any:
    """
    A tool to query OSCAL-related documentation. Use this tool when a question about OSCAL cannot be answered just by analyzing model schemas. In case the question is about an explicit property of an OSCAL model, try to find the answer using the get_schema tool first.

    Args:
        query: Question or search query about OSCAL

    Returns:
        dict: Results retrieved from knowledge base, structured as a Bedrock RetrieveResponseTypeDef object.
    """
    if config.knowledge_base_id is not None:
        logger.info("Using Knowledge Base search path (KB ID: %s)", config.knowledge_base_id)
        try:
            return query_kb(query, ctx)
        except Exception:
            logger.warning(
                "Knowledge Base query failed; falling back to local search"
            )
            return query_local(query, ctx)

    logger.info("Using local documentation search path")
    return query_local(query, ctx)


def query_kb(query: str, ctx: Context | None) -> Any:
    """Query Amazon Bedrock Knowledgebase using Boto SDK."""
    try:
        # Initialize boto session with the configured profile
        aws_profile = config.aws_profile
        if aws_profile:
            logger.debug(f"Using AWS profile: {aws_profile}")
            s = Session(profile_name=aws_profile)
        else:
            logger.debug("Using default AWS profile or environment credentials")
            s = Session()

        # Query Amazon Bedrock Knowledgebase using Boto SDK
        answer = s.client("bedrock-agent-runtime").retrieve(
            knowledgeBaseId=config.knowledge_base_id, retrievalQuery={"text": query}
        )

        logger.debug(json.dumps(answer, indent=1))

        return answer

    except Exception as e:
        msg = f"Error running query {query} documentation: {e}"
        logger.exception(msg)
        try_notify_client_error(msg, ctx)
        raise


def query_local(query: str, ctx: Context | None) -> Any:
    """Perform a local FTS5 search over bundled OSCAL documentation."""
    if _store is None:
        return {"error": "OscalStore has not been initialized"}
    return _store.search_documentation(query)
