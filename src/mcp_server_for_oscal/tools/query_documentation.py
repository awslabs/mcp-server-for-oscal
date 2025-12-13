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

logger = logging.getLogger(__name__)
logger.setLevel(config.log_level)


@tool
def query_oscal_documentation(query: str, ctx: Context) -> Any:
    """
    A tool to query OSCAL-related documentation. Use this tool when a question about OSCAL cannot be answered just by analyzing model schemas. In case the question is about an explicit property of an OSCAL model, try to find the answer using the get_schema tool first.

    Args:
        query: Question or search query about OSCAL

    Returns:
        dict: Results retrieved from knowledge base, structured as a Bedrock RetrieveResponseTypeDef object.
    """
    if config.knowledge_base_id is None:
        msg = "Knowledge base ID is not set. Please set the OSCAL_KB_ID environment variable."
        logger.warning(msg)
        if ctx is not None:
            garbage = ctx.warning(msg)
        return query_local(query, ctx)
    return query_kb(query, ctx)


def query_kb(query: str, ctx: Context) -> Any:
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
        if ctx is not None:
            garbage = ctx.error(msg)
        raise


def query_local(query: str, ctx: Context) -> Any:
    msg = "Not yet implemented"
    logger.error(msg)
    if ctx is not None:
        garbage = ctx.error(msg)
    return {
        "error": msg,
    }
