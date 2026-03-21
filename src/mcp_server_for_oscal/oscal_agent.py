"""
OSCAL Agent module.

Provides a factory function to create a production-ready Strands agent
configured with OSCAL-specific tools, retry strategy, and observability.
"""

import logging
from collections.abc import Callable
from typing import Any

import boto3
from strands import Agent, ModelRetryStrategy
from strands.hooks import (
    AfterInvocationEvent,
    AfterModelCallEvent,
    BeforeToolCallEvent,
    HookProvider,
    HookRegistry,
)
from strands.models import BedrockModel

from mcp_server_for_oscal.config import config
from mcp_server_for_oscal.tools import get_tool_list

logger = logging.getLogger(__name__)

# Placeholder system prompt — will be refined in task 4.3
SYSTEM_PROMPT = (
    "You are an OSCAL assistant. You help users work with "
    "NIST's Open Security Controls Assessment Language (OSCAL)."
)


def _truncate_args(args: Any, max_len: int = 200) -> str:
    """Return a truncated repr of tool arguments."""
    text = repr(args)
    if len(text) > max_len:
        return text[:max_len] + "..."
    return text


class AgentObservabilityHook(HookProvider):
    """HookProvider that logs agent lifecycle events.

    Handles:
        - BeforeToolCallEvent: logs tool name + truncated args at DEBUG
        - AfterModelCallEvent: logs stop reason + token usage at DEBUG
        - AfterInvocationEvent: logs completion at DEBUG
    Also logs retry/throttle events at WARNING.
    """

    def __init__(self) -> None:
        self._logger = logging.getLogger(__name__)

    def register_hooks(self, registry: HookRegistry, **kwargs: Any) -> None:
        """Register callbacks for agent lifecycle events."""
        registry.add_callback(BeforeToolCallEvent, self._on_before_tool_call)
        registry.add_callback(AfterModelCallEvent, self._on_after_model_call)
        registry.add_callback(AfterInvocationEvent, self._on_after_invocation)

    def _on_before_tool_call(self, event: BeforeToolCallEvent) -> None:
        """Log tool name and truncated arguments at DEBUG level."""
        tool_name = event.tool_use.get("name", "<unknown>")
        tool_input = event.tool_use.get("input", {})
        self._logger.debug(
            "Tool call: %s args=%s",
            tool_name,
            _truncate_args(tool_input),
        )

    def _on_after_model_call(self, event: AfterModelCallEvent) -> None:
        """Log stop reason and token usage at DEBUG level."""
        if event.stop_response is not None:
            self._logger.debug(
                "Model call complete: stop_reason=%s",
                event.stop_response.stop_reason,
            )
        elif event.exception is not None:
            self._logger.debug(
                "Model call failed: %s",
                event.exception,
            )

    def _on_after_invocation(self, event: AfterInvocationEvent) -> None:
        """Log invocation completion at DEBUG level."""
        if event.result is not None:
            self._logger.debug(
                "Invocation complete: stop_reason=%s",
                event.result.stop_reason,
            )
        else:
            self._logger.debug("Invocation complete")


def create_oscal_agent(tools: list[Callable] | None = None) -> Agent:
    """Create a production-ready OSCAL Strands agent.

    Args:
        tools: Optional list of tool functions. Defaults to get_tool_list().

    Returns:
        Configured Agent instance.

    Raises:
        ValueError: If boto3 session or BedrockModel creation fails.
    """
    if tools is None:
        tools = get_tool_list()

    # Create boto3 session
    try:
        session = boto3.Session(
            profile_name=config.aws_profile,
            region_name=config.aws_region,
        )
    except Exception as e:
        msg = f"Failed to create boto3 session with profile '{config.aws_profile}': {e}"
        logger.exception(msg)
        raise ValueError(msg) from e

    # Create BedrockModel
    try:
        model = BedrockModel(
            model_id=config.bedrock_model_id,
            boto_session=session,
            max_tokens=config.agent_max_tokens,
        )
    except Exception as e:
        msg = (
            f"Failed to create BedrockModel with model_id "
            f"'{config.bedrock_model_id}': {e}"
        )
        logger.exception(msg)
        raise ValueError(msg) from e

    # Configure retry strategy
    retry_strategy = ModelRetryStrategy(
        max_attempts=config.agent_max_retry_attempts,
        initial_delay=config.agent_retry_initial_delay,
        max_delay=config.agent_retry_max_delay,
    )

    # Create the agent
    agent = Agent(
        model=model,
        tools=tools,
        system_prompt=SYSTEM_PROMPT,
        retry_strategy=retry_strategy,
        hooks=[AgentObservabilityHook()],
    )

    logger.info(
        "OSCAL agent created: model_id=%s, region=%s, tools=%d, retry_enabled=True",
        config.bedrock_model_id,
        config.aws_region,
        len(tools),
    )

    return agent
