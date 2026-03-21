"""
OSCAL Agent module.

Provides a factory function to create a production-ready Strands agent
configured with OSCAL-specific tools, retry strategy, and observability.
"""

import argparse
import logging
from collections.abc import Callable
from pathlib import Path
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
from mcp_server_for_oscal.tools.utils import verify_package_integrity

logger = logging.getLogger(__name__)

def _build_system_prompt(tools: list[Callable]) -> str:
    """Build the system prompt with dynamically injected tool names.

    Args:
        tools: List of tool functions whose names will be included in the prompt.

    Returns:
        The complete system prompt string.
    """
    tool_names = [getattr(t, "__name__", str(t)) for t in tools]
    tool_list_str = ", ".join(sorted(tool_names))

    return (
        "You're an expert in modeling and interpreting GRC (governance, risk, and "
        "compliance) data in machine-readable format: OSCAL (Open Security Controls "
        "Assessment Language). Interoperability is the biggest constraint to GRC "
        "automation. GRC automation is the only way to make regulatory compliance "
        "sustainable for stakeholders. The interoperability problem stems from the "
        "fact that input artifacts (e.g., control frameworks, policies) are owned by "
        "external stakeholders (e.g., regulators, customers, auditors) and maintained "
        "in digital-paper formats (e.g., PDF) meant for humans, not machines. To "
        "solve the interoperability problem, we will make OSCAL the common language "
        "of GRC. Your job is to help people make good use of OSCAL without having to "
        "become experts in OSCAL. You may have OSCAL-based sources of information "
        "about systems and services from AWS and other vendors.\n"
        "\n"
        "You help users understand OSCAL concepts, models, and implementation "
        "approaches. You are knowledgeable about:\n"
        "- OSCAL architecture and layers (Control, Implementation, Assessment)\n"
        "- All OSCAL model types and their relationships\n"
        "- OSCAL implementation best practices\n"
        "- Integration with compliance frameworks like NIST SP 800-53, FedRAMP, etc.\n"
        "\n"
        "## Available Tools\n"
        "\n"
        f"You have access to the following tools: {tool_list_str}\n"
        "\n"
        "## Behavioral Guidelines\n"
        "\n"
        "1. **Prefer your tools over general knowledge.** Always try your OSCAL-specific "
        "tools, resources, and documentation before relying on general knowledge or "
        "external sources. Use the official NIST documentation when available.\n"
        "2. **Stay in scope.** You are an OSCAL, GRC, and compliance assistant. If a "
        "request is unrelated to OSCAL, GRC, or compliance, politely decline and "
        "explain that you are specialized in OSCAL and GRC topics.\n"
        "3. **Be honest about uncertainty.** If you don't have enough information to "
        "answer a question accurately, say so. Do not guess or fabricate information. "
        "State what you do know and suggest how the user might find the answer.\n"
        "4. **Provide practical, actionable guidance.** Explain concepts clearly for "
        "both beginners and experts. Reference official sources and examples.\n"
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

    # Build system prompt with dynamic tool names
    system_prompt = _build_system_prompt(tools)

    # Create the agent
    agent = Agent(
        model=model,
        tools=tools,
        system_prompt=system_prompt,
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


def main() -> None:
    """Standalone agent entry point.

    Parses CLI args, configures logging, verifies integrity,
    creates agent, runs interactive loop.
    """
    parser = argparse.ArgumentParser(description="OSCAL Agent")
    parser.add_argument(
        "--aws-profile",
        type=str,
        default=config.aws_profile,
        help="AWS profile name to use for authentication",
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
        help="Bedrock model ID to use (overrides BEDROCK_MODEL_ID env var)",
    )
    parser.add_argument(
        "--knowledge-base-id",
        type=str,
        help="Knowledge base ID to use (overrides OSCAL_KB_ID env var)",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        help="Maximum tokens for agent responses",
    )
    args = parser.parse_args()

    # Update configuration with CLI arguments
    config.update_from_args(
        bedrock_model_id=args.bedrock_model_id,
        knowledge_base_id=args.knowledge_base_id,
        log_level=args.log_level,
    )
    if args.max_tokens is not None:
        config.agent_max_tokens = args.max_tokens

    # Configure logging (same pattern as main.py)
    try:
        logging.basicConfig(level=config.log_level)
        logging.getLogger("strands").setLevel(config.log_level)
        logging.getLogger("trestle.*").setLevel(config.log_level)
        logging.getLogger(__package__ + ".*").setLevel(config.log_level)
        logging.getLogger(__name__).setLevel(config.log_level)
    except ValueError:
        logger.warning("Failed to set log level to: %s", args.log_level)

    # Verify bundled content integrity
    try:
        my_dir = Path(__file__).parent
        verify_package_integrity(my_dir.joinpath("oscal_schemas"))
        verify_package_integrity(my_dir.joinpath("oscal_docs"))

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

    # Create agent
    try:
        agent = create_oscal_agent()
    except ValueError as err:
        logger.exception("Failed to create OSCAL agent")
        raise SystemExit(1) from err

    # Interactive stdin/stdout loop
    logger.info("OSCAL Agent ready. Type your questions below.")
    try:
        while True:
            try:
                user_input = input("You: ")
                if not user_input.strip():
                    continue
                response = agent(user_input)
                print(f"\nAgent: {response}\n")  # noqa: T201
            except (KeyboardInterrupt, EOFError):
                break
    except KeyboardInterrupt:
        pass

    logger.info("Shutdown due to keyboard interrupt")


if __name__ == "__main__":
    main()
