"""
Tests for the oscal_agent module.

Covers:
- Unit tests for create_oscal_agent factory (Task 4.7)
- Property test for error context propagation (Task 4.4)
- Property test for hook event logging completeness (Task 4.5)
- Property test for system prompt tool name inclusion (Task 4.6)
- Property test for factory manager forwarding (Task 3.2)

Feature: oscal-agent-production, agent-session-state
"""

import logging
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

import pytest
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

from mcp_server_for_oscal.oscal_agent import (
    AgentObservabilityHook,
    _build_system_prompt,
    create_oscal_agent,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_tool(name: str):
    """Create a mock callable with a __name__ attribute."""
    fn = Mock()
    fn.__name__ = name
    return fn


# ---------------------------------------------------------------------------
# Task 4.7 — Unit tests for create_oscal_agent
# ---------------------------------------------------------------------------


class TestCreateOscalAgent:
    """Unit tests for the create_oscal_agent factory function."""

    @patch("mcp_server_for_oscal.oscal_agent.Agent")
    @patch("mcp_server_for_oscal.oscal_agent.BedrockModel")
    @patch("mcp_server_for_oscal.oscal_agent.boto3.Session")
    def test_returns_agent_with_correct_system_prompt(
        self, mock_session_cls, mock_bedrock_cls, mock_agent_cls
    ):
        """Agent system prompt contains OSCAL domain, boundaries, tool preference, uncertainty."""
        tools = [_make_mock_tool("tool_a")]
        create_oscal_agent(tools=tools)

        call_kwargs = mock_agent_cls.call_args[1]
        prompt = call_kwargs["system_prompt"]

        assert "OSCAL" in prompt
        assert "decline" in prompt.lower() or "unrelated" in prompt.lower()
        assert "Prefer" in prompt or "prefer" in prompt.lower() or "tools" in prompt.lower()
        assert "uncertainty" in prompt.lower() or "don't have enough information" in prompt.lower()

    @patch("mcp_server_for_oscal.oscal_agent.Agent")
    @patch("mcp_server_for_oscal.oscal_agent.BedrockModel")
    @patch("mcp_server_for_oscal.oscal_agent.boto3.Session")
    @patch("mcp_server_for_oscal.oscal_agent.get_tool_list")
    def test_agent_configured_with_tools_from_registry(
        self, mock_get_tools, mock_session_cls, mock_bedrock_cls, mock_agent_cls
    ):
        """When no tools param given, agent uses tools from get_tool_list()."""
        sentinel_tools = [_make_mock_tool("registry_tool")]
        mock_get_tools.return_value = sentinel_tools

        create_oscal_agent()

        call_kwargs = mock_agent_cls.call_args[1]
        assert call_kwargs["tools"] == sentinel_tools

    @patch("mcp_server_for_oscal.oscal_agent.Agent")
    @patch("mcp_server_for_oscal.oscal_agent.BedrockModel")
    @patch("mcp_server_for_oscal.oscal_agent.boto3.Session")
    def test_retry_strategy_defaults(
        self, mock_session_cls, mock_bedrock_cls, mock_agent_cls
    ):
        """ModelRetryStrategy uses defaults: max_attempts=4, initial_delay=2, max_delay=60."""
        tools = [_make_mock_tool("t")]
        create_oscal_agent(tools=tools)

        call_kwargs = mock_agent_cls.call_args[1]
        retry = call_kwargs["retry_strategy"]
        assert retry._max_attempts == 4
        assert retry._initial_delay == 2
        assert retry._max_delay == 60

    @patch("mcp_server_for_oscal.oscal_agent.Agent")
    @patch("mcp_server_for_oscal.oscal_agent.BedrockModel")
    @patch("mcp_server_for_oscal.oscal_agent.boto3.Session")
    def test_max_tokens_default(
        self, mock_session_cls, mock_bedrock_cls, mock_agent_cls
    ):
        """BedrockModel is created with max_tokens=4096 by default."""
        tools = [_make_mock_tool("t")]
        create_oscal_agent(tools=tools)

        bedrock_kwargs = mock_bedrock_cls.call_args[1]
        assert bedrock_kwargs["max_tokens"] == 4096

    @patch("mcp_server_for_oscal.oscal_agent.Agent")
    @patch("mcp_server_for_oscal.oscal_agent.BedrockModel")
    @patch("mcp_server_for_oscal.oscal_agent.boto3.Session")
    def test_custom_tools_override_registry(
        self, mock_session_cls, mock_bedrock_cls, mock_agent_cls
    ):
        """Passing explicit tools overrides the registry."""
        custom_tools = [_make_mock_tool("custom_a"), _make_mock_tool("custom_b")]
        create_oscal_agent(tools=custom_tools)

        call_kwargs = mock_agent_cls.call_args[1]
        assert call_kwargs["tools"] == custom_tools

    @patch("mcp_server_for_oscal.oscal_agent.boto3.Session", side_effect=Exception("profile boom"))
    def test_valueerror_on_boto3_session_failure(self, mock_session_cls):
        """ValueError raised when boto3.Session fails, message contains profile name."""
        with pytest.raises(ValueError, match="boto3 session"):
            create_oscal_agent(tools=[_make_mock_tool("t")])

    @patch(
        "mcp_server_for_oscal.oscal_agent.BedrockModel",
        side_effect=Exception("model boom"),
    )
    @patch("mcp_server_for_oscal.oscal_agent.boto3.Session")
    def test_valueerror_on_bedrock_model_failure(
        self, mock_session_cls, mock_bedrock_cls
    ):
        """ValueError raised when BedrockModel fails, message contains model ID."""
        with pytest.raises(ValueError, match="BedrockModel"):
            create_oscal_agent(tools=[_make_mock_tool("t")])

    @patch("mcp_server_for_oscal.oscal_agent.boto3.Session", side_effect=Exception("err"))
    def test_error_log_emitted_before_raising(self, mock_session_cls, caplog):
        """ERROR log is emitted before the ValueError is raised."""
        with caplog.at_level(logging.ERROR, logger="mcp_server_for_oscal.oscal_agent"):
            with pytest.raises(ValueError):
                create_oscal_agent(tools=[_make_mock_tool("t")])

        assert any(
            record.levelno == logging.ERROR for record in caplog.records
        ), "Expected an ERROR log record before raising"

    @patch("mcp_server_for_oscal.oscal_agent.Agent")
    @patch("mcp_server_for_oscal.oscal_agent.BedrockModel")
    @patch("mcp_server_for_oscal.oscal_agent.boto3.Session")
    def test_observability_hook_registered(
        self, mock_session_cls, mock_bedrock_cls, mock_agent_cls
    ):
        """AgentObservabilityHook is passed in the hooks list."""
        tools = [_make_mock_tool("t")]
        create_oscal_agent(tools=tools)

        call_kwargs = mock_agent_cls.call_args[1]
        hooks = call_kwargs["hooks"]
        assert any(
            isinstance(h, AgentObservabilityHook) for h in hooks
        ), "Expected AgentObservabilityHook in hooks list"

    def test_no_module_level_agent_attribute(self):
        """The oscal_agent module must not have a module-level 'agent' attribute."""
        import mcp_server_for_oscal.oscal_agent as mod

        assert not hasattr(mod, "agent"), (
            "Module should not have a module-level 'agent' attribute"
        )


# ---------------------------------------------------------------------------
# Task 4.4 — Property 2: Error context propagation
# ---------------------------------------------------------------------------

# Strategies for generating safe text (no null bytes)
safe_text = st.text(
    min_size=1,
    max_size=50,
    alphabet=st.characters(
        whitelist_categories=("L", "N", "P", "Z"),
        blacklist_characters="\x00",
    ),
).filter(lambda t: t.strip())


class TestProperty2ErrorContextPropagation:
    """
    Property 2: Error context propagation

    For any profile name and underlying error message, when
    create_oscal_agent fails during boto3 session creation, the raised
    ValueError message contains both the profile name and the original
    error string. Similarly for model ID and BedrockModel failure.

    **Validates: Requirements 3.2, 3.3**
    """

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    @given(profile_name=safe_text, error_msg=safe_text)
    def test_boto3_error_contains_profile_and_original_error(
        self, profile_name, error_msg
    ):
        """
        Feature: oscal-agent-production, Property 2: Error context propagation

        ValueError from boto3 session failure contains the profile name
        and the original error message.
        """
        with patch("mcp_server_for_oscal.oscal_agent.config") as mock_config:
            mock_config.aws_profile = profile_name
            mock_config.aws_region = "us-east-1"

            with patch(
                "mcp_server_for_oscal.oscal_agent.boto3.Session",
                side_effect=Exception(error_msg),
            ):
                with pytest.raises(ValueError) as exc_info:
                    create_oscal_agent(tools=[_make_mock_tool("t")])

                err_str = str(exc_info.value)
                assert profile_name in err_str, (
                    f"Profile name '{profile_name}' not found in error: {err_str}"
                )
                assert error_msg in err_str, (
                    f"Original error '{error_msg}' not found in error: {err_str}"
                )

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    @given(model_id=safe_text, error_msg=safe_text)
    def test_bedrock_error_contains_model_id_and_original_error(
        self, model_id, error_msg
    ):
        """
        Feature: oscal-agent-production, Property 2: Error context propagation

        ValueError from BedrockModel failure contains the model ID
        and the original error message.
        """
        with patch("mcp_server_for_oscal.oscal_agent.config") as mock_config:
            mock_config.aws_profile = None
            mock_config.aws_region = "us-east-1"
            mock_config.bedrock_model_id = model_id
            mock_config.agent_max_tokens = 4096

            with patch("mcp_server_for_oscal.oscal_agent.boto3.Session"):
                with patch(
                    "mcp_server_for_oscal.oscal_agent.BedrockModel",
                    side_effect=Exception(error_msg),
                ):
                    with pytest.raises(ValueError) as exc_info:
                        create_oscal_agent(tools=[_make_mock_tool("t")])

                    err_str = str(exc_info.value)
                    assert model_id in err_str, (
                        f"Model ID '{model_id}' not found in error: {err_str}"
                    )
                    assert error_msg in err_str, (
                        f"Original error '{error_msg}' not found in error: {err_str}"
                    )


# ---------------------------------------------------------------------------
# Task 4.5 — Property 4: Hook event logging completeness
# ---------------------------------------------------------------------------

# Strategy for generating argument dicts
arg_dict_strategy = st.dictionaries(
    keys=st.text(min_size=1, max_size=20, alphabet=st.characters(
        whitelist_categories=("L", "N"),
    )),
    values=st.one_of(st.text(max_size=30), st.integers(), st.booleans()),
    max_size=5,
)


class TestProperty4HookEventLoggingCompleteness:
    """
    Property 4: Hook event logging completeness

    For any BeforeToolCallEvent with a random tool name and argument dict,
    the AgentObservabilityHook produces a DEBUG log entry containing the
    tool name. For any AfterModelCallEvent with a random stop reason,
    the hook produces a DEBUG log entry containing the stop reason.

    **Validates: Requirements 6.2, 6.3**
    """

    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
        deadline=None,
    )
    @given(tool_name=safe_text, args=arg_dict_strategy)
    def test_before_tool_call_logs_tool_name(self, tool_name, args, caplog):
        """
        Feature: oscal-agent-production, Property 4: Hook event logging completeness

        BeforeToolCallEvent handler logs the tool name at DEBUG level.
        """
        caplog.clear()
        hook = AgentObservabilityHook()

        event = MagicMock()
        event.tool_use = {"name": tool_name, "input": args}

        with caplog.at_level(logging.DEBUG, logger="mcp_server_for_oscal.oscal_agent"):
            hook._on_before_tool_call(event)

        assert any(
            tool_name in record.message for record in caplog.records
        ), f"Tool name '{tool_name}' not found in log output"

    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
        deadline=None,
    )
    @given(stop_reason=safe_text)
    def test_after_model_call_logs_stop_reason(self, stop_reason, caplog):
        """
        Feature: oscal-agent-production, Property 4: Hook event logging completeness

        AfterModelCallEvent handler logs the stop reason at DEBUG level.
        """
        caplog.clear()
        hook = AgentObservabilityHook()

        stop_response = SimpleNamespace(stop_reason=stop_reason)
        event = MagicMock()
        event.stop_response = stop_response
        event.exception = None

        with caplog.at_level(logging.DEBUG, logger="mcp_server_for_oscal.oscal_agent"):
            hook._on_after_model_call(event)

        assert any(
            stop_reason in record.message for record in caplog.records
        ), f"Stop reason '{stop_reason}' not found in log output"


# ---------------------------------------------------------------------------
# Task 4.6 — Property 5: System prompt tool name inclusion
# ---------------------------------------------------------------------------

# Strategy for generating tool name identifiers
tool_name_strategy = st.text(
    min_size=1,
    max_size=30,
    alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="_"),
).filter(lambda t: t.strip() and t[0].isalpha())


class TestProperty5SystemPromptToolNameInclusion:
    """
    Property 5: System prompt tool name inclusion

    For any list of tool functions passed to _build_system_prompt,
    the returned string contains the name of every tool in that list.

    **Validates: Requirements 7.5**
    """

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    @given(
        tool_names=st.lists(tool_name_strategy, min_size=1, max_size=10, unique=True)
    )
    def test_system_prompt_contains_all_tool_names(self, tool_names):
        """
        Feature: oscal-agent-production, Property 5: System prompt tool name inclusion

        _build_system_prompt includes every tool name in the returned prompt.
        """
        tools = [_make_mock_tool(name) for name in tool_names]
        prompt = _build_system_prompt(tools)

        for name in tool_names:
            assert name in prompt, (
                f"Tool name '{name}' not found in system prompt"
            )


# ---------------------------------------------------------------------------
# Task 7.3 — Unit tests for agent entry point main()
# ---------------------------------------------------------------------------


class TestMainEntryPoint:
    """Unit tests for the main() entry point in oscal_agent.py."""

    @patch("mcp_server_for_oscal.oscal_agent.create_oscal_agent")
    @patch("mcp_server_for_oscal.oscal_agent.verify_package_integrity")
    @patch("mcp_server_for_oscal.oscal_agent.config")
    @patch("sys.argv", ["agent", "--aws-profile", "my-profile", "--log-level", "DEBUG"])
    def test_cli_parses_aws_profile_and_log_level(
        self, mock_config, mock_verify, mock_create_agent
    ):
        """CLI --aws-profile and --log-level are forwarded to config.update_from_args."""
        from mcp_server_for_oscal.oscal_agent import main

        mock_config.aws_profile = None
        mock_config.log_level = "INFO"
        mock_config.component_definitions_dir = "component_definitions"
        mock_config.agent_max_tokens = 4096

        mock_agent = MagicMock()
        mock_create_agent.return_value = mock_agent

        # Make input raise EOFError to exit the interactive loop immediately
        with patch("builtins.input", side_effect=EOFError):
            main()

        mock_config.update_from_args.assert_called_once()
        call_kwargs = mock_config.update_from_args.call_args[1]
        assert call_kwargs["log_level"] == "DEBUG"

    @patch("mcp_server_for_oscal.oscal_agent.create_oscal_agent")
    @patch("mcp_server_for_oscal.oscal_agent.verify_package_integrity")
    @patch("mcp_server_for_oscal.oscal_agent.config")
    @patch(
        "sys.argv",
        [
            "agent",
            "--bedrock-model-id",
            "anthropic.claude-v2",
            "--knowledge-base-id",
            "kb-123",
            "--max-tokens",
            "8192",
        ],
    )
    def test_cli_parses_model_kb_and_max_tokens(
        self, mock_config, mock_verify, mock_create_agent
    ):
        """CLI --bedrock-model-id, --knowledge-base-id, --max-tokens are parsed."""
        from mcp_server_for_oscal.oscal_agent import main

        mock_config.aws_profile = None
        mock_config.log_level = "INFO"
        mock_config.component_definitions_dir = "component_definitions"
        mock_config.agent_max_tokens = 4096

        mock_agent = MagicMock()
        mock_create_agent.return_value = mock_agent

        with patch("builtins.input", side_effect=EOFError):
            main()

        call_kwargs = mock_config.update_from_args.call_args[1]
        assert call_kwargs["bedrock_model_id"] == "anthropic.claude-v2"
        assert call_kwargs["knowledge_base_id"] == "kb-123"
        # max_tokens is set directly on config
        assert mock_config.agent_max_tokens == 8192

    @patch("mcp_server_for_oscal.oscal_agent.verify_package_integrity")
    @patch("mcp_server_for_oscal.oscal_agent.config")
    @patch("sys.argv", ["agent"])
    def test_exit_code_2_on_integrity_failure(self, mock_config, mock_verify):
        """SystemExit(2) raised when verify_package_integrity raises RuntimeError."""
        from mcp_server_for_oscal.oscal_agent import main

        mock_config.aws_profile = None
        mock_config.log_level = "INFO"
        mock_config.component_definitions_dir = "component_definitions"

        mock_verify.side_effect = RuntimeError("tampered content")

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 2

    @patch("mcp_server_for_oscal.oscal_agent.create_oscal_agent")
    @patch("mcp_server_for_oscal.oscal_agent.verify_package_integrity")
    @patch("mcp_server_for_oscal.oscal_agent.config")
    @patch("sys.argv", ["agent"])
    def test_keyboard_interrupt_handled_gracefully(
        self, mock_config, mock_verify, mock_create_agent
    ):
        """KeyboardInterrupt in the interactive loop exits without propagating."""
        from mcp_server_for_oscal.oscal_agent import main

        mock_config.aws_profile = None
        mock_config.log_level = "INFO"
        mock_config.component_definitions_dir = "component_definitions"
        mock_config.agent_max_tokens = 4096

        mock_agent = MagicMock()
        mock_create_agent.return_value = mock_agent

        with patch("builtins.input", side_effect=KeyboardInterrupt):
            # Should NOT raise — KeyboardInterrupt is caught internally
            main()

    @patch("mcp_server_for_oscal.oscal_agent.create_oscal_agent")
    @patch("mcp_server_for_oscal.oscal_agent.verify_package_integrity")
    @patch("mcp_server_for_oscal.oscal_agent.config")
    @patch("sys.argv", ["agent"])
    def test_exit_code_1_on_agent_creation_failure(
        self, mock_config, mock_verify, mock_create_agent
    ):
        """SystemExit(1) raised when create_oscal_agent raises ValueError."""
        from mcp_server_for_oscal.oscal_agent import main

        mock_config.aws_profile = None
        mock_config.log_level = "INFO"
        mock_config.component_definitions_dir = "component_definitions"

        mock_create_agent.side_effect = ValueError("bad model")

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# Task 3.2 — Property 1: Factory manager forwarding
# ---------------------------------------------------------------------------

# Strategy: generate either None or a unique mock object for each manager.
# We use st.booleans() to decide None vs mock, ensuring Hypothesis explores
# all four combinations (None/None, None/mock, mock/None, mock/mock).
_use_mock = st.booleans()


class TestProperty1FactoryManagerForwarding:
    """
    Property 1: Factory Manager Forwarding

    For any non-None mock session/conversation manager passed to
    create_oscal_agent(), the Agent constructor receives that exact
    object as the corresponding keyword argument. When None is passed
    (or the parameter is omitted), the corresponding keyword argument
    is absent from the Agent constructor call.

    **Validates: Requirements 1.1, 1.2, 2.1, 2.2**
    """

    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    @given(use_session=_use_mock, use_conversation=_use_mock)
    @patch("mcp_server_for_oscal.oscal_agent.ModelRetryStrategy")
    @patch("mcp_server_for_oscal.oscal_agent.Agent")
    @patch("mcp_server_for_oscal.oscal_agent.BedrockModel")
    @patch("mcp_server_for_oscal.oscal_agent.boto3.Session")
    def test_manager_forwarding(
        self,
        mock_boto_session_cls,
        mock_bedrock_cls,
        mock_agent_cls,
        mock_retry_cls,
        use_session,
        use_conversation,
    ):
        """
        Feature: agent-session-state, Property 1: Factory manager forwarding

        When session_manager or conversation_manager is non-None, Agent()
        receives that exact object; when None, the kwarg is absent.
        """
        # Build distinct sentinel objects so identity checks are meaningful
        session_mgr = Mock(name="session_manager") if use_session else None
        conversation_mgr = Mock(name="conversation_manager") if use_conversation else None

        create_oscal_agent(
            tools=[_make_mock_tool("t")],
            session_manager=session_mgr,
            conversation_manager=conversation_mgr,
        )

        agent_call_kwargs = mock_agent_cls.call_args[1]

        # --- session_manager ---
        if session_mgr is not None:
            assert "session_manager" in agent_call_kwargs, (
                "session_manager should be in Agent kwargs when non-None"
            )
            assert agent_call_kwargs["session_manager"] is session_mgr, (
                "Agent must receive the exact session_manager object"
            )
        else:
            assert "session_manager" not in agent_call_kwargs, (
                "session_manager should be absent from Agent kwargs when None"
            )

        # --- conversation_manager ---
        if conversation_mgr is not None:
            assert "conversation_manager" in agent_call_kwargs, (
                "conversation_manager should be in Agent kwargs when non-None"
            )
            assert agent_call_kwargs["conversation_manager"] is conversation_mgr, (
                "Agent must receive the exact conversation_manager object"
            )
        else:
            assert "conversation_manager" not in agent_call_kwargs, (
                "conversation_manager should be absent from Agent kwargs when None"
            )


# ---------------------------------------------------------------------------
# Task 3.3 — Unit tests for factory backward compatibility
# ---------------------------------------------------------------------------


class TestFactoryBackwardCompatibility:
    """
    Unit tests verifying that create_oscal_agent() remains backward-compatible.

    - No new args → Agent kwargs omit session_manager and conversation_manager.
    - Explicit session_manager/conversation_manager → passed through to Agent.

    **Validates: Requirements 1.2, 2.2, 8.3**
    """

    @patch("mcp_server_for_oscal.oscal_agent.ModelRetryStrategy")
    @patch("mcp_server_for_oscal.oscal_agent.Agent")
    @patch("mcp_server_for_oscal.oscal_agent.BedrockModel")
    @patch("mcp_server_for_oscal.oscal_agent.boto3.Session")
    def test_no_new_args_omits_session_and_conversation_manager(
        self,
        mock_boto_session_cls,
        mock_bedrock_cls,
        mock_agent_cls,
        mock_retry_cls,
    ):
        """Calling create_oscal_agent() with no new args produces Agent kwargs
        without session_manager or conversation_manager (Req 1.2, 2.2, 8.3)."""
        create_oscal_agent(tools=[_make_mock_tool("t")])

        agent_call_kwargs = mock_agent_cls.call_args[1]
        assert "session_manager" not in agent_call_kwargs, (
            "session_manager should be absent when not provided"
        )
        assert "conversation_manager" not in agent_call_kwargs, (
            "conversation_manager should be absent when not provided"
        )

    @patch("mcp_server_for_oscal.oscal_agent.ModelRetryStrategy")
    @patch("mcp_server_for_oscal.oscal_agent.Agent")
    @patch("mcp_server_for_oscal.oscal_agent.BedrockModel")
    @patch("mcp_server_for_oscal.oscal_agent.boto3.Session")
    def test_explicit_managers_passed_through(
        self,
        mock_boto_session_cls,
        mock_bedrock_cls,
        mock_agent_cls,
        mock_retry_cls,
    ):
        """Calling with explicit session_manager and conversation_manager passes
        them through to Agent kwargs (Req 1.2, 2.2, 8.3)."""
        mock_session_mgr = Mock(name="session_manager")
        mock_conversation_mgr = Mock(name="conversation_manager")

        create_oscal_agent(
            tools=[_make_mock_tool("t")],
            session_manager=mock_session_mgr,
            conversation_manager=mock_conversation_mgr,
        )

        agent_call_kwargs = mock_agent_cls.call_args[1]
        assert agent_call_kwargs["session_manager"] is mock_session_mgr, (
            "Agent must receive the exact session_manager object"
        )
        assert agent_call_kwargs["conversation_manager"] is mock_conversation_mgr, (
            "Agent must receive the exact conversation_manager object"
        )
