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
import uuid
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
        mock_config.agent_max_tokens = 4096

        mock_agent = MagicMock()
        mock_create_agent.return_value = mock_agent

        # Make input raise EOFError to exit the interactive loop immediately
        with patch("builtins.input", side_effect=EOFError):
            main()

        mock_config.update_from_args.assert_called_once()
        call_kwargs = mock_config.update_from_args.call_args[1]
        assert call_kwargs["log_level"] == "DEBUG"
        # Only oscal_schemas is verified (1 call, not 2)
        mock_verify.assert_called_once()

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
        # Only oscal_schemas is verified (1 call, not 2)
        mock_verify.assert_called_once()

    @patch("mcp_server_for_oscal.oscal_agent.verify_package_integrity")
    @patch("mcp_server_for_oscal.oscal_agent.config")
    @patch("sys.argv", ["agent"])
    def test_exit_code_2_on_integrity_failure(self, mock_config, mock_verify):
        """SystemExit(2) raised when verify_package_integrity raises RuntimeError.

        verify_package_integrity is called exactly once for oscal_schemas only.
        """
        from mcp_server_for_oscal.oscal_agent import main

        mock_config.aws_profile = None
        mock_config.log_level = "INFO"

        mock_verify.side_effect = RuntimeError("tampered content")

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 2
        # Only oscal_schemas is verified — oscal_docs and component_definitions removed
        mock_verify.assert_called_once()
        call_args = mock_verify.call_args[0][0]
        assert str(call_args).endswith("oscal_schemas")

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
        mock_config.agent_max_tokens = 4096

        mock_agent = MagicMock()
        mock_create_agent.return_value = mock_agent

        with patch("builtins.input", side_effect=KeyboardInterrupt):
            # Should NOT raise — KeyboardInterrupt is caught internally
            main()

        # Only oscal_schemas is verified (1 call, not 2)
        mock_verify.assert_called_once()

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

        mock_create_agent.side_effect = ValueError("bad model")

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1
        # Only oscal_schemas is verified (1 call, not 2)
        mock_verify.assert_called_once()

    # -----------------------------------------------------------------------
    # Task 5.5 — Session ID logging and discoverability (Req 9.1–9.4)
    # -----------------------------------------------------------------------

    @patch("mcp_server_for_oscal.oscal_agent.create_oscal_agent")
    @patch("mcp_server_for_oscal.oscal_agent._build_conversation_manager", return_value=None)
    @patch("mcp_server_for_oscal.oscal_agent._build_session_manager")
    @patch("mcp_server_for_oscal.oscal_agent.verify_package_integrity")
    @patch("mcp_server_for_oscal.oscal_agent.config")
    @patch("sys.argv", ["agent"])
    def test_interactive_mode_logs_session_id_at_info_and_prints(
        self,
        mock_config,
        mock_verify,
        mock_build_sm,
        mock_build_cm,
        mock_create_agent,
        caplog,
        capsys,
    ):
        """Req 9.1, 9.2: Interactive mode logs session ID at INFO and prints to stdout."""
        from mcp_server_for_oscal.oscal_agent import main

        mock_config.aws_profile = None
        mock_config.log_level = "INFO"
        mock_config.agent_max_tokens = 4096

        mock_build_sm.return_value = (MagicMock(), "test-session-abc")
        mock_create_agent.return_value = MagicMock()

        with patch("builtins.input", side_effect=EOFError):
            with caplog.at_level(logging.DEBUG, logger="mcp_server_for_oscal.oscal_agent"):
                main()

        # Verify INFO log contains session ID
        assert any(
            "Session ID: test-session-abc" in record.message
            and record.levelno == logging.INFO
            for record in caplog.records
        ), f"Expected INFO log with session ID, got: {[r.message for r in caplog.records]}"

        # Verify stdout contains session ID
        captured = capsys.readouterr()
        assert "Session ID: test-session-abc" in captured.out
        # Only oscal_schemas is verified (1 call, not 2)
        mock_verify.assert_called_once()

    @patch("mcp_server_for_oscal.oscal_agent.create_oscal_agent")
    @patch("mcp_server_for_oscal.oscal_agent._build_conversation_manager", return_value=None)
    @patch("mcp_server_for_oscal.oscal_agent._build_session_manager")
    @patch("mcp_server_for_oscal.oscal_agent.verify_package_integrity")
    @patch("mcp_server_for_oscal.oscal_agent.config")
    @patch("sys.argv", ["agent", "--query", "hello"])
    def test_query_mode_logs_session_id_at_debug_no_stdout(
        self,
        mock_config,
        mock_verify,
        mock_build_sm,
        mock_build_cm,
        mock_create_agent,
        caplog,
        capsys,
    ):
        """Req 9.3, 9.4: Query mode logs session ID at DEBUG, not printed to stdout."""
        from mcp_server_for_oscal.oscal_agent import main

        # Use DEBUG log level so the logger.debug() call is captured by caplog.
        mock_config.aws_profile = None
        mock_config.log_level = "DEBUG"
        mock_config.agent_max_tokens = 4096

        mock_build_sm.return_value = (MagicMock(), "test-session-xyz")
        mock_agent = MagicMock()
        mock_agent.return_value = "agent response"
        mock_create_agent.return_value = mock_agent

        with caplog.at_level(logging.DEBUG, logger="mcp_server_for_oscal.oscal_agent"):
            main()

        # Verify DEBUG log contains session ID (not INFO)
        session_logs = [
            r for r in caplog.records if "Session ID: test-session-xyz" in r.message
        ]
        assert len(session_logs) == 1, (
            f"Expected exactly one session ID log, got: "
            f"{[(r.levelno, r.message) for r in caplog.records]}"
        )
        assert session_logs[0].levelno == logging.DEBUG

        # Verify stdout does NOT contain "Session ID:" (only the agent response)
        captured = capsys.readouterr()
        assert "Session ID:" not in captured.out
        # Only oscal_schemas is verified (1 call, not 2)
        mock_verify.assert_called_once()

    @patch("mcp_server_for_oscal.oscal_agent.create_oscal_agent")
    @patch("mcp_server_for_oscal.oscal_agent._build_conversation_manager", return_value=None)
    @patch("mcp_server_for_oscal.oscal_agent._build_session_manager")
    @patch("mcp_server_for_oscal.oscal_agent.verify_package_integrity")
    @patch("mcp_server_for_oscal.oscal_agent.config")
    @patch("sys.argv", ["agent"])
    def test_no_session_manager_skips_session_id_logging(
        self,
        mock_config,
        mock_verify,
        mock_build_sm,
        mock_build_cm,
        mock_create_agent,
        caplog,
        capsys,
    ):
        """When no session manager is configured, no session ID is logged or printed."""
        from mcp_server_for_oscal.oscal_agent import main

        mock_config.aws_profile = None
        mock_config.log_level = "INFO"
        mock_config.agent_max_tokens = 4096

        mock_build_sm.return_value = (None, None)
        mock_create_agent.return_value = MagicMock()

        with patch("builtins.input", side_effect=EOFError):
            with caplog.at_level(logging.DEBUG, logger="mcp_server_for_oscal.oscal_agent"):
                main()

        # No "Session ID:" in logs
        assert not any(
            "Session ID:" in record.message for record in caplog.records
        ), f"Unexpected session ID log: {[r.message for r in caplog.records]}"

        # No "Session ID:" in stdout
        captured = capsys.readouterr()
        assert "Session ID:" not in captured.out
        # Only oscal_schemas is verified (1 call, not 2)
        mock_verify.assert_called_once()


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


# ---------------------------------------------------------------------------
# Task 5.6 — Unit tests for CLI argument parsing and manager construction
# ---------------------------------------------------------------------------


class TestBuildSessionManager:
    """Unit tests for _build_session_manager() helper.

    **Validates: Requirements 3.1, 3.2, 3.3, 4.1, 4.2, 4.3, 4.4, 4.8**
    """

    def _make_args(self, **overrides):
        """Build a minimal argparse-like namespace with session defaults."""
        defaults = {
            "session_id": None,
            "session_storage": None,
            "session_dir": None,
            "session_s3_bucket": None,
            "session_s3_prefix": None,
        }
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    def _make_config(self, **overrides):
        """Build a minimal config-like namespace with session defaults."""
        defaults = {
            "session_storage": "",
            "session_dir": ".oscal_sessions",
            "session_s3_bucket": "",
            "session_s3_prefix": "oscal-agent-sessions/",
        }
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    @patch("strands.session.FileSessionManager")
    def test_file_storage_returns_file_session_manager(self, mock_file_sm_cls):
        """--session-storage=file creates a FileSessionManager (Req 4.2)."""
        from mcp_server_for_oscal.oscal_agent import _build_session_manager

        sentinel = MagicMock(name="FileSessionManager_instance")
        mock_file_sm_cls.return_value = sentinel

        args = self._make_args(session_storage="file", session_id="my-session")
        cfg = self._make_config()

        sm, sid = _build_session_manager(args, cfg)

        mock_file_sm_cls.assert_called_once_with(
            session_id="my-session",
            storage_dir=".oscal_sessions",
        )
        assert sm is sentinel
        assert sid == "my-session"

    @patch("strands.session.S3SessionManager")
    def test_s3_storage_returns_s3_session_manager(self, mock_s3_sm_cls):
        """--session-storage=s3 with bucket creates an S3SessionManager (Req 4.3)."""
        from mcp_server_for_oscal.oscal_agent import _build_session_manager

        sentinel = MagicMock(name="S3SessionManager_instance")
        mock_s3_sm_cls.return_value = sentinel

        args = self._make_args(
            session_storage="s3",
            session_id="s3-session",
            session_s3_bucket="my-bucket",
            session_s3_prefix="prefix/",
        )
        cfg = self._make_config()

        sm, sid = _build_session_manager(args, cfg)

        mock_s3_sm_cls.assert_called_once_with(
            session_id="s3-session",
            bucket="my-bucket",
            prefix="prefix/",
        )
        assert sm is sentinel
        assert sid == "s3-session"

    def test_no_storage_returns_none(self):
        """No --session-storage and empty config returns (None, None) (Req 4.4)."""
        from mcp_server_for_oscal.oscal_agent import _build_session_manager

        args = self._make_args()
        cfg = self._make_config()

        sm, sid = _build_session_manager(args, cfg)

        assert sm is None
        assert sid is None

    def test_s3_without_bucket_exits_with_code_1(self):
        """--session-storage=s3 without bucket exits with code 1 (Req 4.8)."""
        from mcp_server_for_oscal.oscal_agent import _build_session_manager

        args = self._make_args(session_storage="s3", session_id="x")
        cfg = self._make_config()

        with pytest.raises(SystemExit) as exc_info:
            _build_session_manager(args, cfg)

        assert exc_info.value.code == 1

    @patch("strands.session.FileSessionManager")
    def test_auto_generates_uuid_v4_when_session_id_omitted(self, mock_file_sm_cls):
        """Auto-generates a valid UUID v4 when --session-id is not provided (Req 3.3)."""
        from mcp_server_for_oscal.oscal_agent import _build_session_manager

        args = self._make_args(session_storage="file")
        cfg = self._make_config()

        _, sid = _build_session_manager(args, cfg)

        # Validate it's a proper UUID v4
        parsed = uuid.UUID(sid, version=4)
        assert str(parsed) == sid
        assert parsed.version == 4

    @patch("strands.session.FileSessionManager")
    def test_cli_session_dir_overrides_config(self, mock_file_sm_cls):
        """CLI --session-dir overrides config.session_dir (Req 4.5)."""
        from mcp_server_for_oscal.oscal_agent import _build_session_manager

        args = self._make_args(
            session_storage="file",
            session_id="x",
            session_dir="/custom/dir",
        )
        cfg = self._make_config(session_dir="/default/dir")

        _build_session_manager(args, cfg)

        call_kwargs = mock_file_sm_cls.call_args[1]
        assert call_kwargs["storage_dir"] == "/custom/dir"

    @patch("strands.session.S3SessionManager")
    def test_cli_s3_prefix_overrides_config(self, mock_s3_sm_cls):
        """CLI --session-s3-prefix overrides config.session_s3_prefix (Req 4.7)."""
        from mcp_server_for_oscal.oscal_agent import _build_session_manager

        args = self._make_args(
            session_storage="s3",
            session_id="x",
            session_s3_bucket="bucket",
            session_s3_prefix="cli-prefix/",
        )
        cfg = self._make_config(session_s3_prefix="env-prefix/")

        _build_session_manager(args, cfg)

        call_kwargs = mock_s3_sm_cls.call_args[1]
        assert call_kwargs["prefix"] == "cli-prefix/"


class TestBuildConversationManager:
    """Unit tests for _build_conversation_manager() helper.

    **Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.5**
    """

    def _make_args(self, **overrides):
        defaults = {"conversation_manager": None}
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    def _make_config(self, **overrides):
        defaults = {"conversation_manager_type": ""}
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    @patch("strands.agent.conversation_manager.SlidingWindowConversationManager")
    def test_sliding_window_returns_correct_type(self, mock_sw_cls):
        """--conversation-manager=sliding-window creates SlidingWindowConversationManager (Req 5.2)."""
        from mcp_server_for_oscal.oscal_agent import _build_conversation_manager

        sentinel = MagicMock(name="SlidingWindowCM")
        mock_sw_cls.return_value = sentinel

        args = self._make_args(conversation_manager="sliding-window")
        cfg = self._make_config()

        result = _build_conversation_manager(args, cfg)

        mock_sw_cls.assert_called_once()
        assert result is sentinel

    @patch("strands.agent.conversation_manager.SummarizingConversationManager")
    def test_summarizing_returns_correct_type(self, mock_sum_cls):
        """--conversation-manager=summarizing creates SummarizingConversationManager (Req 5.3)."""
        from mcp_server_for_oscal.oscal_agent import _build_conversation_manager

        sentinel = MagicMock(name="SummarizingCM")
        mock_sum_cls.return_value = sentinel

        args = self._make_args(conversation_manager="summarizing")
        cfg = self._make_config()

        result = _build_conversation_manager(args, cfg)

        mock_sum_cls.assert_called_once()
        assert result is sentinel

    @patch("strands.agent.conversation_manager.NullConversationManager")
    def test_null_returns_correct_type(self, mock_null_cls):
        """--conversation-manager=null creates NullConversationManager (Req 5.4)."""
        from mcp_server_for_oscal.oscal_agent import _build_conversation_manager

        sentinel = MagicMock(name="NullCM")
        mock_null_cls.return_value = sentinel

        args = self._make_args(conversation_manager="null")
        cfg = self._make_config()

        result = _build_conversation_manager(args, cfg)

        mock_null_cls.assert_called_once()
        assert result is sentinel

    def test_no_conversation_manager_returns_none(self):
        """No --conversation-manager and empty config returns None (Req 5.5)."""
        from mcp_server_for_oscal.oscal_agent import _build_conversation_manager

        args = self._make_args()
        cfg = self._make_config()

        result = _build_conversation_manager(args, cfg)

        assert result is None

    @patch("strands.agent.conversation_manager.SummarizingConversationManager")
    def test_config_default_used_when_cli_not_set(self, mock_sum_cls):
        """Config conversation_manager_type is used when CLI arg is None (Req 5.3, 7.5)."""
        from mcp_server_for_oscal.oscal_agent import _build_conversation_manager

        sentinel = MagicMock(name="SummarizingCM")
        mock_sum_cls.return_value = sentinel

        args = self._make_args()  # conversation_manager=None
        cfg = self._make_config(conversation_manager_type="summarizing")

        result = _build_conversation_manager(args, cfg)

        mock_sum_cls.assert_called_once()
        assert result is sentinel


class TestCLISessionArgParsing:
    """Unit tests for CLI argument parsing of session/conversation args.

    **Validates: Requirements 3.1, 4.1, 4.5, 4.6, 4.7, 5.1**
    """

    @patch("mcp_server_for_oscal.oscal_agent.create_oscal_agent")
    @patch("mcp_server_for_oscal.oscal_agent._build_conversation_manager", return_value=None)
    @patch("mcp_server_for_oscal.oscal_agent._build_session_manager", return_value=(None, None))
    @patch("mcp_server_for_oscal.oscal_agent.verify_package_integrity")
    @patch("mcp_server_for_oscal.oscal_agent.config")
    @patch(
        "sys.argv",
        [
            "agent",
            "--session-id", "abc-123",
            "--session-storage", "file",
            "--session-dir", "/tmp/sessions",
            "--conversation-manager", "summarizing",
        ],
    )
    def test_session_args_parsed_and_forwarded(
        self,
        mock_config,
        mock_verify,
        mock_build_sm,
        mock_build_cm,
        mock_create_agent,
    ):
        """All session/conversation CLI args are parsed and forwarded to builders (Req 3.1, 4.1, 5.1)."""
        from mcp_server_for_oscal.oscal_agent import main

        mock_config.aws_profile = None
        mock_config.log_level = "INFO"
        mock_config.agent_max_tokens = 4096

        mock_create_agent.return_value = MagicMock()

        with patch("builtins.input", side_effect=EOFError):
            main()

        # Verify _build_session_manager was called with parsed args
        sm_call_args = mock_build_sm.call_args[0][0]  # first positional arg = args namespace
        assert sm_call_args.session_id == "abc-123"
        assert sm_call_args.session_storage == "file"
        assert sm_call_args.session_dir == "/tmp/sessions"

        # Verify _build_conversation_manager was called with parsed args
        cm_call_args = mock_build_cm.call_args[0][0]
        assert cm_call_args.conversation_manager == "summarizing"
        # Only oscal_schemas is verified (1 call, not 2)
        mock_verify.assert_called_once()

    @patch("mcp_server_for_oscal.oscal_agent.create_oscal_agent")
    @patch("mcp_server_for_oscal.oscal_agent._build_conversation_manager", return_value=None)
    @patch("mcp_server_for_oscal.oscal_agent._build_session_manager", return_value=(None, None))
    @patch("mcp_server_for_oscal.oscal_agent.verify_package_integrity")
    @patch("mcp_server_for_oscal.oscal_agent.config")
    @patch(
        "sys.argv",
        [
            "agent",
            "--session-storage", "s3",
            "--session-s3-bucket", "my-bucket",
            "--session-s3-prefix", "my-prefix/",
        ],
    )
    def test_s3_args_parsed_correctly(
        self,
        mock_config,
        mock_verify,
        mock_build_sm,
        mock_build_cm,
        mock_create_agent,
    ):
        """S3-specific CLI args are parsed correctly (Req 4.6, 4.7)."""
        from mcp_server_for_oscal.oscal_agent import main

        mock_config.aws_profile = None
        mock_config.log_level = "INFO"
        mock_config.agent_max_tokens = 4096

        mock_create_agent.return_value = MagicMock()

        with patch("builtins.input", side_effect=EOFError):
            main()

        sm_call_args = mock_build_sm.call_args[0][0]
        assert sm_call_args.session_storage == "s3"
        assert sm_call_args.session_s3_bucket == "my-bucket"
        assert sm_call_args.session_s3_prefix == "my-prefix/"
        # Only oscal_schemas is verified (1 call, not 2)
        mock_verify.assert_called_once()

    @patch("mcp_server_for_oscal.oscal_agent.create_oscal_agent")
    @patch("mcp_server_for_oscal.oscal_agent._build_conversation_manager", return_value=None)
    @patch("mcp_server_for_oscal.oscal_agent._build_session_manager", return_value=(None, None))
    @patch("mcp_server_for_oscal.oscal_agent.verify_package_integrity")
    @patch("mcp_server_for_oscal.oscal_agent.config")
    @patch("sys.argv", ["agent"])
    def test_session_args_default_to_none(
        self,
        mock_config,
        mock_verify,
        mock_build_sm,
        mock_build_cm,
        mock_create_agent,
    ):
        """Session/conversation args default to None when not provided (Req 4.4, 5.5)."""
        from mcp_server_for_oscal.oscal_agent import main

        mock_config.aws_profile = None
        mock_config.log_level = "INFO"
        mock_config.agent_max_tokens = 4096

        mock_create_agent.return_value = MagicMock()

        with patch("builtins.input", side_effect=EOFError):
            main()

        sm_call_args = mock_build_sm.call_args[0][0]
        assert sm_call_args.session_id is None
        assert sm_call_args.session_storage is None
        assert sm_call_args.session_dir is None
        assert sm_call_args.session_s3_bucket is None
        assert sm_call_args.session_s3_prefix is None
        assert sm_call_args.conversation_manager is None
        # Only oscal_schemas is verified (1 call, not 2)
        mock_verify.assert_called_once()


# ---------------------------------------------------------------------------
# Task 5.7 — Property 3: CLI Precedence Over Environment Variables
# ---------------------------------------------------------------------------

# Strategy for generating non-empty strings suitable for config/CLI values.
# We use printable characters and filter out empty/whitespace-only strings
# to ensure both CLI and config values are "truthy" (non-empty).
_nonempty_text = st.text(
    min_size=1,
    max_size=40,
    alphabet=st.characters(
        whitelist_categories=("L", "N", "P"),
        blacklist_characters="\x00/\\",
    ),
).filter(lambda t: t.strip())

# Strategy for conversation manager types (valid choices)
_cm_types = st.sampled_from(["sliding-window", "summarizing", "null"])


class TestProperty3CLIPrecedenceOverEnvVars:
    """
    Property 3: CLI Precedence Over Environment Variables

    For any (env_var_value, cli_arg_value) pair, when both are set
    (non-empty), the effective value used to construct the
    session/conversation manager equals the CLI argument value,
    not the environment variable value.

    **Validates: Requirements 7.6**
    """

    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    @given(
        cli_session_dir=_nonempty_text,
        config_session_dir=_nonempty_text,
    )
    @patch("strands.session.FileSessionManager")
    def test_cli_session_dir_wins_over_config(
        self,
        mock_file_sm_cls,
        cli_session_dir,
        config_session_dir,
    ):
        """
        Feature: agent-session-state, Property 3: CLI precedence over env vars

        When both CLI --session-dir and config.session_dir are set,
        FileSessionManager receives the CLI value.
        """
        from mcp_server_for_oscal.oscal_agent import _build_session_manager

        args = SimpleNamespace(
            session_id="fixed-id",
            session_storage="file",
            session_dir=cli_session_dir,
            session_s3_bucket=None,
            session_s3_prefix=None,
        )
        cfg = SimpleNamespace(
            session_storage="file",
            session_dir=config_session_dir,
            session_s3_bucket="",
            session_s3_prefix="oscal-agent-sessions/",
        )

        _build_session_manager(args, cfg)

        call_kwargs = mock_file_sm_cls.call_args[1]
        assert call_kwargs["storage_dir"] == cli_session_dir, (
            f"Expected CLI value '{cli_session_dir}', "
            f"got '{call_kwargs['storage_dir']}' "
            f"(config was '{config_session_dir}')"
        )

    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    @given(
        cli_cm_type=_cm_types,
        config_cm_type=_cm_types,
    )
    def test_cli_conversation_manager_wins_over_config(
        self,
        cli_cm_type,
        config_cm_type,
    ):
        """
        Feature: agent-session-state, Property 3: CLI precedence over env vars

        When both CLI --conversation-manager and config.conversation_manager_type
        are set, the conversation manager type used equals the CLI value.
        """
        from mcp_server_for_oscal.oscal_agent import _build_conversation_manager

        args = SimpleNamespace(conversation_manager=cli_cm_type)
        cfg = SimpleNamespace(conversation_manager_type=config_cm_type)

        # Map type to expected class name
        type_to_class = {
            "sliding-window": "SlidingWindowConversationManager",
            "summarizing": "SummarizingConversationManager",
            "null": "NullConversationManager",
        }

        with patch("strands.agent.conversation_manager.SlidingWindowConversationManager") as mock_sw, \
             patch("strands.agent.conversation_manager.SummarizingConversationManager") as mock_sum, \
             patch("strands.agent.conversation_manager.NullConversationManager") as mock_null:

            mock_sw.return_value = MagicMock(name="SlidingWindowCM")
            mock_sum.return_value = MagicMock(name="SummarizingCM")
            mock_null.return_value = MagicMock(name="NullCM")

            result = _build_conversation_manager(args, cfg)

            # The CLI type should determine which class was instantiated
            expected_class = type_to_class[cli_cm_type]
            mock_map = {
                "SlidingWindowConversationManager": mock_sw,
                "SummarizingConversationManager": mock_sum,
                "NullConversationManager": mock_null,
            }

            assert mock_map[expected_class].called, (
                f"Expected {expected_class} to be called for CLI type '{cli_cm_type}', "
                f"but it was not (config type was '{config_cm_type}')"
            )
            assert result is mock_map[expected_class].return_value

    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    @given(
        cli_storage=st.sampled_from(["file", "s3"]),
        config_storage=st.sampled_from(["file", "s3"]),
    )
    def test_cli_session_storage_wins_over_config(
        self,
        cli_storage,
        config_storage,
    ):
        """
        Feature: agent-session-state, Property 3: CLI precedence over env vars

        When both CLI --session-storage and config.session_storage are set,
        the storage type used equals the CLI value.
        """
        from mcp_server_for_oscal.oscal_agent import _build_session_manager

        args = SimpleNamespace(
            session_id="fixed-id",
            session_storage=cli_storage,
            session_dir="/cli/dir",
            session_s3_bucket="cli-bucket",
            session_s3_prefix="cli-prefix/",
        )
        cfg = SimpleNamespace(
            session_storage=config_storage,
            session_dir="/config/dir",
            session_s3_bucket="config-bucket",
            session_s3_prefix="config-prefix/",
        )

        with patch("strands.session.FileSessionManager") as mock_file, \
             patch("strands.session.S3SessionManager") as mock_s3:

            mock_file.return_value = MagicMock(name="FileSM")
            mock_s3.return_value = MagicMock(name="S3SM")

            _build_session_manager(args, cfg)

            if cli_storage == "file":
                assert mock_file.called, (
                    f"Expected FileSessionManager for CLI storage '{cli_storage}', "
                    f"but it was not called (config was '{config_storage}')"
                )
            else:
                assert mock_s3.called, (
                    f"Expected S3SessionManager for CLI storage '{cli_storage}', "
                    f"but it was not called (config was '{config_storage}')"
                )


# ---------------------------------------------------------------------------
# Task 5.8 — Property 4: Session ID Propagation
# ---------------------------------------------------------------------------

# Strategy for generating non-empty session ID strings.
_session_id_text = st.text(
    min_size=1,
    max_size=60,
    alphabet=st.characters(
        whitelist_categories=("L", "N", "P"),
        blacklist_characters="\x00",
    ),
).filter(lambda t: t.strip())


class TestProperty4SessionIDPropagation:
    """
    Property 4: Session ID Propagation

    For any valid session ID string provided via --session-id, the session
    manager constructed by _build_session_manager() receives that exact
    string as its session ID. When no --session-id is provided and session
    storage is enabled, the generated session ID is a valid UUID v4 string.

    **Validates: Requirements 3.2, 3.3**
    """

    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    @given(session_id=_session_id_text)
    @patch("strands.session.FileSessionManager")
    def test_provided_session_id_propagated_to_session_manager(
        self,
        mock_file_sm_cls,
        session_id,
    ):
        """
        Feature: agent-session-state, Property 4: Session ID propagation

        When session_id is provided (non-empty string), FileSessionManager
        receives that exact string as its session_id argument.
        """
        from mcp_server_for_oscal.oscal_agent import _build_session_manager

        args = SimpleNamespace(
            session_id=session_id,
            session_storage="file",
            session_dir=None,
            session_s3_bucket=None,
            session_s3_prefix=None,
        )
        cfg = SimpleNamespace(
            session_storage="file",
            session_dir=".oscal_sessions",
            session_s3_bucket="",
            session_s3_prefix="oscal-agent-sessions/",
        )

        sm, returned_sid = _build_session_manager(args, cfg)

        # The returned session_id must be the exact string provided
        assert returned_sid == session_id, (
            f"Expected returned session_id '{session_id}', got '{returned_sid}'"
        )

        # FileSessionManager must have been called with the exact session_id
        call_kwargs = mock_file_sm_cls.call_args[1]
        assert call_kwargs["session_id"] == session_id, (
            f"Expected FileSessionManager session_id '{session_id}', "
            f"got '{call_kwargs['session_id']}'"
        )

    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    @given(data=st.data())
    @patch("strands.session.FileSessionManager")
    def test_omitted_session_id_generates_valid_uuid_v4(
        self,
        mock_file_sm_cls,
        data,
    ):
        """
        Feature: agent-session-state, Property 4: Session ID propagation

        When session_id is None (omitted), the returned session_id is a
        valid UUID v4 string.
        """
        from mcp_server_for_oscal.oscal_agent import _build_session_manager

        args = SimpleNamespace(
            session_id=None,
            session_storage="file",
            session_dir=None,
            session_s3_bucket=None,
            session_s3_prefix=None,
        )
        cfg = SimpleNamespace(
            session_storage="file",
            session_dir=".oscal_sessions",
            session_s3_bucket="",
            session_s3_prefix="oscal-agent-sessions/",
        )

        _, returned_sid = _build_session_manager(args, cfg)

        # Must be a valid UUID v4
        assert returned_sid is not None, "Session ID should not be None when storage is enabled"
        parsed = uuid.UUID(returned_sid, version=4)
        assert str(parsed) == returned_sid, (
            f"Session ID '{returned_sid}' is not a canonical UUID v4 string"
        )
        assert parsed.version == 4, (
            f"Expected UUID version 4, got version {parsed.version}"
        )

        # FileSessionManager must have received the same UUID
        call_kwargs = mock_file_sm_cls.call_args[1]
        assert call_kwargs["session_id"] == returned_sid, (
            f"FileSessionManager received '{call_kwargs['session_id']}' "
            f"but returned session_id was '{returned_sid}'"
        )
