# Requirements Document

## Introduction

The `oscal_agent.py` module contains a Strands agent (`create_oscal_agent`) that is not currently wired into the application. The agent was prototyped early but never integrated, and it has several issues that prevent production use: mutable global state, no error handling, no retry strategy, no observability, reliance on `load_tools_from_directory=True` (which won't find the project's tools), no `max_tokens` configuration, and no tests.

All existing MCP tools already use the `@tool` decorator from `strands-agents`, making them compatible with both the FastMCP server and a Strands agent. This refactoring will make the agent production-ready, explicitly wire it to the same tools the MCP server uses, add observability and resilience, and provide test coverage. Since the agent is unused, we can safely make breaking changes.

Additionally, the `main.py` module has accumulated a `_setup_tools()` function that manually imports and registers each tool. This is a maintenance burden that grows with every new tool. As part of this work, we will centralize the tool registry so both the MCP server and the Strands agent share a single source of truth for which tools are available.

## Glossary

- **OSCAL_Agent**: The Strands `Agent` instance configured with OSCAL-specific tools and system prompt, created by the `oscal_agent` module.
- **Tool_Registry**: A centralized list of tool functions that both the MCP server and the Strands agent consume, eliminating duplicate registration logic.
- **Retry_Strategy**: A `ModelRetryStrategy` configuration that handles Bedrock throttling with exponential backoff.
- **Agent_Hook**: A Strands `HookProvider` implementation that subscribes to agent lifecycle events for logging and observability.
- **Agent_Config**: The subset of `Config` attributes relevant to agent behavior (model ID, region, profile, max tokens, retry parameters).

## Requirements

### Requirement 1: Centralized tool registry

**User Story:** As a developer, I want a single source of truth for which tools are available, so that adding a new tool doesn't require updating both `main.py` and `oscal_agent.py` separately.

#### Acceptance Criteria

1. THE Tool_Registry SHALL be defined in `src/mcp_server_for_oscal/tools/__init__.py` as a function that returns the list of all tool functions.
2. THE Tool_Registry SHALL include all tools currently registered in `main.py::_setup_tools()`: `list_oscal_models`, `get_oscal_schema`, `list_oscal_resources`, `query_component_definition`, `list_component_definitions`, `list_components`, `list_capabilities`, `get_capability`, `validate_oscal_content`, `validate_oscal_file`.
3. THE Tool_Registry SHALL conditionally include `query_oscal_documentation` only when `config.knowledge_base_id` is set, preserving the current conditional registration behavior.
4. THE `main.py::_setup_tools()` function SHALL be refactored to consume the Tool_Registry instead of importing and registering tools individually.
5. THE OSCAL_Agent SHALL consume the same Tool_Registry to get its tool list, replacing `load_tools_from_directory=True`.
6. THE `about` tool currently defined inline in `main.py::_setup_tools()` SHALL remain MCP-server-only and SHALL NOT be included in the Tool_Registry (it is MCP metadata, not an OSCAL tool).

### Requirement 2: Remove global state from oscal_agent module

**User Story:** As a developer, I want the agent module to be stateless and testable, so that I can create agent instances in isolation without side effects.

#### Acceptance Criteria

1. THE module-level `agent: Agent` declaration and `global agent` usage SHALL be removed from `oscal_agent.py`.
2. THE `create_oscal_agent` function SHALL return an `Agent` instance without storing it in module-level state.
3. THE caller of `create_oscal_agent` SHALL be responsible for managing the agent's lifecycle.
4. THE `create_oscal_agent` function SHALL accept an optional `tools` parameter; WHEN omitted, it SHALL default to the Tool_Registry.

### Requirement 3: Error handling for agent creation

**User Story:** As an operator, I want clear error messages when the agent fails to initialize, so that I can diagnose credential, region, or model configuration problems quickly.

#### Acceptance Criteria

1. WHEN `create_oscal_agent` is called, it SHALL validate that the boto3 session can be created with the configured profile and region before constructing the Agent.
2. WHEN the boto3 session creation fails (e.g., invalid profile name), `create_oscal_agent` SHALL raise a `ValueError` with a message that includes the profile name and the underlying error.
3. WHEN the `BedrockModel` constructor fails (e.g., invalid model ID), `create_oscal_agent` SHALL raise a `ValueError` with a message that includes the model ID and the underlying error.
4. ALL exceptions raised by `create_oscal_agent` SHALL be logged at ERROR level before being raised.

### Requirement 4: Retry strategy for model throttling

**User Story:** As an operator, I want the agent to automatically retry when Bedrock rate-limits requests, so that transient throttling doesn't cause failures.

#### Acceptance Criteria

1. THE OSCAL_Agent SHALL be configured with a `ModelRetryStrategy`.
2. THE default retry configuration SHALL use `max_attempts=4`, `initial_delay=2`, and `max_delay=60`.
3. THE retry parameters SHALL be configurable via environment variables: `OSCAL_AGENT_MAX_RETRY_ATTEMPTS`, `OSCAL_AGENT_RETRY_INITIAL_DELAY`, `OSCAL_AGENT_RETRY_MAX_DELAY`.
4. WHEN all retry attempts are exhausted, the original `ModelThrottledException` SHALL propagate to the caller.

### Requirement 5: Max tokens configuration

**User Story:** As an operator, I want to control the maximum token output for the agent, so that I can manage costs and prevent runaway responses.

#### Acceptance Criteria

1. THE `BedrockModel` SHALL be configured with an explicit `max_tokens` value.
2. THE default `max_tokens` SHALL be 4096.
3. THE `max_tokens` value SHALL be configurable via the `OSCAL_AGENT_MAX_TOKENS` environment variable.
4. THE `Config` class SHALL include the `agent_max_tokens` attribute, loaded from the environment variable with the default value.

### Requirement 6: Observability via logging

**User Story:** As an operator, I want the agent to log key lifecycle events, so that I can monitor agent behavior, diagnose issues, and track tool usage in production.

#### Acceptance Criteria

1. WHEN the agent is created, `create_oscal_agent` SHALL log at INFO level the model ID, region, number of tools loaded, and whether retry is enabled.
2. WHEN the agent invokes a tool, the tool name and a truncated summary of arguments SHALL be logged at DEBUG level.
3. WHEN a model call completes, the stop reason and token usage (if available) SHALL be logged at DEBUG level.
4. WHEN a retry occurs due to throttling, the attempt number and delay SHALL be logged at WARNING level.
5. THE observability logic SHALL be implemented as a Strands `HookProvider` class in `oscal_agent.py` that registers callbacks for `BeforeToolCallEvent`, `AfterModelCallEvent`, and `AfterInvocationEvent`.

### Requirement 7: System prompt refinement

**User Story:** As a product owner, I want the agent's system prompt to include explicit behavioral boundaries, so that the agent stays focused on OSCAL and doesn't attempt tasks outside its scope.

#### Acceptance Criteria

1. THE system prompt SHALL retain the existing OSCAL domain expertise content.
2. THE system prompt SHALL add explicit instructions to decline requests unrelated to OSCAL, GRC, or compliance.
3. THE system prompt SHALL instruct the agent to prefer its OSCAL-specific tools over general knowledge for any OSCAL-related question.
4. THE system prompt SHALL instruct the agent to state when it doesn't have enough information rather than guessing.
5. THE system prompt SHALL reference the specific tool names available to the agent so the model knows what it can call.

### Requirement 8: Test coverage for oscal_agent module

**User Story:** As a developer, I want comprehensive tests for the agent module, so that I can refactor with confidence and catch regressions.

#### Acceptance Criteria

1. THERE SHALL be a test file `tests/test_oscal_agent.py` with unit tests for the `create_oscal_agent` function.
2. THE tests SHALL verify that `create_oscal_agent` returns an `Agent` instance with the correct system prompt.
3. THE tests SHALL verify that the agent is configured with tools from the Tool_Registry.
4. THE tests SHALL verify that the agent is configured with a `ModelRetryStrategy` matching the expected defaults.
5. THE tests SHALL verify that `create_oscal_agent` raises `ValueError` with a descriptive message when the boto3 session cannot be created (mocked failure).
6. THE tests SHALL verify that `create_oscal_agent` raises `ValueError` with a descriptive message when the BedrockModel cannot be created (mocked failure).
7. THE tests SHALL verify that the observability hook is registered on the agent.
8. THERE SHALL be a test file `tests/test_tool_registry.py` that verifies the Tool_Registry returns the expected set of tools and respects the conditional `query_oscal_documentation` inclusion.
9. ALL tests SHALL mock boto3 and BedrockModel to avoid requiring AWS credentials.

### Requirement 9: Clean up dead code in main.py

**User Story:** As a developer, I want `main.py` free of unused agent references, so that the codebase is clear about where the agent is managed.

#### Acceptance Criteria

1. THE `agent = None` global variable in `main.py` SHALL be removed.
2. THE `_setup_tools()` function in `main.py` SHALL be refactored to use the Tool_Registry, removing the manual per-tool imports and `mcp.add_tool()` calls for tools that are in the registry.
3. THE `about` tool SHALL remain defined inline in `main.py` since it is MCP-server-specific metadata.
4. THE refactored `main.py` SHALL pass all existing tests in `tests/test_main.py` without modification to those tests (or with minimal fixture updates if imports change).

### Requirement 10: Agent entry point

**User Story:** As a user, I want to run the OSCAL agent as a standalone interactive process, so that I can ask OSCAL questions directly without needing an MCP client.

#### Acceptance Criteria

1. THE `oscal_agent.py` module SHALL contain a `main()` function that serves as the agent's entry point.
2. THE `main()` function SHALL parse its own CLI arguments: `--aws-profile`, `--log-level`, `--bedrock-model-id`, `--knowledge-base-id`, and `--max-tokens`.
3. THE `main()` function SHALL configure logging using the same logger names and pattern as `main.py` (strands, trestle, package loggers).
4. THE `main()` function SHALL verify bundled content integrity using `verify_package_integrity` for `oscal_schemas`, `oscal_docs`, and `component_definitions` (if present), exiting with status code 2 on failure — same behavior as the MCP server entry point.
5. THE `main()` function SHALL call `create_oscal_agent()` and invoke the agent in a simple interactive loop that reads user input from stdin and prints agent responses to stdout.
6. THE `main()` function SHALL handle `KeyboardInterrupt` gracefully, logging shutdown and exiting cleanly.
7. A new `[project.scripts]` entry SHALL be added to `pyproject.toml`: `agent = "mcp_server_for_oscal.oscal_agent:main"`.
8. THE agent entry point SHALL NOT import or depend on the MCP server (`FastMCP`, `mcp.server.*`); it uses only the tool registry, config, and strands.
9. CLI argument parsing SHALL be local to `oscal_agent.py` — there SHALL NOT be a shared CLI module. Shared behavior (config loading, integrity verification) is consumed from `config.py` and `tools/utils.py` respectively.
