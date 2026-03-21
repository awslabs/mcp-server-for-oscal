# Implementation Plan: OSCAL Agent Production

## Overview

Refactor the `oscal_agent.py` module from an unused prototype into a production-ready Strands agent. Centralize the tool registry so both the MCP server and agent share a single source of truth. Add error handling, retry strategy, observability, config extensions, test coverage, and a standalone agent entry point. Changes span `tools/__init__.py`, `config.py`, `oscal_agent.py`, `main.py`, `pyproject.toml`, and two new test files.

## Tasks

- [x] 1. Implement centralized tool registry in `tools/__init__.py`
  - [x] 1.1 Create `get_tool_list()` function in `src/mcp_server_for_oscal/tools/__init__.py`
    - Import all 10 tool functions from their respective modules
    - Return them as a list
    - Conditionally include `query_oscal_documentation` only when `config.knowledge_base_id` is set
    - Exclude the `about` tool (MCP-server-only)
    - _Requirements: 1.1, 1.2, 1.3, 1.6_

  - [x]* 1.2 Write property test for conditional tool inclusion
    - **Property 1: Conditional tool inclusion**
    - Generate random non-empty and empty strings for `knowledge_base_id`, patch `config.knowledge_base_id`, call `get_tool_list()`, verify `query_oscal_documentation` is present iff KB ID is non-empty, and all 10 base tools are always present
    - **Validates: Requirements 1.2, 1.3**

  - [x]* 1.3 Write unit tests for tool registry in `tests/test_tool_registry.py`
    - Test `get_tool_list()` returns all 10 base tools
    - Test `get_tool_list()` excludes `about`
    - Test `get_tool_list()` includes `query_oscal_documentation` when KB ID is set
    - Test `get_tool_list()` excludes `query_oscal_documentation` when KB ID is empty
    - _Requirements: 8.8_

- [x] 2. Extend `Config` class with agent-specific attributes
  - [x] 2.1 Add agent config attributes to `src/mcp_server_for_oscal/config.py`
    - Add `agent_max_tokens` (env: `OSCAL_AGENT_MAX_TOKENS`, default: `4096`)
    - Add `agent_max_retry_attempts` (env: `OSCAL_AGENT_MAX_RETRY_ATTEMPTS`, default: `4`)
    - Add `agent_retry_initial_delay` (env: `OSCAL_AGENT_RETRY_INITIAL_DELAY`, default: `2`)
    - Add `agent_retry_max_delay` (env: `OSCAL_AGENT_RETRY_MAX_DELAY`, default: `60`)
    - _Requirements: 4.3, 5.3, 5.4_

  - [x]* 2.2 Write property test for agent config env var parsing
    - **Property 3: Agent config environment variable parsing**
    - Generate random positive integers, set agent env vars, construct `Config`, verify attributes match
    - **Validates: Requirements 4.3, 5.3**

  - [x]* 2.3 Write unit tests for new config attributes in `tests/test_config.py`
    - Test defaults: `agent_max_tokens=4096`, `agent_max_retry_attempts=4`, `agent_retry_initial_delay=2`, `agent_retry_max_delay=60`
    - _Requirements: 5.4, 4.3_

- [x] 3. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Rewrite `oscal_agent.py` as production-ready agent factory
  - [x] 4.1 Remove global state and implement `create_oscal_agent()` factory
    - Remove module-level `agent: Agent` declaration and `global agent` usage
    - `create_oscal_agent(tools=None)` returns an `Agent` without storing module state
    - Accept optional `tools` parameter; default to `get_tool_list()` from the registry
    - Create boto3 session with `config.aws_profile` and `config.aws_region`; wrap failures in `ValueError` with profile name and original error
    - Create `BedrockModel` with `config.bedrock_model_id` and `config.agent_max_tokens`; wrap failures in `ValueError` with model ID and original error
    - Log all errors at ERROR level before raising
    - Configure `ModelRetryStrategy` with `config.agent_max_retry_attempts`, `config.agent_retry_initial_delay`, `config.agent_retry_max_delay`
    - Log at INFO level on successful creation: model ID, region, tool count, retry enabled
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 3.1, 3.2, 3.3, 3.4, 4.1, 4.2, 4.4, 5.1, 5.2, 6.1_

  - [x] 4.2 Implement `AgentObservabilityHook` class
    - Implement as a Strands `HookProvider` in `oscal_agent.py`
    - Handle `BeforeToolCallEvent`: log tool name + truncated args at DEBUG
    - Handle `AfterModelCallEvent`: log stop reason + token usage at DEBUG
    - Handle `AfterInvocationEvent`: log completion at DEBUG
    - Log retry/throttle events at WARNING (attempt number + delay)
    - Register the hook on the Agent instance in `create_oscal_agent()`
    - _Requirements: 6.2, 6.3, 6.4, 6.5_

  - [x] 4.3 Refine the system prompt
    - Retain existing OSCAL domain expertise content
    - Add explicit instruction to decline non-OSCAL/GRC/compliance requests
    - Add instruction to prefer OSCAL tools over general knowledge
    - Add instruction to state uncertainty rather than guess
    - Dynamically inject tool names from the tool list into the prompt
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

  - [x]* 4.4 Write property test for error context propagation
    - **Property 2: Error context propagation**
    - Generate random profile names/model IDs and error messages, mock boto3/BedrockModel to raise, verify `ValueError` contains both identifiers
    - **Validates: Requirements 3.2, 3.3**

  - [x]* 4.5 Write property test for hook event logging completeness
    - **Property 4: Hook event logging completeness**
    - Generate random tool names and argument dicts, fire `BeforeToolCallEvent`, verify DEBUG log contains tool name; generate random stop reasons, fire `AfterModelCallEvent`, verify DEBUG log contains stop reason
    - **Validates: Requirements 6.2, 6.3**

  - [x]* 4.6 Write property test for system prompt tool name inclusion
    - **Property 5: System prompt tool name inclusion**
    - Generate random lists of mock tool functions with known `__name__` attributes, call `create_oscal_agent(tools=...)`, verify system prompt contains each tool name
    - **Validates: Requirements 7.5**

  - [x]* 4.7 Write unit tests for `create_oscal_agent` in `tests/test_oscal_agent.py`
    - Test returns an `Agent` instance with correct system prompt content
    - Test agent configured with tools from Tool_Registry
    - Test `ModelRetryStrategy` defaults (4, 2, 60)
    - Test `max_tokens=4096` default
    - Test custom `tools` parameter overrides registry
    - Test `ValueError` raised on boto3 session failure (mocked) with descriptive message
    - Test `ValueError` raised on BedrockModel failure (mocked) with descriptive message
    - Test ERROR log emitted before raising
    - Test `AgentObservabilityHook` is registered on the agent
    - Test no module-level `agent` attribute exists
    - All tests mock boto3 and BedrockModel
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.9_

- [x] 5. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 6. Refactor `main.py` to use tool registry and remove dead code
  - [x] 6.1 Refactor `_setup_tools()` to consume `get_tool_list()`
    - Replace manual per-tool imports and `mcp.add_tool()` calls with a loop over `get_tool_list()`
    - Keep the `about` tool defined inline (MCP-server-specific)
    - Remove the `agent = None` global variable
    - _Requirements: 1.4, 9.1, 9.2, 9.3_

  - [x]* 6.2 Verify existing `tests/test_main.py` still passes
    - Run existing tests; make minimal fixture updates only if import paths changed
    - _Requirements: 9.4_

- [x] 7. Implement agent entry point in `oscal_agent.py`
  - [x] 7.1 Add `main()` function to `oscal_agent.py`
    - Parse CLI args: `--aws-profile`, `--log-level`, `--bedrock-model-id`, `--knowledge-base-id`, `--max-tokens`
    - Configure logging using same logger names and pattern as `main.py`
    - Verify bundled content integrity (`oscal_schemas`, `oscal_docs`, `component_definitions` if present); exit with code 2 on failure
    - Call `create_oscal_agent()` and run interactive stdin/stdout loop
    - Handle `KeyboardInterrupt` gracefully (log + clean exit)
    - Handle agent creation `ValueError` → log + `SystemExit(1)`
    - Do NOT import FastMCP or `mcp.server.*`
    - CLI parsing is local to `oscal_agent.py` — no shared CLI module
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.8, 10.9_

  - [x] 7.2 Add `agent` entry point to `pyproject.toml`
    - Add `agent = "mcp_server_for_oscal.oscal_agent:main"` under `[project.scripts]`
    - _Requirements: 10.7_

  - [x]* 7.3 Write unit tests for agent entry point
    - Test CLI argument parsing
    - Test exit code 2 on integrity verification failure
    - Test `KeyboardInterrupt` handled gracefully
    - All tests mock boto3, BedrockModel, and stdin
    - _Requirements: 8.1, 10.2, 10.4, 10.6_

- [x] 8. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- All tests mock boto3 and BedrockModel to avoid requiring AWS credentials
