# Implementation Plan: Agent Session State

## Overview

Wire Strands SDK session management, conversation management, and agent state into the OSCAL agent factory and CLI. All changes are isolated to `config.py`, `oscal_agent.py`, and their test files. No new dependencies required.

## Tasks

- [x] 1. Add session and conversation config attributes to `Config`
  - [x] 1.1 Add session/conversation environment variable attributes to `Config.__init__`
    - Add `session_storage` (from `OSCAL_AGENT_SESSION_STORAGE`, default `""`)
    - Add `session_dir` (from `OSCAL_AGENT_SESSION_DIR`, default `".oscal_sessions"`)
    - Add `session_s3_bucket` (from `OSCAL_AGENT_SESSION_S3_BUCKET`, default `""`)
    - Add `session_s3_prefix` (from `OSCAL_AGENT_SESSION_S3_PREFIX`, default `"oscal-agent-sessions/"`)
    - Add `conversation_manager_type` (from `OSCAL_AGENT_CONVERSATION_MANAGER`, default `""`)
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

  - [x] 1.2 Write unit tests for session/conversation config defaults
    - Verify all five new attributes have correct defaults when env vars are unset
    - Verify attributes match env var values when set
    - Add to `tests/test_config.py`
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

  - [x] 1.3 Write property test for session/conversation config env var parsing
    - **Property 2: Session/Conversation Config Environment Variable Parsing**
    - For any valid value of the five session/conversation env vars, constructing `Config` yields matching attributes
    - **Validates: Requirements 7.1, 7.2, 7.3, 7.4, 7.5**

- [x] 2. Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 3. Extend `create_oscal_agent()` with session and conversation manager parameters
  - [x] 3.1 Add `session_manager` and `conversation_manager` optional parameters to `create_oscal_agent()`
    - When not `None`, pass to `Agent(...)` constructor kwargs
    - When `None` (default), omit from kwargs entirely to preserve SDK defaults
    - Import no session/conversation classes in the factory — accept pre-built instances
    - _Requirements: 1.1, 1.2, 1.3, 2.1, 2.2, 2.3, 8.3_

  - [x] 3.2 Write property test for factory manager forwarding
    - **Property 1: Factory Manager Forwarding**
    - For any non-None mock session/conversation manager, `Agent()` receives that exact object; when `None`, the kwarg is absent
    - **Validates: Requirements 1.1, 1.2, 2.1, 2.2**

  - [x] 3.3 Write unit tests for factory backward compatibility
    - Calling `create_oscal_agent()` with no new args produces Agent kwargs without `session_manager` or `conversation_manager`
    - Calling with explicit `session_manager=mock` and `conversation_manager=mock` passes them through
    - Add to `tests/test_oscal_agent.py`
    - _Requirements: 1.2, 2.2, 8.3_

- [x] 4. Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Add CLI arguments and session/conversation manager construction in `main()`
  - [x] 5.1 Add new CLI arguments to `main()` argparse
    - `--session-id` (str, optional)
    - `--session-storage` (choices: `file`, `s3`, optional)
    - `--session-dir` (str, optional)
    - `--session-s3-bucket` (str, optional)
    - `--session-s3-prefix` (str, optional)
    - `--conversation-manager` (choices: `sliding-window`, `summarizing`, `null`, optional)
    - _Requirements: 3.1, 4.1, 4.5, 4.6, 4.7, 5.1_

  - [x] 5.2 Implement `_build_session_manager()` helper in `oscal_agent.py`
    - Resolve effective storage from CLI arg or config default (CLI wins)
    - Return `None` when storage is not set (stateless mode)
    - Create `FileSessionManager` for `file`, `S3SessionManager` for `s3`
    - Auto-generate UUID v4 session ID when `--session-id` is not provided
    - Exit with code 1 and descriptive error when `s3` is selected without `--session-s3-bucket`
    - _Requirements: 3.2, 3.3, 4.2, 4.3, 4.4, 4.8, 7.6_

  - [x] 5.3 Implement `_build_conversation_manager()` helper in `oscal_agent.py`
    - Resolve effective type from CLI arg or config default (CLI wins)
    - Return `None` when type is not set (SDK default behavior)
    - Create `SlidingWindowConversationManager`, `SummarizingConversationManager`, or `NullConversationManager`
    - _Requirements: 5.2, 5.3, 5.4, 5.5, 7.6_

  - [x] 5.4 Wire session/conversation managers into `main()` agent creation
    - Call `_build_session_manager()` and `_build_conversation_manager()` before `create_oscal_agent()`
    - Pass results to `create_oscal_agent(session_manager=..., conversation_manager=...)`
    - _Requirements: 1.1, 2.1, 6.1, 6.2, 6.3, 6.4_

  - [x] 5.5 Add session ID logging and discoverability in `main()`
    - Interactive mode: log session ID at INFO and print to stdout before first prompt
    - Single-query mode (`--query`): log session ID at DEBUG only, do not print to stdout
    - _Requirements: 9.1, 9.2, 9.3, 9.4_

  - [x] 5.6 Write unit tests for CLI argument parsing and manager construction
    - Test each new CLI arg is parsed correctly
    - Test `_build_session_manager()` returns correct types for `file`, `s3`, and `None`
    - Test `_build_session_manager()` exits with code 1 when `s3` without bucket
    - Test `_build_conversation_manager()` returns correct types for each choice and `None`
    - Test session ID auto-generation produces valid UUID v4
    - Test session ID logging: INFO + stdout in interactive, DEBUG only in query mode
    - Add to `tests/test_oscal_agent.py`
    - _Requirements: 3.1, 3.2, 3.3, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 5.1, 5.2, 5.3, 5.4, 5.5, 9.1, 9.2, 9.3, 9.4_

  - [x] 5.7 Write property test for CLI precedence over environment variables
    - **Property 3: CLI Precedence Over Environment Variables**
    - For any (env_var_value, cli_arg_value) pair, the effective value used equals the CLI arg value
    - **Validates: Requirements 7.6**

  - [x] 5.8 Write property test for session ID propagation
    - **Property 4: Session ID Propagation**
    - For any valid session ID string via `--session-id`, the session manager receives that exact string; when omitted, a valid UUID v4 is generated
    - **Validates: Requirements 3.2, 3.3**

- [x] 6. Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 7. MCP server isolation verification
  - [x] 7.1 Verify `main.py` does not import session/conversation manager classes
    - Inspect `main.py` source to confirm no session or conversation management references
    - Add a unit test in `tests/test_integration.py` that asserts `main.py` source does not contain session/conversation manager imports
    - _Requirements: 8.1, 8.2_

- [x] 8. Final checkpoint — Ensure all tests pass
  - Run `hatch run tests` to verify typing, all tests, coverage, and security scan pass.
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- All code is Python, using `pytest`, `hypothesis`, and `unittest.mock`
- Build/test command: `hatch run tests`
