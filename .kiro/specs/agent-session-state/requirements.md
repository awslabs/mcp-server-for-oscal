# Requirements Document

## Introduction

Add session management, conversation persistence, and agent state to the OSCAL standalone agent (`oscal_agent.py`). The Strands SDK already provides `FileSessionManager`, `S3SessionManager`, `SlidingWindowConversationManager`, `SummarizingConversationManager`, and `agent.state` key-value storage. This feature wires those capabilities into the agent factory and CLI entry point so that conversation history and user context survive across invocations. The MCP server (`main.py`) is not affected.

## Glossary

- **Agent**: The Strands `Agent` instance created by `create_oscal_agent()` in `oscal_agent.py`.
- **Session_Manager**: A Strands SDK object (`FileSessionManager` or `S3SessionManager`) that persists and restores conversation history and agent state between invocations.
- **Conversation_Manager**: A Strands SDK object that controls how the message window is maintained during a single agent run (e.g., `SlidingWindowConversationManager`, `SummarizingConversationManager`, `NullConversationManager`).
- **Agent_State**: A JSON-serializable key-value store on `agent.state`, accessible from tools via `ToolContext`, persisted by the Session_Manager.
- **Session_ID**: A unique string identifier for a conversation session, either user-supplied via CLI or auto-generated as a UUID.
- **File_Session_Manager**: A Strands SDK `FileSessionManager` that stores session data on the local filesystem.
- **S3_Session_Manager**: A Strands SDK `S3SessionManager` that stores session data in an Amazon S3 bucket.
- **Summarizing_Conversation_Manager**: A Strands SDK `SummarizingConversationManager` that summarizes older messages to keep the context window manageable during long workflows.
- **CLI**: The `argparse`-based command-line interface in `oscal_agent.py:main()`.
- **MCP_Server**: The FastMCP server in `main.py`, which is out of scope for this feature.

## Requirements

### Requirement 1: Session Manager Parameter in Agent Factory

**User Story:** As a developer integrating the OSCAL agent, I want to pass an optional session manager to `create_oscal_agent()`, so that conversation history and agent state are persisted without modifying the factory internals.

#### Acceptance Criteria

1. WHEN a `session_manager` argument is provided to `create_oscal_agent()`, THE Agent SHALL be constructed with that Session_Manager instance.
2. WHEN no `session_manager` argument is provided to `create_oscal_agent()`, THE Agent SHALL be constructed without a Session_Manager (preserving current stateless behavior).
3. THE `create_oscal_agent()` function signature SHALL accept an optional `session_manager` parameter typed to the Strands SDK session manager protocol.

### Requirement 2: Conversation Manager Parameter in Agent Factory

**User Story:** As a developer integrating the OSCAL agent, I want to pass an optional conversation manager to `create_oscal_agent()`, so that I can control how the message window is maintained during long workflows.

#### Acceptance Criteria

1. WHEN a `conversation_manager` argument is provided to `create_oscal_agent()`, THE Agent SHALL be constructed with that Conversation_Manager instance.
2. WHEN no `conversation_manager` argument is provided to `create_oscal_agent()`, THE Agent SHALL be constructed without an explicit Conversation_Manager (preserving the SDK default sliding-window behavior).
3. THE `create_oscal_agent()` function signature SHALL accept an optional `conversation_manager` parameter typed to the Strands SDK conversation manager protocol.

### Requirement 3: CLI Session ID Argument

**User Story:** As an operator running the OSCAL agent from the command line, I want to specify a session ID so that I can resume a previous conversation.

#### Acceptance Criteria

1. THE CLI SHALL accept an optional `--session-id` argument of type string.
2. WHEN `--session-id` is provided, THE CLI SHALL use the provided value as the Session_ID for the Session_Manager.
3. WHEN `--session-id` is not provided and session persistence is enabled, THE CLI SHALL generate a UUID v4 as the Session_ID and log the generated value at INFO level.

### Requirement 4: CLI Session Storage Backend Selection

**User Story:** As an operator, I want to choose between local filesystem and S3 session storage so that I can use the backend appropriate for my environment.

#### Acceptance Criteria

1. THE CLI SHALL accept an optional `--session-storage` argument with allowed values `file` and `s3`.
2. WHEN `--session-storage` is `file`, THE CLI SHALL create a File_Session_Manager using a configurable local directory path.
3. WHEN `--session-storage` is `s3`, THE CLI SHALL create an S3_Session_Manager using a configurable S3 bucket name and optional prefix.
4. WHEN `--session-storage` is not provided, THE CLI SHALL not create a Session_Manager (stateless mode, preserving backward compatibility).
5. THE CLI SHALL accept an optional `--session-dir` argument specifying the local directory for File_Session_Manager storage (default: `.oscal_sessions` in the current working directory).
6. THE CLI SHALL accept an optional `--session-s3-bucket` argument specifying the S3 bucket for S3_Session_Manager storage.
7. THE CLI SHALL accept an optional `--session-s3-prefix` argument specifying the S3 key prefix for S3_Session_Manager storage (default: `oscal-agent-sessions/`).
8. IF `--session-storage` is `s3` and `--session-s3-bucket` is not provided, THEN THE CLI SHALL exit with a descriptive error message and non-zero exit code.

### Requirement 5: CLI Conversation Manager Selection

**User Story:** As an operator running long autonomous workflows, I want to select a summarizing conversation manager so that the agent context window stays manageable.

#### Acceptance Criteria

1. THE CLI SHALL accept an optional `--conversation-manager` argument with allowed values `sliding-window`, `summarizing`, and `null`.
2. WHEN `--conversation-manager` is `sliding-window`, THE CLI SHALL create a `SlidingWindowConversationManager` (the SDK default).
3. WHEN `--conversation-manager` is `summarizing`, THE CLI SHALL create a `SummarizingConversationManager`.
4. WHEN `--conversation-manager` is `null`, THE CLI SHALL create a `NullConversationManager`.
5. WHEN `--conversation-manager` is not provided, THE CLI SHALL not pass an explicit Conversation_Manager to the agent factory (preserving SDK default behavior).

### Requirement 6: Agent State Initialization

**User Story:** As a developer building OSCAL tools, I want the agent to have a state store available so that tools can track user context across calls within a session.

#### Acceptance Criteria

1. WHEN a Session_Manager is configured, THE Agent_State SHALL be available as a key-value store on the Agent instance.
2. THE Agent_State SHALL be JSON-serializable.
3. WHEN the agent session is saved by the Session_Manager, THE Agent_State SHALL be persisted alongside the conversation history.
4. WHEN the agent session is restored by the Session_Manager, THE Agent_State SHALL be restored to the values from the previous session.

### Requirement 7: Configuration Environment Variables

**User Story:** As an operator, I want to configure session defaults via environment variables so that I do not need to pass CLI arguments for every invocation.

#### Acceptance Criteria

1. THE Config class SHALL read an `OSCAL_AGENT_SESSION_STORAGE` environment variable with allowed values `file`, `s3`, or empty string.
2. THE Config class SHALL read an `OSCAL_AGENT_SESSION_DIR` environment variable for the File_Session_Manager directory path.
3. THE Config class SHALL read an `OSCAL_AGENT_SESSION_S3_BUCKET` environment variable for the S3_Session_Manager bucket name.
4. THE Config class SHALL read an `OSCAL_AGENT_SESSION_S3_PREFIX` environment variable for the S3_Session_Manager key prefix.
5. THE Config class SHALL read an `OSCAL_AGENT_CONVERSATION_MANAGER` environment variable with allowed values `sliding-window`, `summarizing`, `null`, or empty string.
6. WHEN both a CLI argument and an environment variable are set for the same setting, THE CLI argument SHALL take precedence over the environment variable.

### Requirement 8: MCP Server Isolation

**User Story:** As a developer maintaining the MCP server, I want session management changes to be isolated to the agent module so that the MCP server behavior is unaffected.

#### Acceptance Criteria

1. THE MCP_Server entry point (`main.py`) SHALL not import or reference any session management or conversation management classes.
2. THE MCP_Server behavior SHALL remain identical before and after this feature is implemented.
3. THE `create_oscal_agent()` function SHALL remain backward-compatible: existing callers that pass no session or conversation manager arguments SHALL observe identical behavior to the current implementation.

### Requirement 9: Session ID Logging and Discoverability

**User Story:** As an operator, I want to know which session ID is active so that I can resume the session later or debug issues.

#### Acceptance Criteria

1. WHEN a session is started in interactive mode, THE Agent SHALL log the active Session_ID at INFO level.
2. WHEN a session is started in interactive mode, THE Agent SHALL print the active Session_ID to stdout in a human-readable format before the first prompt.
3. WHEN a session is started in single-query mode (`--query`), THE Agent SHALL not print the Session_ID to stdout (to keep output clean for piping).
4. WHEN a session is started in single-query mode (`--query`), THE Agent SHALL log the active Session_ID at DEBUG level.
