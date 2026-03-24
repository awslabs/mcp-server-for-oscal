# Developing MCP Server for OSCAL


### Install from Source

1. Clone the repository:
```bash
git clone https://github.com/awslabs/mcp-server-for-oscal.git
cd mcp-server-for-oscal
```

2. [Install Hatch](https://hatch.pypa.io/latest/install/). (e.g., `pipx install hatch`)

3. [Install uv](https://docs.astral.sh/uv/getting-started/installation/) (e.g., `pipx install uv`)

4. Setup the default environment and install project in dev mode
```bash
hatch env create
```

## Configuration

The server can be configured through environment variables or command-line arguments.

### Environment Variables

Create a `.env` file from the template and set the relevant values:
```
cp dotenv.example .env
```

See [dotenv.example](dotenv.example) for available options. Key environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `BEDROCK_MODEL_ID` | Bedrock model for agent features | `us.anthropic.claude-sonnet-4-20250514-v1:0` |
| `OSCAL_KB_ID` | AWS Bedrock Knowledge Base ID (enables `query_oscal_documentation`) | _(empty — tool not registered)_ |
| `AWS_PROFILE` | AWS profile for Bedrock access | _(default credentials)_ |
| `AWS_REGION` | AWS region | _(SDK default)_ |
| `LOG_LEVEL` | Server log level | `INFO` |
| `OSCAL_MCP_SERVER_NAME` | Server name | `OSCAL` |
| `OSCAL_MCP_TRANSPORT` | Transport protocol (`stdio` or `streamable-http`) | `stdio` |
| `OSCAL_MCP_HOST` | Server host (for streamable-http) | `127.0.0.1` |
| `OSCAL_MCP_STATELESS_HTTP` | Stateless HTTP mode | `false` |
| `OSCAL_ALLOW_REMOTE_URIS` | Allow `validate_oscal_file` to fetch remote URIs | `false` |
| `OSCAL_REQUEST_TIMEOUT` | Timeout for remote requests (seconds) | `30` |
| `OSCAL_MAX_URI_DEPTH` | Max URI depth for remote loading | `3` |
| `OSCAL_COMPONENT_DEFINITIONS_DIR` | Component definitions directory | `component_definitions` |
| `OSCAL_AGENT_MAX_TOKENS` | Agent max tokens | `4096` |
| `OSCAL_AGENT_MAX_RETRY_ATTEMPTS` | Agent retry attempts | `4` |
| `OSCAL_AGENT_RETRY_INITIAL_DELAY` | Initial retry delay (seconds) | `2` |
| `OSCAL_AGENT_RETRY_MAX_DELAY` | Max retry delay (seconds) | `60` |
| `OSCAL_AGENT_SESSION_STORAGE` | Session storage backend (`file` or `s3`) | _(empty — disabled)_ |
| `OSCAL_AGENT_SESSION_DIR` | Local directory for file-based session storage | `.oscal_sessions` |
| `OSCAL_AGENT_SESSION_S3_BUCKET` | S3 bucket for S3-based session storage | _(empty)_ |
| `OSCAL_AGENT_SESSION_S3_PREFIX` | S3 key prefix for session storage | `oscal-agent-sessions/` |
| `OSCAL_AGENT_CONVERSATION_MANAGER` | Conversation manager type (`sliding-window`, `summarizing`, or `null`) | _(empty — SDK default)_ |

### AWS Setup

To use the documentation query feature, you need:

1. **AWS Credentials**: Configure AWS credentials using AWS CLI, environment variables, or IAM roles
2. **Bedrock Access**: Ensure your AWS account has access to Amazon Bedrock
3. **Knowledge Base**: Optionally create an OSCAL knowledge base in Bedrock for enhanced documentation queries

## Usage

### Running the Server

Start the MCP server:

```bash
# Using hatch (for development, streamable-http transport)
hatch run http-server

# With custom configuration
python -m mcp_server_for_oscal.main --aws-profile myprofile --log-level DEBUG
```

### Running the Agent

The package also includes a standalone OSCAL agent (requires AWS Bedrock access):

```bash
# Via entry point
oscal-agent

# Or via module
python -m mcp_server_for_oscal.oscal_agent

# With session persistence (file-based)
oscal-agent --session-storage file

# Resume a previous session
oscal-agent --session-storage file --session-id <your-session-id>

# With S3 session storage
oscal-agent --session-storage s3 --session-s3-bucket my-bucket

# With conversation management
oscal-agent --session-storage file --conversation-manager summarizing
```

### Command Line Options

```bash
python -m mcp_server_for_oscal.main --help
```

Available options:
- `--aws-profile`: AWS profile name for authentication
- `--log-level`: Logging level (DEBUG, INFO, WARNING, ERROR)
- `--bedrock-model-id`: Override the Bedrock model ID
- `--knowledge-base-id`: Override the knowledge base ID

Agent-specific options (for `oscal-agent`):
- `--session-id`: Session ID for resuming a previous conversation
- `--session-storage`: Session storage backend (`file` or `s3`)
- `--session-dir`: Local directory for file-based session storage
- `--session-s3-bucket`: S3 bucket for S3-based session storage
- `--session-s3-prefix`: S3 key prefix for session storage
- `--conversation-manager`: Conversation manager type (`sliding-window`, `summarizing`, or `null`)
- `--query`: Run a single query and exit (non-interactive mode)
- `--max-tokens`: Maximum tokens for agent responses

### Setup Development Environment

```bash

# Or using hatch
hatch shell
```

### Running Tests

```bash
# Run full test suite (invokes type checking, security scan, pytest, code coverage, etc.)
hatch run tests

# Run a specific test
hatch test tests/tools/test_validate_oscal_content.py::TestValidateOscalContent
```

### Code Quality

```bash
# Type checking
hatch run typing

# Opinionated linting and formatting using Ruff
hatch fmt
```

### Updating Bundled Content

```bash
# Update bundled OSCAL schemas from NIST
hatch run update-oscal-schemas

# Regenerate hash manifests for bundled content
hatch run rehash
```

### Updating OSCAL Schemas

To update the bundled OSCAL schemas manually:

```bash
./bin/update-oscal-schemas.sh
```

## Project Structure

```
mcp-server-for-oscal/
├── src/mcp_server_for_oscal/
│   ├── __init__.py
│   ├── __main__.py            # Module entry point
│   ├── main.py                # MCP server setup, CLI arg parsing, startup integrity checks
│   ├── config.py              # Config class — loads env vars, CLI overrides, singleton config
│   ├── oscal_agent.py         # Strands agent integration
│   ├── oscal_schemas/         # Bundled OSCAL JSON & XSD schemas + hashes.json manifest
│   ├── oscal_docs/            # Bundled OSCAL documentation + hashes.json manifest
│   ├── component_definitions/ # Bundled AWS component definitions (zip) + hashes.json
│   └── tools/                 # MCP tool implementations (one tool per file)
│       ├── __init__.py        # get_tool_list() — canonical tool registry
│       ├── utils.py           # Shared: OSCALModelType enum, schema loading, hash verification
│       ├── get_schema.py
│       ├── list_models.py
│       ├── list_oscal_resources.py
│       ├── query_component_definition.py
│       ├── query_documentation.py
│       └── validate_oscal_content.py
├── tests/                     # Test suite (mirrors src structure)
│   ├── conftest.py            # Shared fixtures, pytest markers
│   ├── fixtures/              # JSON test fixtures
│   └── tools/                 # Per-tool test files
├── bin/                       # Utility scripts (update_hashes.py, update-oscal-schemas.sh)
├── conf/
│   ├── agentcore/             # Dockerfile for Bedrock AgentCore deployment (local dev only)
│   └── powers/oscal/          # Kiro Power config (POWER.md, mcp.json)
├── pyproject.toml             # Project metadata, dependencies, hatch config, tool settings
├── _version.py                # Auto-generated version file (hatch-vcs)
└── requirements.txt           # Pinned dependencies for reproducible builds
```

## Build system (Hatch)

This uses the [hatch](https://hatch.pypa.io/latest/) build system.

A number of scripts and commands exist in `pyproject.toml` under the `scripts`
configurations with more documentation in the comments of `pyproject.toml`.
Running a script for a specific environment is simply running 
`hatch run <env_name>:<script>`.  You can omit the `<env_name>` for those under
the `default` environment. 

`hatch run tests`
This is the primary test command. It runs typing (mypy), security scanning (bandit), pytest, and coverage.

`hatch run release`
This is the release command. It runs the full test suite and then builds the package.

`hatch test`
This runs pytest and coverage directly.

`hatch run typing`
This runs mypy for static type checking.

`hatch fmt`
Formats and lints your code using ruff.

`hatch run rehash`
Regenerates SHA-256 hash manifests for all bundled content directories.

`hatch run update-oscal-schemas`
Downloads and updates the bundled OSCAL schemas from NIST.

`hatch run http-server`
Starts the MCP server with `streamable-http` transport (development only).

