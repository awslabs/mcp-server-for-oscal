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

### AWS Setup

To use the documentation query feature, you need:

1. **AWS Credentials**: Configure AWS credentials using AWS CLI, environment variables, or IAM roles
2. **Bedrock Access**: Ensure your AWS account has access to Amazon Bedrock
3. **Knowledge Base**: Optionally create an OSCAL knowledge base in Bedrock for enhanced documentation queries

## Usage

### Running the Server

Start the MCP server:

```bash
# Or using hatch (for development)
hatch run http-server

# With custom configuration
python -m mcp_server_for_oscal.main --aws-profile myprofile --log-level DEBUG
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

### Setup Development Environment

```bash

# Or using hatch
hatch shell
```

### Running Tests

```bash
# Run full test suite (invokes type checking, security scan, pytest, code coverage, etc.)
hatch run tests
```

### Code Quality

```bash
# Type checking
hatch run typing

# Opinionated linting and formatting using Ruff
hatch fmt
```

### Updating OSCAL Schemas

To update the bundled OSCAL schemas:

```bash
./bin/update-oscal-schemas.sh
```

## Project Structure

```
mcp-server-for-oscal/
├── src/mcp_server_for_oscal/
│   ├── main.py              # MCP server entry point
│   ├── config.py            # Configuration management
│   ├── oscal_schemas/       # Bundled OSCAL schemas
│   └── tools/               # MCP tool implementations
│       ├── query_documentation.py
│       ├── list_models.py
│       ├── get_schema.py
│       └── utils.py
├── tests/                   # Test suite
├── bin/                     # Utility scripts
└── requirements.txt         # Python dependencies
```

## Build system (Hatch)

This uses the [hatch](https://hatch.pypa.io/latest/) build system.

A number of scripts and commands exist in `pyproject.toml` under the `scripts`
configurations with more documentation in the comments of `pyproject.toml`.
Running a script for a specific environment is simply running 
`hatch run <env_name>:<script>`.  You can omit the `<env_name>` for those under
the `default` environment. 

`hatch run release`
This is the release command. It runs scripts to check typing (using mypy), and it 
also runs tests and coverage for those tests. 

`hatch test`
This is the test command. It runs the tests and runs coverage on those tests. 

`hatch typing`
This is the command to run typing. It runs mypy by default. 

`hatch fmt`
Formats your code using ruff.

