# Requirements Document

## Introduction

This feature enables publishing the `mcp-server-for-oscal` MCP server to the official MCP Registry at https://modelcontextprotocol.io/registry/. The MCP Registry is a metadata registry that points to packages hosted on PyPI, npm, Docker Hub, etc. Publishing involves creating a `server.json` metadata file, adding a PyPI ownership verification tag to the README, and automating the publish process via GitHub Actions using OIDC authentication under the `io.github.awslabs` namespace.

## Glossary

- **MCP_Registry**: The official Model Context Protocol server registry at https://modelcontextprotocol.io/registry/, a metadata catalog that indexes MCP servers and points to their distribution packages.
- **server.json**: A JSON metadata file in the project root conforming to the MCP Registry schema that describes the server's name, version, packages, and capabilities.
- **MCP_Publisher_CLI**: The `mcp-publisher` command-line tool used to validate and publish `server.json` to the MCP_Registry.
- **PyPI_Verification_Tag**: An HTML comment embedded in the package README containing `mcp-name: <SERVER_NAME>` that the MCP_Registry uses to verify PyPI package ownership.
- **GitHub_OIDC**: GitHub's OpenID Connect token-based authentication mechanism that allows GitHub Actions workflows to authenticate with external services without storing secrets.
- **Namespace**: A scoped identifier prefix in the MCP_Registry derived from the GitHub organization (e.g., `io.github.awslabs`).
- **Server_Name**: The fully qualified identifier for the server in the MCP_Registry, formatted as `io.github.awslabs/mcp-server-for-oscal`.
- **Hatch_VCS**: The hatch build plugin that derives the Python package version from git tags.
- **Release_Workflow**: The existing GitHub Actions workflow (`.github/workflows/release.yml`) triggered on GitHub release events that publishes the package to PyPI.

## Requirements

### Requirement 1: server.json Metadata File

**User Story:** As a maintainer, I want a `server.json` file in the project root that conforms to the MCP Registry schema, so that the MCP_Registry can index the server with accurate metadata.

#### Acceptance Criteria

1. THE server.json SHALL contain a `$schema` field pointing to `https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json`.
2. THE server.json SHALL contain a `name` field set to the Server_Name `io.github.awslabs/mcp-server-for-oscal`.
3. THE server.json SHALL contain `title`, `description`, and `version` fields describing the server.
4. THE server.json SHALL contain a `repository` object with `url` set to `https://github.com/awslabs/mcp-server-for-oscal` and `source` set to `github`.
5. THE server.json SHALL contain a `packages` array with at least one entry where `registryType` is `pypi`, `identifier` is `mcp-server-for-oscal`, and `transport` includes an entry with `type` set to `stdio`.
6. THE server.json SHALL be valid JSON that passes validation against the MCP Registry schema.

### Requirement 2: PyPI Ownership Verification

**User Story:** As a maintainer, I want the PyPI_Verification_Tag added to the README, so that the MCP_Registry can verify ownership of the `mcp-server-for-oscal` PyPI package.

#### Acceptance Criteria

1. THE README.md SHALL contain an HTML comment with the text `mcp-name: io.github.awslabs/mcp-server-for-oscal`.
2. THE PyPI_Verification_Tag in README.md SHALL match the `name` field in server.json exactly.
3. WHEN the package is built and published to PyPI, THE PyPI_Verification_Tag SHALL be present in the published package description visible to the MCP_Registry verification process.

### Requirement 3: Version Synchronization

**User Story:** As a maintainer, I want the version in `server.json` to stay in sync with the package version derived from git tags, so that the MCP_Registry always reflects the correct released version.

#### Acceptance Criteria

1. WHEN a new git tag is created and a GitHub release is published, THE Release_Workflow SHALL update the `version` field in server.json to match the release tag version before publishing to the MCP_Registry.
2. THE version in server.json `packages` entries SHALL match the top-level `version` field in server.json.
3. IF the version in server.json does not match the release tag, THEN THE Release_Workflow SHALL fail the MCP_Registry publish step and report the mismatch.

### Requirement 4: GitHub Actions MCP Registry Publish Workflow

**User Story:** As a maintainer, I want automated publishing to the MCP_Registry from GitHub Actions, so that new releases are indexed in the registry without manual intervention.

#### Acceptance Criteria

1. WHEN a GitHub release is published, THE Release_Workflow SHALL publish the server metadata to the MCP_Registry after the PyPI publish step completes successfully.
2. THE Release_Workflow SHALL authenticate with the MCP_Registry using GitHub_OIDC with the `id-token: write` permission.
3. THE Release_Workflow SHALL use the MCP_Publisher_CLI to publish server.json to the MCP_Registry.
4. IF the MCP_Registry publish step fails, THEN THE Release_Workflow SHALL report the failure without affecting the PyPI publish result.
5. THE Release_Workflow SHALL run the MCP_Registry publish step only after the PyPI publish step succeeds.

### Requirement 5: server.json Schema Compliance

**User Story:** As a maintainer, I want the CI pipeline to validate server.json against the MCP Registry schema, so that schema violations are caught before release.

#### Acceptance Criteria

1. WHEN a pull request is opened or updated, THE CI build workflow SHALL validate that server.json conforms to the MCP Registry schema.
2. IF server.json fails schema validation, THEN THE CI build workflow SHALL fail and report the validation errors.
3. THE CI build workflow SHALL validate server.json using the MCP_Publisher_CLI `validate` command or equivalent JSON schema validation.

### Requirement 6: server.json Environment Variables Documentation

**User Story:** As a user discovering the server through the MCP_Registry, I want the server.json to document optional environment variables, so that I can configure the server correctly.

#### Acceptance Criteria

1. WHERE the server supports optional environment variables, THE server.json SHALL document each variable in an `environmentVariables` field with its name and description.
2. THE server.json SHALL document the `BEDROCK_MODEL_ID`, `OSCAL_KB_ID`, `AWS_PROFILE`, `AWS_REGION`, and `LOG_LEVEL` environment variables.
3. THE server.json SHALL indicate which environment variables are required and which are optional.
