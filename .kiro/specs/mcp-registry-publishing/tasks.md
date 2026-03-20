# Tasks: MCP Registry Publishing

## Task 1: Create server.json metadata file
- [x] 1.1 Create `server.json` in the project root with `$schema`, `name`, `title`, `description`, and `version` fields per the design Data Models section
- [x] 1.2 Add `repository` object with `url` and `source` fields
- [x] 1.3 Add `packages` array with PyPI entry including `registryType`, `name`, `version`, and `transport` with `stdio` type
- [x] 1.4 Add `environmentVariables` array inside the packages entry documenting `BEDROCK_MODEL_ID`, `OSCAL_KB_ID`, `AWS_PROFILE`, `AWS_REGION`, and `LOG_LEVEL` with `name`, `description`, and `required` fields

## Task 2: Add PyPI ownership verification tag to README
- [x] 2.1 Add `<!-- mcp-name: io.github.awslabs/mcp-server-for-oscal -->` HTML comment near the top of `README.md`

## Task 3: Update release workflow for MCP Registry publishing
- [x] 3.1 Add `mcp-registry-publish` job to `.github/workflows/release.yml` that depends on `pypi-publish` job
- [x] 3.2 Add `id-token: write` permission to the new job for GitHub OIDC authentication
- [x] 3.3 Add steps to extract version from release tag, update `server.json` version fields using `jq`, and validate the update
- [x] 3.4 Add step to publish to MCP Registry using `npx @anthropic-ai/mcp-publisher publish` with error isolation (continue-on-error or separate job failure handling)

## Task 4: Add server.json schema validation to CI build workflow
- [x] 4.1 Add a step to `.github/workflows/build.yml` that validates `server.json` against the MCP Registry schema using `npx @anthropic-ai/mcp-publisher validate` or equivalent

## Task 5: Write unit tests for static artifacts
- [x] 5.1 Create `tests/test_server_json.py` with tests verifying `server.json` required fields, values, and structure (Req 1.1–1.6)
- [x] 5.2 Create `tests/test_readme_verification.py` with test verifying README contains the PyPI verification HTML comment (Req 2.1)
- [x] 5.3 Create `tests/test_workflow_validation.py` with tests verifying release workflow has OIDC permissions, uses mcp-publisher, has error isolation, and correct job ordering (Req 4.2–4.5), and build workflow has validation step (Req 5.1, 5.3)

## Task 6: Write property-based tests
- [x] 6.1 Create `tests/test_mcp_registry_properties.py` with Property 1 test: version update consistency — for any valid semver, all version fields in server.json match after update (Req 3.1, 3.2) [PBT]
- [x] 6.2 Add Property 2 test: environment variable entry completeness — for any env var entry, it has non-empty name, description, and boolean required field (Req 6.1, 6.3) [PBT]
- [x] 6.3 Add Property 3 test: cross-file name consistency — the name extracted from README mcp-name comment matches server.json name field (Req 2.2) [PBT]
