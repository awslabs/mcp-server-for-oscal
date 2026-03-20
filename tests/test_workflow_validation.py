"""
Tests for GitHub Actions workflow configuration.

Validates requirements 4.1–4.5 and 5.1, 5.3 from the MCP Registry Publishing spec.
"""

from pathlib import Path

import pytest
import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RELEASE_WORKFLOW_PATH = PROJECT_ROOT / ".github" / "workflows" / "release.yml"
BUILD_WORKFLOW_PATH = PROJECT_ROOT / ".github" / "workflows" / "build.yml"


@pytest.fixture
def release_workflow():
    """Load and parse the release workflow YAML."""
    text = RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")
    return yaml.safe_load(text)


@pytest.fixture
def build_workflow():
    """Load and parse the build workflow YAML."""
    text = BUILD_WORKFLOW_PATH.read_text(encoding="utf-8")
    return yaml.safe_load(text)


class TestReleaseWorkflowMcpRegistryJob:
    """Req 4.1: mcp-registry-publish job exists in release workflow."""

    def test_mcp_registry_publish_job_exists(self, release_workflow):
        jobs = release_workflow["jobs"]
        assert "mcp-registry-publish" in jobs, (
            "release.yml must contain a 'mcp-registry-publish' job"
        )


class TestReleaseWorkflowOidcPermissions:
    """Req 4.2: mcp-registry-publish job has id-token: write permission."""

    def test_id_token_write_permission(self, release_workflow):
        job = release_workflow["jobs"]["mcp-registry-publish"]
        permissions = job.get("permissions", {})
        assert permissions.get("id-token") == "write", (
            "mcp-registry-publish job must have 'id-token: write' permission"
        )


class TestReleaseWorkflowMcpPublisher:
    """Req 4.3: mcp-registry-publish job uses mcp-publisher CLI."""

    def test_uses_mcp_publisher(self, release_workflow):
        job = release_workflow["jobs"]["mcp-registry-publish"]
        steps = job.get("steps", [])
        has_mcp_publisher = any(
            "mcp-publisher" in str(step.get("run", ""))
            for step in steps
        )
        assert has_mcp_publisher, (
            "mcp-registry-publish job must use mcp-publisher in at least one step"
        )


class TestReleaseWorkflowErrorIsolation:
    """Req 4.4: mcp-registry-publish job has error isolation."""

    def test_has_continue_on_error(self, release_workflow):
        job = release_workflow["jobs"]["mcp-registry-publish"]
        steps = job.get("steps", [])
        has_error_isolation = any(
            step.get("continue-on-error") is True
            for step in steps
        )
        assert has_error_isolation, (
            "mcp-registry-publish job must have at least one step "
            "with continue-on-error: true"
        )


class TestReleaseWorkflowJobOrdering:
    """Req 4.5: mcp-registry-publish job depends on pypi-publish."""

    def test_needs_pypi_publish(self, release_workflow):
        job = release_workflow["jobs"]["mcp-registry-publish"]
        needs = job.get("needs", [])
        if isinstance(needs, str):
            needs = [needs]
        assert "pypi-publish" in needs, (
            "mcp-registry-publish job must depend on pypi-publish via 'needs'"
        )


class TestBuildWorkflowValidation:
    """Req 5.1, 5.3: Build workflow validates server.json."""

    def test_has_server_json_validation_step(self, build_workflow):
        jobs = build_workflow.get("jobs", {})
        found = False
        for job in jobs.values():
            steps = job.get("steps", [])
            for step in steps:
                step_name = str(step.get("name", "")).lower()
                step_run = str(step.get("run", "")).lower()
                if (
                    "mcp-publisher" in step_run and "validate" in step_run
                ) or (
                    "server.json" in step_name and "validat" in step_name
                ):
                    found = True
                    break
            if found:
                break
        assert found, (
            "build.yml must have a step that validates server.json "
            "using mcp-publisher validate or similar"
        )
