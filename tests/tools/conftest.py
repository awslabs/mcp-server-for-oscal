"""Shared fixtures for tools tests."""

import pytest


@pytest.fixture(autouse=True)
def reset_oscal_store():
    """Reset the OscalStore singleton before each test to prevent cross-test leakage.

    When test_query_oscal_models.py (or similar) calls init_store(), it sets
    _oscal_store at module level. If that module runs before
    test_query_component_definition.py, the legacy ComponentDefinitionStore
    tests break because the MCP wrappers delegate to the (empty) OscalStore
    instead of _store.
    """
    from mcp_server_for_oscal.tools import query_component_definition

    saved = query_component_definition._oscal_store
    query_component_definition._oscal_store = None
    yield
    query_component_definition._oscal_store = saved
