"""
Property-based tests for OSCAL MCP Server correctness properties.

Uses Hypothesis to generate random OSCAL-like data and verify that
the ComponentDefinitionStore correctly scopes queries when a
component_definition_filter is provided.

Feature: oscal-mcp-server
"""

import json
import uuid as uuid_mod
from pathlib import Path
from unittest.mock import Mock

import pytest
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

from mcp_server_for_oscal.tools.query_component_definition import (
    _store,
    query_component_definition,
)


# ---------------------------------------------------------------------------
# Hypothesis strategies for generating OSCAL-like test data
# ---------------------------------------------------------------------------

def _uuid() -> str:
    return str(uuid_mod.uuid4())


@st.composite
def oscal_component(draw):
    """Generate a single OSCAL DefinedComponent dict."""
    return {
        "uuid": _uuid(),
        "type": draw(st.sampled_from(["software", "service", "hardware", "policy"])),
        "title": draw(st.text(min_size=1, max_size=40, alphabet=st.characters(
            whitelist_categories=("L", "N", "Z"),
            whitelist_characters="-_ ",
        )).filter(lambda t: t.strip())),
        "description": "Generated component",
    }


@st.composite
def oscal_component_definition(draw, min_components=1, max_components=4):
    """Generate a full component-definition wrapper dict."""
    components = draw(
        st.lists(oscal_component(), min_size=min_components, max_size=max_components)
    )
    return {
        "component-definition": {
            "uuid": _uuid(),
            "metadata": {
                "title": draw(st.text(min_size=1, max_size=40, alphabet=st.characters(
                    whitelist_categories=("L", "N", "Z"),
                    whitelist_characters="-_ ",
                )).filter(lambda t: t.strip())),
                "last-modified": "2024-01-01T00:00:00Z",
                "version": "1.0",
                "oscal-version": "1.0.4",
            },
            "components": components,
        }
    }


def _mock_context():
    ctx = Mock()
    ctx.error = Mock()
    ctx.session = Mock()
    ctx.session.client_params = {}
    return ctx


# ---------------------------------------------------------------------------
# Property 16: Component Definition Filter Scoping
# ---------------------------------------------------------------------------

class TestProperty16ComponentDefinitionFilterScoping:
    """
    Property 16: Component Definition Filter Scoping

    For any valid Component Definition UUID or title used as
    component_definition_filter, the query should only search
    components within that specific Component Definition.

    Validates: Requirements 11.2
    """

    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    @given(
        cdef_a=oscal_component_definition(min_components=1, max_components=3),
        cdef_b=oscal_component_definition(min_components=1, max_components=3),
    )
    def test_filter_by_uuid_scopes_to_single_cdef(self, cdef_a, cdef_b, tmp_path_factory):
        """
        Feature: oscal-mcp-server, Property 16: Component Definition Filter Scoping

        When two distinct ComponentDefinitions are loaded and a query uses
        component_definition_filter with the UUID of cdef_a, only components
        belonging to cdef_a should appear in the results.
        """
        tmp_path = tmp_path_factory.mktemp("filter_uuid")
        comp_defs_dir = tmp_path / "cdefs"
        comp_defs_dir.mkdir()

        # Write both cdefs to disk
        (comp_defs_dir / "a.json").write_text(json.dumps(cdef_a))
        (comp_defs_dir / "b.json").write_text(json.dumps(cdef_b))

        # Load into the store
        _store._reset()
        _store.load_from_directory(comp_defs_dir)

        cdef_a_uuid = cdef_a["component-definition"]["uuid"]
        cdef_b_uuid = cdef_b["component-definition"]["uuid"]

        # Skip degenerate case where both cdefs got the same UUID (astronomically unlikely)
        if cdef_a_uuid == cdef_b_uuid:
            return

        ctx = _mock_context()

        # Query scoped to cdef_a by UUID
        result = query_component_definition(
            ctx=ctx,
            component_definition_filter=cdef_a_uuid,
            query_type="all",
            return_format="raw",
        )

        assert result["component_definitions_searched"] == 1
        assert result["filtered_by"] == cdef_a_uuid

        # Collect the UUIDs of components that belong to cdef_a
        expected_uuids = {
            c["uuid"] for c in cdef_a["component-definition"]["components"]
        }
        # Collect the UUIDs of components that belong to cdef_b
        excluded_uuids = {
            c["uuid"] for c in cdef_b["component-definition"]["components"]
        }

        returned_uuids = {c["uuid"] for c in result["components"]}

        # Every returned component must belong to cdef_a
        assert returned_uuids <= expected_uuids, (
            f"Returned components {returned_uuids - expected_uuids} "
            f"are not in the filtered Component Definition"
        )
        # No component from cdef_b should appear
        assert returned_uuids.isdisjoint(excluded_uuids), (
            f"Components from the other cdef leaked through the filter: "
            f"{returned_uuids & excluded_uuids}"
        )

    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    @given(
        cdef_a=oscal_component_definition(min_components=1, max_components=3),
        cdef_b=oscal_component_definition(min_components=1, max_components=3),
    )
    def test_filter_by_title_scopes_to_single_cdef(self, cdef_a, cdef_b, tmp_path_factory):
        """
        Feature: oscal-mcp-server, Property 16: Component Definition Filter Scoping

        When two distinct ComponentDefinitions are loaded and a query uses
        component_definition_filter with the title of cdef_a, only components
        belonging to cdef_a should appear in the results.
        """
        tmp_path = tmp_path_factory.mktemp("filter_title")
        comp_defs_dir = tmp_path / "cdefs"
        comp_defs_dir.mkdir()

        title_a = cdef_a["component-definition"]["metadata"]["title"]
        title_b = cdef_b["component-definition"]["metadata"]["title"]

        # Skip degenerate case where both cdefs have the same title (case-insensitive)
        if title_a.lower() == title_b.lower():
            return

        (comp_defs_dir / "a.json").write_text(json.dumps(cdef_a))
        (comp_defs_dir / "b.json").write_text(json.dumps(cdef_b))

        _store._reset()
        _store.load_from_directory(comp_defs_dir)

        ctx = _mock_context()

        result = query_component_definition(
            ctx=ctx,
            component_definition_filter=title_a,
            query_type="all",
            return_format="raw",
        )

        assert result["component_definitions_searched"] == 1
        assert result["filtered_by"] == title_a

        expected_uuids = {
            c["uuid"] for c in cdef_a["component-definition"]["components"]
        }
        excluded_uuids = {
            c["uuid"] for c in cdef_b["component-definition"]["components"]
        }

        returned_uuids = {c["uuid"] for c in result["components"]}

        assert returned_uuids <= expected_uuids
        assert returned_uuids.isdisjoint(excluded_uuids)

    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    @given(
        cdef_a=oscal_component_definition(min_components=1, max_components=3),
        cdef_b=oscal_component_definition(min_components=1, max_components=3),
    )
    def test_filter_scoping_with_by_uuid_query(self, cdef_a, cdef_b, tmp_path_factory):
        """
        Feature: oscal-mcp-server, Property 16: Component Definition Filter Scoping

        When querying by_uuid with a component_definition_filter, a component
        UUID from cdef_b should NOT be found when the filter points to cdef_a.
        """
        tmp_path = tmp_path_factory.mktemp("filter_scope_uuid_query")
        comp_defs_dir = tmp_path / "cdefs"
        comp_defs_dir.mkdir()

        cdef_a_uuid = cdef_a["component-definition"]["uuid"]
        cdef_b_uuid = cdef_b["component-definition"]["uuid"]

        if cdef_a_uuid == cdef_b_uuid:
            return

        (comp_defs_dir / "a.json").write_text(json.dumps(cdef_a))
        (comp_defs_dir / "b.json").write_text(json.dumps(cdef_b))

        _store._reset()
        _store.load_from_directory(comp_defs_dir)

        ctx = _mock_context()

        # Pick a component UUID from cdef_b
        comp_b_uuid = cdef_b["component-definition"]["components"][0]["uuid"]

        # Query scoped to cdef_a, searching for a component from cdef_b
        result = query_component_definition(
            ctx=ctx,
            component_definition_filter=cdef_a_uuid,
            query_type="by_uuid",
            query_value=comp_b_uuid,
            return_format="raw",
        )

        # The component from cdef_b must not appear in cdef_a-scoped results
        returned_uuids = {c["uuid"] for c in result["components"] if c}
        assert comp_b_uuid not in returned_uuids, (
            f"Component {comp_b_uuid} from cdef_b leaked through "
            f"the filter scoped to cdef_a"
        )
