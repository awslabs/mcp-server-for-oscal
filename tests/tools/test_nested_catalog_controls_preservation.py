"""
Preservation property tests for nested catalog controls bugfix.

Property 2: Preservation - Non-Nested and Non-Catalog Behavior Unchanged

For any catalog where controls are only at the top level (not inside groups),
or for any non-catalog OSCAL model type, _extract_child_elements() SHALL
produce the same result as the original function, preserving all existing
extraction behavior.

Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5

These tests MUST PASS on the current UNFIXED code. They capture the existing
correct behavior that must be preserved after the fix is applied.
"""

import json
from pathlib import Path

import pytest
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

from mcp_server_for_oscal.tools.oscal_store import OscalStore
from mcp_server_for_oscal.tools.utils import OSCALModelType


# ---------------------------------------------------------------------------
# Common metadata for building valid OSCAL documents
# ---------------------------------------------------------------------------

_COMMON_METADATA = {
    "title": "Test Document",
    "last-modified": "2024-01-01T00:00:00Z",
    "version": "1.0",
    "oscal-version": "1.0.4",
}


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

@st.composite
def oscal_control_id(draw):
    """Generate a valid OSCAL control id string."""
    idx = draw(st.integers(min_value=1, max_value=999))
    return f"ctrl-{idx}"


@st.composite
def oscal_top_level_control(draw):
    """Generate a single top-level OSCAL control (no nested structure)."""
    ctrl_id = draw(oscal_control_id())
    return {"id": ctrl_id, "title": f"Control {ctrl_id}"}


@st.composite
def oscal_empty_group(draw):
    """Generate a group with NO controls and NO nested groups."""
    idx = draw(st.integers(min_value=1, max_value=99))
    return {"id": f"grp-{idx}", "title": f"Group grp-{idx}"}


@st.composite
def catalog_with_only_top_level_controls(draw):
    """Generate a catalog with only top-level controls and empty groups.

    This strategy produces catalogs where isBugCondition is FALSE:
    no group has controls or nested groups.
    """
    controls = draw(
        st.lists(oscal_top_level_control(), min_size=1, max_size=5)
    )
    groups = draw(
        st.lists(oscal_empty_group(), min_size=0, max_size=3)
    )

    catalog_dict = {
        "catalog": {
            "uuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "metadata": {**_COMMON_METADATA},
            "controls": controls,
        }
    }
    if groups:
        catalog_dict["catalog"]["groups"] = groups

    return catalog_dict


@st.composite
def valid_uuid(draw):
    """Generate a valid UUID v4 string."""
    parts = [
        draw(st.from_regex(r"[0-9a-f]{8}", fullmatch=True)),
        draw(st.from_regex(r"[0-9a-f]{4}", fullmatch=True)),
        "4" + draw(st.from_regex(r"[0-9a-f]{3}", fullmatch=True)),
        draw(st.sampled_from(["8", "9", "a", "b"]))
        + draw(st.from_regex(r"[0-9a-f]{3}", fullmatch=True)),
        draw(st.from_regex(r"[0-9a-f]{12}", fullmatch=True)),
    ]
    return "-".join(parts)


@st.composite
def component_definition_doc(draw):
    """Generate a valid OSCAL component definition with components."""
    num_components = draw(st.integers(min_value=1, max_value=3))
    components = []
    for i in range(num_components):
        comp_uuid = draw(valid_uuid())
        components.append({
            "uuid": comp_uuid,
            "type": "software",
            "title": f"Component {i + 1}",
            "description": f"Description for component {i + 1}",
        })

    return {
        "component-definition": {
            "uuid": draw(valid_uuid()),
            "metadata": {**_COMMON_METADATA},
            "components": components,
        }
    }


# ---------------------------------------------------------------------------
# Helper: ingest a document and return the parsed model
# ---------------------------------------------------------------------------

def _ingest_and_parse(store, tmp_path, doc_dict, filename="doc.json"):
    """Write a document JSON to disk, scan it, and return the parsed model."""
    doc_dir = tmp_path / "docs"
    doc_dir.mkdir(exist_ok=True)
    (doc_dir / filename).write_text(json.dumps(doc_dict))
    store.scan_directory(doc_dir)
    row = store._conn.execute("SELECT id FROM documents").fetchone()
    return store.get_parsed_model(row["id"])


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def store(tmp_path):
    """Create an OscalStore with an ephemeral DB in tmp_path."""
    db_path = str(tmp_path / "test.db")
    s = OscalStore(db_path=db_path, cache_size=10)
    yield s
    s.close()


# ---------------------------------------------------------------------------
# Property-based tests: Preservation
# ---------------------------------------------------------------------------

class TestPreservationTopLevelControls:
    """
    Property 2: Preservation - Top-level catalog controls are extracted correctly.

    For any catalog with only top-level controls (no controls inside groups),
    _extract_child_elements() SHALL extract every top-level control with
    element_type="control" and uuid matching the control's id.

    **Validates: Requirements 3.1, 3.2**
    """

    @settings(
        max_examples=30,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    @given(catalog_dict=catalog_with_only_top_level_controls())
    def test_top_level_controls_extracted(
        self, catalog_dict, tmp_path_factory
    ):
        """
        Property 2a: Top-level controls are extracted with element_type="control".

        **Validates: Requirements 3.1**
        """
        tmp_path = tmp_path_factory.mktemp("preserve_ctrl")
        db_path = str(tmp_path / "test.db")
        s = OscalStore(db_path=db_path, cache_size=10)
        try:
            model = _ingest_and_parse(s, tmp_path, catalog_dict)
            children = s._extract_child_elements(
                OSCALModelType.CATALOG, model
            )

            # All top-level control IDs must be in the extracted set
            expected_ctrl_ids = {
                c["id"]
                for c in catalog_dict["catalog"].get("controls", [])
            }
            extracted_ctrl_ids = {
                c["uuid"]
                for c in children
                if c["element_type"] == "control"
            }

            assert expected_ctrl_ids == extracted_ctrl_ids, (
                f"Top-level control extraction mismatch. "
                f"Expected {expected_ctrl_ids}, got {extracted_ctrl_ids}"
            )
        finally:
            s.close()

    @settings(
        max_examples=30,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    @given(catalog_dict=catalog_with_only_top_level_controls())
    def test_groups_extracted_as_group_type(
        self, catalog_dict, tmp_path_factory
    ):
        """
        Property 2b: Groups are extracted with element_type="group".

        **Validates: Requirements 3.2**
        """
        tmp_path = tmp_path_factory.mktemp("preserve_grp")
        db_path = str(tmp_path / "test.db")
        s = OscalStore(db_path=db_path, cache_size=10)
        try:
            model = _ingest_and_parse(s, tmp_path, catalog_dict)
            children = s._extract_child_elements(
                OSCALModelType.CATALOG, model
            )

            expected_group_ids = {
                g["id"]
                for g in catalog_dict["catalog"].get("groups", [])
            }
            extracted_group_ids = {
                c["uuid"]
                for c in children
                if c["element_type"] == "group"
            }

            assert expected_group_ids == extracted_group_ids, (
                f"Group extraction mismatch. "
                f"Expected {expected_group_ids}, got {extracted_group_ids}"
            )
        finally:
            s.close()

    @settings(
        max_examples=30,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    @given(catalog_dict=catalog_with_only_top_level_controls())
    def test_total_children_count_matches(
        self, catalog_dict, tmp_path_factory
    ):
        """
        Property 2c: Total children = number of top-level controls + groups.

        **Validates: Requirements 3.1, 3.2**
        """
        tmp_path = tmp_path_factory.mktemp("preserve_count")
        db_path = str(tmp_path / "test.db")
        s = OscalStore(db_path=db_path, cache_size=10)
        try:
            model = _ingest_and_parse(s, tmp_path, catalog_dict)
            children = s._extract_child_elements(
                OSCALModelType.CATALOG, model
            )

            expected_count = len(
                catalog_dict["catalog"].get("controls", [])
            ) + len(catalog_dict["catalog"].get("groups", []))

            assert len(children) == expected_count, (
                f"Children count mismatch. "
                f"Expected {expected_count}, got {len(children)}"
            )
        finally:
            s.close()


class TestPreservationComponentDefinition:
    """
    Property 2: Preservation - Component definition extraction is unchanged.

    For any component definition, _extract_child_elements() SHALL extract
    components with element_type="component".

    **Validates: Requirements 3.3**
    """

    @settings(
        max_examples=20,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    @given(comp_def_dict=component_definition_doc())
    def test_components_extracted(self, comp_def_dict, tmp_path_factory):
        """
        Property 2d: Component definition components are extracted correctly.

        **Validates: Requirements 3.3**
        """
        tmp_path = tmp_path_factory.mktemp("preserve_comp")
        db_path = str(tmp_path / "test.db")
        s = OscalStore(db_path=db_path, cache_size=10)
        try:
            model = _ingest_and_parse(s, tmp_path, comp_def_dict)
            children = s._extract_child_elements(
                OSCALModelType.COMPONENT_DEFINITION, model
            )

            expected_comp_uuids = {
                c["uuid"]
                for c in comp_def_dict["component-definition"]["components"]
            }
            extracted_comp_uuids = {
                c["uuid"]
                for c in children
                if c["element_type"] == "component"
            }

            assert expected_comp_uuids == extracted_comp_uuids, (
                f"Component extraction mismatch. "
                f"Expected {expected_comp_uuids}, got {extracted_comp_uuids}"
            )

            # All extracted children should be components
            for child in children:
                assert child["element_type"] == "component", (
                    f"Unexpected element_type: {child['element_type']}"
                )
        finally:
            s.close()


class TestPreservationEmptyCatalog:
    """
    Property 2: Preservation - Empty catalog returns empty list.

    **Validates: Requirements 3.4, 3.5**
    """

    def test_empty_catalog_returns_empty_list(self, store, tmp_path):
        """
        Concrete case: Catalog with no controls and no groups returns [].

        **Validates: Requirements 3.4, 3.5**
        """
        empty_cat = {
            "catalog": {
                "uuid": "cccccccc-dddd-4eee-8fff-aaaaaaaaaaaa",
                "metadata": {**_COMMON_METADATA},
            }
        }
        model = _ingest_and_parse(store, tmp_path, empty_cat)
        children = store._extract_child_elements(
            OSCALModelType.CATALOG, model
        )
        assert children == [], (
            f"Empty catalog should return [], got {children}"
        )

    def test_catalog_with_only_empty_groups(self, store, tmp_path):
        """
        Concrete case: Catalog with groups but no controls returns only groups.

        **Validates: Requirements 3.2, 3.5**
        """
        cat = {
            "catalog": {
                "uuid": "dddddddd-eeee-4fff-8aaa-bbbbbbbbbbbb",
                "metadata": {**_COMMON_METADATA},
                "groups": [
                    {"id": "grp-1", "title": "Empty Group 1"},
                    {"id": "grp-2", "title": "Empty Group 2"},
                ],
            }
        }
        model = _ingest_and_parse(store, tmp_path, cat)
        children = store._extract_child_elements(
            OSCALModelType.CATALOG, model
        )

        assert len(children) == 2
        for child in children:
            assert child["element_type"] == "group"

        extracted_ids = {c["uuid"] for c in children}
        assert extracted_ids == {"grp-1", "grp-2"}

    def test_nonexistent_element_returns_none(self, store, tmp_path):
        """
        Concrete case: get_child_element for non-existent ID returns None.

        **Validates: Requirements 3.5**
        """
        cat = {
            "catalog": {
                "uuid": "eeeeeeee-ffff-4aaa-8bbb-cccccccccccc",
                "metadata": {**_COMMON_METADATA},
                "controls": [
                    {"id": "ctrl-1", "title": "Control 1"},
                ],
            }
        }
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir(exist_ok=True)
        (doc_dir / "catalog.json").write_text(json.dumps(cat))
        store.scan_directory(doc_dir)
        row = store._conn.execute("SELECT id FROM documents").fetchone()

        # Ensure indexed
        store._ensure_indexed(row["id"])

        result = store.get_child_element(row["id"], "nonexistent-id")
        assert result is None, (
            f"Expected None for non-existent element, got {result}"
        )
