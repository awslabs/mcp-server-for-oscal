"""
Bug condition exploration test for nested catalog controls.

Property 1: Bug Condition - Nested Controls Are Extracted

For any catalog where controls exist inside groups (at any nesting depth),
_extract_child_elements() SHALL extract every such control into the
child_elements list with element_type="control", making them queryable.

Validates: Requirements 1.1, 1.2, 1.5

CRITICAL: This test is EXPECTED TO FAIL on unfixed code — failure confirms
the bug exists. DO NOT fix the test or the code when it fails.
"""

import json
from pathlib import Path

import pytest
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

from mcp_server_for_oscal.tools.oscal_store import OscalStore
from mcp_server_for_oscal.tools.utils import OSCALModelType


# ---------------------------------------------------------------------------
# Common metadata for building valid OSCAL catalogs
# ---------------------------------------------------------------------------

_COMMON_METADATA = {
    "title": "Test Catalog",
    "last-modified": "2024-01-01T00:00:00Z",
    "version": "1.0",
    "oscal-version": "1.0.4",
}


# ---------------------------------------------------------------------------
# Hypothesis strategies for generating catalogs with nested controls
# ---------------------------------------------------------------------------

@st.composite
def oscal_control(draw, prefix="ctrl"):
    """Generate a single OSCAL control dict with a unique id."""
    idx = draw(st.integers(min_value=1, max_value=999))
    return {
        "id": f"{prefix}-{idx}",
        "title": f"Control {prefix}-{idx}",
    }


@st.composite
def oscal_group_with_controls(draw, depth=0, max_depth=2):
    """Generate a group with EITHER controls OR nested groups (not both).

    Trestle uses a discriminated union for catalog groups: Group2 accepts
    ``controls`` but forbids ``groups``, while Group1 accepts ``groups``
    but forbids ``controls``.  This strategy respects that constraint by
    drawing a boolean to decide which variant to produce when nesting is
    still possible.  At max_depth the group always carries controls
    (leaf node).
    """
    group_idx = draw(st.integers(min_value=1, max_value=99))
    group_id = f"grp-d{depth}-{group_idx}"

    group = {
        "id": group_id,
        "title": f"Group {group_id}",
    }

    if depth < max_depth:
        # Decide: True → controls (leaf-like), False → nested groups
        has_controls = draw(st.booleans())
        if has_controls:
            controls = draw(
                st.lists(
                    oscal_control(prefix=f"g{depth}-{group_idx}"),
                    min_size=1,
                    max_size=3,
                )
            )
            group["controls"] = controls
        else:
            nested_groups = draw(
                st.lists(
                    oscal_group_with_controls(
                        depth=depth + 1, max_depth=max_depth
                    ),
                    min_size=1,
                    max_size=2,
                )
            )
            group["groups"] = nested_groups
    else:
        # Leaf level — must have controls
        controls = draw(
            st.lists(
                oscal_control(prefix=f"g{depth}-{group_idx}"),
                min_size=1,
                max_size=3,
            )
        )
        group["controls"] = controls

    return group


@st.composite
def catalog_with_nested_controls(draw):
    """Generate a catalog with controls nested inside groups.

    This strategy always produces catalogs where isBugCondition is true:
    at least one group has non-empty controls or nested groups.
    """
    groups = draw(
        st.lists(
            oscal_group_with_controls(depth=0, max_depth=2),
            min_size=1,
            max_size=3,
        )
    )

    # Optionally include top-level controls too
    top_level_controls = draw(
        st.lists(oscal_control(prefix="top"), min_size=0, max_size=2)
    )

    catalog_dict = {
        "catalog": {
            "uuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "metadata": {**_COMMON_METADATA},
            "groups": groups,
        }
    }
    if top_level_controls:
        catalog_dict["catalog"]["controls"] = top_level_controls

    return catalog_dict


# ---------------------------------------------------------------------------
# Helper: recursively collect all control IDs from groups
# ---------------------------------------------------------------------------

def _collect_all_control_ids_from_groups(groups):
    """Recursively collect all control IDs from a list of groups."""
    ids = set()
    for group in groups:
        for ctrl in group.get("controls", []):
            ids.add(ctrl["id"])
        for nested_group in group.get("groups", []):
            ids.update(_collect_all_control_ids_from_groups([nested_group]))
    return ids


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def store(tmp_path):
    """Create an OscalStore with an ephemeral DB in tmp_path."""
    db_path = str(tmp_path / "test.db")
    s = OscalStore(db_path=db_path, cache_size=10, seed_from_bundled=False)
    yield s
    s.close()


# ---------------------------------------------------------------------------
# Helper: ingest a catalog dict and return the parsed model
# ---------------------------------------------------------------------------

def _ingest_and_parse(store, tmp_path, catalog_dict):
    """Write a catalog JSON to disk, scan it, and return the parsed model."""
    doc_dir = tmp_path / "docs"
    doc_dir.mkdir(exist_ok=True)
    (doc_dir / "catalog.json").write_text(json.dumps(catalog_dict))
    store.scan_directory(doc_dir)
    row = store._conn.execute("SELECT id FROM documents").fetchone()
    return store.get_parsed_model(row["id"])


# ---------------------------------------------------------------------------
# Property-based test: Bug Condition - Nested Controls Are Extracted
# ---------------------------------------------------------------------------

class TestBugConditionNestedControlsExtracted:
    """
    Property 1: Bug Condition - Nested Controls Are Extracted

    For any catalog where controls exist inside groups (at any nesting
    depth), _extract_child_elements() SHALL extract every such control
    with element_type="control" and uuid matching the control's id.

    **Validates: Requirements 1.1, 1.2, 1.5**
    """

    @settings(
        max_examples=50,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    @given(catalog_dict=catalog_with_nested_controls())
    def test_all_nested_controls_extracted(
        self, catalog_dict, tmp_path_factory
    ):
        """
        Property 1: Bug Condition - Nested Controls Are Extracted

        Every control at every nesting level within groups must appear
        in the _extract_child_elements result with element_type="control"
        and uuid matching the control's id.

        **Validates: Requirements 1.1, 1.2, 1.5**
        """
        tmp_path = tmp_path_factory.mktemp("nested_ctrl")
        db_path = str(tmp_path / "test.db")
        s = OscalStore(db_path=db_path, cache_size=10, seed_from_bundled=False)
        try:
            model = _ingest_and_parse(s, tmp_path, catalog_dict)
            children = s._extract_child_elements(
                OSCALModelType.CATALOG, model
            )

            # Collect all control IDs from groups (nested at any depth)
            groups = catalog_dict["catalog"].get("groups", [])
            expected_nested_ids = _collect_all_control_ids_from_groups(groups)

            # Collect all top-level control IDs
            top_level_ids = {
                c["id"]
                for c in catalog_dict["catalog"].get("controls", [])
            }

            # All expected IDs (top-level + nested)
            all_expected_ids = expected_nested_ids | top_level_ids

            # Extracted control IDs
            extracted_control_ids = {
                c["uuid"]
                for c in children
                if c["element_type"] == "control"
            }

            # Every expected control must be in the extracted set
            missing = all_expected_ids - extracted_control_ids
            assert not missing, (
                f"Controls missing from extraction: {missing}. "
                f"Expected all of {all_expected_ids}, "
                f"got {extracted_control_ids}"
            )
        finally:
            s.close()

    # ------------------------------------------------------------------
    # Concrete failing cases
    # ------------------------------------------------------------------

    def test_single_level_nested_control(self, store, tmp_path):
        """
        Concrete case: Catalog with groups[0].controls = [ctrl_a].
        ctrl_a must appear in children.

        **Validates: Requirements 1.1, 1.2, 1.5**
        """
        catalog_dict = {
            "catalog": {
                "uuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "metadata": {**_COMMON_METADATA},
                "groups": [
                    {
                        "id": "grp-1",
                        "title": "Group 1",
                        "controls": [
                            {"id": "ctrl-a", "title": "Control A"},
                        ],
                    }
                ],
            }
        }

        model = _ingest_and_parse(store, tmp_path, catalog_dict)
        children = store._extract_child_elements(
            OSCALModelType.CATALOG, model
        )

        extracted_control_ids = {
            c["uuid"] for c in children if c["element_type"] == "control"
        }
        assert "ctrl-a" in extracted_control_ids, (
            f"Control 'ctrl-a' nested inside group not found in extracted "
            f"children. Got: {extracted_control_ids}"
        )

    def test_double_nested_control(self, store, tmp_path):
        """
        Concrete case: Catalog with groups[0].groups[0].controls = [ctrl_b].
        ctrl_b must appear in children.

        **Validates: Requirements 1.1, 1.2, 1.5**
        """
        catalog_dict = {
            "catalog": {
                "uuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "metadata": {**_COMMON_METADATA},
                "groups": [
                    {
                        "id": "grp-outer",
                        "title": "Outer Group",
                        "groups": [
                            {
                                "id": "grp-inner",
                                "title": "Inner Group",
                                "controls": [
                                    {
                                        "id": "ctrl-b",
                                        "title": "Control B",
                                    },
                                ],
                            }
                        ],
                    }
                ],
            }
        }

        model = _ingest_and_parse(store, tmp_path, catalog_dict)
        children = store._extract_child_elements(
            OSCALModelType.CATALOG, model
        )

        extracted_control_ids = {
            c["uuid"] for c in children if c["element_type"] == "control"
        }
        assert "ctrl-b" in extracted_control_ids, (
            f"Control 'ctrl-b' nested inside nested group not found in "
            f"extracted children. Got: {extracted_control_ids}"
        )

    def test_mixed_top_level_and_nested_controls(self, store, tmp_path):
        """
        Concrete case: Catalog with both top-level controls and
        group-nested controls — all must appear.

        Uses separate groups to respect Trestle's discriminated union:
        Group2 (controls, no groups) vs Group1 (groups, no controls).

        **Validates: Requirements 1.1, 1.2, 1.5**
        """
        catalog_dict = {
            "catalog": {
                "uuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "metadata": {**_COMMON_METADATA},
                "controls": [
                    {"id": "top-1", "title": "Top Level Control 1"},
                ],
                "groups": [
                    {
                        "id": "grp-1",
                        "title": "Group 1 (controls only)",
                        "controls": [
                            {"id": "nested-1", "title": "Nested Control 1"},
                        ],
                    },
                    {
                        "id": "grp-2",
                        "title": "Group 2 (nested groups only)",
                        "groups": [
                            {
                                "id": "grp-2-1",
                                "title": "Nested Group 2.1",
                                "controls": [
                                    {
                                        "id": "deep-1",
                                        "title": "Deep Control 1",
                                    },
                                ],
                            }
                        ],
                    },
                ],
            }
        }

        model = _ingest_and_parse(store, tmp_path, catalog_dict)
        children = store._extract_child_elements(
            OSCALModelType.CATALOG, model
        )

        extracted_control_ids = {
            c["uuid"] for c in children if c["element_type"] == "control"
        }

        expected_ids = {"top-1", "nested-1", "deep-1"}
        missing = expected_ids - extracted_control_ids
        assert not missing, (
            f"Controls missing from extraction: {missing}. "
            f"Expected {expected_ids}, got {extracted_control_ids}"
        )
