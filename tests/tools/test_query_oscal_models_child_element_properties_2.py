"""
Property-based tests for child element tools (Properties 4–6).

Property 4: Store dependency enforcement
Property 5: Get tool — unambiguous lookup
Property 6: Get tool — ambiguity detection
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings, strategies as st

from mcp_server_for_oscal.tools import query_oscal_models
from mcp_server_for_oscal.tools.oscal_store import OscalStore


# ---------------------------------------------------------------------------
# All 12 list tools + get_child_element
# ---------------------------------------------------------------------------

ALL_LIST_TOOLS = [
    query_oscal_models.list_catalog_controls,
    query_oscal_models.list_catalog_groups,
    query_oscal_models.list_ssp_control_implementations,
    query_oscal_models.list_ssp_system_components,
    query_oscal_models.list_profile_imports,
    query_oscal_models.list_profile_modify,
    query_oscal_models.list_assessment_plan_tasks,
    query_oscal_models.list_assessment_plan_activities,
    query_oscal_models.list_assessment_results_results,
    query_oscal_models.list_assessment_results_findings,
    query_oscal_models.list_poam_items,
    query_oscal_models.list_mapping_collection_mappings,
]

ALL_TOOLS = ALL_LIST_TOOLS + [query_oscal_models.get_child_element]


# ---------------------------------------------------------------------------
# Property 4: Store dependency enforcement
# Validates: Requirements 9.6
# ---------------------------------------------------------------------------


class TestStoreDependencyEnforcement:
    """Feature: query-oscal-models, Property 4: Store dependency enforcement"""

    @pytest.mark.parametrize("tool_fn", ALL_LIST_TOOLS, ids=lambda f: f.__name__)
    def test_list_tool_raises_when_store_is_none(self, tool_fn):
        """Each list tool raises RuntimeError when _store is None."""
        with patch(
            "mcp_server_for_oscal.tools.query_oscal_models._store", None
        ):
            with pytest.raises(RuntimeError):
                tool_fn()

    def test_get_child_element_raises_when_store_is_none(self):
        """get_child_element raises RuntimeError when _store is None."""
        with patch(
            "mcp_server_for_oscal.tools.query_oscal_models._store", None
        ):
            with pytest.raises(RuntimeError):
                query_oscal_models.get_child_element(element_id="test-id")


# ---------------------------------------------------------------------------
# Property 5: Get tool — unambiguous lookup
# Validates: Requirements 11.1, 11.2, 11.5, 11.6
# ---------------------------------------------------------------------------


class TestGetToolUnambiguousLookup:
    """Feature: query-oscal-models, Property 5: Get tool unambiguous lookup"""

    @settings(max_examples=100)
    @given(
        element_id=st.text(min_size=1, max_size=50),
        parent_doc_uuid=st.one_of(st.none(), st.uuids().map(str)),
    )
    def test_get_child_element_delegates_correctly(
        self, element_id, parent_doc_uuid
    ):
        """get_child_element passes element_id and parent_doc_uuid to the store."""
        mock_store = MagicMock(spec=OscalStore)
        mock_store.get_child_element.return_value = None

        with patch(
            "mcp_server_for_oscal.tools.query_oscal_models._get_store",
            return_value=mock_store,
        ):
            result = query_oscal_models.get_child_element(
                element_id=element_id,
                parent_doc_uuid=parent_doc_uuid,
            )

        mock_store.get_child_element.assert_called_once_with(
            element_id=element_id,
            parent_doc_uuid=parent_doc_uuid,
        )
        assert result is None


# ---------------------------------------------------------------------------
# Helpers — minimal catalogs with overlapping control IDs
# ---------------------------------------------------------------------------


def _make_catalog(uuid, title, control_ids):
    """Build a minimal catalog with the given control IDs."""
    return {
        "catalog": {
            "uuid": uuid,
            "metadata": {
                "title": title,
                "last-modified": "2024-01-01T00:00:00Z",
                "version": "1.0",
                "oscal-version": "1.0.4",
            },
            "controls": [
                {"id": cid, "title": f"Control {cid}"} for cid in control_ids
            ],
        }
    }


# ---------------------------------------------------------------------------
# Property 6: Get tool — ambiguity detection
# Validates: Requirements 11.3, 11.4
# ---------------------------------------------------------------------------


class TestGetToolAmbiguityDetection:
    """Feature: query-oscal-models, Property 6: Get tool ambiguity detection"""

    @pytest.fixture
    def ambiguous_store(self, tmp_path):
        """Store with two catalogs that both contain control 'ac-1'."""
        db_path = str(tmp_path / "ambiguous.db")
        s = OscalStore(db_path=db_path, cache_size=10, seed_from_bundled=False)

        docs_dir = tmp_path / "docs"
        docs_dir.mkdir()

        cat1_uuid = "aaaa1111-1111-4111-8111-111111111111"
        cat2_uuid = "bbbb2222-2222-4222-8222-222222222222"

        cat1 = _make_catalog(cat1_uuid, "Catalog A", ["ac-1", "ac-2"])
        cat2 = _make_catalog(cat2_uuid, "Catalog B", ["ac-1", "sc-1"])

        (docs_dir / "cat1.json").write_text(json.dumps(cat1))
        (docs_dir / "cat2.json").write_text(json.dumps(cat2))

        s.scan_directory(docs_dir)

        query_oscal_models.init_store(s)
        yield s, cat1_uuid, cat2_uuid
        s.close()

    def test_ambiguous_element_returns_error_dict(self, ambiguous_store):
        """Calling get_child_element without parent on an overlapping ID
        returns an ambiguity error listing both parent UUIDs."""
        store, cat1_uuid, cat2_uuid = ambiguous_store

        result = query_oscal_models.get_child_element(element_id="ac-1")

        assert result is not None
        assert result["error"] == "ambiguous_element_id"
        assert result["element_id"] == "ac-1"
        assert set(result["matching_documents"]) == {cat1_uuid, cat2_uuid}

    def test_unique_element_returns_element(self, ambiguous_store):
        """Calling get_child_element without parent on a unique ID
        returns the element (not an error)."""
        store, cat1_uuid, cat2_uuid = ambiguous_store

        result = query_oscal_models.get_child_element(element_id="sc-1")

        assert result is not None
        assert "error" not in result
        assert result["id"] == "sc-1"
        assert result["parentDocumentUuid"] == cat2_uuid
        assert "raw_json" in result

    def test_disambiguated_with_parent_returns_element(self, ambiguous_store):
        """Providing parent_doc_uuid resolves ambiguity for overlapping IDs."""
        store, cat1_uuid, cat2_uuid = ambiguous_store

        result = query_oscal_models.get_child_element(
            element_id="ac-1", parent_doc_uuid=cat1_uuid
        )

        assert result is not None
        assert "error" not in result
        assert result["id"] == "ac-1"
        assert result["parentDocumentUuid"] == cat1_uuid
        assert "raw_json" in result
