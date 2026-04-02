"""
Tests for the new OSCAL model type MCP tools in query_oscal_models.py.
"""

import json

import pytest

from mcp_server_for_oscal.tools.oscal_store import OscalStore
from mcp_server_for_oscal.tools.utils import OSCALModelType
from mcp_server_for_oscal.tools import query_oscal_models


# ---------------------------------------------------------------------------
# Helpers — minimal valid OSCAL documents
# ---------------------------------------------------------------------------

def _make_catalog(uuid="c1d2e3f4-5678-4abc-8def-aabbccddeeff",
                  title="Test Catalog"):
    return {
        "catalog": {
            "uuid": uuid,
            "metadata": {
                "title": title,
                "last-modified": "2024-01-01T00:00:00Z",
                "version": "1.0",
                "oscal-version": "1.0.4",
            },
        }
    }


def _make_component_definition(
    uuid="a1b2c3d4-5678-4abc-8def-123456789012",
    title="Test Component Definition",
):
    return {
        "component-definition": {
            "uuid": uuid,
            "metadata": {
                "title": title,
                "last-modified": "2024-01-01T00:00:00Z",
                "version": "1.0",
                "oscal-version": "1.0.4",
            },
            "components": [
                {
                    "uuid": "b2c3d4e5-6789-4bcd-9efa-234567890123",
                    "type": "software",
                    "title": "Sample Component",
                    "description": "A sample component for testing",
                }
            ],
        }
    }


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


@pytest.fixture
def populated_store(store, tmp_path):
    """Store with a catalog and a component-definition ingested."""
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir()

    cat = _make_catalog()
    (docs_dir / "catalog.json").write_text(json.dumps(cat))

    cdef = _make_component_definition()
    (docs_dir / "cdef.json").write_text(json.dumps(cdef))

    store.scan_directory(docs_dir)

    # Wire the module-level singleton so tool functions work
    query_oscal_models.init_store(store)
    return store


# ---------------------------------------------------------------------------
# init_store / _get_store
# ---------------------------------------------------------------------------

class TestInitStore:
    def test_get_store_raises_before_init(self):
        """_get_store raises RuntimeError when no store is set."""
        saved = query_oscal_models._store
        try:
            query_oscal_models._store = None
            with pytest.raises(RuntimeError, match="not been initialised"):
                query_oscal_models._get_store()
        finally:
            query_oscal_models._store = saved

    def test_init_store_sets_singleton(self, store):
        query_oscal_models.init_store(store)
        assert query_oscal_models._get_store() is store


# ---------------------------------------------------------------------------
# Catalog tools
# ---------------------------------------------------------------------------

class TestCatalogTools:
    def test_list_catalogs_returns_page_response(self, populated_store):
        result = query_oscal_models.list_catalogs(ctx=None)
        assert "items" in result
        assert "total" in result
        assert result["total"] == 1
        assert result["items"][0]["title"] == "Test Catalog"

    def test_query_catalog_all(self, populated_store):
        result = query_oscal_models.query_catalog(ctx=None, query_type="all")
        assert result["total"] == 1

    def test_query_catalog_by_uuid(self, populated_store):
        result = query_oscal_models.query_catalog(
            ctx=None,
            query_type="by_uuid",
            query_value="c1d2e3f4-5678-4abc-8def-aabbccddeeff",
        )
        assert result["total"] == 1
        assert result["items"][0]["uuid"] == "c1d2e3f4-5678-4abc-8def-aabbccddeeff"

    def test_query_catalog_by_title(self, populated_store):
        result = query_oscal_models.query_catalog(
            ctx=None,
            query_type="by_title",
            query_value="Test Catalog",
        )
        assert result["total"] == 1

    def test_list_catalogs_empty(self, store):
        """list_catalogs returns empty when no catalogs are loaded."""
        query_oscal_models.init_store(store)
        result = query_oscal_models.list_catalogs(ctx=None)
        assert result["total"] == 0
        assert result["items"] == []

    def test_query_catalog_does_not_return_cdef(self, populated_store):
        """Catalog query should not return component-definition docs."""
        result = query_oscal_models.query_catalog(ctx=None, query_type="all")
        for item in result["items"]:
            assert item["model_type"] == "catalog"


# ---------------------------------------------------------------------------
# SSP tools
# ---------------------------------------------------------------------------

class TestSSPTools:
    def test_list_ssps_empty(self, populated_store):
        result = query_oscal_models.list_ssps(ctx=None)
        assert result["total"] == 0

    def test_query_ssp_all_empty(self, populated_store):
        result = query_oscal_models.query_ssp(ctx=None, query_type="all")
        assert result["total"] == 0


# ---------------------------------------------------------------------------
# Profile tools
# ---------------------------------------------------------------------------

class TestProfileTools:
    def test_list_profiles_empty(self, populated_store):
        result = query_oscal_models.list_profiles(ctx=None)
        assert result["total"] == 0

    def test_query_profile_all_empty(self, populated_store):
        result = query_oscal_models.query_profile(ctx=None, query_type="all")
        assert result["total"] == 0


# ---------------------------------------------------------------------------
# Assessment Plan tools
# ---------------------------------------------------------------------------

class TestAssessmentPlanTools:
    def test_list_assessment_plans_empty(self, populated_store):
        result = query_oscal_models.list_assessment_plans(ctx=None)
        assert result["total"] == 0

    def test_query_assessment_plan_all_empty(self, populated_store):
        result = query_oscal_models.query_assessment_plan(
            ctx=None, query_type="all"
        )
        assert result["total"] == 0


# ---------------------------------------------------------------------------
# Assessment Results tools
# ---------------------------------------------------------------------------

class TestAssessmentResultsTools:
    def test_list_assessment_results_empty(self, populated_store):
        result = query_oscal_models.list_assessment_results(ctx=None)
        assert result["total"] == 0

    def test_query_assessment_results_all_empty(self, populated_store):
        result = query_oscal_models.query_assessment_results(
            ctx=None, query_type="all"
        )
        assert result["total"] == 0


# ---------------------------------------------------------------------------
# POA&M tools
# ---------------------------------------------------------------------------

class TestPOAMTools:
    def test_list_poams_empty(self, populated_store):
        result = query_oscal_models.list_poams(ctx=None)
        assert result["total"] == 0

    def test_query_poam_all_empty(self, populated_store):
        result = query_oscal_models.query_poam(ctx=None, query_type="all")
        assert result["total"] == 0


# ---------------------------------------------------------------------------
# Mapping Collection tools
# ---------------------------------------------------------------------------

class TestMappingCollectionTools:
    def test_list_mapping_collections_empty(self, populated_store):
        result = query_oscal_models.list_mapping_collections(ctx=None)
        assert result["total"] == 0

    def test_query_mapping_collection_all_empty(self, populated_store):
        result = query_oscal_models.query_mapping_collection(
            ctx=None, query_type="all"
        )
        assert result["total"] == 0


# ---------------------------------------------------------------------------
# text_search_oscal
# ---------------------------------------------------------------------------

class TestTextSearchOscal:
    def test_text_search_empty_query(self, populated_store):
        result = query_oscal_models.text_search_oscal(
            ctx=None, query_text=""
        )
        assert result["total"] == 0

    def test_text_search_finds_catalog(self, populated_store):
        """After indexing, the catalog title should be searchable."""
        # Trigger indexing by querying the catalog
        query_oscal_models.query_catalog(ctx=None, query_type="all")
        result = query_oscal_models.text_search_oscal(
            ctx=None, query_text="Test Catalog"
        )
        assert result["total"] >= 1

    def test_text_search_scoped_to_model_type(self, populated_store):
        """Scoping to catalog should exclude component-definition results."""
        # Trigger indexing for both
        query_oscal_models.query_catalog(ctx=None, query_type="all")
        populated_store.query(
            oscal_model_type=OSCALModelType.COMPONENT_DEFINITION,
            query_type="all",
        )
        result = query_oscal_models.text_search_oscal(
            ctx=None,
            query_text="Test",
            oscal_model_type="catalog",
        )
        for item in result["items"]:
            assert item["model_type"] == "catalog"

    def test_text_search_invalid_model_type_searches_all(
        self, populated_store
    ):
        """An invalid model type string falls back to searching all types."""
        query_oscal_models.query_catalog(ctx=None, query_type="all")
        result = query_oscal_models.text_search_oscal(
            ctx=None,
            query_text="Test",
            oscal_model_type="not-a-real-type",
        )
        # Should not raise; returns results across all types
        assert "items" in result


# ---------------------------------------------------------------------------
# Page_Response structure
# ---------------------------------------------------------------------------

class TestPageResponseFormat:
    """All tools should return the standard Page_Response envelope."""

    @pytest.mark.parametrize(
        "tool_fn",
        [
            query_oscal_models.list_catalogs,
            query_oscal_models.list_ssps,
            query_oscal_models.list_profiles,
            query_oscal_models.list_assessment_plans,
            query_oscal_models.list_assessment_results,
            query_oscal_models.list_poams,
            query_oscal_models.list_mapping_collections,
        ],
    )
    def test_list_tools_return_page_response_keys(
        self, populated_store, tool_fn
    ):
        result = tool_fn(ctx=None)
        assert set(result.keys()) == {
            "items", "total", "offset", "limit", "hasMore"
        }

    @pytest.mark.parametrize(
        "tool_fn",
        [
            query_oscal_models.query_catalog,
            query_oscal_models.query_ssp,
            query_oscal_models.query_profile,
            query_oscal_models.query_assessment_plan,
            query_oscal_models.query_assessment_results,
            query_oscal_models.query_poam,
            query_oscal_models.query_mapping_collection,
        ],
    )
    def test_query_tools_return_page_response_keys(
        self, populated_store, tool_fn
    ):
        result = tool_fn(ctx=None, query_type="all")
        assert set(result.keys()) == {
            "items", "total", "offset", "limit", "hasMore"
        }


# ---------------------------------------------------------------------------
# Integration helpers — additional OSCAL document fixtures
# ---------------------------------------------------------------------------

def _make_poam(
    uuid="e5f6a7b8-9abc-4ef0-a1ab-567890123456",
    title="Test POA&M",
):
    """Minimal valid POA&M with poam-items."""
    return {
        "plan-of-action-and-milestones": {
            "uuid": uuid,
            "metadata": {
                "title": title,
                "last-modified": "2024-01-01T00:00:00Z",
                "version": "1.0",
                "oscal-version": "1.0.4",
            },
            "poam-items": [
                {
                    "uuid": "f6a7b8c9-abcd-4f01-a2ab-678901234567",
                    "title": "Fix vulnerability",
                    "description": "Remediate CVE-2024-0001",
                },
            ],
        }
    }


def _make_catalog_with_controls(
    uuid="d2e3f4a5-6789-4bcd-9ef0-bbccddeeff00",
    title="Security Controls Catalog",
):
    """Catalog with controls and a group for richer search content."""
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
                {"id": "ac-1", "title": "Access Control Policy"},
                {"id": "ac-2", "title": "Account Management"},
            ],
            "groups": [
                {"id": "ac", "title": "Access Control"},
            ],
        }
    }


# ---------------------------------------------------------------------------
# Integration fixture — multi-type store
# ---------------------------------------------------------------------------

@pytest.fixture
def multi_type_store(tmp_path):
    """OscalStore populated with catalogs, component-definitions, and POA&Ms.

    Provides a richer dataset for integration-level tests that exercise
    the full flow across multiple document types.
    """
    db_path = str(tmp_path / "integration.db")
    s = OscalStore(db_path=db_path, cache_size=10, seed_from_bundled=False)

    docs_dir = tmp_path / "docs"
    docs_dir.mkdir()

    # Two catalogs
    cat1 = _make_catalog(
        uuid="c1d2e3f4-5678-4abc-8def-aabbccddeeff",
        title="Test Catalog",
    )
    (docs_dir / "catalog1.json").write_text(json.dumps(cat1))

    cat2 = _make_catalog_with_controls(
        uuid="d2e3f4a5-6789-4bcd-9ef0-bbccddeeff00",
        title="Security Controls Catalog",
    )
    (docs_dir / "catalog2.json").write_text(json.dumps(cat2))

    # One component-definition
    cdef = _make_component_definition(
        uuid="a1b2c3d4-5678-4abc-8def-123456789012",
        title="Test Component Definition",
    )
    (docs_dir / "cdef.json").write_text(json.dumps(cdef))

    # One POA&M
    poam = _make_poam(
        uuid="e5f6a7b8-9abc-4ef0-a1ab-567890123456",
        title="Test POA&M",
    )
    (docs_dir / "poam.json").write_text(json.dumps(poam))

    s.scan_directory(docs_dir)

    # Wire the module-level singleton
    query_oscal_models.init_store(s)
    yield s
    s.close()


# ---------------------------------------------------------------------------
# Integration tests — multi-type queries
# ---------------------------------------------------------------------------

class TestMultiTypeIntegration:
    """Integration tests exercising the full flow with multiple doc types."""

    # -- Catalog tools with real data --

    def test_list_catalogs_returns_both(self, multi_type_store):
        """list_catalogs returns exactly the two ingested catalogs."""
        result = query_oscal_models.list_catalogs(ctx=None)
        assert result["total"] == 2
        titles = {item["title"] for item in result["items"]}
        assert titles == {"Test Catalog", "Security Controls Catalog"}

    def test_query_catalog_by_uuid(self, multi_type_store):
        """query_catalog by_uuid returns the correct catalog."""
        result = query_oscal_models.query_catalog(
            ctx=None,
            query_type="by_uuid",
            query_value="d2e3f4a5-6789-4bcd-9ef0-bbccddeeff00",
        )
        assert result["total"] == 1
        assert result["items"][0]["title"] == "Security Controls Catalog"

    def test_query_catalog_by_title(self, multi_type_store):
        """query_catalog by_title finds the right catalog."""
        result = query_oscal_models.query_catalog(
            ctx=None,
            query_type="by_title",
            query_value="Test Catalog",
        )
        assert result["total"] == 1
        assert result["items"][0]["uuid"] == "c1d2e3f4-5678-4abc-8def-aabbccddeeff"

    def test_query_catalog_all_excludes_other_types(self, multi_type_store):
        """query_catalog all returns only catalogs, not cdefs or poams."""
        result = query_oscal_models.query_catalog(ctx=None, query_type="all")
        assert result["total"] == 2
        for item in result["items"]:
            assert item["model_type"] == "catalog"

    # -- POA&M tools with real data --

    def test_list_poams_returns_one(self, multi_type_store):
        """list_poams returns the single ingested POA&M."""
        result = query_oscal_models.list_poams(ctx=None)
        assert result["total"] == 1
        assert result["items"][0]["title"] == "Test POA&M"

    def test_query_poam_by_uuid(self, multi_type_store):
        """query_poam by_uuid returns the correct POA&M."""
        result = query_oscal_models.query_poam(
            ctx=None,
            query_type="by_uuid",
            query_value="e5f6a7b8-9abc-4ef0-a1ab-567890123456",
        )
        assert result["total"] == 1
        assert result["items"][0]["model_type"] == "plan-of-action-and-milestones"

    # -- Empty-type queries return empty results --

    def test_query_ssp_empty_with_multi_type_store(self, multi_type_store):
        """SSP queries return empty when no SSPs are loaded."""
        result = query_oscal_models.query_ssp(ctx=None, query_type="all")
        assert result["total"] == 0
        assert result["items"] == []

    def test_list_ssps_empty_with_multi_type_store(self, multi_type_store):
        """list_ssps returns empty when no SSPs are loaded."""
        result = query_oscal_models.list_ssps(ctx=None)
        assert result["total"] == 0
        assert result["items"] == []

    def test_list_profiles_empty_with_multi_type_store(self, multi_type_store):
        """list_profiles returns empty when no profiles are loaded."""
        result = query_oscal_models.list_profiles(ctx=None)
        assert result["total"] == 0

    def test_list_assessment_plans_empty_with_multi_type_store(
        self, multi_type_store
    ):
        """list_assessment_plans returns empty when none loaded."""
        result = query_oscal_models.list_assessment_plans(ctx=None)
        assert result["total"] == 0

    def test_list_assessment_results_empty_with_multi_type_store(
        self, multi_type_store
    ):
        """list_assessment_results returns empty when none loaded."""
        result = query_oscal_models.list_assessment_results(ctx=None)
        assert result["total"] == 0

    def test_list_mapping_collections_empty_with_multi_type_store(
        self, multi_type_store
    ):
        """list_mapping_collections returns empty when none loaded."""
        result = query_oscal_models.list_mapping_collections(ctx=None)
        assert result["total"] == 0


# ---------------------------------------------------------------------------
# Integration tests — cross-model text search
# ---------------------------------------------------------------------------

class TestTextSearchIntegration:
    """Integration tests for text_search_oscal across multiple model types."""

    def test_text_search_finds_results_across_types(self, multi_type_store):
        """text_search_oscal returns results from multiple model types."""
        # Trigger indexing for all document types
        query_oscal_models.query_catalog(ctx=None, query_type="all")
        multi_type_store.query(
            oscal_model_type=OSCALModelType.COMPONENT_DEFINITION,
            query_type="all",
        )
        query_oscal_models.query_poam(ctx=None, query_type="all")

        # "Test" appears in titles across catalogs, cdef, and poam
        result = query_oscal_models.text_search_oscal(
            ctx=None, query_text="Test"
        )
        assert result["total"] >= 3
        model_types = {item["model_type"] for item in result["items"]}
        # Should have results from at least two different model types
        assert len(model_types) >= 2

    def test_text_search_scoped_to_catalog(self, multi_type_store):
        """text_search_oscal scoped to catalog excludes other types."""
        # Trigger indexing
        query_oscal_models.query_catalog(ctx=None, query_type="all")
        multi_type_store.query(
            oscal_model_type=OSCALModelType.COMPONENT_DEFINITION,
            query_type="all",
        )
        query_oscal_models.query_poam(ctx=None, query_type="all")

        result = query_oscal_models.text_search_oscal(
            ctx=None,
            query_text="Test",
            oscal_model_type="catalog",
        )
        assert result["total"] >= 1
        for item in result["items"]:
            assert item["model_type"] == "catalog"

    def test_text_search_scoped_to_poam(self, multi_type_store):
        """text_search_oscal scoped to POA&M returns only POA&M results."""
        # Trigger indexing
        query_oscal_models.query_poam(ctx=None, query_type="all")

        result = query_oscal_models.text_search_oscal(
            ctx=None,
            query_text="vulnerability",
            oscal_model_type="plan-of-action-and-milestones",
        )
        assert result["total"] >= 1
        for item in result["items"]:
            assert item["model_type"] == "plan-of-action-and-milestones"

    def test_text_search_scoped_to_component_definition(
        self, multi_type_store
    ):
        """text_search_oscal scoped to component-definition filters correctly."""
        # Trigger indexing
        multi_type_store.query(
            oscal_model_type=OSCALModelType.COMPONENT_DEFINITION,
            query_type="all",
        )

        result = query_oscal_models.text_search_oscal(
            ctx=None,
            query_text="Sample",
            oscal_model_type="component-definition",
        )
        assert result["total"] >= 1
        for item in result["items"]:
            assert item["model_type"] == "component-definition"

    def test_text_search_child_elements_indexed(self, multi_type_store):
        """text_search finds child element content (e.g. control titles)."""
        # Trigger indexing for the catalog with controls
        query_oscal_models.query_catalog(ctx=None, query_type="all")

        result = query_oscal_models.text_search_oscal(
            ctx=None, query_text="Access Control"
        )
        assert result["total"] >= 1
        # At least one result should be a child_element from the catalog
        entity_types = {item["entity_type"] for item in result["items"]}
        assert "child_element" in entity_types

    def test_text_search_no_match_returns_empty(self, multi_type_store):
        """text_search with a term that matches nothing returns empty."""
        query_oscal_models.query_catalog(ctx=None, query_type="all")

        result = query_oscal_models.text_search_oscal(
            ctx=None, query_text="zzzznonexistenttermzzzz"
        )
        assert result["total"] == 0
        assert result["items"] == []
