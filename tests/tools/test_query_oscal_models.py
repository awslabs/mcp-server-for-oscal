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
    s = OscalStore(db_path=db_path, cache_size=10)
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
