"""
Property-based tests for the 12 list child element tools in query_oscal_models.py.

Feature: query-oscal-models
"""

import inspect
import json
from unittest.mock import patch

import pytest
from hypothesis import given, settings, strategies as st

from mcp_server_for_oscal.tools.oscal_store import OscalStore
from mcp_server_for_oscal.tools import query_oscal_models


# ---------------------------------------------------------------------------
# Tool → expected element_type mapping
# ---------------------------------------------------------------------------

LIST_TOOLS_AND_ELEMENT_TYPES: list[tuple] = [
    (query_oscal_models.list_catalog_controls, "control"),
    (query_oscal_models.list_catalog_groups, "group"),
    (query_oscal_models.list_ssp_control_implementations, "control-implementation"),
    (query_oscal_models.list_ssp_system_components, "system-component"),
    (query_oscal_models.list_profile_imports, "import"),
    (query_oscal_models.list_profile_modify, "modify"),
    (query_oscal_models.list_assessment_plan_tasks, "task"),
    (query_oscal_models.list_assessment_plan_activities, "activity"),
    (query_oscal_models.list_assessment_results_results, "result"),
    (query_oscal_models.list_assessment_results_findings, "finding"),
    (query_oscal_models.list_poam_items, "poam-item"),
    (query_oscal_models.list_mapping_collection_mappings, "mapping"),
]


# ---------------------------------------------------------------------------
# Helpers — minimal valid OSCAL documents
# ---------------------------------------------------------------------------

def _make_catalog_with_controls(
    uuid="d2e3f4a5-6789-4bcd-9ef0-bbccddeeff00",
    title="Security Controls Catalog",
):
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
            ],
            "groups": [
                {"id": "ac", "title": "Access Control"},
            ],
        },
    }


def _make_poam(
    uuid="e5f6a7b8-9abc-4ef0-a1ab-567890123456",
    title="Test POA&M",
):
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
        },
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def multi_type_store(tmp_path):
    """OscalStore populated with a catalog (controls + groups) and a POA&M."""
    db_path = str(tmp_path / "prop.db")
    s = OscalStore(db_path=db_path, cache_size=10)

    docs_dir = tmp_path / "docs"
    docs_dir.mkdir()

    cat = _make_catalog_with_controls()
    (docs_dir / "catalog.json").write_text(json.dumps(cat))

    poam = _make_poam()
    (docs_dir / "poam.json").write_text(json.dumps(poam))

    s.scan_directory(docs_dir)
    query_oscal_models.init_store(s)
    yield s
    s.close()


# ---------------------------------------------------------------------------
# Property 1: Correct delegation (list tools)
# Tag: Feature: query-oscal-models, Property 1: Correct delegation
# Validates: Requirements 1.1–1.4, 2.1–2.3, 3.1–3.3, 4.1–4.3, 5.1–5.3,
#            6.1–6.2, 7.1–7.2
# ---------------------------------------------------------------------------


class TestProperty1CorrectDelegation:
    """For each list tool, verify it delegates to list_child_elements with
    the correct fixed element_type and passes all params through unchanged.

    **Validates: Requirements 1.1–1.4, 2.1–2.3, 3.1–3.3, 4.1–4.3,
    5.1–5.3, 6.1–6.2, 7.1–7.2**
    """

    @pytest.mark.parametrize(
        "tool_fn, expected_element_type",
        LIST_TOOLS_AND_ELEMENT_TYPES,
        ids=[fn.__name__ for fn, _ in LIST_TOOLS_AND_ELEMENT_TYPES],
    )
    @settings(max_examples=100)
    @given(
        parent_doc_uuid=st.one_of(st.none(), st.uuids().map(str)),
        offset=st.integers(min_value=0, max_value=1000),
        limit=st.integers(min_value=1, max_value=100),
    )
    def test_delegates_with_correct_element_type(
        self,
        tool_fn,
        expected_element_type,
        parent_doc_uuid,
        offset,
        limit,
    ):
        sentinel = {"items": [], "total": 0, "offset": 0, "limit": 10, "hasMore": False}
        with patch.object(
            OscalStore, "list_child_elements", return_value=sentinel
        ) as mock_lce:
            # Ensure _get_store() returns a real-ish object
            saved = query_oscal_models._store
            try:
                query_oscal_models._store = OscalStore.__new__(OscalStore)
                result = tool_fn(
                    ctx=None,
                    parent_doc_uuid=parent_doc_uuid,
                    offset=offset,
                    limit=limit,
                )
            finally:
                query_oscal_models._store = saved

            mock_lce.assert_called_once_with(
                ctx=None,
                parent_doc_uuid=parent_doc_uuid,
                element_type=expected_element_type,
                offset=offset,
                limit=limit,
            )
            assert result is sentinel


# ---------------------------------------------------------------------------
# Property 2: Consistent interface signature (list tools)
# Tag: Feature: query-oscal-models, Property 2: Consistent interface signature
# Validates: Requirements 9.1, 9.2, 9.3, 9.5
# ---------------------------------------------------------------------------


class TestProperty2ConsistentInterfaceSignature:
    """Verify every list tool has the expected parameter names, types, and
    defaults using inspect.signature().

    **Validates: Requirements 9.1, 9.2, 9.3, 9.5**
    """

    @pytest.mark.parametrize(
        "tool_fn",
        [fn for fn, _ in LIST_TOOLS_AND_ELEMENT_TYPES],
        ids=[fn.__name__ for fn, _ in LIST_TOOLS_AND_ELEMENT_TYPES],
    )
    def test_signature_params(self, tool_fn):
        sig = inspect.signature(tool_fn)
        param_names = list(sig.parameters.keys())
        assert param_names == ["ctx", "parent_doc_uuid", "offset", "limit"]

        # ctx: Context | None = None
        p_ctx = sig.parameters["ctx"]
        assert p_ctx.default is None

        # parent_doc_uuid: str | None = None
        p_parent = sig.parameters["parent_doc_uuid"]
        assert p_parent.default is None

        # offset: int = 0
        p_offset = sig.parameters["offset"]
        assert p_offset.default == 0
        assert p_offset.annotation is int

        # limit: int = 10
        p_limit = sig.parameters["limit"]
        assert p_limit.default == 10
        assert p_limit.annotation is int

    @pytest.mark.parametrize(
        "tool_fn",
        [fn for fn, _ in LIST_TOOLS_AND_ELEMENT_TYPES],
        ids=[fn.__name__ for fn, _ in LIST_TOOLS_AND_ELEMENT_TYPES],
    )
    def test_has_docstring(self, tool_fn):
        assert tool_fn.__doc__ is not None
        assert len(tool_fn.__doc__.strip()) > 0


# ---------------------------------------------------------------------------
# Property 3: Response format contract (list tools)
# Tag: Feature: query-oscal-models, Property 3: Response format contract
# Validates: Requirements 9.4, 10.1, 10.2, 10.3, 10.4
# ---------------------------------------------------------------------------

EXPECTED_PAGE_KEYS = {"items", "total", "offset", "limit", "hasMore"}
EXPECTED_ITEM_KEYS = {
    "id",
    "title",
    "element_type",
    "description",
    "parentDocumentTitle",
    "parentDocumentUuid",
}


class TestProperty3ResponseFormatContract:
    """Call each list tool against a real OscalStore with sample data and
    verify the response envelope and item keys.

    **Validates: Requirements 9.4, 10.1, 10.2, 10.3, 10.4**
    """

    @pytest.mark.parametrize(
        "tool_fn, expected_element_type",
        LIST_TOOLS_AND_ELEMENT_TYPES,
        ids=[fn.__name__ for fn, _ in LIST_TOOLS_AND_ELEMENT_TYPES],
    )
    def test_response_keys(self, multi_type_store, tool_fn, expected_element_type):
        result = tool_fn(ctx=None)

        # Page_Response envelope keys
        assert set(result.keys()) == EXPECTED_PAGE_KEYS

        # Type checks on envelope values
        assert isinstance(result["items"], list)
        assert isinstance(result["total"], int)
        assert isinstance(result["offset"], int)
        assert isinstance(result["limit"], int)
        assert isinstance(result["hasMore"], bool)

        # If there are items, verify each item's keys
        for item in result["items"]:
            assert set(item.keys()) == EXPECTED_ITEM_KEYS
            # description key must be present (value can be None)
            assert "description" in item
            assert isinstance(item["id"], str)
            assert isinstance(item["parentDocumentUuid"], str)
