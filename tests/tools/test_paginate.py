"""Property-based tests for the paginate() helper function."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from mcp_server_for_oscal.tools.utils import paginate

# Shared strategies
items_strategy = st.lists(st.fixed_dictionaries({"id": st.integers()}))
valid_offset = st.integers(min_value=0, max_value=200)
valid_limit = st.integers(min_value=1, max_value=100)


# Feature: list-tools-pagination, Property 1: Pagination round-trip
class TestPaginationRoundTrip:
    """Validates: Requirements 4.4, 1.1, 2.1, 3.1, 5.2"""

    @given(items=items_strategy, limit=valid_limit)
    @settings(max_examples=100)
    def test_round_trip_concatenation_equals_original(self, items, limit):
        """Iterating all pages and concatenating items reproduces the original list."""
        collected = []
        offset = 0
        while True:
            page = paginate(items, offset=offset, limit=limit)
            collected.extend(page["items"])
            if not page["hasMore"]:
                break
            offset += limit
        assert collected == items


# Feature: list-tools-pagination, Property 2: Page size invariant
class TestPageSizeInvariant:
    """Validates: Requirements 4.5, 1.1, 2.1, 3.1"""

    @given(items=items_strategy, offset=valid_offset, limit=valid_limit)
    @settings(max_examples=100)
    def test_page_size_never_exceeds_limit(self, items, offset, limit):
        """The number of items returned is always <= limit."""
        result = paginate(items, offset=offset, limit=limit)
        assert len(result["items"]) <= limit


# Feature: list-tools-pagination, Property 3: hasMore correctness
class TestHasMoreCorrectness:
    """Validates: Requirements 4.6, 1.3, 2.3, 3.3"""

    @given(items=items_strategy, offset=valid_offset, limit=valid_limit)
    @settings(max_examples=100)
    def test_has_more_iff_more_items_remain(self, items, offset, limit):
        """hasMore is True iff offset + limit < total."""
        result = paginate(items, offset=offset, limit=limit)
        expected = offset + limit < len(items)
        assert result["hasMore"] is expected


# Feature: list-tools-pagination, Property 4: Response shape and metadata
class TestResponseShapeAndMetadata:
    """Validates: Requirements 5.1, 5.3, 5.5, 1.3, 2.3, 3.3"""

    @given(items=items_strategy, offset=valid_offset, limit=valid_limit)
    @settings(max_examples=100)
    def test_response_has_exact_keys_and_correct_metadata(self, items, offset, limit):
        """Response has exactly the required keys; total, offset, limit echo inputs."""
        result = paginate(items, offset=offset, limit=limit)
        assert set(result.keys()) == {"items", "total", "offset", "limit", "hasMore"}
        assert result["total"] == len(items)
        assert result["offset"] == offset
        assert result["limit"] == limit


# Feature: list-tools-pagination, Property 5: Invalid inputs raise ValueError
class TestInvalidInputsRaiseValueError:
    """Validates: Requirements 4.3, 1.5, 1.6, 2.5, 2.6, 3.5, 3.6"""

    @given(
        items=items_strategy,
        offset=st.integers(max_value=-1),
        limit=valid_limit,
    )
    @settings(max_examples=100)
    def test_negative_offset_raises(self, items, offset, limit):
        """Negative offset raises ValueError."""
        with pytest.raises(ValueError):
            paginate(items, offset=offset, limit=limit)

    @given(
        items=items_strategy,
        offset=valid_offset,
        limit=st.one_of(st.integers(max_value=0), st.integers(min_value=101)),
    )
    @settings(max_examples=100)
    def test_invalid_limit_raises(self, items, offset, limit):
        """Limit outside [1, 100] raises ValueError."""
        with pytest.raises(ValueError):
            paginate(items, offset=offset, limit=limit)


# Feature: list-tools-pagination, Property 6: Beyond-end offset yields empty page
class TestBeyondEndOffset:
    """Validates: Requirements 1.4, 2.4, 3.4"""

    @given(items=items_strategy, limit=valid_limit)
    @settings(max_examples=100)
    def test_offset_beyond_end_returns_empty_items_and_no_more(self, items, limit):
        """When offset >= len(items), items is [] and hasMore is False."""
        offset = len(items)  # exactly at the end
        result = paginate(items, offset=offset, limit=limit)
        assert result["items"] == []
        assert result["hasMore"] is False

    @given(
        items=items_strategy,
        extra=st.integers(min_value=1, max_value=200),
        limit=valid_limit,
    )
    @settings(max_examples=100)
    def test_offset_well_beyond_end_returns_empty(self, items, extra, limit):
        """When offset > len(items), items is [] and hasMore is False."""
        offset = len(items) + extra
        result = paginate(items, offset=offset, limit=limit)
        assert result["items"] == []
        assert result["hasMore"] is False
