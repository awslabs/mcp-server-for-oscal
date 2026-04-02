"""Tests for local documentation search feature.

Covers schema migration, markdown indexing, documentation-scoped search,
and query_documentation module refactoring.
"""

import sqlite3

import pytest

from mcp_server_for_oscal.tools.oscal_store import OscalStore


class TestContentHashSchemaMigration:
    """Tests for content_hash column addition and migration (Req 6.5, 6.6)."""

    def test_new_db_has_content_hash_column(self, tmp_path):
        """A freshly created DB should include the content_hash column."""
        db_path = str(tmp_path / "new.db")
        store = OscalStore(db_path=db_path)
        try:
            row = store._conn.execute(
                "PRAGMA table_info(documents)"
            ).fetchall()
            col_names = [r["name"] for r in row]
            assert "content_hash" in col_names
        finally:
            store.close()

    def test_migration_adds_content_hash_to_existing_db(self, tmp_path):
        """Opening an old DB (without content_hash) should migrate it."""
        db_path = str(tmp_path / "legacy.db")

        # Create a legacy DB without content_hash
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE documents (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                uuid        TEXT    NOT NULL UNIQUE,
                title       TEXT    NOT NULL,
                model_type  TEXT    NOT NULL,
                file_path   TEXT    NOT NULL UNIQUE,
                file_size   INTEGER NOT NULL,
                file_mtime  REAL    NOT NULL,
                raw_json    TEXT    NOT NULL,
                indexed     INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
                updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
            )
        """)
        conn.execute(
            "INSERT INTO documents "
            "(uuid, title, model_type, file_path, file_size, file_mtime, raw_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("test-uuid", "Test", "component-definition", "/tmp/f.json", 100, 1.0, "{}"),
        )
        conn.commit()
        conn.close()

        # Open with OscalStore — migration should add content_hash
        store = OscalStore(db_path=db_path)
        try:
            row = store._conn.execute(
                "PRAGMA table_info(documents)"
            ).fetchall()
            col_names = [r["name"] for r in row]
            assert "content_hash" in col_names

            # Existing row should have NULL content_hash
            doc = store._conn.execute(
                "SELECT content_hash FROM documents WHERE uuid = ?",
                ("test-uuid",),
            ).fetchone()
            assert doc["content_hash"] is None
        finally:
            store.close()

    def test_null_content_hash_forces_reindex(self, tmp_path):
        """_file_unchanged() returns False when content_hash is NULL."""
        db_path = str(tmp_path / "test.db")
        store = OscalStore(db_path=db_path)
        try:
            # Insert a row with NULL content_hash
            store._conn.execute(
                "INSERT INTO documents "
                "(uuid, title, model_type, file_path, file_size, "
                "file_mtime, raw_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("u1", "T", "component-definition", "/tmp/x.json", 50, 2.0, "{}"),
            )
            store._conn.commit()

            # Even with a valid hash, should return False when stored hash is NULL
            assert store._file_unchanged("/tmp/x.json", "abc123") is False
        finally:
            store.close()

    def test_migration_is_idempotent(self, tmp_path):
        """Calling _init_schema twice should not raise."""
        db_path = str(tmp_path / "idem.db")
        store = OscalStore(db_path=db_path)
        try:
            # Call _init_schema again — should not raise
            store._init_schema()

            row = store._conn.execute(
                "PRAGMA table_info(documents)"
            ).fetchall()
            col_names = [r["name"] for r in row]
            assert col_names.count("content_hash") == 1
        finally:
            store.close()


# ---------------------------------------------------------------------------
# Property-Based Tests (Hypothesis)
# ---------------------------------------------------------------------------
import hashlib
import tempfile
from pathlib import Path

from hypothesis import given, settings, assume
from hypothesis import strategies as st

# Strategy: non-empty markdown content (must survive content.strip() check)
_nonempty_md = st.text(
    alphabet=st.characters(blacklist_categories=["Cs"]),
    min_size=1,
).filter(lambda s: s.strip())


@st.composite
def _same_length_pair(draw):
    """Draw two distinct ASCII strings of the same length (≥1 non-whitespace)."""
    length = draw(st.integers(min_value=1, max_value=50))
    # Use printable ASCII to guarantee 1 byte per char
    alpha = st.characters(
        whitelist_categories=("L", "N", "P", "S"),
        whitelist_characters=" ",
    )
    a = draw(st.text(alphabet=alpha, min_size=length, max_size=length))
    b = draw(st.text(alphabet=alpha, min_size=length, max_size=length))
    assume(a != b)
    assume(a.strip())
    assume(b.strip())
    return a, b


class TestSHA256ChangeDetectionProperty:
    """Property 3: SHA-256 Change Detection.

    *For any* file content, scanning the same unchanged file twice SHALL
    result in the second scan returning 0 new documents (idempotence).
    *For any* two distinct file contents written to the same path, scanning
    after replacing the first content with the second SHALL result in
    re-indexing (the stored ``content_hash`` updates to match the new
    content), even if the two contents have the same byte length.

    **Validates: Requirements 1.3, 6.4**
    """

    @given(
        content_a=_nonempty_md,
        content_b=_nonempty_md,
    )
    @settings(max_examples=100)
    def test_sha256_change_detection(self, content_a, content_b):
        """Scanning after content change re-indexes; scanning unchanged is idempotent.

        **Validates: Requirements 1.3, 6.4**
        """
        assume(content_a != content_b)

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            doc_dir = tmp_path / "docs"
            doc_dir.mkdir()
            md_file = doc_dir / "test-doc.md"

            db_path = str(tmp_path / "test.db")
            store = OscalStore(db_path=db_path)
            try:
                # --- Phase 1: Write first content and scan ---
                md_file.write_text(content_a, encoding="utf-8")
                count_first = store.scan_directory(doc_dir)
                assert count_first == 1, "First scan should ingest the new file"

                # Verify stored content_hash matches content_a
                expected_hash_a = hashlib.sha256(
                    content_a.encode("utf-8")
                ).hexdigest()
                row_a = store._conn.execute(
                    "SELECT content_hash, raw_json FROM documents "
                    "WHERE model_type = 'documentation'"
                ).fetchone()
                assert row_a is not None, (
                    "Document row should exist after first scan"
                )
                assert row_a["content_hash"] == expected_hash_a

                # --- Phase 2: Scan same file again (idempotence) ---
                count_noop = store.scan_directory(doc_dir)
                assert count_noop == 0, (
                    "Second scan of unchanged file should return 0"
                )

                # --- Phase 3: Replace content and scan again ---
                md_file.write_text(content_b, encoding="utf-8")
                count_update = store.scan_directory(doc_dir)
                assert count_update == 1, (
                    "Scan after content change should re-index the file"
                )

                # Verify content_hash updated to match content_b
                expected_hash_b = hashlib.sha256(
                    content_b.encode("utf-8")
                ).hexdigest()
                row_b = store._conn.execute(
                    "SELECT content_hash, raw_json FROM documents "
                    "WHERE model_type = 'documentation'"
                ).fetchone()
                assert row_b is not None
                assert row_b["content_hash"] == expected_hash_b
                assert row_b["content_hash"] != expected_hash_a, (
                    "Hash must differ after content change"
                )
            finally:
                store.close()

    @given(pair=_same_length_pair())
    @settings(max_examples=100)
    def test_same_length_different_content_detected(self, pair):
        """Even when byte lengths are identical, different content triggers re-index.

        **Validates: Requirements 1.3, 6.4**
        """
        content_a, content_b = pair

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            doc_dir = tmp_path / "docs"
            doc_dir.mkdir()
            md_file = doc_dir / "same-len.md"

            db_path = str(tmp_path / "test.db")
            store = OscalStore(db_path=db_path)
            try:
                # Write first content, scan
                md_file.write_text(content_a, encoding="utf-8")
                count_first = store.scan_directory(doc_dir)
                assert count_first == 1

                # Write second content (same byte length), scan
                md_file.write_text(content_b, encoding="utf-8")
                count_update = store.scan_directory(doc_dir)
                assert count_update == 1, (
                    "Same byte length but different content must trigger "
                    "re-index"
                )

                expected_hash_b = hashlib.sha256(
                    content_b.encode("utf-8")
                ).hexdigest()
                row = store._conn.execute(
                    "SELECT content_hash FROM documents "
                    "WHERE model_type = 'documentation'"
                ).fetchone()
                assert row is not None
                assert row["content_hash"] == expected_hash_b
            finally:
                store.close()


import re
import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st


# --- Strategies for Property 2: Title Derivation ---

# Strategy: markdown content that starts with a heading line
_heading_level = st.integers(min_value=1, max_value=6).map(lambda n: "#" * n)
_heading_text = st.text(
    alphabet=st.characters(
        whitelist_categories=("L", "N", "P", "S", "Z"),
        blacklist_characters="\r\n\x00",
    ),
    min_size=1,
    max_size=80,
).filter(lambda t: t.strip())

_body_text = st.text(
    alphabet=st.characters(blacklist_categories=["Cs"]),
    min_size=0,
    max_size=200,
)

heading_strategy = st.tuples(_heading_level, _heading_text, _body_text).map(
    lambda t: f"{t[0]} {t[1]}\n{t[2]}"
)

# Strategy: markdown content with no heading at all (no line starting with #)
no_heading_strategy = st.text(
    alphabet=st.characters(
        blacklist_characters="#\x00",
        blacklist_categories=["Cs"],  # exclude surrogates
    ),
    min_size=1,
    max_size=200,
).filter(lambda t: t.strip())

# Strategy: filenames (valid stem chars + .md extension)
_filename_chars = st.characters(
    whitelist_categories=("L", "N"),
    whitelist_characters="-_",
)
filename_strategy = st.text(
    alphabet=_filename_chars, min_size=1, max_size=40
).filter(lambda s: s.strip() and s.strip("-_")).map(lambda s: s + ".md")


class TestTitleDerivationProperty:
    """Property 2: Title Derivation from Markdown Content.

    Validates: Requirements 1.2
    """

    @given(
        content=st.one_of(heading_strategy, no_heading_strategy),
        filename=filename_strategy,
    )
    @settings(max_examples=100)
    def test_title_derivation_matches_spec(self, content, filename):
        """For any markdown content, the derived title SHALL equal the text
        of the first markdown heading if one exists; otherwise the title
        SHALL equal the filename with .md stripped and hyphens/underscores
        replaced by spaces.

        **Validates: Requirements 1.2**
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            # Write the markdown file
            md_file = tmp_path / filename
            md_file.write_text(content, encoding="utf-8")

            # Compute expected title using the same regex as the implementation
            heading_match = re.search(r"^#{1,6}\s+(.+)", content, re.MULTILINE)
            if heading_match:
                expected_title = heading_match.group(1).strip()
            else:
                expected_title = md_file.stem.replace("-", " ").replace("_", " ")

            # Create a fresh store and scan the directory
            db_path = str(tmp_path / "test.db")
            store = OscalStore(db_path=db_path)
            try:
                store.scan_directory(tmp_path)

                # Retrieve the indexed document title
                row = store._conn.execute(
                    "SELECT title FROM documents WHERE file_path = ?",
                    (str(md_file),),
                ).fetchone()

                assert row is not None, (
                    f"Document not indexed for file {filename}"
                )
                assert row["title"] == expected_title, (
                    f"Title mismatch: got {row['title']!r}, "
                    f"expected {expected_title!r}"
                )
            finally:
                store.close()


# ---------------------------------------------------------------------------
# Property-Based Tests (Hypothesis)
# ---------------------------------------------------------------------------

import hashlib
from pathlib import Path

from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st


class TestMarkdownIndexingRoundTripProperty:
    """Feature: local-documentation-search, Property 1: Markdown indexing round-trip.

    *For any* valid markdown file with non-empty content, after
    ``scan_directory()`` processes it, the ``documents`` table SHALL contain a
    row with ``model_type="documentation"``, ``raw_json`` equal to the file's
    text content, and a correct SHA-256 ``content_hash``; AND the
    ``fts_index`` table SHALL contain a corresponding row with
    ``entity_type="documentation"`` and ``description`` equal to the full
    markdown body text.

    **Validates: Requirements 1.1, 1.4, 6.1**
    """

    @pytest.mark.slow
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    @given(
        content=st.text(
            alphabet=st.characters(
                blacklist_characters="\r",
                blacklist_categories=("Cs",),  # type: ignore[arg-type]
            ),
            min_size=1,
        ).filter(lambda s: s.strip())
    )
    def test_markdown_round_trip(self, content, tmp_path_factory):
        """After scanning a directory with a markdown file, the documents
        table has a row with model_type='documentation', correct content_hash,
        and the fts_index has a matching entity_type='documentation' entry
        with the full body in description.

        **Validates: Requirements 1.1, 1.4, 6.1**
        """
        tmp_path = tmp_path_factory.mktemp("prop1")
        db_path = str(tmp_path / "test.db")
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()

        # Write the generated markdown content to a temp file
        md_file = doc_dir / "test_doc.md"
        md_file.write_text(content, encoding="utf-8")

        # Compute expected SHA-256 hash
        expected_hash = hashlib.sha256(md_file.read_bytes()).hexdigest()

        store = OscalStore(db_path=db_path)
        try:
            ingested = store.scan_directory(doc_dir)
            assert ingested == 1, f"Expected 1 ingested file, got {ingested}"

            # Verify documents table row
            doc_row = store._conn.execute(
                "SELECT model_type, raw_json, content_hash, file_path "
                "FROM documents WHERE model_type = 'documentation'"
            ).fetchone()
            assert doc_row is not None, "No documentation row in documents table"
            assert doc_row["model_type"] == "documentation"
            assert doc_row["raw_json"] == content
            assert doc_row["content_hash"] == expected_hash
            assert doc_row["file_path"] == str(md_file)

            # Verify fts_index row
            doc_id_row = store._conn.execute(
                "SELECT id FROM documents WHERE model_type = 'documentation'"
            ).fetchone()
            fts_row = store._conn.execute(
                "SELECT entity_type, description, model_type "
                "FROM fts_index WHERE entity_type = 'documentation' "
                "AND entity_id = ?",
                (str(doc_id_row["id"]),),
            ).fetchone()
            assert fts_row is not None, "No documentation row in fts_index"
            assert fts_row["entity_type"] == "documentation"
            assert fts_row["description"] == content
            assert fts_row["model_type"] == "documentation"
        finally:
            store.close()


# ---------------------------------------------------------------------------
# Unit Tests for search_documentation() (Task 4.1)
# ---------------------------------------------------------------------------


class TestSearchDocumentation:
    """Unit tests for OscalStore.search_documentation().

    Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5, 2.6
    """

    @pytest.fixture()
    def store_with_docs(self, tmp_path):
        """Create a store with indexed markdown documentation files."""
        db_path = str(tmp_path / "test.db")
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()

        # Create several markdown files with known content
        (doc_dir / "oscal-overview.md").write_text(
            "# OSCAL Overview\n\nOSCAL is a framework for security compliance.\n"
            "It provides machine-readable formats for security controls.",
            encoding="utf-8",
        )
        (doc_dir / "getting-started.md").write_text(
            "# Getting Started with OSCAL\n\nThis guide helps you get started.\n"
            "Learn about catalogs, profiles, and component definitions.",
            encoding="utf-8",
        )
        (doc_dir / "component-definitions.md").write_text(
            "# Component Definitions\n\nComponent definitions describe security "
            "capabilities.\nThey map controls to implementations.",
            encoding="utf-8",
        )

        store = OscalStore(db_path=db_path)
        store.scan_directory(doc_dir)
        yield store
        store.close()

    def test_empty_query_returns_empty_response(self, store_with_docs):
        """Empty/whitespace queries return empty page response.

        Validates: Requirement 2.4
        """
        result = store_with_docs.search_documentation("")
        assert result["items"] == []
        assert result["total"] == 0
        assert result["hasMore"] is False

        result_ws = store_with_docs.search_documentation("   ")
        assert result_ws["items"] == []
        assert result_ws["total"] == 0

    def test_search_returns_matching_results(self, store_with_docs):
        """Search with a valid query returns matching documentation.

        Validates: Requirements 2.1, 2.2
        """
        result = store_with_docs.search_documentation("OSCAL")
        assert result["total"] > 0
        assert len(result["items"]) > 0

    def test_result_item_structure(self, store_with_docs):
        """Each result item has title, snippet, and source keys.

        Validates: Requirement 2.3
        """
        result = store_with_docs.search_documentation("OSCAL")
        for item in result["items"]:
            assert "title" in item
            assert "snippet" in item
            assert "source" in item
            assert isinstance(item["title"], str)
            assert isinstance(item["snippet"], str)
            assert isinstance(item["source"], str)

    def test_snippet_max_200_chars(self, store_with_docs):
        """Snippets are at most 200 characters.

        Validates: Requirement 2.3
        """
        result = store_with_docs.search_documentation("OSCAL")
        for item in result["items"]:
            assert len(item["snippet"]) <= 200

    def test_page_response_structure(self, store_with_docs):
        """Response has items, total, offset, limit, hasMore keys.

        Validates: Requirement 2.6
        """
        result = store_with_docs.search_documentation("OSCAL")
        assert "items" in result
        assert "total" in result
        assert "offset" in result
        assert "limit" in result
        assert "hasMore" in result
        assert isinstance(result["items"], list)
        assert isinstance(result["total"], int)
        assert isinstance(result["offset"], int)
        assert isinstance(result["limit"], int)
        assert isinstance(result["hasMore"], bool)

    def test_pagination_offset_and_limit(self, store_with_docs):
        """Offset and limit control pagination correctly.

        Validates: Requirement 2.6
        """
        result_all = store_with_docs.search_documentation("OSCAL", offset=0, limit=100)
        total = result_all["total"]

        if total > 1:
            result_page = store_with_docs.search_documentation(
                "OSCAL", offset=0, limit=1
            )
            assert len(result_page["items"]) == 1
            assert result_page["hasMore"] is True

            result_offset = store_with_docs.search_documentation(
                "OSCAL", offset=total, limit=10
            )
            assert len(result_offset["items"]) == 0
            assert result_offset["hasMore"] is False

    def test_limit_capped_at_100(self, store_with_docs):
        """Limit is capped at 100 even if a larger value is passed.

        Validates: Requirement 2.1
        """
        result = store_with_docs.search_documentation("OSCAL", limit=200)
        assert result["limit"] == 100

    def test_fts5_fallback_to_like_on_bad_syntax(self, store_with_docs):
        """Invalid FTS5 syntax falls back to LIKE search.

        Validates: Requirement 2.5
        """
        # FTS5 syntax like unbalanced quotes should trigger OperationalError
        result = store_with_docs.search_documentation('"unclosed quote')
        # Should not raise — falls back to LIKE
        assert "items" in result
        assert "total" in result

    def test_source_is_file_path(self, store_with_docs):
        """Source field contains the file path from the documents table.

        Validates: Requirement 2.3
        """
        result = store_with_docs.search_documentation("OSCAL")
        for item in result["items"]:
            assert item["source"].endswith(".md")

    def test_only_documentation_results(self, tmp_path):
        """search_documentation only returns documentation, not OSCAL models.

        Validates: Requirement 2.1
        """
        db_path = str(tmp_path / "mixed.db")
        doc_dir = tmp_path / "mixed"
        doc_dir.mkdir()

        # Create a markdown doc
        (doc_dir / "test-doc.md").write_text(
            "# Security Controls\n\nThis document describes security controls.",
            encoding="utf-8",
        )

        store = OscalStore(db_path=db_path)
        try:
            store.scan_directory(doc_dir)

            # Manually insert a non-documentation FTS entry to simulate OSCAL model
            store._conn.execute(
                """
                INSERT INTO fts_index
                    (entity_type, entity_id, title, description, model_type)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    "document",
                    "999",
                    "Security Controls Catalog",
                    "A catalog of security controls for testing",
                    "catalog",
                ),
            )
            store._conn.commit()

            # Search should only return documentation entries
            result = store.search_documentation("security")
            for item in result["items"]:
                # All results should come from documentation files
                assert item["source"].endswith(".md")
        finally:
            store.close()


# ---------------------------------------------------------------------------
# Property 6: Empty Query Returns Empty Response (Task 4.4)
# ---------------------------------------------------------------------------


class TestEmptyQueryReturnsEmptyResponseProperty:
    """Property 6: Empty Query Returns Empty Response.

    *For any* string composed entirely of whitespace characters (including
    the empty string), ``search_documentation()`` SHALL return a page
    response with ``items`` as an empty list, ``total`` of 0, and
    ``hasMore`` of ``False``.

    **Validates: Requirements 2.4, 3.5**
    """

    @given(query=st.from_regex(r"^\s*$", fullmatch=True))
    @settings(max_examples=100)
    def test_whitespace_only_queries_return_empty(self, query, tmp_path_factory):
        """For any whitespace-only string, search_documentation returns an
        empty page response.

        **Validates: Requirements 2.4, 3.5**
        """
        tmp_path = tmp_path_factory.mktemp("prop6")
        db_path = str(tmp_path / "test.db")
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()

        # Index a real document so the store is non-empty
        (doc_dir / "sample.md").write_text(
            "# Sample\n\nSome searchable content here.",
            encoding="utf-8",
        )

        store = OscalStore(db_path=db_path)
        try:
            store.scan_directory(doc_dir)

            result = store.search_documentation(query)

            assert result["items"] == [], (
                f"Expected empty items for query {query!r}, got {result['items']}"
            )
            assert result["total"] == 0, (
                f"Expected total=0 for query {query!r}, got {result['total']}"
            )
            assert result["hasMore"] is False, (
                f"Expected hasMore=False for query {query!r}, "
                f"got {result['hasMore']}"
            )
        finally:
            store.close()

    def test_empty_string_returns_empty(self, tmp_path):
        """Explicit test: the empty string '' returns an empty page response.

        **Validates: Requirements 2.4, 3.5**
        """
        db_path = str(tmp_path / "test.db")
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()

        (doc_dir / "sample.md").write_text(
            "# Sample\n\nSome searchable content here.",
            encoding="utf-8",
        )

        store = OscalStore(db_path=db_path)
        try:
            store.scan_directory(doc_dir)

            result = store.search_documentation("")

            assert result["items"] == []
            assert result["total"] == 0
            assert result["offset"] == 0
            assert result["limit"] == 10
            assert result["hasMore"] is False
        finally:
            store.close()


# ---------------------------------------------------------------------------
# Property 5: Search Result Structure
# ---------------------------------------------------------------------------


class TestSearchResultStructureProperty:
    """Feature: local-documentation-search, Property 5: Search result structure.

    *For any* non-empty search query that produces results from
    ``search_documentation()``, each result item SHALL contain a ``"title"``
    string, a ``"snippet"`` string of at most 200 characters, and a
    ``"source"`` string representing the file path.  The response dict SHALL
    contain keys ``"items"``, ``"total"``, ``"offset"``, ``"limit"``, and
    ``"hasMore"``.

    **Validates: Requirements 2.3, 2.6**
    """

    @pytest.mark.slow
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    @given(
        body=st.text(
            alphabet=st.characters(blacklist_categories=["Cs"], blacklist_characters="\r"),
            min_size=0,
            max_size=500,
        ),
    )
    def test_search_result_structure(self, body, tmp_path_factory):
        """Index generated markdown with a known keyword, search, and verify
        every result item has title/snippet/source and the response envelope
        has items/total/offset/limit/hasMore.

        **Validates: Requirements 2.3, 2.6**
        """
        # Prepend a known heading so FTS always finds at least one result
        content = "# OSCAL Documentation\n\n" + body
        tmp_path = tmp_path_factory.mktemp("prop5")
        db_path = str(tmp_path / "test.db")
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()

        md_file = doc_dir / "searchable.md"
        md_file.write_text(content, encoding="utf-8")

        store = OscalStore(db_path=db_path)
        try:
            store.scan_directory(doc_dir)
            result = store.search_documentation("OSCAL")

            # --- Response envelope keys ---
            assert "items" in result
            assert "total" in result
            assert "offset" in result
            assert "limit" in result
            assert "hasMore" in result

            assert isinstance(result["items"], list)
            assert isinstance(result["total"], int)
            assert isinstance(result["offset"], int)
            assert isinstance(result["limit"], int)
            assert isinstance(result["hasMore"], bool)

            # We indexed content containing "OSCAL" so expect ≥1 result
            assert result["total"] >= 1, (
                "Expected at least one result for 'OSCAL' query"
            )

            # --- Per-item structure ---
            for item in result["items"]:
                assert "title" in item, "Result item missing 'title' key"
                assert "snippet" in item, "Result item missing 'snippet' key"
                assert "source" in item, "Result item missing 'source' key"

                assert isinstance(item["title"], str)
                assert isinstance(item["snippet"], str)
                assert isinstance(item["source"], str)

                # Snippet must be ≤200 characters
                assert len(item["snippet"]) <= 200, (
                    f"Snippet exceeds 200 chars: {len(item['snippet'])}"
                )
        finally:
            store.close()


# ---------------------------------------------------------------------------
# Property 4: Documentation Search Scoping (Task 4.2)
# ---------------------------------------------------------------------------


class TestDocumentationSearchScopingProperty:
    """Feature: local-documentation-search, Property 4: Documentation search scoping.

    *For any* OscalStore containing both OSCAL model documents and
    documentation entries, calling ``search_documentation()`` with any query
    string SHALL return only results where ``entity_type`` is
    ``"documentation"`` — no OSCAL model content (catalogs, SSPs, etc.)
    SHALL appear in the results.

    **Validates: Requirements 2.1**
    """

    # OSCAL model types that could appear in fts_index
    _oscal_model_types = [
        "catalog",
        "profile",
        "component-definition",
        "system-security-plan",
        "assessment-plan",
        "assessment-results",
        "plan-of-action-and-milestones",
    ]

    @pytest.mark.slow
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    @given(
        md_body=st.text(
            alphabet=st.characters(
                blacklist_categories=["Cs"], blacklist_characters="\r"
            ),
            min_size=0,
            max_size=300,
        ),
        oscal_model_type=st.sampled_from(_oscal_model_types),
        num_oscal_entries=st.integers(min_value=1, max_value=5),
    )
    def test_search_returns_only_documentation(
        self, md_body, oscal_model_type, num_oscal_entries, tmp_path_factory
    ):
        """Index markdown docs and inject OSCAL model FTS entries sharing
        the same keyword; verify search_documentation() returns only
        documentation-sourced results.

        **Validates: Requirements 2.1**
        """
        keyword = "compliance"
        tmp_path = tmp_path_factory.mktemp("prop4")
        db_path = str(tmp_path / "test.db")
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()

        # Create a markdown file containing the keyword so search has results
        md_content = f"# {keyword.title()} Guide\n\n{md_body}\n\n{keyword} details."
        (doc_dir / "guide.md").write_text(md_content, encoding="utf-8")

        store = OscalStore(db_path=db_path)
        try:
            store.scan_directory(doc_dir)

            # Inject OSCAL model entries into fts_index with the same keyword
            for i in range(num_oscal_entries):
                store._conn.execute(
                    """
                    INSERT INTO fts_index
                        (entity_type, entity_id, title, description, model_type)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        "document",
                        str(9000 + i),
                        f"OSCAL {keyword.title()} {oscal_model_type} #{i}",
                        f"An {oscal_model_type} about {keyword} controls #{i}",
                        oscal_model_type,
                    ),
                )
            store._conn.commit()

            # Search using the shared keyword
            result = store.search_documentation(keyword)

            # Every returned item must be documentation-sourced (.md file)
            for item in result["items"]:
                assert item["source"].endswith(".md"), (
                    f"Non-documentation result leaked through: source={item['source']!r}"
                )

            # If there are results, they should all come from our markdown file
            if result["total"] > 0:
                for item in result["items"]:
                    assert not any(
                        mt in item["source"] for mt in self._oscal_model_types
                    ), (
                        f"OSCAL model content appeared in documentation search: "
                        f"{item!r}"
                    )
        finally:
            store.close()


# ---------------------------------------------------------------------------
# Unit Tests for query_documentation refactor (Task 5.4)
# ---------------------------------------------------------------------------
import logging
from unittest.mock import MagicMock, patch

from mcp_server_for_oscal.tools import query_documentation


class TestInitStore:
    """Tests for init_store() setting the module-level singleton.

    Validates: Requirements 3.2, 5.1
    """

    def test_init_store_sets_module_singleton(self, tmp_path):
        """init_store() sets the module-level _store variable."""
        db_path = str(tmp_path / "test.db")
        store = OscalStore(db_path=db_path)
        try:
            old_store = query_documentation._store
            query_documentation.init_store(store)
            assert query_documentation._store is store
        finally:
            # Restore original state
            query_documentation._store = old_store
            store.close()

    def test_init_store_replaces_previous(self, tmp_path):
        """Calling init_store() again replaces the previous singleton."""
        db1 = str(tmp_path / "db1.db")
        db2 = str(tmp_path / "db2.db")
        store1 = OscalStore(db_path=db1)
        store2 = OscalStore(db_path=db2)
        try:
            old_store = query_documentation._store
            query_documentation.init_store(store1)
            assert query_documentation._store is store1
            query_documentation.init_store(store2)
            assert query_documentation._store is store2
        finally:
            query_documentation._store = old_store
            store1.close()
            store2.close()


class TestQueryLocalErrorHandling:
    """Tests for query_local() when store is not initialized.

    Validates: Requirements 3.2, 3.3
    """

    def test_query_local_returns_error_when_store_none(self):
        """query_local() returns error dict when _store is None."""
        old_store = query_documentation._store
        try:
            query_documentation._store = None
            result = query_documentation.query_local("some query", ctx=None)
            assert result == {"error": "OscalStore has not been initialized"}
        finally:
            query_documentation._store = old_store

    def test_query_local_delegates_to_search_documentation(self, tmp_path):
        """query_local() delegates to store.search_documentation() when store is set."""
        db_path = str(tmp_path / "test.db")
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "test.md").write_text(
            "# Test Doc\n\nSome content about OSCAL.",
            encoding="utf-8",
        )

        store = OscalStore(db_path=db_path)
        store.scan_directory(doc_dir)

        old_store = query_documentation._store
        try:
            query_documentation.init_store(store)
            result = query_documentation.query_local("OSCAL", ctx=None)
            assert "items" in result
            assert "total" in result
        finally:
            query_documentation._store = old_store
            store.close()

    def test_query_local_delegates_with_mock(self):
        """query_local() calls search_documentation on the store singleton."""
        mock_store = MagicMock()
        expected = {"items": [{"title": "T", "snippet": "S", "source": "f.md"}], "total": 1}
        mock_store.search_documentation.return_value = expected

        old_store = query_documentation._store
        try:
            query_documentation._store = mock_store
            result = query_documentation.query_local("test query", ctx=None)
            mock_store.search_documentation.assert_called_once_with("test query")
            assert result == expected
        finally:
            query_documentation._store = old_store


class TestQueryOscalDocumentationRouting:
    """Tests for query_oscal_documentation() routing logic.

    Validates: Requirements 4.2, 4.3, 4.4, 4.5, 4.6
    """

    def test_kb_path_when_knowledge_base_id_set(self):
        """When knowledge_base_id is set, query_kb() is called.

        Validates: Requirement 4.2
        """
        with patch.object(
            query_documentation, "config"
        ) as mock_config, patch.object(
            query_documentation, "query_kb"
        ) as mock_kb:
            mock_config.knowledge_base_id = "my-kb-id"
            mock_kb.return_value = {"results": []}

            # Call the underlying function directly (unwrap @tool decorator)
            fn = query_documentation.query_oscal_documentation
            # strands @tool wraps the function; access it directly
            result = fn(query="test query", ctx=None)

            mock_kb.assert_called_once_with("test query", None)
            assert result == {"results": []}

    def test_local_path_when_knowledge_base_id_not_set(self):
        """When knowledge_base_id is not set, query_local() is called.

        Validates: Requirement 4.3
        """
        with patch.object(
            query_documentation, "config"
        ) as mock_config, patch.object(
            query_documentation, "query_local"
        ) as mock_local:
            mock_config.knowledge_base_id = None
            mock_local.return_value = {"items": [], "total": 0}

            fn = query_documentation.query_oscal_documentation
            result = fn(query="test query", ctx=None)

            mock_local.assert_called_once_with("test query", None)
            assert result == {"items": [], "total": 0}

    def test_kb_failure_falls_back_to_local(self):
        """When query_kb() raises, falls back to query_local().

        Validates: Requirement 4.4
        """
        with patch.object(
            query_documentation, "config"
        ) as mock_config, patch.object(
            query_documentation, "query_kb", side_effect=RuntimeError("KB down")
        ), patch.object(
            query_documentation, "query_local"
        ) as mock_local:
            mock_config.knowledge_base_id = "my-kb-id"
            mock_local.return_value = {"items": [{"title": "Fallback"}], "total": 1}

            fn = query_documentation.query_oscal_documentation
            result = fn(query="test query", ctx=None)

            mock_local.assert_called_once_with("test query", None)
            assert result["items"][0]["title"] == "Fallback"

    def test_local_path_when_kb_id_empty_string(self):
        """Empty string knowledge_base_id uses local path.

        Validates: Requirement 4.3
        """
        with patch.object(
            query_documentation, "config"
        ) as mock_config, patch.object(
            query_documentation, "query_local"
        ) as mock_local:
            # Empty string is falsy but not None — check the actual code path
            mock_config.knowledge_base_id = None
            mock_local.return_value = {"items": [], "total": 0}

            fn = query_documentation.query_oscal_documentation
            result = fn(query="hello", ctx=None)

            mock_local.assert_called_once()


class TestSearchPathLogging:
    """Tests for logging of search path selection.

    Validates: Requirement 4.5
    """

    def test_logs_kb_path_when_kb_id_set(self, caplog):
        """Logs 'Knowledge Base search path' when KB ID is configured.

        Validates: Requirement 4.5
        """
        with patch.object(
            query_documentation, "config"
        ) as mock_config, patch.object(
            query_documentation, "query_kb"
        ) as mock_kb:
            mock_config.knowledge_base_id = "kb-123"
            mock_kb.return_value = {"results": []}

            with caplog.at_level(logging.INFO, logger="mcp_server_for_oscal.tools.query_documentation"):
                fn = query_documentation.query_oscal_documentation
                fn(query="test", ctx=None)

            assert any("Knowledge Base" in msg for msg in caplog.messages)

    def test_logs_local_path_when_kb_id_not_set(self, caplog):
        """Logs 'local documentation search path' when KB ID is not configured.

        Validates: Requirement 4.5
        """
        with patch.object(
            query_documentation, "config"
        ) as mock_config, patch.object(
            query_documentation, "query_local"
        ) as mock_local:
            mock_config.knowledge_base_id = None
            mock_local.return_value = {"items": [], "total": 0}

            with caplog.at_level(logging.INFO, logger="mcp_server_for_oscal.tools.query_documentation"):
                fn = query_documentation.query_oscal_documentation
                fn(query="test", ctx=None)

            assert any("local" in msg.lower() for msg in caplog.messages)

    def test_logs_fallback_on_kb_failure(self, caplog):
        """Logs fallback warning when KB query fails.

        Validates: Requirements 4.4, 4.5
        """
        with patch.object(
            query_documentation, "config"
        ) as mock_config, patch.object(
            query_documentation, "query_kb", side_effect=RuntimeError("fail")
        ), patch.object(
            query_documentation, "query_local"
        ) as mock_local:
            mock_config.knowledge_base_id = "kb-123"
            mock_local.return_value = {"items": [], "total": 0}

            with caplog.at_level(logging.WARNING, logger="mcp_server_for_oscal.tools.query_documentation"):
                fn = query_documentation.query_oscal_documentation
                fn(query="test", ctx=None)

            assert any("falling back" in msg.lower() or "failed" in msg.lower() for msg in caplog.messages)


class TestUnconditionalToolRegistration:
    """Test that query_oscal_documentation is always in the tool list.

    Validates: Requirement 4.1
    """

    def test_tool_present_without_kb_id(self):
        """query_oscal_documentation is in get_tool_list() even without KB ID."""
        from mcp_server_for_oscal.tools import get_tool_list

        with patch("mcp_server_for_oscal.config.config") as mock_config:
            mock_config.knowledge_base_id = None
            tools = get_tool_list()
            tool_names = {t.__name__ for t in tools}
            assert "query_oscal_documentation" in tool_names

    def test_tool_present_with_kb_id(self):
        """query_oscal_documentation is in get_tool_list() when KB ID is set."""
        from mcp_server_for_oscal.tools import get_tool_list

        with patch("mcp_server_for_oscal.config.config") as mock_config:
            mock_config.knowledge_base_id = "some-kb-id"
            tools = get_tool_list()
            tool_names = {t.__name__ for t in tools}
            assert "query_oscal_documentation" in tool_names


# ---------------------------------------------------------------------------
# Unit Tests for startup wiring in main.py (Task 6.2)
# ---------------------------------------------------------------------------
from unittest.mock import patch, MagicMock, call


class TestStartupWiring:
    """Tests for _init_oscal_store() wiring in main.py.

    Validates: Requirements 5.2, 5.3, 5.4
    """

    def test_init_oscal_store_calls_query_documentation_init_store(self):
        """_init_oscal_store() calls query_documentation.init_store(store).

        Validates: Requirement 5.2
        """
        from mcp_server_for_oscal.main import _init_oscal_store

        mock_store = MagicMock()

        with patch(
            "mcp_server_for_oscal.tools.oscal_store.OscalStore",
            return_value=mock_store,
        ), patch(
            "mcp_server_for_oscal.main.config"
        ) as mock_config, patch(
            "mcp_server_for_oscal.tools.list_oscal_resources.init_store"
        ), patch(
            "mcp_server_for_oscal.tools.query_component_definition.init_store"
        ), patch(
            "mcp_server_for_oscal.tools.query_oscal_models.init_store"
        ), patch(
            "mcp_server_for_oscal.tools.query_documentation.init_store"
        ) as mock_doc_init:
            mock_config.oscal_store_db_path = None
            mock_config.oscal_store_cache_size = 100
            mock_config.component_definitions_dir = "component_definitions"
            mock_config.oscal_documents_dir = None

            _init_oscal_store()

            mock_doc_init.assert_called_once_with(mock_store)

    def test_init_oscal_store_does_not_scan_oscal_docs_directory(self):
        """_init_oscal_store() no longer calls scan_directory() on oscal_docs/.

        oscal_docs/ was moved out of the package to data/ (build-time only).
        The bundled DB already contains all indexed content.

        Validates: Requirement 3.2
        """
        from mcp_server_for_oscal.main import _init_oscal_store

        mock_store = MagicMock()

        with patch(
            "mcp_server_for_oscal.tools.oscal_store.OscalStore",
            return_value=mock_store,
        ), patch(
            "mcp_server_for_oscal.main.config"
        ) as mock_config, patch(
            "mcp_server_for_oscal.tools.list_oscal_resources.init_store"
        ), patch(
            "mcp_server_for_oscal.tools.query_component_definition.init_store"
        ), patch(
            "mcp_server_for_oscal.tools.query_oscal_models.init_store"
        ), patch(
            "mcp_server_for_oscal.tools.query_documentation.init_store"
        ):
            mock_config.oscal_store_db_path = None
            mock_config.oscal_store_cache_size = 100
            mock_config.component_definitions_dir = "component_definitions"
            mock_config.oscal_documents_dir = None

            _init_oscal_store()

            # Verify scan_directory was NOT called with a path ending in "oscal_docs"
            scan_calls = mock_store.scan_directory.call_args_list
            oscal_docs_scanned = any(
                str(c.args[0]).endswith("oscal_docs")
                for c in scan_calls
                if c.args
            )
            assert not oscal_docs_scanned, (
                f"Expected scan_directory NOT to be called with a path ending in "
                f"'oscal_docs', but got calls: {scan_calls}"
            )

    def test_init_oscal_store_failure_leaves_store_none(self):
        """If _init_oscal_store() fails, query_documentation._store stays None.

        Validates: Requirement 5.4
        """
        from mcp_server_for_oscal.main import _init_oscal_store

        old_store = query_documentation._store
        try:
            # Reset _store to None before the test
            query_documentation._store = None

            # Make OscalStore constructor raise so _init_oscal_store fails
            with patch(
                "mcp_server_for_oscal.tools.oscal_store.OscalStore",
                side_effect=RuntimeError("DB init failed"),
            ):
                # Should not raise — it catches and logs
                _init_oscal_store()

            # _store should still be None because init_store was never called
            assert query_documentation._store is None
        finally:
            query_documentation._store = old_store

    def test_init_oscal_store_calls_all_init_stores(self):
        """_init_oscal_store() wires the store into all four modules.

        Validates: Requirements 5.2
        """
        from mcp_server_for_oscal.main import _init_oscal_store

        mock_store = MagicMock()

        with patch(
            "mcp_server_for_oscal.tools.oscal_store.OscalStore",
            return_value=mock_store,
        ), patch(
            "mcp_server_for_oscal.main.config"
        ) as mock_config, patch(
            "mcp_server_for_oscal.tools.list_oscal_resources.init_store"
        ) as mock_lr_init, patch(
            "mcp_server_for_oscal.tools.query_component_definition.init_store"
        ) as mock_cd_init, patch(
            "mcp_server_for_oscal.tools.query_oscal_models.init_store"
        ) as mock_models_init, patch(
            "mcp_server_for_oscal.tools.query_documentation.init_store"
        ) as mock_doc_init:
            mock_config.oscal_store_db_path = None
            mock_config.oscal_store_cache_size = 100
            mock_config.component_definitions_dir = "component_definitions"
            mock_config.oscal_documents_dir = None

            _init_oscal_store()

            mock_lr_init.assert_called_once_with(mock_store)
            mock_cd_init.assert_called_once_with(mock_store)
            mock_models_init.assert_called_once_with(mock_store)
            mock_doc_init.assert_called_once_with(mock_store)
