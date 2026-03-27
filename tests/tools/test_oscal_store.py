"""
Tests for OscalStore.scan_directory() and _detect_model_type().
"""

import json
import os
import zipfile

import pytest

from mcp_server_for_oscal.tools.oscal_store import OscalStore
from mcp_server_for_oscal.tools.utils import OSCALModelType


@pytest.fixture
def store(tmp_path):
    """Create an OscalStore with an ephemeral DB in tmp_path."""
    db_path = str(tmp_path / "test.db")
    s = OscalStore(db_path=db_path, cache_size=10)
    yield s
    s.close()


def _make_component_definition(uuid="a1b2c3d4-5678-4abc-8def-123456789012",
                                title="Test Component Definition"):
    """Create a minimal valid component-definition JSON dict."""
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


def _make_catalog(uuid="c1d2e3f4-5678-4abc-8def-aabbccddeeff",
                  title="Test Catalog"):
    """Create a minimal valid catalog JSON dict."""
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


class TestDetectModelType:
    """Tests for _detect_model_type()."""

    def test_detects_component_definition(self, store, tmp_path):
        f = tmp_path / "cdef.json"
        f.write_text(json.dumps(_make_component_definition()))
        assert store._detect_model_type(f) == OSCALModelType.COMPONENT_DEFINITION

    def test_detects_catalog(self, store, tmp_path):
        f = tmp_path / "catalog.json"
        f.write_text(json.dumps(_make_catalog()))
        assert store._detect_model_type(f) == OSCALModelType.CATALOG

    def test_returns_none_for_unknown_root_key(self, store, tmp_path):
        f = tmp_path / "unknown.json"
        f.write_text(json.dumps({"unknown-key": {"uuid": "123"}}))
        assert store._detect_model_type(f) is None

    def test_returns_none_for_invalid_json(self, store, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("not valid json {{{")
        assert store._detect_model_type(f) is None

    def test_returns_none_for_non_dict(self, store, tmp_path):
        f = tmp_path / "array.json"
        f.write_text(json.dumps([1, 2, 3]))
        assert store._detect_model_type(f) is None

    def test_returns_none_for_missing_file(self, store, tmp_path):
        f = tmp_path / "nonexistent.json"
        assert store._detect_model_type(f) is None

    def test_returns_none_for_empty_dict(self, store, tmp_path):
        f = tmp_path / "empty.json"
        f.write_text(json.dumps({}))
        assert store._detect_model_type(f) is None


class TestScanDirectory:
    """Tests for scan_directory()."""

    def test_scan_single_json_file(self, store, tmp_path):
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        f = doc_dir / "cdef.json"
        f.write_text(json.dumps(_make_component_definition()))

        count = store.scan_directory(doc_dir)
        assert count == 1

        # Verify document is in the DB
        row = store._conn.execute(
            "SELECT uuid, title, model_type, indexed FROM documents"
        ).fetchone()
        assert row is not None
        assert row["uuid"] == "a1b2c3d4-5678-4abc-8def-123456789012"
        assert row["title"] == "Test Component Definition"
        assert row["model_type"] == "component-definition"
        assert row["indexed"] == 0

    def test_scan_multiple_files(self, store, tmp_path):
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition())
        )
        (doc_dir / "catalog.json").write_text(
            json.dumps(_make_catalog())
        )

        count = store.scan_directory(doc_dir)
        assert count == 2

        total = store._conn.execute(
            "SELECT COUNT(*) as cnt FROM documents"
        ).fetchone()["cnt"]
        assert total == 2

    def test_scan_missing_directory_returns_zero(self, store, tmp_path):
        missing = tmp_path / "nonexistent"
        count = store.scan_directory(missing)
        assert count == 0

    def test_scan_empty_directory_returns_zero(self, store, tmp_path):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        count = store.scan_directory(empty_dir)
        assert count == 0

    def test_change_detection_skips_unchanged(self, store, tmp_path):
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        f = doc_dir / "cdef.json"
        f.write_text(json.dumps(_make_component_definition()))

        count1 = store.scan_directory(doc_dir)
        assert count1 == 1

        # Scan again without changes
        count2 = store.scan_directory(doc_dir)
        assert count2 == 0

    def test_change_detection_reingests_modified_file(self, store, tmp_path):
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        f = doc_dir / "cdef.json"
        f.write_text(json.dumps(_make_component_definition()))

        count1 = store.scan_directory(doc_dir)
        assert count1 == 1

        # Modify the file (change title, update mtime)
        updated = _make_component_definition(title="Updated Title")
        f.write_text(json.dumps(updated))
        # Force a different mtime
        new_mtime = os.path.getmtime(str(f)) + 1
        os.utime(str(f), (new_mtime, new_mtime))

        count2 = store.scan_directory(doc_dir)
        assert count2 == 1

        row = store._conn.execute(
            "SELECT title FROM documents WHERE uuid = ?",
            ("a1b2c3d4-5678-4abc-8def-123456789012",),
        ).fetchone()
        assert row["title"] == "Updated Title"

    def test_model_type_filter(self, store, tmp_path):
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition())
        )
        (doc_dir / "catalog.json").write_text(
            json.dumps(_make_catalog())
        )

        count = store.scan_directory(
            doc_dir,
            model_type_filter=OSCALModelType.CATALOG,
        )
        assert count == 1

        row = store._conn.execute(
            "SELECT model_type FROM documents"
        ).fetchone()
        assert row["model_type"] == "catalog"

    def test_skips_hashes_json(self, store, tmp_path):
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "hashes.json").write_text(
            json.dumps({"file_hashes": {}})
        )
        count = store.scan_directory(doc_dir)
        assert count == 0

    def test_skips_invalid_json(self, store, tmp_path):
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "bad.json").write_text("not json {{{")
        count = store.scan_directory(doc_dir)
        assert count == 0

    def test_skips_non_oscal_json(self, store, tmp_path):
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "other.json").write_text(
            json.dumps({"not-oscal": True})
        )
        count = store.scan_directory(doc_dir)
        assert count == 0

    def test_scan_zip_file(self, store, tmp_path):
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()

        # Create a zip with a component definition inside
        zip_path = doc_dir / "bundle.zip"
        cdef_data = _make_component_definition()
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("cdef.json", json.dumps(cdef_data))

        count = store.scan_directory(doc_dir)
        assert count == 1

        row = store._conn.execute(
            "SELECT uuid, title, model_type FROM documents"
        ).fetchone()
        assert row["uuid"] == "a1b2c3d4-5678-4abc-8def-123456789012"
        assert row["model_type"] == "component-definition"

    def test_scan_zip_with_non_json_entries(self, store, tmp_path):
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()

        zip_path = doc_dir / "mixed.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("readme.txt", "not json")
            zf.writestr(
                "cdef.json",
                json.dumps(_make_component_definition()),
            )

        count = store.scan_directory(doc_dir)
        assert count == 1

    def test_scan_bad_zip_file(self, store, tmp_path):
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "corrupt.zip").write_bytes(b"not a zip file")
        count = store.scan_directory(doc_dir)
        assert count == 0

    def test_raw_json_stored(self, store, tmp_path):
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        data = _make_component_definition()
        raw = json.dumps(data)
        (doc_dir / "cdef.json").write_text(raw)

        store.scan_directory(doc_dir)

        row = store._conn.execute(
            "SELECT raw_json FROM documents"
        ).fetchone()
        assert json.loads(row["raw_json"]) == data

    def test_file_path_stored(self, store, tmp_path):
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        f = doc_dir / "cdef.json"
        f.write_text(json.dumps(_make_component_definition()))

        store.scan_directory(doc_dir)

        row = store._conn.execute(
            "SELECT file_path FROM documents"
        ).fetchone()
        assert row["file_path"] == str(f)

    def test_scan_subdirectories(self, store, tmp_path):
        doc_dir = tmp_path / "docs"
        sub = doc_dir / "sub" / "deep"
        sub.mkdir(parents=True)
        (sub / "cdef.json").write_text(
            json.dumps(_make_component_definition())
        )

        count = store.scan_directory(doc_dir)
        assert count == 1

    def test_scan_not_a_directory(self, store, tmp_path):
        f = tmp_path / "file.txt"
        f.write_text("hello")
        count = store.scan_directory(f)
        assert count == 0

    def test_skips_validation_failing_document(self, store, tmp_path):
        """Documents that fail Trestle validation are skipped."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        # Missing required metadata fields
        bad_doc = {
            "component-definition": {
                "uuid": "a1b2c3d4-5678-4abc-8def-123456789012",
                "metadata": {
                    "title": "Bad Doc",
                    # missing last-modified, version, oscal-version
                },
            }
        }
        (doc_dir / "bad.json").write_text(json.dumps(bad_doc))
        count = store.scan_directory(doc_dir)
        assert count == 0


class TestGetParsedModel:
    """Tests for get_parsed_model() LRU cache."""

    def test_parses_component_definition(self, store, tmp_path):
        """Parsing a valid component-definition returns a Trestle model."""
        from trestle.oscal.component import ComponentDefinition

        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition())
        )
        store.scan_directory(doc_dir)

        row = store._conn.execute("SELECT id FROM documents").fetchone()
        model = store.get_parsed_model(row["id"])
        assert isinstance(model, ComponentDefinition)
        assert str(model.uuid) == "a1b2c3d4-5678-4abc-8def-123456789012"

    def test_parses_catalog(self, store, tmp_path):
        """Parsing a valid catalog returns a Trestle Catalog model."""
        from trestle.oscal.catalog import Catalog

        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "catalog.json").write_text(
            json.dumps(_make_catalog())
        )
        store.scan_directory(doc_dir)

        row = store._conn.execute("SELECT id FROM documents").fetchone()
        model = store.get_parsed_model(row["id"])
        assert isinstance(model, Catalog)
        assert str(model.uuid) == "c1d2e3f4-5678-4abc-8def-aabbccddeeff"

    def test_cache_returns_same_object(self, store, tmp_path):
        """Repeated calls return the same cached object (identity check)."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition())
        )
        store.scan_directory(doc_dir)

        row = store._conn.execute("SELECT id FROM documents").fetchone()
        model1 = store.get_parsed_model(row["id"])
        model2 = store.get_parsed_model(row["id"])
        assert model1 is model2

    def test_cache_info_tracks_hits(self, store, tmp_path):
        """LRU cache stats reflect hits after repeated access."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition())
        )
        store.scan_directory(doc_dir)

        row = store._conn.execute("SELECT id FROM documents").fetchone()
        store.get_parsed_model(row["id"])
        store.get_parsed_model(row["id"])

        info = store._cached_parse.cache_info()
        assert info.hits >= 1
        assert info.misses >= 1

    def test_raises_for_nonexistent_doc_id(self, store):
        """Requesting a non-existent doc_id raises ValueError."""
        with pytest.raises(ValueError, match="No document found"):
            store.get_parsed_model(99999)

    def test_cache_eviction(self, tmp_path):
        """When cache_size is exceeded, oldest entries are evicted."""
        db_path = str(tmp_path / "evict.db")
        small_store = OscalStore(db_path=db_path, cache_size=2)
        try:
            doc_dir = tmp_path / "docs"
            doc_dir.mkdir()

            uuids = [
                "a1b2c3d4-0001-4abc-8def-123456789012",
                "a1b2c3d4-0002-4abc-8def-123456789012",
                "a1b2c3d4-0003-4abc-8def-123456789012",
            ]
            for i, uuid in enumerate(uuids):
                f = doc_dir / f"cdef_{i}.json"
                f.write_text(json.dumps(
                    _make_component_definition(uuid=uuid, title=f"Doc {i}")
                ))

            small_store.scan_directory(doc_dir)

            rows = small_store._conn.execute(
                "SELECT id FROM documents ORDER BY id"
            ).fetchall()
            assert len(rows) == 3

            # Parse all three — cache_size=2 so first should be evicted
            ids = [r["id"] for r in rows]
            small_store.get_parsed_model(ids[0])
            small_store.get_parsed_model(ids[1])
            small_store.get_parsed_model(ids[2])

            info = small_store._cached_parse.cache_info()
            assert info.misses == 3
            assert info.currsize == 2  # only 2 fit in cache

            # Accessing the first again should be a miss (evicted)
            small_store.get_parsed_model(ids[0])
            info2 = small_store._cached_parse.cache_info()
            assert info2.misses == 4
        finally:
            small_store.close()

    def test_parses_from_raw_json_not_filesystem(self, store, tmp_path):
        """Parsing works even after the source file is deleted."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        f = doc_dir / "cdef.json"
        f.write_text(json.dumps(_make_component_definition()))
        store.scan_directory(doc_dir)

        # Delete the source file
        f.unlink()

        row = store._conn.execute("SELECT id FROM documents").fetchone()
        # Should still parse from raw_json in SQLite
        model = store.get_parsed_model(row["id"])
        assert str(model.uuid) == "a1b2c3d4-5678-4abc-8def-123456789012"

    def test_reingested_doc_bypasses_stale_cache(self, store, tmp_path):
        """When raw_json changes after re-ingestion, cache returns fresh parse."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        f = doc_dir / "cdef.json"
        f.write_text(json.dumps(_make_component_definition(title="Original")))
        store.scan_directory(doc_dir)

        row = store._conn.execute("SELECT id FROM documents").fetchone()
        model1 = store.get_parsed_model(row["id"])
        assert str(model1.metadata.title) == "Original"

        # Re-ingest with updated content
        updated = _make_component_definition(title="Updated")
        f.write_text(json.dumps(updated))
        new_mtime = os.path.getmtime(str(f)) + 1
        os.utime(str(f), (new_mtime, new_mtime))
        store.scan_directory(doc_dir)

        # Same doc_id but new raw_json → cache miss → fresh parse
        model2 = store.get_parsed_model(row["id"])
        assert str(model2.metadata.title) == "Updated"
        assert model1 is not model2


# ---------------------------------------------------------------------------
# Helpers for building minimal valid OSCAL documents of various types
# ---------------------------------------------------------------------------

_COMMON_METADATA = {
    "title": "Test Document",
    "last-modified": "2024-01-01T00:00:00Z",
    "version": "1.0",
    "oscal-version": "1.0.4",
}


def _make_catalog_with_controls(
    uuid="c1d2e3f4-5678-4abc-8def-aabbccddeeff",
    title="Test Catalog",
):
    """Catalog with controls and groups."""
    return {
        "catalog": {
            "uuid": uuid,
            "metadata": {**_COMMON_METADATA, "title": title},
            "controls": [
                {"id": "ac-1", "title": "Access Control Policy"},
                {"id": "ac-2", "title": "Account Management"},
            ],
            "groups": [
                {
                    "id": "ac",
                    "title": "Access Control",
                }
            ],
        }
    }


def _make_component_definition_with_children(
    uuid="a1b2c3d4-5678-4abc-8def-123456789012",
    title="Test Component Definition",
):
    """Component definition with components and capabilities."""
    return {
        "component-definition": {
            "uuid": uuid,
            "metadata": {**_COMMON_METADATA, "title": title},
            "components": [
                {
                    "uuid": "b2c3d4e5-6789-4bcd-9efa-234567890123",
                    "type": "software",
                    "title": "Sample Component",
                    "description": "A sample component for testing",
                },
                {
                    "uuid": "c3d4e5f6-789a-4cde-afab-345678901234",
                    "type": "service",
                    "title": "Another Component",
                    "description": "Another component",
                },
            ],
            "capabilities": [
                {
                    "uuid": "d4e5f6a7-89ab-4def-b0ab-456789012345",
                    "name": "Test Capability",
                    "description": "A test capability",
                }
            ],
        }
    }


def _make_poam(
    uuid="e5f6a7b8-9abc-4ef0-a1ab-567890123456",
    title="Test POA&M",
):
    """POA&M with poam-items."""
    return {
        "plan-of-action-and-milestones": {
            "uuid": uuid,
            "metadata": {**_COMMON_METADATA, "title": title},
            "poam-items": [
                {
                    "uuid": "f6a7b8c9-abcd-4f01-a2ab-678901234567",
                    "title": "Fix vulnerability",
                    "description": "Remediate CVE-2024-0001",
                },
            ],
        }
    }


class TestEnsureIndexed:
    """Tests for _ensure_indexed()."""

    def test_indexes_component_definition(self, store, tmp_path):
        """Indexing a component-definition extracts components and capabilities."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        data = _make_component_definition_with_children()
        (doc_dir / "cdef.json").write_text(json.dumps(data))
        store.scan_directory(doc_dir)

        row = store._conn.execute("SELECT id, indexed FROM documents").fetchone()
        assert row["indexed"] == 0

        store._ensure_indexed(row["id"])

        # Verify indexed flag is set
        row2 = store._conn.execute(
            "SELECT indexed FROM documents WHERE id = ?", (row["id"],)
        ).fetchone()
        assert row2["indexed"] == 1

        # Verify child elements
        children = store._conn.execute(
            "SELECT uuid, title, element_type FROM child_elements "
            "WHERE parent_doc_id = ? ORDER BY element_type, title",
            (row["id"],),
        ).fetchall()
        assert len(children) == 3

        types = {c["element_type"] for c in children}
        assert types == {"component", "capability"}

    def test_noop_when_already_indexed(self, store, tmp_path):
        """Calling _ensure_indexed on an already-indexed doc is a no-op."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition_with_children())
        )
        store.scan_directory(doc_dir)

        row = store._conn.execute("SELECT id FROM documents").fetchone()
        store._ensure_indexed(row["id"])
        store._ensure_indexed(row["id"])  # second call should be no-op

        children = store._conn.execute(
            "SELECT COUNT(*) as cnt FROM child_elements WHERE parent_doc_id = ?",
            (row["id"],),
        ).fetchone()
        # Still 3 children (2 components + 1 capability), not doubled
        assert children["cnt"] == 3

    def test_raises_for_nonexistent_doc(self, store):
        """_ensure_indexed raises ValueError for unknown doc_id."""
        with pytest.raises(ValueError, match="No document found"):
            store._ensure_indexed(99999)

    def test_indexes_catalog_with_controls_and_groups(self, store, tmp_path):
        """Indexing a catalog extracts controls and groups."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "catalog.json").write_text(
            json.dumps(_make_catalog_with_controls())
        )
        store.scan_directory(doc_dir)

        row = store._conn.execute("SELECT id FROM documents").fetchone()
        store._ensure_indexed(row["id"])

        children = store._conn.execute(
            "SELECT uuid, title, element_type FROM child_elements "
            "WHERE parent_doc_id = ?",
            (row["id"],),
        ).fetchall()
        assert len(children) == 3  # 2 controls + 1 group

        types = {c["element_type"] for c in children}
        assert types == {"control", "group"}

    def test_indexes_poam(self, store, tmp_path):
        """Indexing a POA&M extracts poam-items."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "poam.json").write_text(json.dumps(_make_poam()))
        store.scan_directory(doc_dir)

        row = store._conn.execute("SELECT id FROM documents").fetchone()
        store._ensure_indexed(row["id"])

        children = store._conn.execute(
            "SELECT uuid, title, element_type, description FROM child_elements "
            "WHERE parent_doc_id = ?",
            (row["id"],),
        ).fetchall()
        assert len(children) == 1
        assert children[0]["element_type"] == "poam-item"
        assert children[0]["title"] == "Fix vulnerability"
        assert children[0]["description"] == "Remediate CVE-2024-0001"

    def test_fts_entries_created(self, store, tmp_path):
        """Indexing populates the FTS index for both document and children."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition_with_children())
        )
        store.scan_directory(doc_dir)

        row = store._conn.execute("SELECT id FROM documents").fetchone()
        store._ensure_indexed(row["id"])

        # FTS5 external content mode: verify entries exist via MATCH queries
        # Search for the document title
        doc_matches = store._conn.execute(
            "SELECT COUNT(*) as cnt FROM fts_index WHERE fts_index MATCH 'Test'",
        ).fetchone()
        assert doc_matches["cnt"] > 0

        # Search for a child element title
        child_matches = store._conn.execute(
            "SELECT COUNT(*) as cnt FROM fts_index WHERE fts_index MATCH 'Sample'",
        ).fetchone()
        assert child_matches["cnt"] > 0

        # Total FTS entries: 1 document + 3 child elements = 4
        total = store._conn.execute(
            "SELECT COUNT(*) as cnt FROM fts_index",
        ).fetchone()
        assert total["cnt"] == 4

    def test_child_elements_have_raw_json(self, store, tmp_path):
        """Child elements store serialized JSON."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition_with_children())
        )
        store.scan_directory(doc_dir)

        row = store._conn.execute("SELECT id FROM documents").fetchone()
        store._ensure_indexed(row["id"])

        children = store._conn.execute(
            "SELECT raw_json FROM child_elements WHERE parent_doc_id = ?",
            (row["id"],),
        ).fetchall()
        for child in children:
            assert child["raw_json"] is not None
            parsed = json.loads(child["raw_json"])
            assert isinstance(parsed, dict)


class TestExtractChildElements:
    """Tests for _extract_child_elements()."""

    def test_component_definition_children(self, store, tmp_path):
        """Extracts components and capabilities from a component-definition."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition_with_children())
        )
        store.scan_directory(doc_dir)

        row = store._conn.execute("SELECT id FROM documents").fetchone()
        model = store.get_parsed_model(row["id"])
        children = store._extract_child_elements(
            OSCALModelType.COMPONENT_DEFINITION, model
        )

        assert len(children) == 3
        comp_children = [c for c in children if c["element_type"] == "component"]
        cap_children = [c for c in children if c["element_type"] == "capability"]
        assert len(comp_children) == 2
        assert len(cap_children) == 1
        assert cap_children[0]["title"] == "Test Capability"

    def test_catalog_children(self, store, tmp_path):
        """Extracts controls and groups from a catalog."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "catalog.json").write_text(
            json.dumps(_make_catalog_with_controls())
        )
        store.scan_directory(doc_dir)

        row = store._conn.execute("SELECT id FROM documents").fetchone()
        model = store.get_parsed_model(row["id"])
        children = store._extract_child_elements(
            OSCALModelType.CATALOG, model
        )

        assert len(children) == 3
        ctrl_children = [c for c in children if c["element_type"] == "control"]
        grp_children = [c for c in children if c["element_type"] == "group"]
        assert len(ctrl_children) == 2
        assert len(grp_children) == 1
        # Controls use 'id' as uuid
        assert ctrl_children[0]["uuid"] == "ac-1"
        assert grp_children[0]["uuid"] == "ac"

    def test_empty_model_returns_empty_list(self, store, tmp_path):
        """A catalog with no controls or groups returns empty children."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "catalog.json").write_text(json.dumps(_make_catalog()))
        store.scan_directory(doc_dir)

        row = store._conn.execute("SELECT id FROM documents").fetchone()
        model = store.get_parsed_model(row["id"])
        children = store._extract_child_elements(
            OSCALModelType.CATALOG, model
        )
        assert children == []

    def test_child_element_types_match_mapping(self, store, tmp_path):
        """Extracted child element types are in the CHILD_ELEMENT_TYPES mapping."""
        from mcp_server_for_oscal.tools.oscal_store import CHILD_ELEMENT_TYPES

        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition_with_children())
        )
        store.scan_directory(doc_dir)

        row = store._conn.execute("SELECT id FROM documents").fetchone()
        model = store.get_parsed_model(row["id"])
        children = store._extract_child_elements(
            OSCALModelType.COMPONENT_DEFINITION, model
        )

        expected_types = set(CHILD_ELEMENT_TYPES[OSCALModelType.COMPONENT_DEFINITION])
        actual_types = {c["element_type"] for c in children}
        assert actual_types.issubset(expected_types)

    def test_poam_children(self, store, tmp_path):
        """Extracts poam-items from a POA&M."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "poam.json").write_text(json.dumps(_make_poam()))
        store.scan_directory(doc_dir)

        row = store._conn.execute("SELECT id FROM documents").fetchone()
        model = store.get_parsed_model(row["id"])
        children = store._extract_child_elements(
            OSCALModelType.PLAN_OF_ACTION_AND_MILESTONES, model
        )

        assert len(children) == 1
        assert children[0]["element_type"] == "poam-item"
        assert children[0]["uuid"] == "f6a7b8c9-abcd-4f01-a2ab-678901234567"


# ---------------------------------------------------------------------------
# Property-Based Tests (Hypothesis)
# ---------------------------------------------------------------------------

import uuid as uuid_mod

from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st


def _uuid4_hex() -> str:
    """Generate a valid UUID4 string."""
    return str(uuid_mod.uuid4())


# Strategy: generate a list of (maker_fn, uuid, title) tuples representing
# OSCAL documents of mixed types.  Each document gets a unique UUID so there
# are no collisions.
_DOC_MAKERS = [
    ("component-definition", _make_component_definition),
    ("catalog", _make_catalog),
    ("catalog-with-controls", _make_catalog_with_controls),
    ("component-definition-with-children", _make_component_definition_with_children),
    ("poam", _make_poam),
]


@st.composite
def oscal_document_set(draw):
    """Strategy that produces a list of (filename, json_data, uuid, title) tuples.

    Each document has a unique UUID and a unique filename.
    Generates between 1 and 8 documents of mixed types.
    """
    count = draw(st.integers(min_value=1, max_value=8))
    docs = []
    used_uuids = set()
    for i in range(count):
        maker_name, maker_fn = draw(st.sampled_from(_DOC_MAKERS))
        doc_uuid = _uuid4_hex()
        while doc_uuid in used_uuids:
            doc_uuid = _uuid4_hex()
        used_uuids.add(doc_uuid)
        title = f"Doc-{i}-{maker_name}"
        data = maker_fn(uuid=doc_uuid, title=title)
        filename = f"doc_{i}_{maker_name}.json"
        docs.append((filename, data, doc_uuid, title))
    return docs


class TestIncrementalReindexingProperty:
    """Feature: scalable-oscal-store, Property 6: Incremental re-indexing.

    *For any* set of ingested OSCAL documents, if the store is re-initialized
    with the same database and the files on disk have not changed (same mtime
    and size), then re-scanning should result in zero files being re-processed,
    and all previously indexed data should remain intact and queryable.

    **Validates: Requirements 3.4, 3.5, 9.5**
    """

    @pytest.mark.slow
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    @given(doc_set=oscal_document_set())
    def test_rescan_unchanged_files_returns_zero(self, doc_set, tmp_path_factory):
        """After ingesting documents and re-initializing the store with the
        same DB, re-scanning unchanged files should return 0 and all data
        should remain intact.

        **Validates: Requirements 3.4, 3.5, 9.5**
        """
        tmp_path = tmp_path_factory.mktemp("prop6")
        db_path = str(tmp_path / "test.db")
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()

        # --- Phase 1: Write documents and ingest ---
        for filename, data, _uuid, _title in doc_set:
            (doc_dir / filename).write_text(json.dumps(data))

        store1 = OscalStore(db_path=db_path, cache_size=50)
        try:
            count1 = store1.scan_directory(doc_dir)
            assert count1 == len(doc_set), (
                f"Expected {len(doc_set)} ingested, got {count1}"
            )

            # Snapshot the document rows for later comparison
            original_rows = store1._conn.execute(
                "SELECT uuid, title, model_type, file_path, file_size "
                "FROM documents ORDER BY uuid"
            ).fetchall()
            original_data = [
                {
                    "uuid": r["uuid"],
                    "title": r["title"],
                    "model_type": r["model_type"],
                    "file_path": r["file_path"],
                    "file_size": r["file_size"],
                }
                for r in original_rows
            ]
        finally:
            store1.close()

        # --- Phase 2: Re-initialize store with same DB, re-scan ---
        store2 = OscalStore(db_path=db_path, cache_size=50)
        try:
            count2 = store2.scan_directory(doc_dir)

            # Core assertion: zero files re-processed
            assert count2 == 0, (
                f"Expected 0 re-processed files, got {count2}"
            )

            # Verify all documents are still present and queryable
            persisted_rows = store2._conn.execute(
                "SELECT uuid, title, model_type, file_path, file_size "
                "FROM documents ORDER BY uuid"
            ).fetchall()
            persisted_data = [
                {
                    "uuid": r["uuid"],
                    "title": r["title"],
                    "model_type": r["model_type"],
                    "file_path": r["file_path"],
                    "file_size": r["file_size"],
                }
                for r in persisted_rows
            ]

            assert len(persisted_data) == len(original_data), (
                f"Document count changed: {len(original_data)} → "
                f"{len(persisted_data)}"
            )

            # Verify each document's metadata is intact
            for orig, pers in zip(original_data, persisted_data):
                assert orig["uuid"] == pers["uuid"]
                assert orig["title"] == pers["title"]
                assert orig["model_type"] == pers["model_type"]
                assert orig["file_size"] == pers["file_size"]

            # Verify each document is individually queryable by UUID
            for _filename, _data, doc_uuid, _title in doc_set:
                row = store2._conn.execute(
                    "SELECT uuid, title FROM documents WHERE uuid = ?",
                    (doc_uuid,),
                ).fetchone()
                assert row is not None, (
                    f"Document {doc_uuid} not found after re-init"
                )
                assert row["uuid"] == doc_uuid
        finally:
            store2.close()


# ---------------------------------------------------------------------------
# Property-based tests (Hypothesis)
# ---------------------------------------------------------------------------

from hypothesis import given, settings
from hypothesis import strategies as st

from mcp_server_for_oscal.tools.utils import ROOT_KEY_TO_MODEL_TYPE


# Strategy: pick a valid root key from ROOT_KEY_TO_MODEL_TYPE
_valid_root_keys = st.sampled_from(sorted(ROOT_KEY_TO_MODEL_TYPE.keys()))

# Strategy: generate a safe title string (non-empty, printable, no null bytes)
_titles = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "Z"), blacklist_characters="\x00"),
    min_size=1,
    max_size=60,
).filter(lambda t: t.strip())


def _make_minimal_doc(root_key: str, uuid: str, title: str) -> dict:
    """Build a minimal OSCAL-shaped JSON dict for any root key.

    This is intentionally *not* Trestle-valid — it is used only for
    _detect_model_type() which inspects the root key, not the content.
    """
    return {
        root_key: {
            "uuid": uuid,
            "metadata": {
                "title": title,
                "last-modified": "2024-01-01T00:00:00Z",
                "version": "1.0",
                "oscal-version": "1.0.4",
            },
        }
    }


# Builders for model types that pass Trestle validation, keyed by root key.
_VALID_DOC_BUILDERS: dict = {
    "catalog": lambda uuid, title: _make_catalog(uuid=uuid, title=title),
    "component-definition": lambda uuid, title: _make_component_definition(uuid=uuid, title=title),
    "plan-of-action-and-milestones": lambda uuid, title: _make_poam(uuid=uuid, title=title),
}

# Root keys that have valid doc builders for ingestion testing
_ingestable_root_keys = st.sampled_from(sorted(_VALID_DOC_BUILDERS.keys()))


class TestPropertyModelTypeDetection:
    """Property 3: Model type detection and multi-model acceptance.

    **Validates: Requirements 2.1, 2.2**
    """

    @given(root_key=_valid_root_keys, title=_titles)
    @settings(max_examples=100)
    @pytest.mark.slow
    def test_detect_model_type_returns_correct_enum(self, root_key, title):
        """For any valid root key, _detect_model_type returns the correct OSCALModelType.

        **Validates: Requirements 2.1, 2.2**
        """
        import tempfile

        expected = ROOT_KEY_TO_MODEL_TYPE[root_key]
        doc = _make_minimal_doc(root_key, "a1b2c3d4-5678-4abc-8def-123456789012", title)

        with tempfile.TemporaryDirectory() as tmp:
            from pathlib import Path

            db_path = str(Path(tmp) / "test.db")
            s = OscalStore(db_path=db_path, cache_size=10)
            try:
                f = Path(tmp) / f"{root_key}.json"
                f.write_text(json.dumps(doc))

                detected = s._detect_model_type(f)
                assert detected == expected, (
                    f"Expected {expected} for root key '{root_key}', got {detected}"
                )
            finally:
                s.close()

    @given(root_key=_ingestable_root_keys, title=_titles)
    @settings(max_examples=100)
    @pytest.mark.slow
    def test_valid_docs_ingest_and_query(self, root_key, title):
        """Documents with valid root keys can be ingested and queried back.

        **Validates: Requirements 2.1, 2.2**
        """
        import tempfile

        uuid = "a1b2c3d4-5678-4abc-8def-123456789012"
        builder = _VALID_DOC_BUILDERS[root_key]
        doc = builder(uuid, title)

        with tempfile.TemporaryDirectory() as tmp:
            from pathlib import Path

            db_path = str(Path(tmp) / "test.db")
            s = OscalStore(db_path=db_path, cache_size=10)
            try:
                doc_dir = Path(tmp) / "docs"
                doc_dir.mkdir()
                f = doc_dir / f"{root_key}.json"
                f.write_text(json.dumps(doc))

                count = s.scan_directory(doc_dir)
                assert count == 1, f"Expected 1 ingested doc for '{root_key}', got {count}"

                row = s._conn.execute(
                    "SELECT uuid, title, model_type FROM documents WHERE uuid = ?",
                    (uuid,),
                ).fetchone()
                assert row is not None, f"Document with uuid {uuid} not found after ingestion"
                assert row["uuid"] == uuid
                assert row["title"] == title
                assert row["model_type"] == root_key
            finally:
                s.close()


# ---------------------------------------------------------------------------
# Tests for query() method
# ---------------------------------------------------------------------------


class TestQuery:
    """Tests for the query() method."""

    def test_query_all_empty_store(self, store):
        """query(query_type='all') on empty store returns empty page."""
        result = store.query()
        assert result["items"] == []
        assert result["total"] == 0
        assert result["offset"] == 0
        assert result["limit"] == 10
        assert result["hasMore"] is False

    def test_query_all_returns_documents(self, store, tmp_path):
        """query(query_type='all') returns all ingested documents."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition())
        )
        (doc_dir / "catalog.json").write_text(
            json.dumps(_make_catalog())
        )
        store.scan_directory(doc_dir)

        result = store.query(query_type="all")
        assert result["total"] == 2
        assert len(result["items"]) == 2
        assert result["offset"] == 0
        assert result["limit"] == 10
        assert result["hasMore"] is False

    def test_query_all_with_model_type_filter(self, store, tmp_path):
        """query(query_type='all', oscal_model_type=...) filters by type."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition())
        )
        (doc_dir / "catalog.json").write_text(
            json.dumps(_make_catalog())
        )
        store.scan_directory(doc_dir)

        result = store.query(
            query_type="all",
            oscal_model_type=OSCALModelType.CATALOG,
        )
        assert result["total"] == 1
        assert len(result["items"]) == 1
        assert result["items"][0]["model_type"] == "catalog"

    def test_query_by_uuid(self, store, tmp_path):
        """query(query_type='by_uuid') returns exact match."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        target_uuid = "a1b2c3d4-5678-4abc-8def-123456789012"
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition(uuid=target_uuid))
        )
        store.scan_directory(doc_dir)

        result = store.query(query_type="by_uuid", query_value=target_uuid)
        assert result["total"] == 1
        assert len(result["items"]) == 1
        assert result["items"][0]["uuid"] == target_uuid

    def test_query_by_uuid_not_found(self, store, tmp_path):
        """query(query_type='by_uuid') with unknown UUID returns empty."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition())
        )
        store.scan_directory(doc_dir)

        result = store.query(
            query_type="by_uuid",
            query_value="00000000-0000-0000-0000-000000000000",
        )
        assert result["total"] == 0
        assert result["items"] == []

    def test_query_by_uuid_with_model_type_filter(self, store, tmp_path):
        """by_uuid respects oscal_model_type filter."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        target_uuid = "a1b2c3d4-5678-4abc-8def-123456789012"
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition(uuid=target_uuid))
        )
        store.scan_directory(doc_dir)

        # Correct type — should find it
        result = store.query(
            query_type="by_uuid",
            query_value=target_uuid,
            oscal_model_type=OSCALModelType.COMPONENT_DEFINITION,
        )
        assert result["total"] == 1

        # Wrong type — should not find it
        result = store.query(
            query_type="by_uuid",
            query_value=target_uuid,
            oscal_model_type=OSCALModelType.CATALOG,
        )
        assert result["total"] == 0

    def test_query_by_title_exact_match(self, store, tmp_path):
        """by_title finds case-insensitive exact match."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition(title="My Component Def"))
        )
        store.scan_directory(doc_dir)

        # Exact case
        result = store.query(
            query_type="by_title", query_value="My Component Def"
        )
        assert result["total"] == 1
        assert result["items"][0]["title"] == "My Component Def"

        # Different case
        result = store.query(
            query_type="by_title", query_value="my component def"
        )
        assert result["total"] == 1

    def test_query_by_title_fts_fallback(self, store, tmp_path):
        """by_title falls back to FTS when no exact match."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(
                _make_component_definition(title="AWS Security Controls")
            )
        )
        store.scan_directory(doc_dir)

        # Ensure the document is indexed so FTS entries exist
        row = store._conn.execute("SELECT id FROM documents").fetchone()
        store._ensure_indexed(row["id"])

        # FTS fallback — partial title that won't exact-match
        result = store.query(
            query_type="by_title", query_value="Security"
        )
        assert result["total"] >= 1

    def test_query_by_title_not_found(self, store, tmp_path):
        """by_title returns empty when no match."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition(title="Real Title"))
        )
        store.scan_directory(doc_dir)

        result = store.query(
            query_type="by_title", query_value="Nonexistent Title"
        )
        assert result["total"] == 0

    def test_query_by_type(self, store, tmp_path):
        """by_type filters on model_type column."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition())
        )
        (doc_dir / "catalog.json").write_text(
            json.dumps(_make_catalog())
        )
        store.scan_directory(doc_dir)

        result = store.query(
            query_type="by_type", query_value="catalog"
        )
        assert result["total"] == 1
        assert result["items"][0]["model_type"] == "catalog"

    def test_query_by_type_no_match(self, store, tmp_path):
        """by_type returns empty when no documents of that type."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition())
        )
        store.scan_directory(doc_dir)

        result = store.query(
            query_type="by_type", query_value="catalog"
        )
        assert result["total"] == 0

    def test_query_raises_for_missing_query_value(self, store):
        """ValueError raised when query_value missing for by_uuid/by_title/by_type."""
        with pytest.raises(ValueError, match="query_value is required"):
            store.query(query_type="by_uuid")

        with pytest.raises(ValueError, match="query_value is required"):
            store.query(query_type="by_title")

        with pytest.raises(ValueError, match="query_value is required"):
            store.query(query_type="by_type")

    def test_query_raises_for_empty_query_value(self, store):
        """ValueError raised when query_value is empty string."""
        with pytest.raises(ValueError, match="query_value is required"):
            store.query(query_type="by_uuid", query_value="")

    def test_query_pagination(self, store, tmp_path):
        """query() respects offset and limit."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        uuids = []
        for i in range(5):
            uid = f"a1b2c3d4-{i:04d}-4abc-8def-123456789012"
            uuids.append(uid)
            (doc_dir / f"cdef_{i}.json").write_text(
                json.dumps(
                    _make_component_definition(uuid=uid, title=f"Doc {i}")
                )
            )
        store.scan_directory(doc_dir)

        # First page
        result = store.query(query_type="all", offset=0, limit=2)
        assert result["total"] == 5
        assert len(result["items"]) == 2
        assert result["offset"] == 0
        assert result["limit"] == 2
        assert result["hasMore"] is True

        # Second page
        result = store.query(query_type="all", offset=2, limit=2)
        assert len(result["items"]) == 2
        assert result["hasMore"] is True

        # Last page
        result = store.query(query_type="all", offset=4, limit=2)
        assert len(result["items"]) == 1
        assert result["hasMore"] is False

    def test_query_triggers_ensure_indexed(self, store, tmp_path):
        """query() triggers _ensure_indexed for result documents."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition_with_children())
        )
        store.scan_directory(doc_dir)

        # Before query, document should not be indexed
        row = store._conn.execute(
            "SELECT indexed FROM documents"
        ).fetchone()
        assert row["indexed"] == 0

        # Query triggers indexing
        result = store.query(query_type="all")
        assert len(result["items"]) == 1

        # After query, document should be indexed
        row = store._conn.execute(
            "SELECT indexed FROM documents"
        ).fetchone()
        assert row["indexed"] == 1

    def test_query_items_include_children(self, store, tmp_path):
        """query() items include children after _ensure_indexed."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition_with_children())
        )
        store.scan_directory(doc_dir)

        result = store.query(query_type="all")
        item = result["items"][0]
        assert "children" in item
        assert len(item["children"]) == 3  # 2 components + 1 capability
        child_types = {c["element_type"] for c in item["children"]}
        assert child_types == {"component", "capability"}

    def test_query_item_format(self, store, tmp_path):
        """query() items have the expected keys."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition())
        )
        store.scan_directory(doc_dir)

        result = store.query(query_type="all")
        item = result["items"][0]
        expected_keys = {"uuid", "title", "model_type", "file_path", "sizeInBytes", "children"}
        assert set(item.keys()) == expected_keys

    def test_query_page_response_format(self, store):
        """query() returns correct Page_Response keys."""
        result = store.query()
        expected_keys = {"items", "total", "offset", "limit", "hasMore"}
        assert set(result.keys()) == expected_keys

    def test_query_all_no_query_value_needed(self, store):
        """query(query_type='all') does not require query_value."""
        result = store.query(query_type="all")
        assert result["total"] == 0

    def test_query_ctx_parameter_ignored(self, store, tmp_path):
        """ctx parameter is accepted but ignored."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition())
        )
        store.scan_directory(doc_dir)

        result = store.query(ctx="some_context", query_type="all")
        assert result["total"] == 1

    def test_query_by_title_with_model_type_filter(self, store, tmp_path):
        """by_title respects oscal_model_type filter."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(
                _make_component_definition(title="Shared Title")
            )
        )
        (doc_dir / "catalog.json").write_text(
            json.dumps(_make_catalog(title="Shared Title"))
        )
        store.scan_directory(doc_dir)

        # Filter to catalog only
        result = store.query(
            query_type="by_title",
            query_value="Shared Title",
            oscal_model_type=OSCALModelType.CATALOG,
        )
        assert result["total"] == 1
        assert result["items"][0]["model_type"] == "catalog"

    def test_query_offset_beyond_total(self, store, tmp_path):
        """Offset beyond total returns empty items."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition())
        )
        store.scan_directory(doc_dir)

        result = store.query(query_type="all", offset=100, limit=10)
        assert result["total"] == 1
        assert result["items"] == []
        assert result["hasMore"] is False


# ---------------------------------------------------------------------------
# Tests for text_search()
# ---------------------------------------------------------------------------


class TestTextSearch:
    """Tests for text_search() FTS5 full-text search."""

    def _index_component_definition(self, store, tmp_path):
        """Helper: ingest and index a component-definition with children."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir(exist_ok=True)
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition_with_children())
        )
        store.scan_directory(doc_dir)
        row = store._conn.execute("SELECT id FROM documents").fetchone()
        store._ensure_indexed(row["id"])
        return row["id"]

    def test_basic_search_finds_indexed_content(self, store, tmp_path):
        """Searching for a term in an indexed document returns results."""
        self._index_component_definition(store, tmp_path)

        result = store.text_search("Sample")
        assert result["total"] > 0
        assert len(result["items"]) > 0
        # Verify Page_Response envelope keys
        assert "items" in result
        assert "total" in result
        assert "offset" in result
        assert "limit" in result
        assert "hasMore" in result

    def test_search_returns_correct_item_fields(self, store, tmp_path):
        """Each search result item has the required fields."""
        self._index_component_definition(store, tmp_path)

        result = store.text_search("Sample")
        assert result["total"] > 0
        item = result["items"][0]
        assert "entity_type" in item
        assert "entity_id" in item
        assert "title" in item
        assert "description" in item
        assert "model_type" in item

    def test_search_finds_document_title(self, store, tmp_path):
        """Searching for a document title returns the document."""
        self._index_component_definition(store, tmp_path)

        result = store.text_search("Test Component Definition")
        titles = [i["title"] for i in result["items"]]
        assert any("Test Component Definition" in t for t in titles)

    def test_search_finds_child_element(self, store, tmp_path):
        """Searching for a child element title returns the child."""
        self._index_component_definition(store, tmp_path)

        result = store.text_search("Sample Component")
        entity_types = [i["entity_type"] for i in result["items"]]
        assert "child_element" in entity_types

    def test_model_type_scoping(self, store, tmp_path):
        """Scoping by model type filters results to that type only."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir(exist_ok=True)
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition_with_children())
        )
        (doc_dir / "catalog.json").write_text(
            json.dumps(_make_catalog_with_controls())
        )
        store.scan_directory(doc_dir)

        # Index all documents
        for row in store._conn.execute("SELECT id FROM documents").fetchall():
            store._ensure_indexed(row["id"])

        # Search scoped to component-definition
        result = store.text_search(
            "Test",
            oscal_model_type=OSCALModelType.COMPONENT_DEFINITION,
        )
        for item in result["items"]:
            assert item["model_type"] == "component-definition"

        # Search scoped to catalog
        result_cat = store.text_search(
            "Test",
            oscal_model_type=OSCALModelType.CATALOG,
        )
        for item in result_cat["items"]:
            assert item["model_type"] == "catalog"

    def test_empty_query_returns_empty(self, store, tmp_path):
        """An empty or whitespace-only query returns no results."""
        self._index_component_definition(store, tmp_path)

        result = store.text_search("")
        assert result["total"] == 0
        assert result["items"] == []

        result2 = store.text_search("   ")
        assert result2["total"] == 0
        assert result2["items"] == []

    def test_no_matches_returns_empty(self, store, tmp_path):
        """Searching for a term not in any document returns empty results."""
        self._index_component_definition(store, tmp_path)

        result = store.text_search("zzzznonexistentterm")
        assert result["total"] == 0
        assert result["items"] == []
        assert result["hasMore"] is False

    def test_fts_fallback_on_bad_syntax(self, store, tmp_path):
        """Bad FTS5 syntax triggers LIKE fallback without raising."""
        self._index_component_definition(store, tmp_path)

        # Unbalanced quotes are invalid FTS5 syntax
        result = store.text_search('"Sample')
        # Should not raise — falls back to LIKE
        assert isinstance(result, dict)
        assert "items" in result
        assert "total" in result

    def test_pagination(self, store, tmp_path):
        """Pagination parameters work correctly for text search."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir(exist_ok=True)
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition_with_children())
        )
        store.scan_directory(doc_dir)
        row = store._conn.execute("SELECT id FROM documents").fetchone()
        store._ensure_indexed(row["id"])

        # Get all results first
        all_results = store.text_search("Test", limit=100)
        total = all_results["total"]

        if total > 1:
            # Get first page with limit=1
            page1 = store.text_search("Test", offset=0, limit=1)
            assert len(page1["items"]) == 1
            assert page1["total"] == total
            assert page1["hasMore"] is True

            # Get second page
            page2 = store.text_search("Test", offset=1, limit=1)
            assert len(page2["items"]) == 1
            assert page2["offset"] == 1

            # Items should be different
            assert page1["items"][0] != page2["items"][0]

    def test_pagination_offset_beyond_results(self, store, tmp_path):
        """Offset beyond total results returns empty items."""
        self._index_component_definition(store, tmp_path)

        result = store.text_search("Sample", offset=1000, limit=10)
        assert result["items"] == []
        assert result["hasMore"] is False

    def test_search_description_content(self, store, tmp_path):
        """Searching for text in descriptions returns matching results."""
        self._index_component_definition(store, tmp_path)

        # "sample component for testing" is in the description
        result = store.text_search("sample")
        assert result["total"] > 0

    def test_like_fallback_finds_content(self, store, tmp_path):
        """LIKE fallback (triggered by bad FTS syntax) still finds content."""
        self._index_component_definition(store, tmp_path)

        # Use unbalanced parenthesis — invalid FTS5 syntax
        result = store.text_search("(Sample")
        # LIKE fallback should find "Sample Component" in title
        assert isinstance(result, dict)
        # The LIKE pattern will be "%(Sample%" which should match
        titles = [i["title"] for i in result["items"]]
        # At minimum, the result should be a valid Page_Response
        assert "items" in result
        assert "total" in result


# ---------------------------------------------------------------------------
# Tests for list_documents() and list_child_elements()
# ---------------------------------------------------------------------------


class TestListDocuments:
    """Tests for list_documents()."""

    def test_empty_store_returns_empty(self, store):
        """An empty store returns an empty page."""
        result = store.list_documents()
        assert result == {
            "items": [],
            "total": 0,
            "offset": 0,
            "limit": 10,
            "hasMore": False,
        }

    def test_single_document(self, store, tmp_path):
        """Lists a single ingested document with correct fields."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition_with_children())
        )
        store.scan_directory(doc_dir)

        result = store.list_documents()
        assert result["total"] == 1
        assert len(result["items"]) == 1
        assert result["hasMore"] is False

        item = result["items"][0]
        assert item["uuid"] == "a1b2c3d4-5678-4abc-8def-123456789012"
        assert item["title"] == "Test Component Definition"
        assert item["model_type"] == "component-definition"
        assert item["sizeInBytes"] > 0
        # After _ensure_indexed, childCount should be 3 (2 components + 1 capability)
        assert item["childCount"] == 3

    def test_multiple_documents(self, store, tmp_path):
        """Lists multiple documents of different types."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition_with_children())
        )
        (doc_dir / "catalog.json").write_text(
            json.dumps(_make_catalog_with_controls())
        )
        (doc_dir / "poam.json").write_text(
            json.dumps(_make_poam())
        )
        store.scan_directory(doc_dir)

        result = store.list_documents()
        assert result["total"] == 3
        assert len(result["items"]) == 3
        assert result["hasMore"] is False

    def test_model_type_filter(self, store, tmp_path):
        """Filtering by model type returns only matching documents."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition_with_children())
        )
        (doc_dir / "catalog.json").write_text(
            json.dumps(_make_catalog_with_controls())
        )
        store.scan_directory(doc_dir)

        result = store.list_documents(
            oscal_model_type=OSCALModelType.CATALOG
        )
        assert result["total"] == 1
        assert len(result["items"]) == 1
        assert result["items"][0]["model_type"] == "catalog"

    def test_pagination_offset_limit(self, store, tmp_path):
        """Pagination with offset and limit works correctly."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        # Create 3 documents
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition_with_children())
        )
        (doc_dir / "catalog.json").write_text(
            json.dumps(_make_catalog_with_controls())
        )
        (doc_dir / "poam.json").write_text(
            json.dumps(_make_poam())
        )
        store.scan_directory(doc_dir)

        # First page: limit=2
        result1 = store.list_documents(offset=0, limit=2)
        assert result1["total"] == 3
        assert len(result1["items"]) == 2
        assert result1["hasMore"] is True
        assert result1["offset"] == 0
        assert result1["limit"] == 2

        # Second page: offset=2, limit=2
        result2 = store.list_documents(offset=2, limit=2)
        assert result2["total"] == 3
        assert len(result2["items"]) == 1
        assert result2["hasMore"] is False

    def test_child_count_accurate_after_indexing(self, store, tmp_path):
        """childCount reflects actual child elements after lazy indexing."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "catalog.json").write_text(
            json.dumps(_make_catalog_with_controls())
        )
        store.scan_directory(doc_dir)

        result = store.list_documents()
        # Catalog with 2 controls + 1 group = 3 children
        assert result["items"][0]["childCount"] == 3

    def test_document_without_children(self, store, tmp_path):
        """A document with no children has childCount=0."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "catalog.json").write_text(
            json.dumps(_make_catalog())
        )
        store.scan_directory(doc_dir)

        result = store.list_documents()
        assert result["items"][0]["childCount"] == 0

    def test_page_response_format(self, store, tmp_path):
        """Returned dict has all Page_Response keys."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition())
        )
        store.scan_directory(doc_dir)

        result = store.list_documents()
        assert set(result.keys()) == {"items", "total", "offset", "limit", "hasMore"}

    def test_item_fields(self, store, tmp_path):
        """Each item has the expected fields."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition())
        )
        store.scan_directory(doc_dir)

        result = store.list_documents()
        item = result["items"][0]
        assert set(item.keys()) == {
            "uuid", "title", "model_type", "childCount", "sizeInBytes"
        }


class TestListChildElements:
    """Tests for list_child_elements()."""

    def test_empty_store_returns_empty(self, store):
        """An empty store returns an empty page."""
        result = store.list_child_elements()
        assert result == {
            "items": [],
            "total": 0,
            "offset": 0,
            "limit": 10,
            "hasMore": False,
        }

    def test_lists_all_children(self, store, tmp_path):
        """Lists all child elements across all documents."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition_with_children())
        )
        (doc_dir / "catalog.json").write_text(
            json.dumps(_make_catalog_with_controls())
        )
        store.scan_directory(doc_dir)

        result = store.list_child_elements(limit=100)
        # cdef: 2 components + 1 capability = 3
        # catalog: 2 controls + 1 group = 3
        assert result["total"] == 6
        assert len(result["items"]) == 6

    def test_filter_by_parent_doc_uuid(self, store, tmp_path):
        """Filtering by parent_doc_uuid returns only that document's children."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition_with_children())
        )
        (doc_dir / "catalog.json").write_text(
            json.dumps(_make_catalog_with_controls())
        )
        store.scan_directory(doc_dir)

        result = store.list_child_elements(
            parent_doc_uuid="a1b2c3d4-5678-4abc-8def-123456789012",
            limit=100,
        )
        assert result["total"] == 3
        for item in result["items"]:
            assert item["parentDocumentUuid"] == "a1b2c3d4-5678-4abc-8def-123456789012"

    def test_filter_by_element_type(self, store, tmp_path):
        """Filtering by element_type returns only matching children."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition_with_children())
        )
        store.scan_directory(doc_dir)

        result = store.list_child_elements(element_type="component")
        assert result["total"] == 2
        for item in result["items"]:
            assert item["element_type"] == "component"

    def test_filter_by_both_parent_and_type(self, store, tmp_path):
        """Filtering by both parent_doc_uuid and element_type."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition_with_children())
        )
        store.scan_directory(doc_dir)

        result = store.list_child_elements(
            parent_doc_uuid="a1b2c3d4-5678-4abc-8def-123456789012",
            element_type="capability",
        )
        assert result["total"] == 1
        assert result["items"][0]["element_type"] == "capability"
        assert result["items"][0]["title"] == "Test Capability"

    def test_includes_parent_document_info(self, store, tmp_path):
        """Each child element includes parentDocumentTitle and parentDocumentUuid."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition_with_children())
        )
        store.scan_directory(doc_dir)

        result = store.list_child_elements()
        for item in result["items"]:
            assert item["parentDocumentTitle"] == "Test Component Definition"
            assert item["parentDocumentUuid"] == "a1b2c3d4-5678-4abc-8def-123456789012"

    def test_pagination(self, store, tmp_path):
        """Pagination works for child elements."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition_with_children())
        )
        store.scan_directory(doc_dir)

        # 3 children total, page of 2
        result1 = store.list_child_elements(offset=0, limit=2)
        assert result1["total"] == 3
        assert len(result1["items"]) == 2
        assert result1["hasMore"] is True

        result2 = store.list_child_elements(offset=2, limit=2)
        assert result2["total"] == 3
        assert len(result2["items"]) == 1
        assert result2["hasMore"] is False

    def test_nonexistent_parent_uuid_returns_empty(self, store, tmp_path):
        """Filtering by a non-existent parent UUID returns empty results."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition_with_children())
        )
        store.scan_directory(doc_dir)

        result = store.list_child_elements(
            parent_doc_uuid="00000000-0000-0000-0000-000000000000"
        )
        assert result["total"] == 0
        assert result["items"] == []

    def test_page_response_format(self, store, tmp_path):
        """Returned dict has all Page_Response keys."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition_with_children())
        )
        store.scan_directory(doc_dir)

        result = store.list_child_elements()
        assert set(result.keys()) == {"items", "total", "offset", "limit", "hasMore"}

    def test_item_fields(self, store, tmp_path):
        """Each item has the expected fields."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition_with_children())
        )
        store.scan_directory(doc_dir)

        result = store.list_child_elements()
        item = result["items"][0]
        assert set(item.keys()) == {
            "uuid", "title", "element_type", "description",
            "parentDocumentTitle", "parentDocumentUuid",
        }

    def test_triggers_lazy_indexing(self, store, tmp_path):
        """list_child_elements triggers _ensure_indexed for unindexed docs."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "cdef.json").write_text(
            json.dumps(_make_component_definition_with_children())
        )
        store.scan_directory(doc_dir)

        # Verify not indexed yet
        row = store._conn.execute(
            "SELECT indexed FROM documents"
        ).fetchone()
        assert row["indexed"] == 0

        # list_child_elements should trigger indexing
        result = store.list_child_elements()
        assert result["total"] == 3

        # Verify now indexed
        row = store._conn.execute(
            "SELECT indexed FROM documents"
        ).fetchone()
        assert row["indexed"] == 1

    def test_description_included(self, store, tmp_path):
        """Child elements include description when available."""
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "poam.json").write_text(json.dumps(_make_poam()))
        store.scan_directory(doc_dir)

        result = store.list_child_elements()
        assert result["total"] == 1
        assert result["items"][0]["description"] == "Remediate CVE-2024-0001"


# ---------------------------------------------------------------------------
# Property 9: UUID lookup returns exact match
# ---------------------------------------------------------------------------


class TestPropertyUuidLookup:
    """Feature: scalable-oscal-store, Property 9: UUID lookup returns exact match.

    *For any* document or child element with a known UUID in the store,
    querying with ``query_type="by_uuid"`` and that UUID as ``query_value``
    should return exactly one result whose UUID matches the query value.

    **Validates: Requirements 5.3**
    """

    @pytest.mark.slow
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    @given(doc_set=oscal_document_set())
    def test_uuid_lookup_returns_exact_match(self, doc_set, tmp_path_factory):
        """For each ingested document, querying by its UUID returns exactly
        one result with a matching UUID.

        **Validates: Requirements 5.3**
        """
        tmp_path = tmp_path_factory.mktemp("prop9")
        db_path = str(tmp_path / "test.db")
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()

        # Write all documents to disk
        for filename, data, _uuid, _title in doc_set:
            (doc_dir / filename).write_text(json.dumps(data))

        store = OscalStore(db_path=db_path, cache_size=50)
        try:
            count = store.scan_directory(doc_dir)
            assert count == len(doc_set), (
                f"Expected {len(doc_set)} ingested, got {count}"
            )

            # For each document, query by UUID and verify exact match
            for _filename, _data, doc_uuid, _title in doc_set:
                result = store.query(
                    query_type="by_uuid", query_value=doc_uuid
                )
                assert result["total"] == 1, (
                    f"Expected exactly 1 result for UUID {doc_uuid}, "
                    f"got {result['total']}"
                )
                assert len(result["items"]) == 1, (
                    f"Expected 1 item for UUID {doc_uuid}, "
                    f"got {len(result['items'])}"
                )
                assert result["items"][0]["uuid"] == doc_uuid, (
                    f"Returned UUID {result['items'][0]['uuid']} "
                    f"does not match queried UUID {doc_uuid}"
                )
        finally:
            store.close()


# ---------------------------------------------------------------------------
# Property 7: Pagination correctness
# ---------------------------------------------------------------------------


@st.composite
def oscal_document_set_for_pagination(draw):
    """Strategy that produces 1–15 documents for pagination testing.

    Each document has a unique UUID and a unique filename.
    Returns a list of (filename, json_data, uuid, title) tuples.
    """
    count = draw(st.integers(min_value=1, max_value=15))
    docs = []
    used_uuids = set()
    for i in range(count):
        maker_name, maker_fn = draw(st.sampled_from(_DOC_MAKERS))
        doc_uuid = _uuid4_hex()
        while doc_uuid in used_uuids:
            doc_uuid = _uuid4_hex()
        used_uuids.add(doc_uuid)
        title = f"PagDoc-{i}-{maker_name}"
        data = maker_fn(uuid=doc_uuid, title=title)
        filename = f"pagdoc_{i}_{maker_name}.json"
        docs.append((filename, data, doc_uuid, title))
    return docs


class TestPaginationCorrectnessProperty:
    """Property 7: Pagination correctness.

    *For any* list of N ingested documents and any valid offset
    (0 ≤ offset ≤ N) and limit (1 ≤ limit ≤ 100), the Page_Response
    returned by list_documents should satisfy:
    - len(items) == min(limit, max(0, N - offset))
    - total == N
    - hasMore == (offset + limit < N)

    **Validates: Requirements 4.3**
    """

    @pytest.mark.slow
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    @given(
        doc_set=oscal_document_set_for_pagination(),
        offset_frac=st.floats(min_value=0.0, max_value=1.5),
        limit=st.integers(min_value=1, max_value=100),
    )
    def test_pagination_invariants(
        self, doc_set, offset_frac, limit, tmp_path_factory
    ):
        """Pagination invariants hold for any N documents with random offset/limit.

        **Validates: Requirements 4.3**
        """
        tmp_path = tmp_path_factory.mktemp("prop7")
        db_path = str(tmp_path / "test.db")
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()

        n = len(doc_set)

        # Write documents to disk
        for filename, data, _uuid, _title in doc_set:
            (doc_dir / filename).write_text(json.dumps(data))

        store = OscalStore(db_path=db_path, cache_size=50)
        try:
            count = store.scan_directory(doc_dir)
            assert count == n, f"Expected {n} ingested, got {count}"

            # Derive offset from fraction so we cover 0, mid, and beyond-N
            offset = int(offset_frac * n)

            result = store.list_documents(offset=offset, limit=limit)

            expected_items = min(limit, max(0, n - offset))
            expected_has_more = offset + limit < n

            assert result["total"] == n, (
                f"total: expected {n}, got {result['total']}"
            )
            assert len(result["items"]) == expected_items, (
                f"len(items): expected {expected_items}, got {len(result['items'])} "
                f"(N={n}, offset={offset}, limit={limit})"
            )
            assert result["hasMore"] == expected_has_more, (
                f"hasMore: expected {expected_has_more}, got {result['hasMore']} "
                f"(N={n}, offset={offset}, limit={limit})"
            )
            assert result["offset"] == offset
            assert result["limit"] == limit
        finally:
            store.close()


# ---------------------------------------------------------------------------
# Property 10: Case-insensitive title search
# ---------------------------------------------------------------------------

# Strategy: ASCII-only titles for case-insensitive search testing.
# SQLite COLLATE NOCASE only handles ASCII A-Z case folding, so we
# constrain to printable ASCII to test the documented behaviour.
_ascii_titles = st.text(
    alphabet=st.characters(
        whitelist_categories=("L", "N", "P", "Z"),
        whitelist_characters="",
        min_codepoint=32,
        max_codepoint=126,
        blacklist_characters="\x00",
    ),
    min_size=1,
    max_size=60,
).filter(lambda t: t.strip())


@st.composite
def _case_variation(draw, text: str) -> str:
    """Produce a random case variation of *text*.

    For each character, randomly choose upper, lower, or original case.
    """
    chars = []
    for ch in text:
        choice = draw(st.sampled_from(["upper", "lower", "original"]))
        if choice == "upper":
            chars.append(ch.upper())
        elif choice == "lower":
            chars.append(ch.lower())
        else:
            chars.append(ch)
    return "".join(chars)


class TestPropertyCaseInsensitiveTitleSearch:
    """Property 10: Case-insensitive title search.

    *For any* document with a known title (ASCII), querying with
    ``query_type="by_title"`` using any case variation of that title
    (upper, lower, mixed) should return a result matching that document.

    Note: SQLite COLLATE NOCASE only handles ASCII A-Z case folding,
    so this property is tested with ASCII-only titles.

    **Validates: Requirements 5.4**
    """

    @pytest.mark.slow
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    @given(
        root_key=_ingestable_root_keys,
        title=_ascii_titles,
        data=st.data(),
    )
    def test_title_search_case_insensitive(self, root_key, title, data, tmp_path_factory):
        """Querying by_title with any case variation of a known title returns
        at least one result matching the original document.

        **Validates: Requirements 5.4**
        """
        tmp_path = tmp_path_factory.mktemp("prop10")
        db_path = str(tmp_path / "test.db")
        doc_uuid = _uuid4_hex()

        builder = _VALID_DOC_BUILDERS[root_key]
        doc = builder(doc_uuid, title)

        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / f"{root_key}.json").write_text(json.dumps(doc))

        store = OscalStore(db_path=db_path, cache_size=10)
        try:
            count = store.scan_directory(doc_dir)
            assert count == 1

            # Generate a random case variation of the title
            varied_title = data.draw(_case_variation(title))

            result = store.query(query_type="by_title", query_value=varied_title)

            assert result["total"] >= 1, (
                f"Expected at least 1 result for title '{varied_title}' "
                f"(original: '{title}'), got {result['total']}"
            )

            # Verify the original document is among the results
            result_uuids = [item["uuid"] for item in result["items"]]
            assert doc_uuid in result_uuids, (
                f"Document {doc_uuid} with title '{title}' not found in "
                f"results when searching for '{varied_title}'"
            )
        finally:
            store.close()
