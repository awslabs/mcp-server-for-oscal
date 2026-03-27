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
