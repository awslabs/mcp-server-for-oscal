"""Tests for bin/build_oscal_db.py build script."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_minimal_component_def(directory: Path, uuid: str = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d") -> Path:
    """Write a minimal valid OSCAL component-definition JSON file."""
    doc = {
        "component-definition": {
            "uuid": uuid,
            "metadata": {
                "title": f"Test Component Definition {uuid[:8]}",
                "last-modified": "2024-01-01T00:00:00Z",
                "version": "1.0.0",
                "oscal-version": "1.1.2",
            },
            "components": [
                {
                    "uuid": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
                    "type": "software",
                    "title": "Test Component",
                    "description": "A test component for build script testing",
                }
            ],
        }
    }
    fp = directory / f"test-cdef-{uuid[:8]}.json"
    fp.write_text(json.dumps(doc, indent=2))
    return fp


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestPathConstants:
    """Tests for module-level path constants."""

    def test_component_defs_dir_points_to_data(self):
        """COMPONENT_DEFS_DIR equals REPO_ROOT / 'data' / 'component_definitions'."""
        from bin.build_oscal_db import COMPONENT_DEFS_DIR, REPO_ROOT

        assert COMPONENT_DEFS_DIR == REPO_ROOT / "data" / "component_definitions"

    def test_oscal_docs_dir_points_to_data(self):
        """OSCAL_DOCS_DIR equals REPO_ROOT / 'data' / 'oscal_docs'."""
        from bin.build_oscal_db import OSCAL_DOCS_DIR, REPO_ROOT

        assert OSCAL_DOCS_DIR == REPO_ROOT / "data" / "oscal_docs"


class TestBuildOscalDb:
    """Tests for the build_db function."""

    def test_build_db_with_temp_directory(self):
        """build_db creates a DB, indexes documents, and returns stats."""
        from bin.build_oscal_db import build_db

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            db_path = tmp / "test_oscal_store.db"
            comp_dir = tmp / "component_definitions"
            comp_dir.mkdir()
            docs_dir = tmp / "oscal_docs"
            docs_dir.mkdir()

            # Write a minimal component definition
            _write_minimal_component_def(comp_dir)

            stats = build_db(
                db_path=db_path,
                component_defs_dir=comp_dir,
                oscal_docs_dir=docs_dir,
            )

            assert db_path.exists()
            assert stats["docs_indexed"] >= 1
            assert stats["children"] >= 1
            assert stats["db_size_bytes"] > 0

    def test_build_db_idempotent(self):
        """Running build_db twice with same input produces same doc/child counts."""
        from bin.build_oscal_db import build_db

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            db_path = tmp / "test_oscal_store.db"
            comp_dir = tmp / "component_definitions"
            comp_dir.mkdir()
            docs_dir = tmp / "oscal_docs"
            docs_dir.mkdir()

            _write_minimal_component_def(comp_dir)

            stats1 = build_db(
                db_path=db_path,
                component_defs_dir=comp_dir,
                oscal_docs_dir=docs_dir,
            )
            stats2 = build_db(
                db_path=db_path,
                component_defs_dir=comp_dir,
                oscal_docs_dir=docs_dir,
            )

            assert stats1["docs_indexed"] == stats2["docs_indexed"]
            assert stats1["children"] == stats2["children"]

    def test_build_db_empty_directories(self):
        """build_db handles empty directories gracefully."""
        from bin.build_oscal_db import build_db

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            db_path = tmp / "test_oscal_store.db"
            comp_dir = tmp / "component_definitions"
            comp_dir.mkdir()
            docs_dir = tmp / "oscal_docs"
            docs_dir.mkdir()

            stats = build_db(
                db_path=db_path,
                component_defs_dir=comp_dir,
                oscal_docs_dir=docs_dir,
            )

            assert db_path.exists()
            assert stats["docs_indexed"] == 0
            assert stats["children"] == 0

    def test_build_db_missing_directories(self):
        """build_db handles non-existent directories gracefully."""
        from bin.build_oscal_db import build_db

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            db_path = tmp / "test_oscal_store.db"

            stats = build_db(
                db_path=db_path,
                component_defs_dir=tmp / "nonexistent_comp",
                oscal_docs_dir=tmp / "nonexistent_docs",
            )

            assert db_path.exists()
            assert stats["docs_indexed"] == 0


class TestComputeSha256:
    """Tests for the SHA-256 computation helper."""

    def test_compute_sha256(self):
        """compute_sha256 returns a valid hex digest."""
        from bin.build_oscal_db import compute_sha256

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            f.write(b"test content for hashing")
            f.flush()
            path = Path(f.name)

        try:
            digest = compute_sha256(path)
            assert len(digest) == 64
            assert all(c in "0123456789abcdef" for c in digest)
        finally:
            os.unlink(path)


class TestUpdateHashesJson:
    """Tests for the hashes.json update helper."""

    def test_update_creates_new_manifest(self):
        """update_hashes_json creates a new manifest when none exists."""
        from bin.build_oscal_db import update_hashes_json, HASHES_FILE

        with tempfile.TemporaryDirectory() as tmpdir:
            fake_hashes = Path(tmpdir) / "hashes.json"
            with patch("bin.build_oscal_db.HASHES_FILE", fake_hashes):
                update_hashes_json("abc123")

            manifest = json.loads(fake_hashes.read_text())
            assert manifest["file_hashes"]["oscal_store.db"] == "abc123"

    def test_update_preserves_existing_entries(self):
        """update_hashes_json preserves existing file_hashes entries."""
        from bin.build_oscal_db import update_hashes_json

        with tempfile.TemporaryDirectory() as tmpdir:
            fake_hashes = Path(tmpdir) / "hashes.json"
            existing = {
                "commit": "deadbeef",
                "file_hashes": {"other_file.txt": "existinghash"},
            }
            fake_hashes.write_text(json.dumps(existing))

            with patch("bin.build_oscal_db.HASHES_FILE", fake_hashes):
                update_hashes_json("newhash")

            manifest = json.loads(fake_hashes.read_text())
            assert manifest["commit"] == "deadbeef"
            assert manifest["file_hashes"]["other_file.txt"] == "existinghash"
            assert manifest["file_hashes"]["oscal_store.db"] == "newhash"
