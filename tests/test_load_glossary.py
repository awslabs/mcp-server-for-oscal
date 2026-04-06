"""Unit tests for load_glossary() in bin/generate_oscal_glossary.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

# Load the script as a module since it lives in bin/ (not a package)
_spec = importlib.util.spec_from_file_location(
    "generate_oscal_glossary",
    Path(__file__).resolve().parent.parent / "bin" / "generate_oscal_glossary.py",
)
assert _spec is not None, "Could not find generate_oscal_glossary.py"
_mod = importlib.util.module_from_spec(_spec)
_mod.__name__ = "generate_oscal_glossary"
if "generate_oscal_glossary" not in sys.modules:
    sys.modules["generate_oscal_glossary"] = _mod
    assert _spec.loader is not None, "Module spec has no loader"
    _spec.loader.exec_module(_mod)
else:
    _mod = sys.modules["generate_oscal_glossary"]

load_glossary = _mod.load_glossary


class TestLoadGlossary:
    """Tests for load_glossary()."""

    def test_loads_valid_glossary(self, tmp_path: Path) -> None:
        """A valid glossary file is loaded and indexed by lowercase term."""
        data = {
            "parentTerms": [
                {
                    "term": "Access Control",
                    "link": "https://example.com/ac",
                    "definitions": [{"text": "A definition.", "sources": []}],
                    "abbrSyn": [{"text": "AC"}],
                },
            ]
        }
        p = tmp_path / "glossary.json"
        p.write_text(json.dumps(data))

        result = load_glossary(p)

        assert "access control" in result
        assert result["access control"]["term"] == "Access Control"
        assert result["access control"]["link"] == "https://example.com/ac"

    def test_case_insensitive_index(self, tmp_path: Path) -> None:
        """Terms are indexed by their lowercase form."""
        data = {
            "parentTerms": [
                {"term": "CATALOG", "link": "", "definitions": None, "abbrSyn": None},
            ]
        }
        p = tmp_path / "glossary.json"
        p.write_text(json.dumps(data))

        result = load_glossary(p)
        assert "catalog" in result
        assert "CATALOG" not in result

    def test_indexes_entries_with_null_definitions(self, tmp_path: Path) -> None:
        """Entries with null definitions are still indexed."""
        data: dict = {
            "parentTerms": [
                {"term": "SomeAbbr", "link": "https://x", "definitions": None, "abbrSyn": [{"text": "SA"}]},
            ]
        }
        p = tmp_path / "glossary.json"
        p.write_text(json.dumps(data))

        result = load_glossary(p)
        assert "someabbr" in result
        assert result["someabbr"]["definitions"] is None
        assert result["someabbr"]["abbrSyn"] == [{"text": "SA"}]

    def test_indexes_entries_with_empty_definitions(self, tmp_path: Path) -> None:
        """Entries with empty definitions list are still indexed."""
        data: dict = {
            "parentTerms": [
                {"term": "EmptyDef", "link": "", "definitions": [], "abbrSyn": None},
            ]
        }
        p = tmp_path / "glossary.json"
        p.write_text(json.dumps(data))

        result = load_glossary(p)
        assert "emptydef" in result
        assert result["emptydef"]["definitions"] == []

    def test_fatal_on_missing_file(self, tmp_path: Path) -> None:
        """Missing file triggers sys.exit(1)."""
        with pytest.raises(SystemExit, match="1"):
            load_glossary(tmp_path / "nonexistent.json")

    def test_fatal_on_invalid_json(self, tmp_path: Path) -> None:
        """Invalid JSON triggers sys.exit(1)."""
        p = tmp_path / "bad.json"
        p.write_text("{not valid json")

        with pytest.raises(SystemExit, match="1"):
            load_glossary(p)

    def test_fatal_on_missing_parent_terms(self, tmp_path: Path) -> None:
        """Valid JSON without parentTerms triggers sys.exit(1)."""
        p = tmp_path / "glossary.json"
        p.write_text(json.dumps({"totalRecords": 0}))

        with pytest.raises(SystemExit, match="1"):
            load_glossary(p)

    def test_fatal_on_parent_terms_not_array(self, tmp_path: Path) -> None:
        """parentTerms that is not a list triggers sys.exit(1)."""
        p = tmp_path / "glossary.json"
        p.write_text(json.dumps({"parentTerms": "not-a-list"}))

        with pytest.raises(SystemExit, match="1"):
            load_glossary(p)

    def test_deduplicates_by_lowercase_keeps_first(self, tmp_path: Path) -> None:
        """When multiple entries have the same lowercase term, keep the first."""
        data = {
            "parentTerms": [
                {"term": "Test", "link": "first", "definitions": None, "abbrSyn": None},
                {"term": "test", "link": "second", "definitions": None, "abbrSyn": None},
            ]
        }
        p = tmp_path / "glossary.json"
        p.write_text(json.dumps(data))

        result = load_glossary(p)
        assert result["test"]["link"] == "first"
