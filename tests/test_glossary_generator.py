"""Unit tests for bin/generate_oscal_glossary.py."""

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
_mod = importlib.util.module_from_spec(_spec)
_mod.__name__ = "generate_oscal_glossary"
sys.modules["generate_oscal_glossary"] = _mod
_spec.loader.exec_module(_mod)

parse_schema = _mod.parse_schema
_is_object_type = _mod._is_object_type  # noqa: SLF001
match_terms = _mod.match_terms
generate_markdown = _mod.generate_markdown
MatchedTerm = _mod.MatchedTerm
to_human_readable = _mod.to_human_readable


# ---------------------------------------------------------------------------
# _is_object_type classification
# ---------------------------------------------------------------------------


class TestIsObjectType:
    def test_direct_type_object(self):
        assert _is_object_type({"type": "object", "properties": {"a": {}}}) is True

    def test_type_object_no_properties(self):
        assert _is_object_type({"type": "object"}) is True

    def test_anyof_with_object_variant(self):
        entry = {
            "type": "object",
            "anyOf": [
                {"properties": {"x": {}}, "type": "object"},
                {"properties": {"y": {}}, "type": "object"},
            ],
        }
        assert _is_object_type(entry) is True

    def test_oneof_with_object_variant(self):
        entry = {"oneOf": [{"type": "object"}, {"type": "string"}]}
        assert _is_object_type(entry) is True

    def test_scalar_string(self):
        assert _is_object_type({"type": "string"}) is False

    def test_scalar_integer(self):
        assert _is_object_type({"type": "integer"}) is False

    def test_scalar_boolean(self):
        assert _is_object_type({"type": "boolean"}) is False

    def test_scalar_number(self):
        assert _is_object_type({"type": "number"}) is False

    def test_ref_only_alias(self):
        assert _is_object_type({"$ref": "#/definitions/StringDatatype"}) is False

    def test_anyof_without_object(self):
        entry = {
            "anyOf": [
                {"$ref": "#/definitions/TokenDatatype"},
                {"enum": ["a", "b"]},
            ]
        }
        assert _is_object_type(entry) is False


# ---------------------------------------------------------------------------
# parse_schema
# ---------------------------------------------------------------------------


class TestParseSchema:
    def test_missing_file(self):
        with pytest.raises(SystemExit) as exc_info:
            parse_schema(Path("/nonexistent/schema.json"))
        assert exc_info.value.code == 1

    def test_invalid_json(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json", encoding="utf-8")
        with pytest.raises(SystemExit) as exc_info:
            parse_schema(bad)
        assert exc_info.value.code == 1

    def test_missing_definitions_key(self, tmp_path):
        no_defs = tmp_path / "no_defs.json"
        no_defs.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
        with pytest.raises(SystemExit) as exc_info:
            parse_schema(no_defs)
        assert exc_info.value.code == 1

    def test_empty_definitions(self, tmp_path):
        schema_file = tmp_path / "empty.json"
        schema_file.write_text(json.dumps({"definitions": {}}), encoding="utf-8")
        assert parse_schema(schema_file) == []

    def test_only_scalars_excluded(self, tmp_path):
        schema = {
            "definitions": {
                "StringDatatype": {"type": "string"},
                "IntegerDatatype": {"type": "integer"},
                "BooleanDatatype": {"type": "boolean"},
                "ref-alias": {"$ref": "#/definitions/StringDatatype"},
            }
        }
        schema_file = tmp_path / "scalars.json"
        schema_file.write_text(json.dumps(schema), encoding="utf-8")
        assert parse_schema(schema_file) == []

    def test_object_types_included(self, tmp_path):
        schema = {
            "definitions": {
                "ns:catalog": {"type": "object", "properties": {"uuid": {}}},
                "ns:control": {"type": "object"},
                "StringDatatype": {"type": "string"},
            }
        }
        schema_file = tmp_path / "mixed.json"
        schema_file.write_text(json.dumps(schema), encoding="utf-8")
        result = parse_schema(schema_file)
        assert result == ["catalog", "control"]

    def test_namespace_stripping(self, tmp_path):
        schema = {
            "definitions": {
                "oscal-complete-oscal-catalog:catalog": {"type": "object"},
                "include-all": {"type": "object"},
            }
        }
        schema_file = tmp_path / "ns.json"
        schema_file.write_text(json.dumps(schema), encoding="utf-8")
        result = parse_schema(schema_file)
        assert "catalog" in result
        assert "include-all" in result

    def test_deduplication_keeps_first(self, tmp_path):
        schema = {
            "definitions": {
                "ns-a:widget": {"type": "object", "properties": {"a": {}}},
                "ns-b:widget": {"type": "object", "properties": {"b": {}}},
            }
        }
        schema_file = tmp_path / "dedup.json"
        schema_file.write_text(json.dumps(schema), encoding="utf-8")
        result = parse_schema(schema_file)
        assert result.count("widget") == 1

    def test_sorted_output(self, tmp_path):
        schema = {
            "definitions": {
                "ns:zebra": {"type": "object"},
                "ns:alpha": {"type": "object"},
                "ns:middle": {"type": "object"},
            }
        }
        schema_file = tmp_path / "sort.json"
        schema_file.write_text(json.dumps(schema), encoding="utf-8")
        result = parse_schema(schema_file)
        assert result == ["alpha", "middle", "zebra"]

    def test_anyof_object_variant_included(self, tmp_path):
        schema = {
            "definitions": {
                "ns:group": {
                    "type": "object",
                    "anyOf": [
                        {"properties": {"a": {}}, "type": "object"},
                        {"properties": {"b": {}}, "type": "object"},
                    ],
                },
            }
        }
        schema_file = tmp_path / "anyof.json"
        schema_file.write_text(json.dumps(schema), encoding="utf-8")
        assert parse_schema(schema_file) == ["group"]

    def test_anyof_scalar_only_excluded(self, tmp_path):
        schema = {
            "definitions": {
                "ns:risk-status": {
                    "anyOf": [
                        {"$ref": "#/definitions/TokenDatatype"},
                        {"enum": ["open", "closed"]},
                    ]
                },
            }
        }
        schema_file = tmp_path / "anyof_scalar.json"
        schema_file.write_text(json.dumps(schema), encoding="utf-8")
        assert parse_schema(schema_file) == []

    def test_real_schema(self):
        """Smoke test against the actual bundled OSCAL schema."""
        schema_path = Path(
            "src/mcp_server_for_oscal/oscal_schemas/oscal_complete_schema.json"
        )
        if not schema_path.exists():
            pytest.skip("Real OSCAL schema not available")
        result = parse_schema(schema_path)
        assert len(result) > 50  # expect ~100 object types
        assert result == sorted(result)
        assert len(result) == len(set(result))
        # Known object types should be present
        assert "catalog" in result
        assert "control" in result
        assert "system-security-plan" in result
        # Known scalar types should be absent
        assert "UUIDDatatype" not in result
        assert "StringDatatype" not in result


# ---------------------------------------------------------------------------
# match_terms
# ---------------------------------------------------------------------------


def _make_glossary_entry(
    term: str,
    definitions: list[dict] | None = None,
    link: str = "",
    abbr_syn: list[dict] | None = None,
) -> dict:
    """Helper to build a glossary entry dict."""
    return {
        "term": term,
        "link": link or f"https://csrc.nist.gov/glossary/term/{term.replace(' ', '_')}",
        "definitions": definitions,
        "abbrSyn": abbr_syn,
    }


def _build_glossary(entries: list[dict]) -> dict[str, dict]:
    """Build a case-insensitive glossary index from a list of entries."""
    index: dict[str, dict] = {}
    for entry in entries:
        key = entry["term"].lower()
        if key not in index:
            index[key] = entry
    return index


class TestMatchTerms:
    """Tests for match_terms — Requirements 3.1–3.6."""

    def test_basic_match(self):
        """A short name that maps to a glossary entry with definitions is matched."""
        glossary = _build_glossary([
            _make_glossary_entry(
                "back matter",
                definitions=[{"text": "Appendix info", "sources": []}],
                link="https://csrc.nist.gov/glossary/term/back_matter",
            ),
        ])
        matched, unmatched = match_terms(["back-matter"], glossary)
        assert len(matched) == 1
        assert matched[0].short_name == "back-matter"
        assert matched[0].human_name == "Back Matter"
        assert matched[0].link == "https://csrc.nist.gov/glossary/term/back_matter"
        assert len(matched[0].definitions) == 1
        assert unmatched == []

    def test_unmatched_when_no_glossary_entry(self):
        """A short name with no glossary entry is unmatched."""
        matched, unmatched = match_terms(["some-term"], {})
        assert matched == []
        assert unmatched == ["some-term"]

    def test_unmatched_when_definitions_null(self):
        """A glossary entry with null definitions → unmatched (Req 3.4)."""
        glossary = _build_glossary([
            _make_glossary_entry("catalog", definitions=None),
        ])
        matched, unmatched = match_terms(["catalog"], glossary)
        assert matched == []
        assert unmatched == ["catalog"]

    def test_unmatched_when_definitions_empty(self):
        """A glossary entry with empty definitions list → unmatched (Req 3.4)."""
        glossary = _build_glossary([
            _make_glossary_entry("catalog", definitions=[]),
        ])
        matched, unmatched = match_terms(["catalog"], glossary)
        assert matched == []
        assert unmatched == ["catalog"]

    def test_multi_definition_retained(self):
        """All definitions are retained for multi-definition entries (Req 3.5)."""
        defs = [
            {"text": "Definition one", "sources": []},
            {"text": "Definition two", "sources": []},
            {"text": "Definition three", "sources": []},
        ]
        glossary = _build_glossary([
            _make_glossary_entry("access control", definitions=defs),
        ])
        matched, unmatched = match_terms(["access-control"], glossary)
        assert len(matched) == 1
        assert len(matched[0].definitions) == 3
        assert unmatched == []

    def test_hyphen_to_space_conversion(self):
        """Hyphens in short names are converted to spaces for lookup (Req 3.1)."""
        glossary = _build_glossary([
            _make_glossary_entry(
                "system security plan",
                definitions=[{"text": "A plan", "sources": []}],
            ),
        ])
        matched, unmatched = match_terms(["system-security-plan"], glossary)
        assert len(matched) == 1
        assert matched[0].short_name == "system-security-plan"

    def test_case_insensitive_lookup(self):
        """Lookup is case-insensitive (Req 3.1)."""
        glossary = _build_glossary([
            _make_glossary_entry(
                "Access Control",
                definitions=[{"text": "A def", "sources": []}],
            ),
        ])
        matched, unmatched = match_terms(["access-control"], glossary)
        assert len(matched) == 1

    def test_abbr_syn_preserved(self):
        """abbrSyn from the glossary entry is preserved on MatchedTerm."""
        abbr = [{"text": "AC"}]
        glossary = _build_glossary([
            _make_glossary_entry(
                "access control",
                definitions=[{"text": "A def", "sources": []}],
                abbr_syn=abbr,
            ),
        ])
        matched, _ = match_terms(["access-control"], glossary)
        assert matched[0].abbr_syn == abbr

    def test_mixed_matched_and_unmatched(self):
        """A mix of matched and unmatched terms is partitioned correctly."""
        glossary = _build_glossary([
            _make_glossary_entry(
                "catalog",
                definitions=[{"text": "A catalog", "sources": []}],
            ),
        ])
        matched, unmatched = match_terms(
            ["catalog", "unknown-term", "another-missing"], glossary
        )
        assert len(matched) == 1
        assert matched[0].short_name == "catalog"
        assert sorted(unmatched) == ["another-missing", "unknown-term"]

    def test_empty_input(self):
        """Empty short_names list returns empty results."""
        matched, unmatched = match_terms([], {"some": {}})
        assert matched == []
        assert unmatched == []

    def test_total_equals_input_count(self):
        """matched + unmatched count equals total input count (Req 3.6)."""
        glossary = _build_glossary([
            _make_glossary_entry(
                "catalog",
                definitions=[{"text": "A catalog", "sources": []}],
            ),
            _make_glossary_entry("control", definitions=None),
        ])
        short_names = ["catalog", "control", "missing"]
        matched, unmatched = match_terms(short_names, glossary)
        assert len(matched) + len(unmatched) == len(short_names)


# ---------------------------------------------------------------------------
# generate_markdown
# ---------------------------------------------------------------------------


class TestGenerateMarkdown:
    """Tests for generate_markdown — Requirements 4.1–4.10."""

    def test_creates_output_directory(self, tmp_path):
        """Output directory is created if it doesn't exist (Req 4.8)."""
        out = tmp_path / "nested" / "dir" / "glossary.md"
        generate_markdown([], [], out)
        assert out.exists()

    def test_header_and_timestamp(self, tmp_path):
        """Output contains level-1 heading, intro paragraph, and timestamp (Req 4.2)."""
        out = tmp_path / "glossary.md"
        generate_markdown([], [], out)
        content = out.read_text(encoding="utf-8")
        assert content.startswith("# OSCAL Glossary\n")
        assert "[NIST CSRC Glossary](https://csrc.nist.gov/glossary)" in content
        assert "*Generated: " in content
        # Timestamp should be ISO 8601 format ending with Z
        import re

        assert re.search(r"\*Generated: \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\*", content)

    def test_matched_term_heading_and_link(self, tmp_path):
        """Matched term renders with level-2 heading and CSRC link (Req 4.4)."""
        term = MatchedTerm(
            short_name="catalog",
            human_name="Catalog",
            definitions=[{"text": "A collection of controls.", "sources": []}],
            link="https://csrc.nist.gov/glossary/term/catalog",
        )
        out = tmp_path / "glossary.md"
        generate_markdown([term], [], out)
        content = out.read_text(encoding="utf-8")
        assert "## Catalog" in content
        assert "[CSRC Glossary: Catalog](https://csrc.nist.gov/glossary/term/catalog)" in content

    def test_numbered_definitions_with_sources(self, tmp_path):
        """Multi-definition entries render as numbered list with sources (Req 4.5)."""
        term = MatchedTerm(
            short_name="access-control",
            human_name="Access Control",
            definitions=[
                {
                    "text": "First definition.",
                    "sources": [
                        {
                            "text": "NIST SP 800-53",
                            "link": "https://doi.org/10.6028/NIST.SP.800-53r5",
                        }
                    ],
                },
                {
                    "text": "Second definition.",
                    "sources": [
                        {"text": "CNSSI 4009", "link": "https://example.com/cnssi"}
                    ],
                },
            ],
            link="https://csrc.nist.gov/glossary/term/access_control",
        )
        out = tmp_path / "glossary.md"
        generate_markdown([term], [], out)
        content = out.read_text(encoding="utf-8")
        assert "1. First definition." in content
        assert "2. Second definition." in content
        assert "*Source: [NIST SP 800-53](https://doi.org/10.6028/NIST.SP.800-53r5)*" in content
        assert "*Source: [CNSSI 4009](https://example.com/cnssi)*" in content

    def test_abbr_syn_rendering(self, tmp_path):
        """abbrSyn renders as 'Also known as:' line (Req 4.6)."""
        term = MatchedTerm(
            short_name="access-control",
            human_name="Access Control",
            definitions=[{"text": "A def.", "sources": []}],
            link="https://csrc.nist.gov/glossary/term/access_control",
            abbr_syn=[{"text": "AC"}, {"text": "Access Control List"}],
        )
        out = tmp_path / "glossary.md"
        generate_markdown([term], [], out)
        content = out.read_text(encoding="utf-8")
        assert "**Also known as:** AC, Access Control List" in content

    def test_no_abbr_syn_when_none(self, tmp_path):
        """No 'Also known as:' line when abbrSyn is None."""
        term = MatchedTerm(
            short_name="catalog",
            human_name="Catalog",
            definitions=[{"text": "A def.", "sources": []}],
            link="https://csrc.nist.gov/glossary/term/catalog",
            abbr_syn=None,
        )
        out = tmp_path / "glossary.md"
        generate_markdown([term], [], out)
        content = out.read_text(encoding="utf-8")
        assert "Also known as" not in content

    def test_alphabetical_order(self, tmp_path):
        """Matched terms are sorted case-insensitively by human_name (Req 4.3)."""
        terms = [
            MatchedTerm(
                short_name="zebra",
                human_name="Zebra",
                definitions=[{"text": "Z def.", "sources": []}],
                link="https://example.com/z",
            ),
            MatchedTerm(
                short_name="alpha",
                human_name="Alpha",
                definitions=[{"text": "A def.", "sources": []}],
                link="https://example.com/a",
            ),
            MatchedTerm(
                short_name="middle",
                human_name="Middle",
                definitions=[{"text": "M def.", "sources": []}],
                link="https://example.com/m",
            ),
        ]
        out = tmp_path / "glossary.md"
        generate_markdown(terms, [], out)
        content = out.read_text(encoding="utf-8")
        alpha_pos = content.index("## Alpha")
        middle_pos = content.index("## Middle")
        zebra_pos = content.index("## Zebra")
        assert alpha_pos < middle_pos < zebra_pos

    def test_unmatched_terms_section(self, tmp_path):
        """Unmatched terms render as alphabetical bulleted list (Req 4.7)."""
        out = tmp_path / "glossary.md"
        generate_markdown([], ["select-control", "include-all"], out)
        content = out.read_text(encoding="utf-8")
        assert "## Unmatched Terms" in content
        assert "- Include All" in content
        assert "- Select Control" in content
        # Alphabetical order
        include_pos = content.index("- Include All")
        select_pos = content.index("- Select Control")
        assert include_pos < select_pos

    def test_no_unmatched_section_when_empty(self, tmp_path):
        """No unmatched section when there are no unmatched terms."""
        term = MatchedTerm(
            short_name="catalog",
            human_name="Catalog",
            definitions=[{"text": "A def.", "sources": []}],
            link="https://example.com/catalog",
        )
        out = tmp_path / "glossary.md"
        generate_markdown([term], [], out)
        content = out.read_text(encoding="utf-8")
        assert "## Unmatched Terms" not in content

    def test_write_error_calls_fatal(self, tmp_path):
        """Write errors cause _fatal() to be called (Req 4.10)."""
        # Use a path that can't be written (directory as file)
        bad_dir = tmp_path / "blocked"
        bad_dir.mkdir()
        out = bad_dir  # trying to write to a directory, not a file
        with pytest.raises(SystemExit) as exc_info:
            generate_markdown([], [], out)
        assert exc_info.value.code == 1
