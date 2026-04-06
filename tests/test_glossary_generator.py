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
assert _spec is not None, "Could not find generate_oscal_glossary.py"
_mod = importlib.util.module_from_spec(_spec)
_mod.__name__ = "generate_oscal_glossary"
sys.modules["generate_oscal_glossary"] = _mod
assert _spec.loader is not None, "Module spec has no loader"
_spec.loader.exec_module(_mod)

parse_schema = _mod.parse_schema
_is_object_type = _mod._is_object_type  # noqa: SLF001
match_terms = _mod.match_terms
generate_markdown = _mod.generate_markdown
extract_terms = _mod.extract_terms
read_terms = _mod.read_terms
parse_oscal_terms_page = _mod.parse_oscal_terms_page
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


# ---------------------------------------------------------------------------
# extract_terms
# ---------------------------------------------------------------------------


class TestExtractTerms:
    """Tests for extract_terms — Requirements 7.3, 7.4, 7.5, 7.6, 7.7."""

    def test_comment_header_with_timestamp(self, tmp_path):
        """Output file starts with # comment lines including an ISO 8601 timestamp (Req 7.4)."""
        import re

        out = tmp_path / "terms.txt"
        extract_terms(["alpha", "beta"], out)
        content = out.read_text(encoding="utf-8")
        lines = content.splitlines()

        # First two lines should be comments
        assert lines[0].startswith("#")
        assert lines[1].startswith("#")

        # One of the comment lines should contain an ISO 8601 timestamp
        iso_pattern = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
        header_text = "\n".join(lines[:2])
        assert iso_pattern.search(header_text), (
            f"Expected ISO 8601 timestamp in header, got:\n{header_text}"
        )

    def test_sorted_terms_one_per_line(self, tmp_path):
        """Output contains sorted short names, one per line, no blank lines between terms (Req 7.5)."""
        out = tmp_path / "terms.txt"
        extract_terms(["zebra", "alpha", "middle"], out)
        content = out.read_text(encoding="utf-8")
        lines = content.splitlines()

        # Skip comment lines
        term_lines = [ln for ln in lines if not ln.startswith("#")]

        assert term_lines == ["alpha", "middle", "zebra"]

    def test_no_blank_lines_between_terms(self, tmp_path):
        """No blank lines appear between term entries (Req 7.5)."""
        out = tmp_path / "terms.txt"
        extract_terms(["a", "b", "c"], out)
        content = out.read_text(encoding="utf-8")
        lines = content.splitlines()

        # After the comment header, there should be no blank lines
        term_section = lines[lines.index("a"):]
        for line in term_section:
            assert line.strip() != "", f"Unexpected blank line in term section"

    def test_creates_output_directory(self, tmp_path):
        """Output directory (including nested intermediates) is created if missing (Req 7.6)."""
        out = tmp_path / "nested" / "deep" / "dir" / "terms.txt"
        extract_terms(["catalog"], out)
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "catalog" in content

    def test_empty_input_writes_header_only(self, tmp_path):
        """An empty short_names list writes only the comment header."""
        out = tmp_path / "terms.txt"
        extract_terms([], out)
        content = out.read_text(encoding="utf-8")
        lines = content.splitlines()

        # All lines should be comments
        for line in lines:
            assert line.startswith("#") or line.strip() == ""

    def test_fatal_on_write_failure(self, tmp_path):
        """_fatal() is called (SystemExit with code 1) on write failure (Req 7.7)."""
        # Use a directory path as the file path to trigger a write error
        bad_path = tmp_path / "blocked"
        bad_path.mkdir()
        with pytest.raises(SystemExit) as exc_info:
            extract_terms(["term"], bad_path)
        assert exc_info.value.code == 1

    def test_input_order_does_not_affect_output(self, tmp_path):
        """Terms are always sorted regardless of input order (Req 7.3, 7.5)."""
        out = tmp_path / "terms.txt"
        extract_terms(["delta", "alpha", "charlie", "bravo"], out)
        content = out.read_text(encoding="utf-8")
        term_lines = [ln for ln in content.splitlines() if not ln.startswith("#")]
        assert term_lines == ["alpha", "bravo", "charlie", "delta"]

# ---------------------------------------------------------------------------
# read_terms
# ---------------------------------------------------------------------------


class TestReadTerms:
    """Tests for read_terms — Requirements 8.1, 8.2, 8.3, 8.4, 8.5, 8.6."""

    def test_valid_term_list(self, tmp_path):
        """Reading a valid term list file returns the correct terms in order."""
        terms_file = tmp_path / "terms.txt"
        terms_file.write_text(
            "catalog\ncontrol\nback-matter\n", encoding="utf-8"
        )
        result = read_terms(terms_file)
        assert result == ["catalog", "control", "back-matter"]

    def test_comment_lines_skipped(self, tmp_path):
        """Lines starting with # are skipped (Req 8.3)."""
        terms_file = tmp_path / "terms.txt"
        terms_file.write_text(
            "# This is a comment\ncatalog\n# Another comment\ncontrol\n",
            encoding="utf-8",
        )
        result = read_terms(terms_file)
        assert result == ["catalog", "control"]

    def test_blank_lines_skipped(self, tmp_path):
        """Blank lines are skipped (Req 8.3)."""
        terms_file = tmp_path / "terms.txt"
        terms_file.write_text(
            "catalog\n\n\ncontrol\n   \nback-matter\n",
            encoding="utf-8",
        )
        result = read_terms(terms_file)
        assert result == ["catalog", "control", "back-matter"]

    def test_whitespace_stripped(self, tmp_path):
        """Leading/trailing whitespace is stripped from terms (Req 8.4)."""
        terms_file = tmp_path / "terms.txt"
        terms_file.write_text(
            "  catalog  \n\tcontrol\t\n  back-matter \n",
            encoding="utf-8",
        )
        result = read_terms(terms_file)
        assert result == ["catalog", "control", "back-matter"]

    def test_duplicate_deduplication_first_occurrence(self, tmp_path):
        """Duplicate terms are deduplicated, keeping first occurrence (Req 8.4)."""
        terms_file = tmp_path / "terms.txt"
        terms_file.write_text(
            "catalog\ncontrol\ncatalog\nback-matter\ncontrol\n",
            encoding="utf-8",
        )
        result = read_terms(terms_file)
        assert result == ["catalog", "control", "back-matter"]

    def test_case_sensitive_deduplication(self, tmp_path):
        """Deduplication is case-sensitive: Catalog and catalog are different (Req 8.4)."""
        terms_file = tmp_path / "terms.txt"
        terms_file.write_text(
            "Catalog\ncatalog\nCATALOG\n", encoding="utf-8"
        )
        result = read_terms(terms_file)
        assert result == ["Catalog", "catalog", "CATALOG"]

    def test_missing_file_exits_with_extract_terms_advice(self, tmp_path):
        """Missing file exits with status 1 and advises --extract-terms (Req 8.5)."""
        missing = tmp_path / "nonexistent.txt"
        with pytest.raises(SystemExit) as exc_info:
            read_terms(missing)
        assert exc_info.value.code == 1

    def test_missing_file_error_message(self, tmp_path, capsys):
        """Missing file error message includes 'run with --extract-terms' (Req 8.5)."""
        missing = tmp_path / "nonexistent.txt"
        with pytest.raises(SystemExit):
            read_terms(missing)
        # The error is logged, not printed to stderr directly,
        # so we check via caplog instead
        # But _fatal uses logger.error + sys.exit, so we verify exit code above

    def test_only_comments_and_blanks_exits(self, tmp_path):
        """File with only comments and blanks exits with status 1 (Req 8.6)."""
        terms_file = tmp_path / "terms.txt"
        terms_file.write_text(
            "# Just a comment\n\n# Another comment\n   \n",
            encoding="utf-8",
        )
        with pytest.raises(SystemExit) as exc_info:
            read_terms(terms_file)
        assert exc_info.value.code == 1

    def test_preserves_file_order(self, tmp_path):
        """Terms are returned in file order, not sorted (Req 8.2)."""
        terms_file = tmp_path / "terms.txt"
        terms_file.write_text(
            "zebra\nalpha\nmiddle\n", encoding="utf-8"
        )
        result = read_terms(terms_file)
        assert result == ["zebra", "alpha", "middle"]

    def test_missing_file_error_includes_extract_terms(self, tmp_path, caplog):
        """Error message for missing file includes 'extract-terms' advice (Req 8.5)."""
        import logging

        missing = tmp_path / "nonexistent.txt"
        with caplog.at_level(logging.ERROR):
            with pytest.raises(SystemExit):
                read_terms(missing)
        assert any("--extract-terms" in record.message for record in caplog.records)


# ---------------------------------------------------------------------------
# match_terms — OSCAL page priority (dual-source)
# ---------------------------------------------------------------------------


class TestMatchTermsOscalPagePriority:
    """Tests for match_terms with oscal_terms parameter — Requirements 3.2, 12.1–12.4, 13.1–13.3."""

    def test_oscal_page_priority_over_nist(self):
        """When a term exists in both OSCAL page and NIST glossary, OSCAL page definition is used (Req 12.1)."""
        oscal_terms = {"catalog": "An OSCAL-specific catalog definition."}
        glossary = _build_glossary([
            _make_glossary_entry(
                "catalog",
                definitions=[{"text": "A NIST catalog definition.", "sources": []}],
            ),
        ])
        matched, unmatched = match_terms(["catalog"], glossary, oscal_terms)
        assert len(matched) == 1
        assert matched[0].source == "OSCAL Page"
        assert matched[0].oscal_definition == "An OSCAL-specific catalog definition."
        assert matched[0].definitions == []
        assert matched[0].link == ""
        assert unmatched == []

    def test_override_warning_logged(self, caplog):
        """When OSCAL page overrides NIST definition, a WARNING is emitted (Req 12.2)."""
        import logging

        oscal_terms = {"control": "OSCAL control definition."}
        glossary = _build_glossary([
            _make_glossary_entry(
                "control",
                definitions=[{"text": "NIST control definition.", "sources": []}],
            ),
        ])
        with caplog.at_level(logging.WARNING):
            match_terms(["control"], glossary, oscal_terms)
        warning_messages = [
            r.message for r in caplog.records if r.levelno == logging.WARNING
        ]
        assert any("overriding" in msg.lower() or "override" in msg.lower() for msg in warning_messages), (
            f"Expected a WARNING about OSCAL overriding NIST, got: {warning_messages}"
        )

    def test_oscal_only_term_no_warning(self, caplog):
        """Term in OSCAL page but not NIST glossary: matched with source='OSCAL Page', no warning (Req 12.3)."""
        import logging

        oscal_terms = {"baseline": "A baseline definition from OSCAL page."}
        glossary = _build_glossary([])  # empty NIST glossary
        with caplog.at_level(logging.WARNING):
            matched, unmatched = match_terms(["baseline"], glossary, oscal_terms)
        assert len(matched) == 1
        assert matched[0].source == "OSCAL Page"
        assert matched[0].oscal_definition == "A baseline definition from OSCAL page."
        assert unmatched == []
        # No override warning should be emitted
        warning_messages = [
            r.message for r in caplog.records if r.levelno == logging.WARNING
        ]
        assert not any("overrid" in msg.lower() for msg in warning_messages), (
            f"Unexpected override warning: {warning_messages}"
        )

    def test_nist_only_term_no_warning(self, caplog):
        """Term in NIST glossary but not OSCAL page: matched with source='NIST CSRC', no warning (Req 12.4)."""
        import logging

        oscal_terms = {}  # empty OSCAL terms
        glossary = _build_glossary([
            _make_glossary_entry(
                "access control",
                definitions=[{"text": "NIST access control def.", "sources": []}],
                link="https://csrc.nist.gov/glossary/term/access_control",
            ),
        ])
        with caplog.at_level(logging.WARNING):
            matched, unmatched = match_terms(
                ["access-control"], glossary, oscal_terms
            )
        assert len(matched) == 1
        assert matched[0].source == "NIST CSRC"
        assert matched[0].link == "https://csrc.nist.gov/glossary/term/access_control"
        assert unmatched == []
        # No override warning should be emitted
        warning_messages = [
            r.message for r in caplog.records if r.levelno == logging.WARNING
        ]
        assert not any("overrid" in msg.lower() for msg in warning_messages)

    def test_mixed_sources(self):
        """Some terms from OSCAL, some from NIST, some unmatched — correct classification (Req 3.2, 13.1–13.3)."""
        oscal_terms = {
            "catalog": "OSCAL catalog definition.",
            "baseline": "OSCAL baseline definition.",
        }
        glossary = _build_glossary([
            _make_glossary_entry(
                "catalog",
                definitions=[{"text": "NIST catalog def.", "sources": []}],
            ),
            _make_glossary_entry(
                "access control",
                definitions=[{"text": "NIST AC def.", "sources": []}],
            ),
        ])
        matched, unmatched = match_terms(
            ["catalog", "access-control", "baseline", "unknown-term"],
            glossary,
            oscal_terms,
        )
        # Build lookup by short_name
        by_name = {m.short_name: m for m in matched}
        assert len(matched) == 3
        assert len(unmatched) == 1

        # catalog: in both → OSCAL page wins
        assert by_name["catalog"].source == "OSCAL Page"
        assert by_name["catalog"].oscal_definition == "OSCAL catalog definition."

        # access-control: NIST only
        assert by_name["access-control"].source == "NIST CSRC"

        # baseline: OSCAL only
        assert by_name["baseline"].source == "OSCAL Page"
        assert by_name["baseline"].oscal_definition == "OSCAL baseline definition."

        # unknown-term: unmatched
        assert unmatched == ["unknown-term"]

    def test_oscal_terms_none_backward_compatibility(self):
        """When oscal_terms=None, existing NIST-only behavior is unchanged (Req 13.3)."""
        glossary = _build_glossary([
            _make_glossary_entry(
                "catalog",
                definitions=[{"text": "A NIST catalog.", "sources": []}],
            ),
        ])
        matched, unmatched = match_terms(["catalog", "missing"], glossary, None)
        assert len(matched) == 1
        assert matched[0].source == "NIST CSRC"
        assert matched[0].short_name == "catalog"
        assert unmatched == ["missing"]

    def test_oscal_terms_default_parameter(self):
        """When oscal_terms is omitted entirely, NIST-only behavior is unchanged."""
        glossary = _build_glossary([
            _make_glossary_entry(
                "control",
                definitions=[{"text": "A NIST control.", "sources": []}],
            ),
        ])
        # Call without the third argument at all
        matched, unmatched = match_terms(["control"], glossary)
        assert len(matched) == 1
        assert matched[0].source == "NIST CSRC"
        assert unmatched == []


# ---------------------------------------------------------------------------
# parse_oscal_terms_page
# ---------------------------------------------------------------------------


class TestParseOscalTermsPage:
    """Tests for parse_oscal_terms_page — Requirements 11.1–11.10."""

    def test_front_matter_skipping(self, tmp_path):
        """YAML front matter between --- markers is not in any definition (Req 11.2)."""
        page = tmp_path / "terms.md"
        page.write_text(
            "---\ntitle: My Page\ndate: 2024-01-01\n---\n\n"
            "### Alpha\n\nAlpha definition.\n",
            encoding="utf-8",
        )
        result = parse_oscal_terms_page(page)
        assert "alpha" in result
        assert "title" not in result["alpha"]
        assert "My Page" not in result["alpha"]
        assert "2024-01-01" not in result["alpha"]

    def test_h3_heading_extraction(self, tmp_path):
        """Multiple ### headings each become a key in the returned dict (Req 11.3)."""
        page = tmp_path / "terms.md"
        page.write_text(
            "### Control\n\nControl def.\n\n"
            "### Catalog\n\nCatalog def.\n\n"
            "### Baseline\n\nBaseline def.\n",
            encoding="utf-8",
        )
        result = parse_oscal_terms_page(page)
        assert "control" in result
        assert "catalog" in result
        assert "baseline" in result
        assert len(result) == 3

    def test_h4_headings_not_top_level_keys(self, tmp_path):
        """#### headings do NOT appear as top-level dict keys (Req 11.4)."""
        page = tmp_path / "terms.md"
        page.write_text(
            "### Control\n\nControl def.\n\n"
            "#### Examples of Controls\n\nSome examples.\n\n"
            "### Catalog\n\nCatalog def.\n",
            encoding="utf-8",
        )
        result = parse_oscal_terms_page(page)
        assert "control" in result
        assert "catalog" in result
        assert "examples of controls" not in result
        # The #### content should be part of the Control definition
        assert "Some examples." in result["control"]

    def test_callout_block_inclusion(self, tmp_path):
        """Callout block content is included with delimiters stripped (Req 11.6)."""
        page = tmp_path / "terms.md"
        page.write_text(
            "### Control\n\nControl intro.\n\n"
            "{{% callout %}}\nA security control is defined.\n{{% /callout %}}\n\n"
            "### Catalog\n\nCatalog intro.\n\n"
            "{{<callout>}}NIST defines a catalog.{{</callout>}}\n",
            encoding="utf-8",
        )
        result = parse_oscal_terms_page(page)
        assert "A security control is defined." in result["control"]
        assert "{{% callout %}}" not in result["control"]
        assert "{{% /callout %}}" not in result["control"]
        assert "NIST defines a catalog." in result["catalog"]
        assert "{{<callout>}}" not in result["catalog"]
        assert "{{</callout>}}" not in result["catalog"]

    def test_todo_block_exclusion(self, tmp_path):
        """Content within {{<todo>}}...{{</todo>}} blocks is excluded (Req 11.7)."""
        page = tmp_path / "terms.md"
        page.write_text(
            "### Control\n\nControl def.\n\n"
            "{{<todo>}}\n#### Objective\nTODO placeholder\n{{</todo>}}\n\n"
            "More control content.\n",
            encoding="utf-8",
        )
        result = parse_oscal_terms_page(page)
        assert "control" in result
        assert "TODO placeholder" not in result["control"]
        assert "Objective" not in result["control"]
        assert "More control content." in result["control"]

    def test_missing_file_returns_empty_dict_with_warning(self, tmp_path, caplog):
        """Missing file returns empty dict and logs WARNING (Req 11.9)."""
        import logging

        missing = tmp_path / "nonexistent.md"
        with caplog.at_level(logging.WARNING):
            result = parse_oscal_terms_page(missing)
        assert result == {}
        assert any("not found" in r.message for r in caplog.records)

    def test_no_h3_headings_returns_empty_dict_with_warning(self, tmp_path, caplog):
        """File with no ### headings returns empty dict and logs WARNING (Req 11.10)."""
        import logging

        page = tmp_path / "terms.md"
        page.write_text(
            "---\ntitle: Empty\n---\n\n"
            "## Section One\n\nSome prose.\n\n"
            "## Section Two\n\nMore prose.\n",
            encoding="utf-8",
        )
        with caplog.at_level(logging.WARNING):
            result = parse_oscal_terms_page(page)
        assert result == {}
        assert any("no parseable" in r.message.lower() for r in caplog.records)

    def test_real_oscal_terminology_page_smoke_test(self):
        """Smoke test: parse the actual OSCAL terminology page and verify known terms."""
        page_path = Path(
            "data/oscal_docs/OSCAL-Pages-main/src/content/learn/"
            "concepts/terminology/_index.md"
        )
        if not page_path.exists():
            pytest.skip("Real OSCAL terminology page not available")

        result = parse_oscal_terms_page(page_path)

        # Known terms should be present as keys (lowercased)
        assert "control" in result
        assert "catalog" in result
        assert "baseline" in result

        # Definitions should be non-empty
        assert len(result["control"]) > 0
        assert len(result["catalog"]) > 0
        assert len(result["baseline"]) > 0

        # Front matter should not leak into definitions
        for term, definition in result.items():
            assert "title: Key Concepts" not in definition


# ---------------------------------------------------------------------------
# generate_markdown — source annotations (dual-source rendering)
# ---------------------------------------------------------------------------


class TestGenerateMarkdownSourceAnnotations:
    """Tests for generate_markdown with source annotations — Requirements 4.2, 4.4, 4.5, 4.7, 4.12."""

    def test_oscal_sourced_term_rendering(self, tmp_path):
        """OSCAL-sourced term: level-2 heading, body text (not numbered), *Source: OSCAL Page*, no CSRC link, no 'Also known as:' (Req 4.7, 4.12)."""
        term = MatchedTerm(
            short_name="catalog",
            human_name="Catalog",
            definitions=[],
            link="",
            abbr_syn=None,
            source="OSCAL Page",
            oscal_definition="Framework providers organize control requirements into a **catalog**.",
        )
        out = tmp_path / "glossary.md"
        generate_markdown([term], [], out)
        content = out.read_text(encoding="utf-8")

        # Level-2 heading present
        assert "## Catalog" in content
        # Definition text rendered as body (not numbered)
        assert "Framework providers organize control requirements into a **catalog**." in content
        assert "1. Framework" not in content  # not numbered
        # Source annotation
        assert "*Source: OSCAL Page*" in content
        # No CSRC link
        assert "CSRC Glossary:" not in content
        assert "csrc.nist.gov/glossary/term" not in content
        # No "Also known as:"
        assert "Also known as" not in content

    def test_nist_sourced_term_rendering_with_annotation(self, tmp_path):
        """NIST-sourced term: existing behavior plus *Source: NIST CSRC* annotation (Req 4.4, 4.5, 4.12)."""
        term = MatchedTerm(
            short_name="access-control",
            human_name="Access Control",
            definitions=[
                {
                    "text": "The process of granting or denying specific requests.",
                    "sources": [
                        {
                            "text": "NIST SP 800-53 Rev. 5",
                            "link": "https://doi.org/10.6028/NIST.SP.800-53r5",
                        }
                    ],
                },
            ],
            link="https://csrc.nist.gov/glossary/term/access_control",
            abbr_syn=[{"text": "AC"}],
            source="NIST CSRC",
        )
        out = tmp_path / "glossary.md"
        generate_markdown([term], [], out)
        content = out.read_text(encoding="utf-8")

        # Level-2 heading
        assert "## Access Control" in content
        # Abbreviation
        assert "**Also known as:** AC" in content
        # Numbered definition
        assert "1. The process of granting or denying specific requests." in content
        # Inline source reference
        assert "*Source: [NIST SP 800-53 Rev. 5](https://doi.org/10.6028/NIST.SP.800-53r5)*" in content
        # CSRC link
        assert "[CSRC Glossary: Access Control](https://csrc.nist.gov/glossary/term/access_control)" in content
        # Definition_Source annotation
        assert "*Source: NIST CSRC*" in content

    def test_mixed_oscal_and_nist_rendering(self, tmp_path):
        """Both OSCAL and NIST terms in output have correct source annotations (Req 4.7, 4.12)."""
        oscal_term = MatchedTerm(
            short_name="catalog",
            human_name="Catalog",
            definitions=[],
            link="",
            abbr_syn=None,
            source="OSCAL Page",
            oscal_definition="An OSCAL catalog organizes controls.",
        )
        nist_term = MatchedTerm(
            short_name="access-control",
            human_name="Access Control",
            definitions=[
                {"text": "Granting or denying access.", "sources": []},
            ],
            link="https://csrc.nist.gov/glossary/term/access_control",
            source="NIST CSRC",
        )
        out = tmp_path / "glossary.md"
        generate_markdown([oscal_term, nist_term], [], out)
        content = out.read_text(encoding="utf-8")

        # Both terms present (alphabetical: Access Control before Catalog)
        ac_pos = content.index("## Access Control")
        cat_pos = content.index("## Catalog")
        assert ac_pos < cat_pos

        # NIST term has *Source: NIST CSRC*
        # OSCAL term has *Source: OSCAL Page*
        assert "*Source: NIST CSRC*" in content
        assert "*Source: OSCAL Page*" in content

        # OSCAL term should NOT have CSRC link or numbered definitions
        # Find the Catalog section and check its content
        catalog_section = content[cat_pos:]
        # The catalog section ends at the next --- separator
        separator_pos = catalog_section.index("---")
        catalog_section = catalog_section[:separator_pos]
        assert "An OSCAL catalog organizes controls." in catalog_section
        assert "*Source: OSCAL Page*" in catalog_section
        assert "CSRC Glossary:" not in catalog_section
        assert "1." not in catalog_section

        # NIST term should have CSRC link and numbered definitions
        ac_section = content[ac_pos:cat_pos]
        assert "1. Granting or denying access." in ac_section
        assert "*Source: NIST CSRC*" in ac_section
        assert "CSRC Glossary: Access Control" in ac_section

    def test_intro_paragraph_references_both_sources(self, tmp_path):
        """Intro paragraph references both OSCAL terminology page and NIST CSRC glossary (Req 4.2)."""
        out = tmp_path / "glossary.md"
        generate_markdown([], [], out)
        content = out.read_text(encoding="utf-8")

        assert "[OSCAL Terminology Page]" in content
        assert "https://pages.nist.gov/OSCAL/learn/concepts/terminology/" in content
        assert "[NIST CSRC Glossary]" in content
        assert "https://csrc.nist.gov/glossary" in content
