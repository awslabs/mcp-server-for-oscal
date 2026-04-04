"""
Property-based tests for bin/generate_oscal_glossary.py correctness properties.

Uses Hypothesis to verify universal properties of the OSCAL glossary generator
across randomly generated inputs.

Feature: oscal-glossary-generator
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import tempfile
from pathlib import Path

from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

# ---------------------------------------------------------------------------
# Load the script as a module since it lives in bin/ (not a package)
# ---------------------------------------------------------------------------
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
MatchedTerm = _mod.MatchedTerm
load_glossary = _mod.load_glossary
generate_markdown = _mod.generate_markdown
to_human_readable = _mod.to_human_readable
generate_markdown = _mod.generate_markdown
to_human_readable = _mod.to_human_readable


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

# Strategy for generating valid identifier-like short names (no colons)
_short_name = st.from_regex(r"[a-z][a-z0-9\-]{0,30}", fullmatch=True)

# Strategy for generating namespace prefixes (no colons)
_prefix = st.from_regex(r"[a-z][a-z0-9\-]{0,30}", fullmatch=True)

SCALAR_TYPES = ["string", "integer", "boolean", "number"]

# Strategy for additional optional properties on a definition entry
_extra_properties = st.fixed_dictionaries(
    {},
    optional={
        "title": st.text(min_size=1, max_size=30),
        "description": st.text(min_size=1, max_size=60),
        "additionalProperties": st.just(False),
    },
)


# ---------------------------------------------------------------------------
# Strategies for scalar entries (Property 2)
# ---------------------------------------------------------------------------


@st.composite
def scalar_type_entry(draw):
    """Generate a random scalar definition entry that should be excluded."""
    kind = draw(st.sampled_from(["typed_scalar", "ref_only"]))

    if kind == "typed_scalar":
        scalar_type = draw(st.sampled_from(SCALAR_TYPES))
        entry: dict = {"type": scalar_type}
        if draw(st.booleans()):
            entry["description"] = draw(
                st.text(
                    min_size=0,
                    max_size=50,
                    alphabet=st.characters(whitelist_categories=("L", "N", "Z")),
                )
            )
        if draw(st.booleans()) and scalar_type == "string":
            entry["pattern"] = "^[a-z]+$"
        return entry

    ref_target = draw(
        st.text(
            min_size=1,
            max_size=30,
            alphabet=st.characters(whitelist_categories=("L", "N")),
        )
    )
    entry = {"$ref": f"#/definitions/{ref_target}"}
    if draw(st.booleans()):
        entry["description"] = "A reference alias"
    return entry


@st.composite
def definition_key(draw):
    """Generate a random definition key (namespaced or plain)."""
    name = draw(
        st.text(
            min_size=1,
            max_size=20,
            alphabet=st.characters(
                whitelist_categories=("Ll",), whitelist_characters="-"
            ),
        ).filter(
            lambda s: s.strip("-") and not s.startswith("-") and not s.endswith("-")
        )
    )
    if draw(st.booleans()):
        prefix = draw(
            st.text(
                min_size=1,
                max_size=30,
                alphabet=st.characters(
                    whitelist_categories=("Ll",), whitelist_characters="-"
                ),
            ).filter(
                lambda s: s.strip("-")
                and not s.startswith("-")
                and not s.endswith("-")
            )
        )
        return f"{prefix}:{name}"
    return name


def _write_schema(definitions: dict) -> Path:
    """Write a schema dict to a temp file and return the path."""
    td = tempfile.mkdtemp()
    p = Path(td) / "schema.json"
    p.write_text(json.dumps({"definitions": definitions}), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Strategies for object-type entries (Property 1)
# ---------------------------------------------------------------------------


@st.composite
def object_type_direct(draw):
    """Generate a definition entry with direct `"type": "object"`."""
    entry = {"type": "object"}
    extras = draw(_extra_properties)
    entry.update(extras)
    if draw(st.booleans()):
        prop_name = draw(
            st.text(
                min_size=1, max_size=15, alphabet="abcdefghijklmnopqrstuvwxyz"
            )
        )
        entry["properties"] = {prop_name: {"type": "string"}}
    return entry


@st.composite
def object_type_anyof(draw):
    """Generate a definition with `anyOf` containing at least one object variant."""
    object_variant = {"type": "object"}
    other_variants = draw(
        st.lists(
            st.fixed_dictionaries({"type": st.sampled_from(SCALAR_TYPES)}),
            min_size=0,
            max_size=3,
        )
    )
    variants = other_variants + [object_variant]
    shuffled = draw(st.permutations(variants))
    return {"anyOf": list(shuffled)}


@st.composite
def object_type_oneof(draw):
    """Generate a definition with `oneOf` containing at least one object variant."""
    object_variant = {"type": "object"}
    other_variants = draw(
        st.lists(
            st.fixed_dictionaries({"type": st.sampled_from(SCALAR_TYPES)}),
            min_size=0,
            max_size=3,
        )
    )
    variants = other_variants + [object_variant]
    shuffled = draw(st.permutations(variants))
    return {"oneOf": list(shuffled)}


object_type_entry = st.one_of(
    object_type_direct(),
    object_type_anyof(),
    object_type_oneof(),
)


# ---------------------------------------------------------------------------
# Strategies for deduplication (Property 4)
# ---------------------------------------------------------------------------


@st.composite
def _pairs_with_collisions(draw):
    """Generate (prefix, short_name) pairs with controlled short-name collisions."""
    pool = draw(st.lists(_short_name, min_size=1, max_size=8, unique=True))
    num_pairs = draw(
        st.integers(
            min_value=len(pool),
            max_value=max(len(pool) * 3, len(pool) + 5),
        )
    )
    items = []
    for _ in range(num_pairs):
        prefix = draw(_prefix)
        short = draw(st.sampled_from(pool))
        items.append((prefix, short))
    return items


# ---------------------------------------------------------------------------
# Property 1: Object Type Classification
# ---------------------------------------------------------------------------


class TestProperty1ObjectTypeClassification:
    """
    Feature: oscal-glossary-generator, Property 1: Object Type Classification

    **Validates: Requirements 1.3**
    """

    @settings(max_examples=100, deadline=None)
    @given(entry=object_type_entry)
    def test_is_object_type_classifies_object_entries(self, entry):
        """Feature: oscal-glossary-generator, Property 1: Object Type Classification"""
        assert _is_object_type(entry) is True

    @settings(max_examples=100, deadline=None)
    @given(
        key=st.one_of(
            _short_name,
            st.tuples(_prefix, _short_name).map(lambda t: f"{t[0]}:{t[1]}"),
        ),
        entry=object_type_entry,
    )
    def test_parse_schema_includes_object_types(self, key, entry, tmp_path_factory):
        """Feature: oscal-glossary-generator, Property 1: Object Type Classification"""
        tmp_path = tmp_path_factory.mktemp("obj_classify")
        schema = {"definitions": {key: entry}}
        schema_file = tmp_path / "schema.json"
        schema_file.write_text(json.dumps(schema), encoding="utf-8")

        result = parse_schema(schema_file)
        expected_short = key.split(":")[-1] if ":" in key else key
        assert expected_short in result


# ---------------------------------------------------------------------------
# Property 2: Scalar Type Exclusion
# ---------------------------------------------------------------------------


class TestProperty2ScalarTypeExclusion:
    """
    Feature: oscal-glossary-generator, Property 2: Scalar Type Exclusion

    **Validates: Requirements 1.4**
    """

    @given(entry=scalar_type_entry())
    @settings(max_examples=100, deadline=None)
    def test_is_object_type_rejects_scalars(self, entry):
        """Feature: oscal-glossary-generator, Property 2: Scalar Type Exclusion"""
        assert _is_object_type(entry) is False

    @given(
        entries=st.lists(
            st.tuples(definition_key(), scalar_type_entry()),
            min_size=1,
            max_size=10,
        )
    )
    @settings(max_examples=100, deadline=None)
    def test_parse_schema_excludes_all_scalars(self, entries):
        """Feature: oscal-glossary-generator, Property 2: Scalar Type Exclusion"""
        definitions = {key: entry for key, entry in entries}
        schema_path = _write_schema(definitions)
        result = parse_schema(schema_path)
        assert result == []


# ---------------------------------------------------------------------------
# Property 3: Namespace Prefix Stripping
# ---------------------------------------------------------------------------


class TestProperty3NamespacePrefixStripping:
    """
    Feature: oscal-glossary-generator, Property 3: Namespace Prefix Stripping

    **Validates: Requirements 1.5**
    """

    @settings(max_examples=100, deadline=None)
    @given(prefix=_prefix, short_name=_short_name)
    def test_namespaced_key_strips_prefix(self, prefix, short_name, tmp_path_factory):
        """Feature: oscal-glossary-generator, Property 3: Namespace Prefix Stripping"""
        tmp_path = tmp_path_factory.mktemp("ns_strip")
        namespaced_key = f"{prefix}:{short_name}"
        schema = {"definitions": {namespaced_key: {"type": "object"}}}
        schema_file = tmp_path / "schema.json"
        schema_file.write_text(json.dumps(schema), encoding="utf-8")
        result = parse_schema(schema_file)
        assert short_name in result

    @settings(max_examples=100, deadline=None)
    @given(short_name=_short_name)
    def test_non_namespaced_key_unchanged(self, short_name, tmp_path_factory):
        """Feature: oscal-glossary-generator, Property 3: Namespace Prefix Stripping"""
        tmp_path = tmp_path_factory.mktemp("no_ns")
        schema = {"definitions": {short_name: {"type": "object"}}}
        schema_file = tmp_path / "schema.json"
        schema_file.write_text(json.dumps(schema), encoding="utf-8")
        result = parse_schema(schema_file)
        assert short_name in result

    @settings(max_examples=100, deadline=None)
    @given(prefix1=_prefix, prefix2=_prefix, short_name=_short_name)
    def test_multiple_colons_strips_to_last(
        self, prefix1, prefix2, short_name, tmp_path_factory
    ):
        """Feature: oscal-glossary-generator, Property 3: Namespace Prefix Stripping"""
        tmp_path = tmp_path_factory.mktemp("multi_colon")
        multi_ns_key = f"{prefix1}:{prefix2}:{short_name}"
        schema = {"definitions": {multi_ns_key: {"type": "object"}}}
        schema_file = tmp_path / "schema.json"
        schema_file.write_text(json.dumps(schema), encoding="utf-8")
        result = parse_schema(schema_file)
        assert short_name in result


# ---------------------------------------------------------------------------
# Property 4: Short Name Deduplication
# ---------------------------------------------------------------------------


class TestProperty4ShortNameDeduplication:
    """
    Feature: oscal-glossary-generator, Property 4: Short Name Deduplication

    **Validates: Requirements 1.6**
    """

    @settings(max_examples=100, deadline=None)
    @given(pairs=_pairs_with_collisions())
    def test_deduplication_count_equals_unique_short_names(
        self, pairs, tmp_path_factory
    ):
        """Feature: oscal-glossary-generator, Property 4: Short Name Deduplication"""
        tmp_path = tmp_path_factory.mktemp("dedup")
        definitions = {}
        for prefix, short in pairs:
            key = f"{prefix}:{short}"
            definitions[key] = {"type": "object"}

        schema = {"definitions": definitions}
        schema_file = tmp_path / "schema.json"
        schema_file.write_text(json.dumps(schema), encoding="utf-8")

        result = parse_schema(schema_file)
        unique_short_names = sorted(set(short for _, short in pairs))

        assert len(result) == len(unique_short_names)
        assert result == unique_short_names


# ---------------------------------------------------------------------------
# Helpers for glossary file creation
# ---------------------------------------------------------------------------


def _write_glossary(parent_terms: list[dict], tmp_dir: Path) -> Path:
    """Write a glossary JSON file to a temp directory and return the path."""
    p = tmp_dir / "glossary.json"
    p.write_text(json.dumps({"parentTerms": parent_terms}), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Strategies for glossary terms (Property 5)
# ---------------------------------------------------------------------------

# Strategy for generating term strings using ASCII letters, digits, spaces, and
# hyphens.  This mirrors the real NIST CSRC glossary domain (English terms) and
# avoids Unicode case-folding edge cases (e.g. Turkish dotless-i) that are
# irrelevant to the production data.
_term_text = st.text(
    alphabet=st.characters(
        whitelist_categories=("L", "N"),
        whitelist_characters=" -",
        max_codepoint=127,
    ),
    min_size=1,
    max_size=40,
).filter(lambda s: s.strip())


# ---------------------------------------------------------------------------
# Property 5: Case-Insensitive Glossary Indexing
# ---------------------------------------------------------------------------


class TestProperty5CaseInsensitiveGlossaryIndexing:
    """
    Feature: oscal-glossary-generator, Property 5: Case-Insensitive Glossary Indexing

    **Validates: Requirements 2.2, 2.3**
    """

    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(term=_term_text)
    def test_any_case_variant_returns_same_entry(self, term, tmp_path_factory):
        """Feature: oscal-glossary-generator, Property 5: Case-Insensitive Glossary Indexing"""
        tmp_dir = tmp_path_factory.mktemp("glossary_ci")

        entry = {
            "term": term,
            "link": f"https://csrc.nist.gov/glossary/term/{term.replace(' ', '_')}",
            "definitions": [{"text": f"Definition of {term}", "sources": []}],
            "abbrSyn": None,
        }
        glossary_path = _write_glossary([entry], tmp_dir)

        result = load_glossary(glossary_path)

        # The index key should be the lowercase version of the term
        key = term.lower()
        assert key in result, f"Expected key {key!r} in glossary index"

        # Looking up with the original case (lowered) should return the entry
        indexed_entry = result[key]
        assert indexed_entry["term"] == term

        # All case variants should resolve to the same key and entry
        for variant in [term.upper(), term.lower(), term.swapcase(), term.title()]:
            lookup_key = variant.lower()
            assert lookup_key in result, (
                f"Case variant {variant!r} (key={lookup_key!r}) not found in index"
            )
            assert result[lookup_key] is indexed_entry, (
                f"Case variant {variant!r} returned a different entry"
            )

    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(terms=st.lists(_term_text, min_size=1, max_size=10, unique_by=str.lower))
    def test_multiple_terms_all_indexed_case_insensitively(self, terms, tmp_path_factory):
        """Feature: oscal-glossary-generator, Property 5: Case-Insensitive Glossary Indexing"""
        tmp_dir = tmp_path_factory.mktemp("glossary_ci_multi")

        entries = [
            {
                "term": t,
                "link": f"https://example.com/{i}",
                "definitions": [{"text": f"Def {i}", "sources": []}],
                "abbrSyn": None,
            }
            for i, t in enumerate(terms)
        ]
        glossary_path = _write_glossary(entries, tmp_dir)

        result = load_glossary(glossary_path)

        for t in terms:
            key = t.lower()
            assert key in result
            assert result[key]["term"] == t


# ---------------------------------------------------------------------------
# Strategies for glossary entries (Property 6)
# ---------------------------------------------------------------------------

# Strategy for a hyphenated lowercase short name (like OSCAL short names)
_hyphenated_short_name = st.from_regex(r"[a-z][a-z]{0,9}(-[a-z]{1,8}){0,3}", fullmatch=True)

# Strategy for a single definition entry with source references
_definition_entry = st.fixed_dictionaries(
    {
        "text": st.text(
            min_size=5,
            max_size=80,
            alphabet=st.characters(whitelist_categories=("L", "N", "Z", "P")),
        ),
        "sources": st.lists(
            st.fixed_dictionaries(
                {
                    "text": st.text(
                        min_size=1,
                        max_size=30,
                        alphabet=st.characters(whitelist_categories=("L", "N", "Z")),
                    ),
                    "link": st.from_regex(
                        r"https://example\.com/[a-z]{1,20}", fullmatch=True
                    ),
                }
            ),
            min_size=1,
            max_size=3,
        ),
    }
)


@st.composite
def _glossary_entry_with_definitions(draw):
    """Generate a glossary entry that has non-empty definitions."""
    term = draw(
        st.text(
            min_size=1,
            max_size=30,
            alphabet=st.characters(whitelist_categories=("L", "N", "Z")),
        ).filter(lambda s: s.strip())
    )
    definitions = draw(st.lists(_definition_entry, min_size=1, max_size=3))
    link = draw(
        st.from_regex(r"https://csrc\.nist\.gov/glossary/term/[a-z_]{1,20}", fullmatch=True)
    )
    entry = {"term": term, "link": link, "definitions": definitions}
    if draw(st.booleans()):
        entry["abbrSyn"] = [{"text": draw(st.from_regex(r"[A-Z]{2,5}", fullmatch=True))}]
    return entry


@st.composite
def _glossary_entry_without_definitions(draw):
    """Generate a glossary entry with null or empty definitions."""
    term = draw(
        st.text(
            min_size=1,
            max_size=30,
            alphabet=st.characters(whitelist_categories=("L", "N", "Z")),
        ).filter(lambda s: s.strip())
    )
    definitions = draw(st.sampled_from([None, []]))
    link = draw(
        st.from_regex(r"https://csrc\.nist\.gov/glossary/term/[a-z_]{1,20}", fullmatch=True)
    )
    return {"term": term, "link": link, "definitions": definitions}


# ---------------------------------------------------------------------------
# Property 6: Term Matching Classification
# ---------------------------------------------------------------------------


class TestProperty6TermMatchingClassification:
    """
    Feature: oscal-glossary-generator, Property 6: Term Matching Classification

    **Validates: Requirements 3.1, 3.2, 3.3, 3.4**
    """

    @settings(max_examples=100, deadline=None)
    @given(
        short_names=st.lists(
            _hyphenated_short_name, min_size=1, max_size=10, unique=True
        ),
        data=st.data(),
    )
    def test_matching_classification(self, short_names, data):
        """Feature: oscal-glossary-generator, Property 6: Term Matching Classification"""
        # Build a glossary where some short names have matching entries with
        # definitions and some have entries with null/empty definitions.
        glossary: dict[str, dict] = {}
        expected_matched_names: set[str] = set()
        expected_unmatched_names: set[str] = set()

        for sn in short_names:
            lookup_key = sn.replace("-", " ").lower()
            # Decide: match with defs, match without defs, or no match
            choice = data.draw(
                st.sampled_from(["with_defs", "without_defs", "no_match"])
            )

            if choice == "with_defs":
                entry = data.draw(_glossary_entry_with_definitions())
                # Override the term to match the lookup key
                entry["term"] = lookup_key
                glossary[lookup_key] = entry
                expected_matched_names.add(sn)
            elif choice == "without_defs":
                entry = data.draw(_glossary_entry_without_definitions())
                entry["term"] = lookup_key
                glossary[lookup_key] = entry
                expected_unmatched_names.add(sn)
            else:
                # No entry in glossary for this short name
                expected_unmatched_names.add(sn)

        matched, unmatched = match_terms(short_names, glossary)

        # Verify matched terms are exactly those with glossary entries
        # that have non-null, non-empty definitions
        actual_matched_names = {m.short_name for m in matched}
        actual_unmatched_names = set(unmatched)

        assert actual_matched_names == expected_matched_names
        assert actual_unmatched_names == expected_unmatched_names

        # Total matched + unmatched == total input count
        assert len(matched) + len(unmatched) == len(short_names)


# ---------------------------------------------------------------------------
# Strategies for matched terms (Property 7)
# ---------------------------------------------------------------------------


@st.composite
def _matched_term_for_ordering(draw):
    """Generate a MatchedTerm with a random human_name for ordering tests."""
    short_name = draw(_hyphenated_short_name)
    human_name = to_human_readable(short_name)
    definitions = [
        {
            "text": draw(
                st.text(
                    min_size=5,
                    max_size=60,
                    alphabet=st.characters(
                        whitelist_categories=("L", "N", "Z", "P"),
                        max_codepoint=127,
                    ),
                )
            ),
            "sources": [],
        }
    ]
    link = f"https://csrc.nist.gov/glossary/term/{short_name}"
    return MatchedTerm(
        short_name=short_name,
        human_name=human_name,
        definitions=definitions,
        link=link,
        abbr_syn=None,
    )


# ---------------------------------------------------------------------------
# Property 7: Alphabetical Ordering
# ---------------------------------------------------------------------------


class TestProperty7AlphabeticalOrdering:
    """
    Feature: oscal-glossary-generator, Property 7: Alphabetical Ordering

    **Validates: Requirements 4.3**
    """

    @settings(max_examples=100, deadline=None)
    @given(
        terms=st.lists(
            _matched_term_for_ordering(),
            min_size=1,
            max_size=15,
            unique_by=lambda t: t.short_name,
        ),
    )
    def test_matched_terms_appear_in_alphabetical_order(self, terms, tmp_path_factory):
        """Feature: oscal-glossary-generator, Property 7: Alphabetical Ordering"""
        tmp_dir = tmp_path_factory.mktemp("alpha_order")
        output_path = tmp_dir / "glossary.md"

        generate_markdown(terms, [], output_path)

        content = output_path.read_text(encoding="utf-8")

        # Extract all level-2 headings
        headings = re.findall(r"^## (.+)$", content, re.MULTILINE)

        # Filter out the "Unmatched Terms" heading if present
        term_headings = [h for h in headings if h != "Unmatched Terms"]

        # Verify headings are sorted case-insensitively
        assert term_headings == sorted(term_headings, key=str.lower), (
            f"Headings are not in case-insensitive alphabetical order: {term_headings}"
        )


# ---------------------------------------------------------------------------
# Strategy for generating MatchedTerm instances (Property 8)
# ---------------------------------------------------------------------------


@st.composite
def _matched_term_with_definitions(draw):
    """Generate a random MatchedTerm with 1-5 definitions, each with sources."""
    short_name = draw(_hyphenated_short_name)
    human_name = to_human_readable(short_name)
    num_defs = draw(st.integers(min_value=1, max_value=5))
    definitions = draw(st.lists(_definition_entry, min_size=num_defs, max_size=num_defs))
    link = draw(
        st.from_regex(
            r"https://csrc\.nist\.gov/glossary/term/[a-z_]{1,20}", fullmatch=True
        )
    )
    return MatchedTerm(
        short_name=short_name,
        human_name=human_name,
        definitions=definitions,
        link=link,
        abbr_syn=None,
    )


# ---------------------------------------------------------------------------
# Property 8: Matched Term Rendering Completeness
# ---------------------------------------------------------------------------


class TestProperty8MatchedTermRenderingCompleteness:
    """
    Feature: oscal-glossary-generator, Property 8: Matched Term Rendering Completeness

    **Validates: Requirements 4.4, 4.5**
    """

    @settings(max_examples=100, deadline=None)
    @given(term=_matched_term_with_definitions())
    def test_rendering_completeness(self, term, tmp_path_factory):
        """Feature: oscal-glossary-generator, Property 8: Matched Term Rendering Completeness"""
        tmp_path = tmp_path_factory.mktemp("render_complete")
        output_path = tmp_path / "glossary.md"

        generate_markdown([term], [], output_path)

        content = output_path.read_text(encoding="utf-8")

        # 1. Human name appears as a level-2 heading
        assert f"## {term.human_name}" in content, (
            f"Expected level-2 heading '## {term.human_name}' in output"
        )

        # 2. There are N numbered definitions (1. , 2. , etc.)
        num_defs = len(term.definitions)
        for i in range(1, num_defs + 1):
            assert f"{i}. " in content, (
                f"Expected numbered definition '{i}. ' in output"
            )

        # 3. Source references appear as *Source: [text](link)*
        for defn in term.definitions:
            for source in defn.get("sources", []):
                src_text = source.get("text", "")
                src_link = source.get("link", "")
                if src_text and src_link:
                    expected_source = f"*Source: [{src_text}]({src_link})*"
                    assert expected_source in content, (
                        f"Expected source reference '{expected_source}' in output"
                    )

        # 4. CSRC link appears as [CSRC Glossary: human_name](link)
        expected_csrc = f"[CSRC Glossary: {term.human_name}]({term.link})"
        assert expected_csrc in content, (
            f"Expected CSRC link '{expected_csrc}' in output"
        )


# ---------------------------------------------------------------------------
# Strategies for abbreviation/synonym entries (Property 9)
# ---------------------------------------------------------------------------

_abbr_syn_entry = st.fixed_dictionaries(
    {
        "text": st.text(
            min_size=1,
            max_size=20,
            alphabet=st.characters(whitelist_categories=("L", "N", "Z")),
        ).filter(lambda s: s.strip()),
    }
)


@st.composite
def _matched_term_with_abbr_syn(draw):
    """Generate a MatchedTerm with a non-empty abbrSyn list."""
    short_name = draw(_hyphenated_short_name)
    abbr_syn = draw(st.lists(_abbr_syn_entry, min_size=1, max_size=5))
    definitions = draw(st.lists(_definition_entry, min_size=1, max_size=3))
    link = draw(
        st.from_regex(
            r"https://csrc\.nist\.gov/glossary/term/[a-z_]{1,20}", fullmatch=True
        )
    )
    return MatchedTerm(
        short_name=short_name,
        human_name=to_human_readable(short_name),
        definitions=definitions,
        link=link,
        abbr_syn=abbr_syn,
    )


@st.composite
def _matched_term_without_abbr_syn(draw):
    """Generate a MatchedTerm with None or empty abbrSyn."""
    short_name = draw(_hyphenated_short_name)
    abbr_syn = draw(st.sampled_from([None, []]))
    definitions = draw(st.lists(_definition_entry, min_size=1, max_size=3))
    link = draw(
        st.from_regex(
            r"https://csrc\.nist\.gov/glossary/term/[a-z_]{1,20}", fullmatch=True
        )
    )
    return MatchedTerm(
        short_name=short_name,
        human_name=to_human_readable(short_name),
        definitions=definitions,
        link=link,
        abbr_syn=abbr_syn,
    )


# ---------------------------------------------------------------------------
# Property 9: Abbreviation/Synonym Rendering
# ---------------------------------------------------------------------------


class TestProperty9AbbreviationSynonymRendering:
    """
    Feature: oscal-glossary-generator, Property 9: Abbreviation/Synonym Rendering

    **Validates: Requirements 4.6**
    """

    @settings(max_examples=100, deadline=None)
    @given(term=_matched_term_with_abbr_syn())
    def test_also_known_as_present_when_abbr_syn_non_empty(
        self, term, tmp_path_factory
    ):
        """Feature: oscal-glossary-generator, Property 9: Abbreviation/Synonym Rendering"""
        tmp_dir = tmp_path_factory.mktemp("abbr_present")
        output_path = tmp_dir / "glossary.md"

        generate_markdown([term], [], output_path)
        content = output_path.read_text(encoding="utf-8")

        # The "Also known as:" line must appear
        assert "**Also known as:**" in content

        # All abbreviation/synonym text values must appear comma-separated
        expected_texts = [a["text"] for a in term.abbr_syn if a.get("text")]
        expected_line = f"**Also known as:** {', '.join(expected_texts)}"
        assert expected_line in content

        # "Also known as:" must appear BEFORE the first numbered definition
        aka_pos = content.index("**Also known as:**")
        first_def_match = re.search(r"^1\. ", content, re.MULTILINE)
        assert first_def_match is not None, "Expected numbered definition '1. ' in output"
        assert aka_pos < first_def_match.start(), (
            "Also known as: line must appear before the first numbered definition"
        )

    @settings(max_examples=100, deadline=None)
    @given(term=_matched_term_without_abbr_syn())
    def test_also_known_as_absent_when_abbr_syn_empty_or_none(
        self, term, tmp_path_factory
    ):
        """Feature: oscal-glossary-generator, Property 9: Abbreviation/Synonym Rendering"""
        tmp_dir = tmp_path_factory.mktemp("abbr_absent")
        output_path = tmp_dir / "glossary.md"

        generate_markdown([term], [], output_path)
        content = output_path.read_text(encoding="utf-8")

        # The "Also known as:" line must NOT appear
        assert "**Also known as:**" not in content


# ---------------------------------------------------------------------------
# Property 10: Glossary Entry Completeness Invariant
# ---------------------------------------------------------------------------


class TestProperty10GlossaryEntryCompletenessInvariant:
    """
    Feature: oscal-glossary-generator, Property 10: Glossary Entry Completeness Invariant

    **Validates: Requirements 6.1, 6.2**
    """

    @settings(max_examples=100, deadline=None)
    @given(
        object_keys=st.lists(
            definition_key(), min_size=1, max_size=10, unique=True
        ),
        scalar_keys=st.lists(
            definition_key(), min_size=0, max_size=5, unique=True
        ),
        data=st.data(),
    )
    def test_completeness_invariant(
        self, object_keys, scalar_keys, data, tmp_path_factory
    ):
        """Feature: oscal-glossary-generator, Property 10: Glossary Entry Completeness Invariant"""
        tmp_dir = tmp_path_factory.mktemp("completeness")

        # --- Build a schema with a mix of object and scalar definitions ---
        definitions: dict = {}
        for key in object_keys:
            definitions[key] = data.draw(object_type_entry)
        for key in scalar_keys:
            # Ensure scalar keys don't collide with object keys
            if key not in definitions:
                definitions[key] = data.draw(scalar_type_entry())

        schema_path = tmp_dir / "schema.json"
        schema_path.write_text(
            json.dumps({"definitions": definitions}), encoding="utf-8"
        )

        # --- Parse schema to get deduplicated Object_Type short names ---
        short_names = parse_schema(schema_path)

        # --- Build a glossary where some short names match and some don't ---
        glossary: dict[str, dict] = {}
        for sn in short_names:
            lookup_key = sn.replace("-", " ").lower()
            choice = data.draw(
                st.sampled_from(["with_defs", "without_defs", "no_match"])
            )
            if choice == "with_defs":
                entry = data.draw(_glossary_entry_with_definitions())
                entry["term"] = lookup_key
                glossary[lookup_key] = entry
            elif choice == "without_defs":
                entry = data.draw(_glossary_entry_without_definitions())
                entry["term"] = lookup_key
                glossary[lookup_key] = entry
            # "no_match" → no glossary entry for this short name

        # --- Run match_terms ---
        matched, unmatched = match_terms(short_names, glossary)

        # --- Run generate_markdown ---
        output_path = tmp_dir / "glossary.md"
        generate_markdown(matched, unmatched, output_path)
        content = output_path.read_text(encoding="utf-8")

        # --- Verify: matched + unmatched == total deduplicated Object_Types ---
        total_object_types = len(short_names)
        assert len(matched) + len(unmatched) == total_object_types, (
            f"matched ({len(matched)}) + unmatched ({len(unmatched)}) "
            f"!= total Object_Types ({total_object_types})"
        )

        # --- Verify: every Object_Type short name appears exactly once ---
        # Extract matched headings (level-2 headings excluding "Unmatched Terms")
        all_headings = re.findall(r"^## (.+)$", content, re.MULTILINE)
        matched_headings = [h for h in all_headings if h != "Unmatched Terms"]

        # Extract unmatched bullet items
        unmatched_bullets = re.findall(r"^- (.+)$", content, re.MULTILINE)

        # Build set of all human-readable names that appear in the output
        output_names = set(matched_headings) | set(unmatched_bullets)

        # Build expected set of human-readable names from short_names
        expected_names = {to_human_readable(sn) for sn in short_names}

        assert output_names == expected_names, (
            f"Output names {output_names} != expected names {expected_names}"
        )

        # Verify each name appears exactly once across both sections
        all_output_names = matched_headings + unmatched_bullets
        assert len(all_output_names) == len(set(all_output_names)), (
            "Some Object_Type names appear more than once in the output"
        )
        assert len(all_output_names) == total_object_types, (
            f"Total entries in output ({len(all_output_names)}) "
            f"!= total Object_Types ({total_object_types})"
        )


# ---------------------------------------------------------------------------
# Property 12: Deterministic Output
# ---------------------------------------------------------------------------


class TestProperty12DeterministicOutput:
    """
    Feature: oscal-glossary-generator, Property 12: Deterministic Output

    **Validates: Requirements 6.5**
    """

    @settings(max_examples=100, deadline=None)
    @given(
        terms=st.lists(
            _matched_term_with_definitions(),
            min_size=0,
            max_size=10,
            unique_by=lambda t: t.short_name,
        ),
        unmatched=st.lists(
            _hyphenated_short_name,
            min_size=0,
            max_size=10,
            unique=True,
        ),
    )
    def test_deterministic_output(self, terms, unmatched, tmp_path_factory):
        """Feature: oscal-glossary-generator, Property 12: Deterministic Output"""
        tmp_dir = tmp_path_factory.mktemp("deterministic")
        output_a = tmp_dir / "glossary_a.md"
        output_b = tmp_dir / "glossary_b.md"

        # Run generate_markdown twice with the same inputs
        generate_markdown(terms, unmatched, output_a)
        generate_markdown(terms, unmatched, output_b)

        content_a = output_a.read_text(encoding="utf-8")
        content_b = output_b.read_text(encoding="utf-8")

        # Strip the timestamp line from both outputs
        stripped_a = re.sub(
            r"^\*Generated: .*Z\*$", "", content_a, flags=re.MULTILINE
        )
        stripped_b = re.sub(
            r"^\*Generated: .*Z\*$", "", content_b, flags=re.MULTILINE
        )

        assert stripped_a == stripped_b, (
            "Output is not deterministic: content differs after excluding timestamp"
        )


# ---------------------------------------------------------------------------
# Strategies for definition fidelity (Property 11)
# ---------------------------------------------------------------------------

# Characters that are "special" in HTML / markdown contexts
_special_chars = st.sampled_from(
    ['"', "'", "&", "<", ">", "©", "®", "—", "–", "…", "•", "§", "¶", "½"]
)

# Strategy for definition text that includes special characters
_fidelity_text = st.builds(
    lambda parts: "".join(parts),
    st.lists(
        st.one_of(
            st.text(
                min_size=1,
                max_size=15,
                alphabet=st.characters(whitelist_categories=("L", "N", "Z")),
            ),
            _special_chars,
        ),
        min_size=2,
        max_size=10,
    ),
).filter(lambda s: len(s.strip()) >= 3)

# Strategy for a definition entry with special-character-rich text and sources
_fidelity_definition_entry = st.fixed_dictionaries(
    {
        "text": _fidelity_text,
        "sources": st.lists(
            st.fixed_dictionaries(
                {
                    "text": st.text(
                        min_size=1,
                        max_size=30,
                        alphabet=st.characters(whitelist_categories=("L", "N", "Z")),
                    ),
                    "link": st.from_regex(
                        r"https://doi\.org/10\.[0-9]{4}/[a-zA-Z0-9\.]{1,20}",
                        fullmatch=True,
                    ),
                }
            ),
            min_size=1,
            max_size=3,
        ),
    }
)


@st.composite
def _matched_term_for_fidelity(draw):
    """Generate a MatchedTerm with special-character-rich definitions for fidelity checks."""
    short_name = draw(_hyphenated_short_name)
    human_name = to_human_readable(short_name)
    definitions = draw(
        st.lists(_fidelity_definition_entry, min_size=1, max_size=4)
    )
    link = draw(
        st.from_regex(
            r"https://csrc\.nist\.gov/glossary/term/[a-z_]{1,20}", fullmatch=True
        )
    )
    abbr_syn = None
    if draw(st.booleans()):
        abbr_syn = [
            {"text": draw(st.from_regex(r"[A-Z]{2,5}", fullmatch=True))}
        ]
    return MatchedTerm(
        short_name=short_name,
        human_name=human_name,
        definitions=definitions,
        link=link,
        abbr_syn=abbr_syn,
    )


# ---------------------------------------------------------------------------
# Property 11: Definition and Link Fidelity
# ---------------------------------------------------------------------------


class TestProperty11DefinitionAndLinkFidelity:
    """
    Feature: oscal-glossary-generator, Property 11: Definition and Link Fidelity

    **Validates: Requirements 6.3, 6.4**
    """

    @settings(max_examples=100, deadline=None)
    @given(term=_matched_term_for_fidelity())
    def test_definition_text_reproduced_verbatim(self, term, tmp_path_factory):
        """Feature: oscal-glossary-generator, Property 11: Definition and Link Fidelity"""
        tmp_dir = tmp_path_factory.mktemp("def_fidelity")
        output_path = tmp_dir / "glossary.md"

        generate_markdown([term], [], output_path)
        content = output_path.read_text(encoding="utf-8")

        # Each definition text must appear character-for-character in the output
        for defn in term.definitions:
            text = defn["text"]
            assert text in content, (
                f"Definition text not found verbatim in output.\n"
                f"Expected: {text!r}\n"
                f"Output excerpt (first 500 chars): {content[:500]!r}"
            )

    @settings(max_examples=100, deadline=None)
    @given(term=_matched_term_for_fidelity())
    def test_csrc_link_reproduced_exactly(self, term, tmp_path_factory):
        """Feature: oscal-glossary-generator, Property 11: Definition and Link Fidelity"""
        tmp_dir = tmp_path_factory.mktemp("link_fidelity")
        output_path = tmp_dir / "glossary.md"

        generate_markdown([term], [], output_path)
        content = output_path.read_text(encoding="utf-8")

        # The CSRC link must appear exactly as the link field value
        expected_csrc = f"[CSRC Glossary: {term.human_name}]({term.link})"
        assert expected_csrc in content, (
            f"CSRC link not found in output.\n"
            f"Expected: {expected_csrc!r}"
        )

    @settings(max_examples=100, deadline=None)
    @given(term=_matched_term_for_fidelity())
    def test_source_references_reproduced_exactly(self, term, tmp_path_factory):
        """Feature: oscal-glossary-generator, Property 11: Definition and Link Fidelity"""
        tmp_dir = tmp_path_factory.mktemp("src_fidelity")
        output_path = tmp_dir / "glossary.md"

        generate_markdown([term], [], output_path)
        content = output_path.read_text(encoding="utf-8")

        # Each source reference text and link must appear exactly in the output
        for defn in term.definitions:
            for source in defn.get("sources", []):
                src_text = source["text"]
                src_link = source["link"]
                expected_source = f"*Source: [{src_text}]({src_link})*"
                assert expected_source in content, (
                    f"Source reference not found in output.\n"
                    f"Expected: {expected_source!r}"
                )
