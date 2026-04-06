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
assert _spec is not None, "Could not find generate_oscal_glossary.py"
_mod = importlib.util.module_from_spec(_spec)
_mod.__name__ = "generate_oscal_glossary"
sys.modules["generate_oscal_glossary"] = _mod
assert _spec.loader is not None, "Module spec has no loader"
_spec.loader.exec_module(_mod)

parse_schema = _mod.parse_schema
_is_object_type = _mod._is_object_type  # noqa: SLF001
match_terms = _mod.match_terms
MatchedTerm = _mod.MatchedTerm
load_glossary = _mod.load_glossary
generate_markdown = _mod.generate_markdown
to_human_readable = _mod.to_human_readable
extract_terms = _mod.extract_terms
read_terms = _mod.read_terms
parse_oscal_terms_page = _mod.parse_oscal_terms_page


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
        short_names=st.lists(
            _hyphenated_short_name, min_size=1, max_size=10, unique=True
        ),
        data=st.data(),
    )
    def test_completeness_invariant(
        self, short_names, data, tmp_path_factory
    ):
        """Feature: oscal-glossary-generator, Property 10: Glossary Entry Completeness Invariant"""
        tmp_dir = tmp_path_factory.mktemp("completeness")

        # --- Write short names to a Term_List_File via extract_terms ---
        terms_path = tmp_dir / "oscal-terms.txt"
        extract_terms(short_names, terms_path)

        # --- Read them back with read_terms ---
        read_back = read_terms(terms_path)

        # --- Build a glossary where some short names match and some don't ---
        glossary: dict[str, dict] = {}
        for sn in read_back:
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
        matched, unmatched = match_terms(read_back, glossary)

        # --- Run generate_markdown ---
        output_path = tmp_dir / "glossary.md"
        generate_markdown(matched, unmatched, output_path)
        content = output_path.read_text(encoding="utf-8")

        # --- Verify: matched + unmatched == total input terms ---
        total_terms = len(read_back)
        assert len(matched) + len(unmatched) == total_terms, (
            f"matched ({len(matched)}) + unmatched ({len(unmatched)}) "
            f"!= total terms ({total_terms})"
        )

        # --- Verify: every term appears exactly once ---
        # Extract matched headings (level-2 headings excluding "Unmatched Terms")
        all_headings = re.findall(r"^## (.+)$", content, re.MULTILINE)
        matched_headings = [h for h in all_headings if h != "Unmatched Terms"]

        # Extract unmatched bullet items
        unmatched_bullets = re.findall(r"^- (.+)$", content, re.MULTILINE)

        # Build set of all human-readable names that appear in the output
        output_names = set(matched_headings) | set(unmatched_bullets)

        # Build expected set of human-readable names from read_back terms
        expected_names = {to_human_readable(sn) for sn in read_back}

        assert output_names == expected_names, (
            f"Output names {output_names} != expected names {expected_names}"
        )

        # Verify each name appears exactly once across both sections
        all_output_names = matched_headings + unmatched_bullets
        assert len(all_output_names) == len(set(all_output_names)), (
            "Some term names appear more than once in the output"
        )
        assert len(all_output_names) == total_terms, (
            f"Total entries in output ({len(all_output_names)}) "
            f"!= total terms ({total_terms})"
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

# ---------------------------------------------------------------------------
# Property 13: Term List File Round Trip
# ---------------------------------------------------------------------------


class TestProperty13TermListFileRoundTrip:
    """
    Feature: oscal-glossary-generator, Property 13: Term List File Round Trip

    **Validates: Requirements 10.5**

    For any sorted, deduplicated list of valid short names, writing them
    with extract_terms() and then reading them back with read_terms()
    SHALL produce an identical list with no terms lost or added.
    """

    @settings(max_examples=100, deadline=None)
    @given(
        short_names=st.lists(
            _hyphenated_short_name, min_size=1, max_size=20, unique=True
        ),
    )
    def test_round_trip_preserves_terms(self, short_names, tmp_path_factory):
        """Feature: oscal-glossary-generator, Property 13: Term List File Round Trip"""
        tmp_dir = tmp_path_factory.mktemp("round_trip")
        terms_path = tmp_dir / "oscal-terms.txt"

        # extract_terms sorts the names internally, so compute expected
        expected = sorted(short_names)

        # Write with extract_terms
        extract_terms(short_names, terms_path)

        # Read back with read_terms
        result = read_terms(terms_path)

        # The round-tripped list must be identical
        assert result == expected, (
            f"Round-trip mismatch:\n"
            f"  Written (sorted): {expected}\n"
            f"  Read back:        {result}"
        )


# ---------------------------------------------------------------------------
# Property 14: Term List Reading Correctness
# ---------------------------------------------------------------------------

# Strategy for generating a valid term (hyphenated short name)
_valid_term = st.from_regex(r"[a-zA-Z][a-zA-Z0-9\-]{0,30}", fullmatch=True)

# Strategy for generating a comment line (starts with #)
_comment_line = st.from_regex(r"#[a-zA-Z0-9 \-]{0,50}", fullmatch=True)

# Strategy for generating a blank line (only whitespace)
_blank_line = st.from_regex(r"[ \t]{0,10}", fullmatch=True)


@st.composite
def _term_list_file_content(draw):
    """Generate random term list file content mixing valid terms, comments,
    blank lines, and duplicate terms.

    Returns a tuple of (file_content_string, expected_terms_in_order).
    The expected terms list reflects deduplication by first occurrence
    (case-sensitive) and whitespace stripping.
    """
    # Generate some unique valid terms (at least 1)
    valid_terms = draw(
        st.lists(_valid_term, min_size=1, max_size=15, unique=True)
    )

    # Decide how many lines to generate: all valid terms + extras
    num_comments = draw(st.integers(min_value=0, max_value=5))
    num_blanks = draw(st.integers(min_value=0, max_value=5))
    num_dupes = draw(
        st.integers(min_value=0, max_value=min(5, len(valid_terms)))
    )

    # Build a list of tagged line items, then shuffle them
    line_items: list[tuple[str, str | None]] = []
    #   ("term", term_value)  — a valid term line
    #   ("comment", None)     — a comment line
    #   ("blank", None)       — a blank line
    #   ("dupe", term_value)  — a duplicate of an existing term

    for term in valid_terms:
        line_items.append(("term", term))

    for _ in range(num_dupes):
        dupe = draw(st.sampled_from(valid_terms))
        line_items.append(("dupe", dupe))

    for _ in range(num_comments):
        line_items.append(("comment", None))

    for _ in range(num_blanks):
        line_items.append(("blank", None))

    # Shuffle the items to get a random ordering
    shuffled = draw(st.permutations(line_items))

    # Now build the actual file lines and compute expected output
    lines: list[str] = []
    expected_order: list[str] = []
    seen: set[str] = set()

    for kind, value in shuffled:
        if kind in ("term", "dupe"):
            padding_left = draw(
                st.from_regex(r"[ \t]{0,3}", fullmatch=True)
            )
            padding_right = draw(
                st.from_regex(r"[ \t]{0,3}", fullmatch=True)
            )
            lines.append(f"{padding_left}{value}{padding_right}")
            if value not in seen:
                seen.add(value)
                expected_order.append(value)
        elif kind == "comment":
            comment = draw(_comment_line)
            lines.append(comment)
        else:  # blank
            blank = draw(_blank_line)
            lines.append(blank)

    content = "\n".join(lines)
    return content, expected_order


class TestProperty14TermListReadingCorrectness:
    """Property 14: Term List Reading Correctness

    **Validates: Requirements 8.2, 8.3, 8.4**

    For any Term_List_File containing a mix of valid term lines, comment
    lines (starting with #), blank lines, and duplicate terms,
    read_terms() SHALL return only the valid terms (skipping comments and
    blanks), deduplicated by first occurrence, with leading and trailing
    whitespace stripped from each term.
    """

    @given(data=_term_list_file_content())
    @settings(max_examples=100, deadline=None)
    def test_property_14_term_list_reading_correctness(self, data):
        content, expected_terms = data

        with tempfile.TemporaryDirectory() as tmp_dir:
            terms_path = Path(tmp_dir) / "terms.txt"
            terms_path.write_text(content, encoding="utf-8")

            result = read_terms(terms_path)

            # 1. Only valid terms returned (no comments, no blanks)
            for term in result:
                assert term.strip() == term, (
                    f"Term not stripped: {term!r}"
                )
                assert term != "", "Empty string in result"
                assert not term.startswith("#"), (
                    f"Comment line leaked through: {term!r}"
                )

            # 2. Duplicates removed — result has unique entries
            assert len(result) == len(set(result)), (
                "Duplicate terms found in result"
            )

            # 3. First occurrence kept — order matches expected
            assert result == expected_terms, (
                f"Expected {expected_terms!r}, got {result!r}"
            )

            # 4. Count matches expected deduplicated count
            assert len(result) == len(expected_terms), (
                f"Expected {len(expected_terms)} terms, got {len(result)}"
            )


# ---------------------------------------------------------------------------
# Strategies for Hugo-format markdown files (Property 15)
# ---------------------------------------------------------------------------

# Strategy for a heading text (letters, digits, spaces — no '#' or newlines)
# We strip to match the parser's behavior of stripping heading text.
_heading_text = st.text(
    alphabet=st.characters(
        whitelist_categories=("L", "N"),
        whitelist_characters=" -",
        max_codepoint=127,
    ),
    min_size=1,
    max_size=30,
).map(lambda s: s.strip()).filter(lambda s: s and not s.startswith("#"))

# Strategy for a prose paragraph line
_prose_line = st.text(
    alphabet=st.characters(
        whitelist_categories=("L", "N", "Z", "P"),
        max_codepoint=127,
    ),
    min_size=1,
    max_size=60,
).filter(lambda s: s.strip() and not s.startswith("#") and "---" not in s)

# Strategy for YAML front matter content (simple key: value lines)
_yaml_line = st.from_regex(r"[a-z]{1,10}: [a-zA-Z0-9 ]{1,20}", fullmatch=True)


@st.composite
def _hugo_markdown_with_headings(draw):
    """Generate a random Hugo-format markdown file with front matter,
    ## section headings, ### term headings, and #### sub-section headings.

    Returns a tuple of (file_content, set_of_h3_heading_texts_lowercase,
    set_of_h4_heading_texts_lowercase).
    """
    lines: list[str] = []

    # --- Hugo front matter ---
    lines.append("---")
    num_yaml = draw(st.integers(min_value=1, max_value=3))
    for _ in range(num_yaml):
        lines.append(draw(_yaml_line))
    lines.append("---")
    lines.append("")

    # Optional intro prose before any heading
    if draw(st.booleans()):
        lines.append(draw(_prose_line))
        lines.append("")

    # Generate sections with ### terms and #### sub-sections
    h3_headings: list[str] = []
    h4_headings: list[str] = []

    num_sections = draw(st.integers(min_value=1, max_value=4))
    for _ in range(num_sections):
        # ## section heading (section boundary, not a term)
        section_text = draw(_heading_text)
        lines.append(f"## {section_text}")
        lines.append("")

        # Optional prose after section heading
        if draw(st.booleans()):
            lines.append(draw(_prose_line))
            lines.append("")

        # ### term headings within this section
        num_terms = draw(st.integers(min_value=0, max_value=3))
        for _ in range(num_terms):
            term_text = draw(_heading_text)
            h3_headings.append(term_text)
            lines.append(f"### {term_text}")
            lines.append("")

            # Prose paragraphs after the term heading
            num_prose = draw(st.integers(min_value=0, max_value=2))
            for _ in range(num_prose):
                lines.append(draw(_prose_line))
                lines.append("")

            # #### sub-section headings within this term
            num_subsections = draw(st.integers(min_value=0, max_value=2))
            for _ in range(num_subsections):
                sub_text = draw(_heading_text)
                h4_headings.append(sub_text)
                lines.append(f"#### {sub_text}")
                lines.append("")

                # Prose after sub-section heading
                if draw(st.booleans()):
                    lines.append(draw(_prose_line))
                    lines.append("")

    content = "\n".join(lines)

    # Compute expected keys: lowercase of each ### heading
    # (heading text is already stripped by the strategy)
    expected_h3_keys = {h.lower() for h in h3_headings}
    h4_keys = {h.lower() for h in h4_headings}

    return content, expected_h3_keys, h4_keys


# ---------------------------------------------------------------------------
# Property 15: OSCAL Page Term Extraction
# ---------------------------------------------------------------------------


class TestProperty15OscalPageTermExtraction:
    """
    Feature: oscal-glossary-generator, Property 15: OSCAL Page Term Extraction

    **Validates: Requirements 11.3, 11.4, 11.8**
    """

    @settings(max_examples=100, deadline=None)
    @given(data=_hugo_markdown_with_headings())
    def test_property_15_oscal_page_term_extraction(self, data):
        """Feature: oscal-glossary-generator, Property 15: OSCAL Page Term Extraction"""
        content, expected_h3_keys, h4_keys = data

        with tempfile.TemporaryDirectory() as tmp_dir:
            page_path = Path(tmp_dir) / "_index.md"
            page_path.write_text(content, encoding="utf-8")

            result = parse_oscal_terms_page(page_path)

            # 1. All keys are lowercase
            for key in result:
                assert key == key.lower(), (
                    f"Key {key!r} is not lowercase"
                )

            # 2. Returned dict keys are exactly the lowercase text
            #    of each ### heading
            assert set(result.keys()) == expected_h3_keys, (
                f"Keys mismatch.\n"
                f"  Expected (from ### headings): {expected_h3_keys}\n"
                f"  Got: {set(result.keys())}"
            )

            # 3. #### headings do NOT appear as top-level keys
            #    (unless they happen to share text with a ### heading)
            h4_only_keys = h4_keys - expected_h3_keys
            for h4_key in h4_only_keys:
                assert h4_key not in result, (
                    f"#### heading {h4_key!r} should not be a top-level key"
                )


# ---------------------------------------------------------------------------
# Strategies for Hugo-format markdown (Property 16)
# ---------------------------------------------------------------------------

# Strategy for a simple term heading name (letters only, no special chars)
_heading_name = st.from_regex(r"[A-Z][a-z]{2,12}", fullmatch=True)

# Strategy for a unique marker string (used to verify inclusion/exclusion)
_marker = st.from_regex(r"MARKER_[a-z]{4,8}_[0-9]{3}", fullmatch=True)


@st.composite
def _hugo_page_with_prose_callout_todo(draw):
    """Generate a Hugo-format markdown page with front matter, ### headings,
    prose paragraphs, callout blocks, and todo blocks.

    Returns a tuple of:
      (file_content, expected_term_names, prose_markers, callout_markers,
       todo_markers, front_matter_marker)

    - prose_markers: list of (term_name, marker) tuples for prose content
    - callout_markers: list of (term_name, marker) tuples for callout content
    - todo_markers: list of markers that should be EXCLUDED from definitions
    - front_matter_marker: a marker in front matter that should be EXCLUDED

    All markers are guaranteed to be unique across the entire page so that
    inclusion/exclusion checks are unambiguous.
    """
    # Generate 1-5 unique term heading names
    num_terms = draw(st.integers(min_value=1, max_value=5))
    term_names = draw(
        st.lists(
            _heading_name,
            min_size=num_terms,
            max_size=num_terms,
            unique=True,
        )
    )

    # Pre-generate all markers we'll need, ensuring global uniqueness.
    # Worst case: 1 front matter + N prose + N callout + N todo = 1 + 3*N
    max_markers = 1 + 3 * num_terms
    all_markers = draw(
        st.lists(
            _marker, min_size=max_markers, max_size=max_markers, unique=True
        )
    )
    marker_iter = iter(all_markers)

    # Front matter with a unique marker
    front_matter_marker = next(marker_iter)
    lines = [
        "---",
        f"title: {front_matter_marker}",
        "date: 2024-01-15",
        "weight: 10",
        "---",
        "",
    ]

    prose_markers: list[tuple[str, str]] = []
    callout_markers: list[tuple[str, str]] = []
    todo_markers: list[str] = []

    for term_name in term_names:
        # Write the ### heading
        lines.append(f"### {term_name}")
        lines.append("")

        # Always add a prose paragraph with a unique marker
        prose_marker = next(marker_iter)
        prose_markers.append((term_name, prose_marker))
        lines.append(f"This is the definition of {term_name}. {prose_marker}")
        lines.append("")

        # Optionally add a callout block
        if draw(st.booleans()):
            callout_marker = next(marker_iter)
            callout_markers.append((term_name, callout_marker))
            # Choose between percent and angle-bracket variant
            if draw(st.booleans()):
                lines.append("{{% callout %}}")
                lines.append(f"Callout content for {term_name}. {callout_marker}")
                lines.append("{{% /callout %}}")
            else:
                lines.append("{{<callout>}}")
                lines.append(f"Callout content for {term_name}. {callout_marker}")
                lines.append("{{</callout>}}")
            lines.append("")

        # Optionally add a todo block
        if draw(st.booleans()):
            todo_marker = next(marker_iter)
            todo_markers.append(todo_marker)
            lines.append("{{<todo>}}")
            lines.append(f"TODO placeholder content. {todo_marker}")
            lines.append("{{</todo>}}")
            lines.append("")

    content = "\n".join(lines)
    return (
        content,
        term_names,
        prose_markers,
        callout_markers,
        todo_markers,
        front_matter_marker,
    )


# ---------------------------------------------------------------------------
# Property 16: OSCAL Page Definition Assembly
# ---------------------------------------------------------------------------


class TestProperty16OSCALPageDefinitionAssembly:
    """
    Feature: oscal-glossary-generator, Property 16: OSCAL Page Definition Assembly

    **Validates: Requirements 11.2, 11.5, 11.6, 11.7**
    """

    @settings(max_examples=100, deadline=None)
    @given(data=_hugo_page_with_prose_callout_todo())
    def test_property_16_definition_assembly(self, data):
        """Feature: oscal-glossary-generator, Property 16: OSCAL Page Definition Assembly"""
        (
            content,
            term_names,
            prose_markers,
            callout_markers,
            todo_markers,
            front_matter_marker,
        ) = data

        with tempfile.TemporaryDirectory() as tmp_dir:
            page_path = Path(tmp_dir) / "terminology.md"
            page_path.write_text(content, encoding="utf-8")

            result = parse_oscal_terms_page(page_path)

            # 1. Prose paragraph content is included in definitions
            for term_name, marker in prose_markers:
                key = term_name.lower()
                assert key in result, (
                    f"Term '{term_name}' not found in parsed result"
                )
                assert marker in result[key], (
                    f"Prose marker '{marker}' not found in definition "
                    f"for term '{term_name}'"
                )

            # 2. Callout content is included in definitions (delimiters stripped)
            for term_name, marker in callout_markers:
                key = term_name.lower()
                assert key in result, (
                    f"Term '{term_name}' not found in parsed result"
                )
                assert marker in result[key], (
                    f"Callout marker '{marker}' not found in definition "
                    f"for term '{term_name}'"
                )

            # 3. Callout delimiters are stripped from definitions
            all_definitions = "\n".join(result.values())
            for delimiter in (
                "{{% callout %}}",
                "{{% /callout %}}",
                "{{<callout>}}",
                "{{</callout>}}",
            ):
                assert delimiter not in all_definitions, (
                    f"Callout delimiter '{delimiter}' found in definitions"
                )

            # 4. Todo content is excluded from definitions
            for marker in todo_markers:
                for key, definition in result.items():
                    assert marker not in definition, (
                        f"Todo marker '{marker}' found in definition "
                        f"for term '{key}'"
                    )

            # 5. Todo delimiters are excluded from definitions
            for delimiter in ("{{<todo>}}", "{{</todo>}}"):
                assert delimiter not in all_definitions, (
                    f"Todo delimiter '{delimiter}' found in definitions"
                )

            # 6. Front matter content is excluded from definitions
            for key, definition in result.items():
                assert front_matter_marker not in definition, (
                    f"Front matter marker '{front_matter_marker}' found "
                    f"in definition for term '{key}'"
                )


# ---------------------------------------------------------------------------
# Strategies for dual-source term matching (Property 17)
# ---------------------------------------------------------------------------

# Strategy for OSCAL short names (hyphenated lowercase strings)
_oscal_short_name = st.from_regex(
    r"[a-z][a-z]{0,7}(-[a-z]{1,6}){0,2}", fullmatch=True
)

# Strategy for OSCAL terms page definition text
_oscal_def_text = st.text(
    min_size=5,
    max_size=80,
    alphabet=st.characters(whitelist_categories=("L", "N", "Z", "P"), max_codepoint=127),
).filter(lambda s: len(s.strip()) >= 5)


@st.composite
def _dual_source_inputs(draw):
    """Generate random OSCAL short names with controlled overlap across
    OSCAL terms page and NIST glossary sources.

    Returns a tuple of:
      (short_names, oscal_terms_index, nist_glossary_index,
       expected_oscal_matched, expected_nist_matched, expected_unmatched)
    """
    # Generate a pool of unique short names
    short_names = draw(
        st.lists(_oscal_short_name, min_size=1, max_size=12, unique=True)
    )

    oscal_terms_index: dict[str, str] = {}
    nist_glossary_index: dict[str, dict] = {}
    expected_oscal_matched: set[str] = set()
    expected_nist_matched: set[str] = set()
    expected_unmatched: set[str] = set()

    for sn in short_names:
        lookup_key = sn.replace("-", " ").lower()

        # Decide which sources contain this term
        category = draw(
            st.sampled_from([
                "oscal_only",
                "nist_only_with_defs",
                "nist_only_empty_defs",
                "both_sources",
                "neither",
            ])
        )

        if category == "oscal_only":
            # Term in OSCAL page only → matched with source="OSCAL Page"
            oscal_terms_index[lookup_key] = draw(_oscal_def_text)
            expected_oscal_matched.add(sn)

        elif category == "nist_only_with_defs":
            # Term in NIST only with non-empty definitions → matched with source="NIST CSRC"
            nist_glossary_index[lookup_key] = {
                "term": lookup_key,
                "link": f"https://csrc.nist.gov/glossary/term/{sn}",
                "definitions": [{"text": f"NIST def for {sn}", "sources": []}],
                "abbrSyn": None,
            }
            expected_nist_matched.add(sn)

        elif category == "nist_only_empty_defs":
            # Term in NIST only with empty/null definitions → unmatched
            empty_defs = draw(st.sampled_from([None, []]))
            nist_glossary_index[lookup_key] = {
                "term": lookup_key,
                "link": f"https://csrc.nist.gov/glossary/term/{sn}",
                "definitions": empty_defs,
                "abbrSyn": None,
            }
            expected_unmatched.add(sn)

        elif category == "both_sources":
            # Term in both OSCAL page and NIST glossary → OSCAL page wins
            oscal_terms_index[lookup_key] = draw(_oscal_def_text)
            nist_glossary_index[lookup_key] = {
                "term": lookup_key,
                "link": f"https://csrc.nist.gov/glossary/term/{sn}",
                "definitions": [{"text": f"NIST def for {sn}", "sources": []}],
                "abbrSyn": None,
            }
            expected_oscal_matched.add(sn)

        else:
            # Neither source → unmatched
            expected_unmatched.add(sn)

    return (
        short_names,
        oscal_terms_index,
        nist_glossary_index,
        expected_oscal_matched,
        expected_nist_matched,
        expected_unmatched,
    )


# ---------------------------------------------------------------------------
# Property 17: Dual-Source Term Matching Priority
# ---------------------------------------------------------------------------


class TestProperty17DualSourceTermMatchingPriority:
    """
    Feature: oscal-glossary-generator, Property 17: Dual-Source Term Matching Priority

    **Validates: Requirements 3.2, 12.1, 12.3, 12.4, 13.1, 13.2, 13.3**
    """

    @settings(max_examples=100, deadline=None)
    @given(inputs=_dual_source_inputs())
    def test_property_17_dual_source_term_matching_priority(self, inputs):
        """Feature: oscal-glossary-generator, Property 17: Dual-Source Term Matching Priority"""
        (
            short_names,
            oscal_terms_index,
            nist_glossary_index,
            expected_oscal_matched,
            expected_nist_matched,
            expected_unmatched,
        ) = inputs

        matched, unmatched = match_terms(
            short_names, nist_glossary_index, oscal_terms_index
        )

        # --- Verify total count invariant ---
        assert len(matched) + len(unmatched) == len(short_names), (
            f"matched ({len(matched)}) + unmatched ({len(unmatched)}) "
            f"!= total ({len(short_names)})"
        )

        # --- Classify actual results by source ---
        actual_oscal_matched: set[str] = set()
        actual_nist_matched: set[str] = set()

        for m in matched:
            if m.source == "OSCAL Page":
                actual_oscal_matched.add(m.short_name)
            elif m.source == "NIST CSRC":
                actual_nist_matched.add(m.short_name)
            else:
                raise AssertionError(
                    f"Unexpected source '{m.source}' for term '{m.short_name}'"
                )

        actual_unmatched = set(unmatched)

        # --- Verify OSCAL page priority: terms in OSCAL page are matched
        #     with source="OSCAL Page" regardless of NIST presence ---
        assert actual_oscal_matched == expected_oscal_matched, (
            f"OSCAL-matched mismatch:\n"
            f"  Expected: {expected_oscal_matched}\n"
            f"  Actual:   {actual_oscal_matched}"
        )

        # --- Verify NIST fallback: terms only in NIST (with non-empty defs)
        #     are matched with source="NIST CSRC" ---
        assert actual_nist_matched == expected_nist_matched, (
            f"NIST-matched mismatch:\n"
            f"  Expected: {expected_nist_matched}\n"
            f"  Actual:   {actual_nist_matched}"
        )

        # --- Verify unmatched: terms in neither source (or NIST with
        #     empty definitions) are unmatched ---
        assert actual_unmatched == expected_unmatched, (
            f"Unmatched mismatch:\n"
            f"  Expected: {expected_unmatched}\n"
            f"  Actual:   {actual_unmatched}"
        )
