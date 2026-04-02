# Nested Catalog Controls Bugfix Design

## Overview

Any element with an ID present in an OSCAL document should be indexed such that a query for it returns the identified object. The `_extract_child_elements()` method in `OscalStore` fails to extract controls nested inside groups in OSCAL catalogs. It only iterates `parsed_model.controls` (top-level controls) and `parsed_model.groups` (top-level groups), but never recurses into `group.controls` or `group.groups`. Since many OSCAL catalogs (e.g., AWS Security Hub) organize all controls inside groups, this renders `list_catalog_controls()`, `text_search_oscal()`, and `get_child_element()` unable to find any controls. The fix adds a recursive helper that walks the group hierarchy and extracts controls at every nesting level, upholding the principle that any identified element is individually queryable.

## Glossary

- **Bug_Condition (C)**: A catalog contains controls nested inside groups (`catalog.groups[].controls[]`) or nested groups (`catalog.groups[].groups[].controls[]`, etc.)
- **Property (P)**: All controls at every nesting level within groups are extracted into `child_elements` and `fts_index`, making them individually queryable
- **Preservation**: Top-level controls, groups, and all non-catalog model type extraction must remain unchanged
- **`_extract_child_elements()`**: The method in `OscalStore` (`oscal_store.py` ~line 627) that extracts child element metadata from a parsed Trestle model for indexing into SQLite
- **`_ensure_indexed()`**: The method that calls `_extract_child_elements()` and persists results to `child_elements` and `fts_index` tables
- **F**: The original `_extract_child_elements()` before the fix
- **F'**: The fixed `_extract_child_elements()` after adding recursive group traversal

## Bug Details

### Bug Condition

The bug manifests when a catalog contains controls nested inside groups. The `_extract_child_elements()` CATALOG branch iterates `parsed_model.controls` and `parsed_model.groups` but never accesses `group.controls` or `group.groups`, so any control that is not a direct child of the catalog root is silently dropped.

**Formal Specification:**
```
FUNCTION isBugCondition(catalog)
  INPUT: catalog of type ParsedCatalogModel
  OUTPUT: boolean

  FOR EACH group IN catalog.groups DO
    IF group.controls IS NOT EMPTY THEN
      RETURN true
    END IF
    IF group.groups IS NOT EMPTY THEN
      RETURN true  // nested groups may contain controls
    END IF
  END FOR
  RETURN false
END FUNCTION
```

### Examples

- `get_child_element("CloudTrail.1")` → `None` (control is inside the "CloudTrail" group)
- `list_catalog_controls()` on AWS Security Hub catalog → 0 results (all controls are inside groups)
- `text_search_oscal("CloudTrail.1")` → empty (control was never indexed)
- `get_child_element("CloudTrail")` → returns the group correctly (groups themselves are extracted)
- A catalog with `groups[0].groups[0].controls[0]` (doubly nested) → that control is invisible

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- Top-level controls (`catalog.controls[]`) must continue to be extracted with `element_type="control"`
- Top-level groups (`catalog.groups[]`) must continue to be extracted with `element_type="group"`
- Component definitions, profiles, SSPs, assessment plans, assessment results, POA&Ms, and mappings must continue to use their existing extraction logic without any changes
- Pagination via `list_child_elements()` must continue to work correctly
- `get_child_element()` for non-existent IDs must continue to return `None`

**Scope:**
All inputs where `isBugCondition` returns false (catalogs with no groups, catalogs with groups that have no nested controls, and all non-catalog model types) must be completely unaffected by this fix.

## Hypothesized Root Cause

Based on code inspection of `_extract_child_elements()` (lines 668–680 of `oscal_store.py`), the root cause is confirmed:

1. **Missing group→control iteration**: The CATALOG branch iterates `parsed_model.groups` to extract groups but never accesses `group.controls` to extract controls within those groups.

2. **Missing recursive group traversal**: OSCAL groups can contain nested groups (`group.groups`). The current code does not recurse into nested groups at all, so controls at any depth beyond the top level are invisible.

3. **No schema or database changes needed**: The `child_elements` table already supports controls with `element_type="control"`. The issue is purely in the extraction logic.

## Correctness Properties

Property 1: Bug Condition - Nested Controls Are Extracted

_For any_ catalog where controls exist inside groups (at any nesting depth), the fixed `_extract_child_elements()` SHALL extract every such control into the `child_elements` list with `element_type="control"`, making them queryable via `list_catalog_controls()`, `text_search_oscal()`, and `get_child_element()`.

**Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5**

Property 2: Preservation - Non-Nested and Non-Catalog Behavior Unchanged

_For any_ catalog where controls are only at the top level (not inside groups), or for any non-catalog OSCAL model type, the fixed `_extract_child_elements()` SHALL produce the same result as the original function, preserving all existing extraction behavior.

**Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**

## Fix Implementation

### Changes Required

**File**: `src/mcp_server_for_oscal/tools/oscal_store.py`

**Function**: `_extract_child_elements()`

**Specific Changes**:

1. **Add a recursive helper** (e.g., `_extract_controls_from_groups`) that takes a list of groups and:
   - For each group, iterates `group.controls` and appends a child dict with `element_type="control"`
   - For each group, recurses into `group.groups` (if present) to handle arbitrary nesting depth

2. **Call the helper from the CATALOG branch** after the existing group extraction loop, passing `parsed_model.groups`

3. **No changes to group extraction**: Groups themselves are already extracted at the top level. The helper only extracts controls from within groups.

4. **No database schema changes**: The `child_elements` table already supports `element_type="control"`.

5. **No build script changes**: `bin/build_oscal_db.py` already calls `_ensure_indexed()` which calls `_extract_child_elements()`. After the code fix, rebuilding the database will automatically pick up nested controls.

## Testing Strategy

### Validation Approach

The testing strategy follows a two-phase approach: first, surface counterexamples that demonstrate the bug on unfixed code, then verify the fix works correctly and preserves existing behavior.

### Exploratory Bug Condition Checking

**Goal**: Surface counterexamples that demonstrate the bug BEFORE implementing the fix. Confirm the root cause.

**Test Plan**: Create a catalog with controls nested inside groups, run `_extract_child_elements()` on the UNFIXED code, and assert that nested controls appear in the result. The test will FAIL on unfixed code, confirming the bug.

**Test Cases**:
1. **Single-level nesting**: Catalog with `groups[0].controls[]` — controls should be extracted (will fail on unfixed code)
2. **Multi-level nesting**: Catalog with `groups[0].groups[0].controls[]` — deeply nested controls should be extracted (will fail on unfixed code)
3. **Mixed structure**: Catalog with both top-level controls and group-nested controls — all controls should appear (will fail on unfixed code for the nested ones)

**Expected Counterexamples**:
- `_extract_child_elements()` returns only top-level controls and groups, missing all group-nested controls
- `list_catalog_controls()` returns 0 when all controls are inside groups

### Fix Checking

**Goal**: Verify that for all inputs where the bug condition holds, the fixed function produces the expected behavior.

**Pseudocode:**
```
FOR ALL catalog WHERE isBugCondition(catalog) DO
  children := _extract_child_elements_fixed(CATALOG, catalog)
  all_nested_controls := recursively_collect_controls(catalog.groups)
  FOR EACH ctrl IN all_nested_controls DO
    ASSERT ctrl.id IN {c.uuid FOR c IN children WHERE c.element_type = "control"}
  END FOR
END FOR
```

### Preservation Checking

**Goal**: Verify that for all inputs where the bug condition does NOT hold, the fixed function produces the same result as the original function.

**Pseudocode:**
```
FOR ALL catalog WHERE NOT isBugCondition(catalog) DO
  ASSERT _extract_child_elements_original(CATALOG, catalog)
       = _extract_child_elements_fixed(CATALOG, catalog)
END FOR

FOR ALL (model_type, model) WHERE model_type != CATALOG DO
  ASSERT _extract_child_elements_original(model_type, model)
       = _extract_child_elements_fixed(model_type, model)
END FOR
```

**Testing Approach**: Property-based testing with Hypothesis is recommended for preservation checking because:
- It generates many catalog structures automatically (varying numbers of top-level controls, groups, nesting depths)
- It catches edge cases like empty groups, groups with no controls, etc.
- It provides strong guarantees that behavior is unchanged for all non-buggy inputs

**Test Plan**: Observe behavior on UNFIXED code for catalogs with only top-level controls and for non-catalog models, then write property-based tests capturing that behavior.

**Test Cases**:
1. **Top-level control preservation**: Catalogs with only top-level controls produce identical results before and after fix
2. **Group extraction preservation**: Groups themselves continue to be extracted correctly
3. **Non-catalog model preservation**: Component definitions, profiles, SSPs, etc. produce identical results
4. **Pagination preservation**: `list_child_elements()` pagination works correctly with more child elements

### Unit Tests

- Test `_extract_child_elements()` with a catalog containing group-nested controls
- Test with doubly-nested groups (`groups[].groups[].controls[]`)
- Test with mixed top-level and nested controls
- Test with empty groups (no controls inside)
- Test end-to-end: `list_catalog_controls()` returns nested controls after fix

### Property-Based Tests

- Generate random catalog structures with varying nesting depths and verify all controls are extracted
- Generate catalogs with only top-level controls and verify output matches unfixed behavior
- Generate non-catalog models and verify output is unchanged

### Integration Tests

- Rebuild bundled database and verify `list_catalog_controls()` returns controls from AWS Security Hub catalog
- Verify `text_search_oscal("CloudTrail.1")` finds the control after rebuild
- Verify `get_child_element("CloudTrail.1")` returns the control after rebuild
