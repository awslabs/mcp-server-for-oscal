# Bugfix Requirements Document

## Introduction

Any element with an ID present in an OSCAL document should be indexed such that a query for it returns the identified object. Currently, the `_extract_child_elements()` method in `OscalStore` only extracts top-level children from each OSCAL model type but does not recurse into nested structures. The most impactful instance of this is OSCAL catalogs: the method extracts top-level controls (`catalog.controls[]`) and groups (`catalog.groups[]`), but does not recurse into groups to extract their nested controls (`catalog.groups[].controls[]`) or nested groups (`catalog.groups[].groups[]`).

Since OSCAL catalogs commonly organize controls inside groups (e.g., the AWS Security Hub catalog nests all controls under groups like "CloudTrail", "S3", etc.), this means `list_catalog_controls()` returns 0 controls, `text_search_oscal()` cannot find them, and `get_child_element()` cannot retrieve them by ID. Users must fetch the parent group and manually parse raw JSON to locate nested controls.

OSCAL groups can be nested recursively (groups within groups), and controls can exist at any level of this hierarchy. The fix must handle arbitrary nesting depth. The guiding principle is: if an element has an ID in the OSCAL document, it should be individually queryable.

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN a catalog contains controls nested inside groups (e.g., `catalog.groups[].controls[]`) THEN the system does not extract those controls into the `child_elements` table or the `fts_index` FTS5 table during indexing

1.2 WHEN a user calls `list_catalog_controls()` on a catalog whose controls are all nested inside groups THEN the system returns 0 controls (empty result set)

1.3 WHEN a user calls `text_search_oscal()` with a query matching a group-nested control's title or ID (e.g., "CloudTrail.1") THEN the system returns no results

1.4 WHEN a user calls `get_child_element()` with the ID of a group-nested control THEN the system returns `None` (element not found)

1.5 WHEN a catalog contains controls nested inside recursively nested groups (e.g., `catalog.groups[].groups[].controls[]`) THEN the system does not extract those deeply nested controls

### Expected Behavior (Correct)

2.1 WHEN a catalog contains controls nested inside groups THEN the system SHALL extract those controls into the `child_elements` table and `fts_index` during indexing, making them individually queryable

2.2 WHEN a user calls `list_catalog_controls()` on a catalog whose controls are nested inside groups THEN the system SHALL return all nested controls in the paginated result set

2.3 WHEN a user calls `text_search_oscal()` with a query matching a group-nested control's title or ID THEN the system SHALL return matching results

2.4 WHEN a user calls `get_child_element()` with the ID of a group-nested control THEN the system SHALL return the full element dict including `raw_json`

2.5 WHEN a catalog contains controls nested inside recursively nested groups at any depth THEN the system SHALL extract all controls at every nesting level

### Unchanged Behavior (Regression Prevention)

3.1 WHEN a catalog contains top-level controls (not inside groups) THEN the system SHALL CONTINUE TO extract and index those controls correctly

3.2 WHEN a catalog contains groups THEN the system SHALL CONTINUE TO extract and index those groups correctly

3.3 WHEN a component definition, profile, SSP, or other non-catalog OSCAL model is indexed THEN the system SHALL CONTINUE TO extract child elements using the existing logic without any changes

3.4 WHEN `list_catalog_controls()` is called with pagination parameters THEN the system SHALL CONTINUE TO return correctly paginated results

3.5 WHEN `get_child_element()` is called for a non-existent element ID THEN the system SHALL CONTINUE TO return `None`
