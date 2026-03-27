# Design Document: query-cdef-pagination

## Overview

This feature adds offset/limit pagination to `query_component_definition()` and its internal helper `_oscal_store_query_component_definition()`, matching the pattern already used by peer functions like `query_catalog()`. The existing `paginate()` helper from `utils.py` is reused. Capability responses are wrapped in a Page_Response-like envelope for consistency.

### Design Decisions

1. **Reuse `paginate()` from `utils.py`** — The helper already handles slicing, validation, and metadata. No new pagination logic needed.
2. **Pagination at the tool wrapper layer** — `ComponentDefinitionStore.query()` is not modified. Pagination is applied post-query to the `components` list in the response dict.
3. **Capability wrapping** — Capability results are a single-item response. They get `offset=0, limit=1, total=1, hasMore=False` metadata added to the existing response dict for a consistent shape.
4. **Both code paths** — Both the OscalStore path and the legacy path apply pagination to component results.
5. **Empty/error responses** — Empty component results (`components: [], total_count: 0`) get pagination metadata added (`offset`, `limit`, `total: 0`, `hasMore: False`). Error paths (ValueError, missing data) remain unchanged.

## Architecture

```
query_component_definition(ctx, ..., offset, limit)
├── _oscal_store is not None → _oscal_store_query_component_definition(ctx, ..., offset, limit)
│   ├── Capability match → add pagination envelope (offset=0, limit=1, total=1, hasMore=False)
│   └── Component fallback → _store.query(...) → apply paginate() to result["components"]
└── _oscal_store is None → _store.query(...)  → apply paginate() to result["components"]
```

## Changes

### 1. `query_component_definition()` — add parameters, thread through

```python
def query_component_definition(
    ctx: Context | None = None,
    component_definition_filter: str | None = None,
    query_type: Literal["all", "by_uuid", "by_title", "by_type"] = "all",
    query_value: str | None = None,
    return_format: Literal["raw"] = "raw",
    offset: int = 0,
    limit: int = 10,
) -> dict[str, Any]:
```

For the legacy path, call `_store.query()` as before, then apply `_paginate_component_response(result, offset, limit)`.

For the OscalStore path, pass `offset` and `limit` through to `_oscal_store_query_component_definition()`.

### 2. `_oscal_store_query_component_definition()` — add parameters, apply pagination

```python
def _oscal_store_query_component_definition(
    ctx, component_definition_filter, query_type, query_value, return_format,
    offset: int = 0, limit: int = 10,
) -> dict[str, Any]:
```

- Capability match: add `offset=0, limit=1, total=1, hasMore=False` to the response dict.
- Component fallback via `_store.query()`: apply `_paginate_component_response(result, offset, limit)`.

### 3. `_paginate_component_response()` — new private helper

A small helper that takes a component response dict (with `components` and `total_count` keys) and applies `paginate()` to the `components` list, merging the pagination metadata back into the response:

```python
def _paginate_component_response(
    result: dict[str, Any], offset: int, limit: int
) -> dict[str, Any]:
    components = result.get("components", [])
    page = paginate(components, offset, limit)
    result["components"] = page["items"]
    result["total_count"] = page["total"]
    result["offset"] = page["offset"]
    result["limit"] = page["limit"]
    result["hasMore"] = page["hasMore"]
    return result
```

### 4. Capability response wrapping

When a capability is found (in either the legacy `_store.query()` path or the `_oscal_store_query_component_definition()` path), add pagination metadata:

```python
result["offset"] = 0
result["limit"] = 1
result["total"] = 1
result["hasMore"] = False
```

For the legacy path, this means modifying the capability return in `ComponentDefinitionStore.query()` — but since we're not modifying the store, we apply this wrapping in `query_component_definition()` after receiving the result. We detect a capability response by checking for the `"capability"` key.

## Data Models

### Paginated Component_Response (augmented)

| Key | Type | Description |
|---|---|---|
| `components` | `list[dict]` | Paginated slice of component dicts |
| `total_count` | `int` | Total matching components across all pages |
| `offset` | `int` | The offset used |
| `limit` | `int` | The limit used |
| `hasMore` | `bool` | True iff more pages exist |
| `query_type` | `str` | The query type used |
| `component_definitions_searched` | `int` | Number of cdefs searched |
| `filtered_by` | `str \| None` | The filter value used |

### Wrapped Capability_Response (augmented)

| Key | Type | Description |
|---|---|---|
| `capability` | `dict` | Full OSCAL Capability object |
| `component_count` | `int` | Number of incorporated components |
| `offset` | `int` | Always 0 |
| `limit` | `int` | Always 1 |
| `total` | `int` | Always 1 |
| `hasMore` | `bool` | Always False |
| `query_type` | `str` | The query type used |
| `component_definitions_searched` | `int` | Number of cdefs searched |
| `filtered_by` | `str \| None` | The filter value used |

## Error Handling

No changes to error handling. Existing `ValueError` and `RuntimeError` paths remain unchanged. `paginate()` validation (negative offset, out-of-range limit) propagates naturally.

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do.*

Since `paginate()` is already thoroughly property-tested (6 properties in the list-tools-pagination spec), the unique correctness concern here is the wiring: does `query_component_definition` correctly apply pagination to its component results?

### Property 1: Component pagination slice correctness

*For any* set of matching components returned by the underlying store query, and *for any* valid offset (≥ 0) and limit (1–100), the `components` list in the paginated response from `query_component_definition` SHALL be equal to the full components list sliced as `full_list[offset:offset+limit]`, and `total_count` SHALL equal the length of the full list.

**Validates: Requirements 2.1, 2.2, 2.3, 2.4, 3.1, 3.2, 3.3, 3.4**

### Property 2: Capability response always includes pagination envelope

*For any* capability result returned by `query_component_definition`, the response SHALL contain `offset` equal to 0, `limit` equal to 1, `total` equal to 1, and `hasMore` equal to False, alongside the existing `capability` and `component_count` fields.

**Validates: Requirements 4.1, 4.2, 4.3**

## Testing Strategy

### Property-based tests (hypothesis)

- **Property 1** is tested by mocking `_store.query()` to return a component response with a generated list of components, then calling `query_component_definition()` with random valid offset/limit and verifying the slice.
- **Property 2** is an example-based test (capability is a single result, not a range of inputs).

### Unit tests (pytest)

1. Default pagination parameters (offset=0, limit=10) when called without explicit params
2. Explicit offset/limit threading through both code paths
3. Capability response wrapping with pagination metadata
4. Empty results include pagination metadata
5. Existing tests updated to expect pagination metadata in component responses
