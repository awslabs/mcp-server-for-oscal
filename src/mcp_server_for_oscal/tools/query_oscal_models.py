"""
MCP tools for querying all OSCAL model types via the OscalStore.

Each OSCAL model type gets a query/list tool pair that delegates to the
OscalStore singleton.  A cross-model ``text_search_oscal`` tool is also
provided for FTS5 full-text search.

These tools are NOT registered in ``__init__.py`` yet — see task 6.3.
"""

import logging
from typing import Literal

from mcp.server.fastmcp.server import Context
from strands import tool

from mcp_server_for_oscal.tools.oscal_store import OscalStore
from mcp_server_for_oscal.tools.utils import OSCALModelType

logger = logging.getLogger(__name__)

# Module-level singleton — initialised lazily by ``init_store()``.
_store: OscalStore | None = None


def init_store(store: OscalStore) -> None:
    """Set the module-level OscalStore singleton.

    Called during server startup (task 6.3) after the store has been
    initialised and directories have been scanned.
    """
    global _store  # noqa: PLW0603
    _store = store


def _get_store() -> OscalStore:
    """Return the module-level store, raising if not yet initialised."""
    if _store is None:
        raise RuntimeError(
            "OscalStore has not been initialised. "
            "Call init_store() during server startup."
        )
    return _store


# ------------------------------------------------------------------
# Catalog tools
# ------------------------------------------------------------------

@tool()
def query_catalog(
    ctx: Context | None = None,
    query_type: Literal["all", "by_uuid", "by_title", "by_type"] = "all",
    query_value: str | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """Query OSCAL Catalog documents.

    Catalogs are structured collections of security controls and control
    enhancements.  Use ``list_catalogs`` to discover available catalogs,
    then drill into specific ones with this tool.

    Args:
        ctx: MCP server context (injected automatically).
        query_type: ``"all"`` (paginated), ``"by_uuid"``, ``"by_title"``,
            or ``"by_type"``.
        query_value: Required for by_uuid, by_title, by_type queries.
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
    """
    return _get_store().query(
        ctx=ctx,
        oscal_model_type=OSCALModelType.CATALOG,
        query_type=query_type,
        query_value=query_value,
        offset=offset,
        limit=limit,
    )


@tool()
def list_catalogs(
    ctx: Context | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """List loaded OSCAL Catalogs with summary metadata.

    Returns UUID, title, model type, child count, and size for each
    catalog.  Use the returned UUIDs or titles as ``query_value`` in
    ``query_catalog`` for detailed results.

    Args:
        ctx: MCP server context (injected automatically).
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
    """
    return _get_store().list_documents(
        ctx=ctx,
        oscal_model_type=OSCALModelType.CATALOG,
        offset=offset,
        limit=limit,
    )


# ------------------------------------------------------------------
# SSP tools
# ------------------------------------------------------------------

@tool()
def query_ssp(
    ctx: Context | None = None,
    query_type: Literal["all", "by_uuid", "by_title", "by_type"] = "all",
    query_value: str | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """Query OSCAL System Security Plan (SSP) documents.

    SSPs document how a system implements required security controls.

    Args:
        ctx: MCP server context (injected automatically).
        query_type: ``"all"`` (paginated), ``"by_uuid"``, ``"by_title"``,
            or ``"by_type"``.
        query_value: Required for by_uuid, by_title, by_type queries.
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
    """
    return _get_store().query(
        ctx=ctx,
        oscal_model_type=OSCALModelType.SYSTEM_SECURITY_PLAN,
        query_type=query_type,
        query_value=query_value,
        offset=offset,
        limit=limit,
    )



@tool()
def list_ssps(
    ctx: Context | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """List loaded OSCAL System Security Plans with summary metadata.

    Args:
        ctx: MCP server context (injected automatically).
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
    """
    return _get_store().list_documents(
        ctx=ctx,
        oscal_model_type=OSCALModelType.SYSTEM_SECURITY_PLAN,
        offset=offset,
        limit=limit,
    )


# ------------------------------------------------------------------
# Profile tools
# ------------------------------------------------------------------

@tool()
def query_profile(
    ctx: Context | None = None,
    query_type: Literal["all", "by_uuid", "by_title", "by_type"] = "all",
    query_value: str | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """Query OSCAL Profile documents.

    Profiles are baselines or overlays that select and customise controls
    from one or more catalogs.

    Args:
        ctx: MCP server context (injected automatically).
        query_type: ``"all"`` (paginated), ``"by_uuid"``, ``"by_title"``,
            or ``"by_type"``.
        query_value: Required for by_uuid, by_title, by_type queries.
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
    """
    return _get_store().query(
        ctx=ctx,
        oscal_model_type=OSCALModelType.PROFILE,
        query_type=query_type,
        query_value=query_value,
        offset=offset,
        limit=limit,
    )


@tool()
def list_profiles(
    ctx: Context | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """List loaded OSCAL Profiles with summary metadata.

    Args:
        ctx: MCP server context (injected automatically).
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
    """
    return _get_store().list_documents(
        ctx=ctx,
        oscal_model_type=OSCALModelType.PROFILE,
        offset=offset,
        limit=limit,
    )


# ------------------------------------------------------------------
# Assessment Plan tools
# ------------------------------------------------------------------

@tool()
def query_assessment_plan(
    ctx: Context | None = None,
    query_type: Literal["all", "by_uuid", "by_title", "by_type"] = "all",
    query_value: str | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """Query OSCAL Assessment Plan documents.

    Assessment Plans define how security controls will be assessed.

    Args:
        ctx: MCP server context (injected automatically).
        query_type: ``"all"`` (paginated), ``"by_uuid"``, ``"by_title"``,
            or ``"by_type"``.
        query_value: Required for by_uuid, by_title, by_type queries.
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
    """
    return _get_store().query(
        ctx=ctx,
        oscal_model_type=OSCALModelType.ASSESSMENT_PLAN,
        query_type=query_type,
        query_value=query_value,
        offset=offset,
        limit=limit,
    )


@tool()
def list_assessment_plans(
    ctx: Context | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """List loaded OSCAL Assessment Plans with summary metadata.

    Args:
        ctx: MCP server context (injected automatically).
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
    """
    return _get_store().list_documents(
        ctx=ctx,
        oscal_model_type=OSCALModelType.ASSESSMENT_PLAN,
        offset=offset,
        limit=limit,
    )


# ------------------------------------------------------------------
# Assessment Results tools
# ------------------------------------------------------------------

@tool()
def query_assessment_results(
    ctx: Context | None = None,
    query_type: Literal["all", "by_uuid", "by_title", "by_type"] = "all",
    query_value: str | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """Query OSCAL Assessment Results documents.

    Assessment Results document the outcomes of control assessments.

    Args:
        ctx: MCP server context (injected automatically).
        query_type: ``"all"`` (paginated), ``"by_uuid"``, ``"by_title"``,
            or ``"by_type"``.
        query_value: Required for by_uuid, by_title, by_type queries.
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
    """
    return _get_store().query(
        ctx=ctx,
        oscal_model_type=OSCALModelType.ASSESSMENT_RESULTS,
        query_type=query_type,
        query_value=query_value,
        offset=offset,
        limit=limit,
    )


@tool()
def list_assessment_results(
    ctx: Context | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """List loaded OSCAL Assessment Results with summary metadata.

    Args:
        ctx: MCP server context (injected automatically).
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
    """
    return _get_store().list_documents(
        ctx=ctx,
        oscal_model_type=OSCALModelType.ASSESSMENT_RESULTS,
        offset=offset,
        limit=limit,
    )


# ------------------------------------------------------------------
# POA&M tools
# ------------------------------------------------------------------

@tool()
def query_poam(
    ctx: Context | None = None,
    query_type: Literal["all", "by_uuid", "by_title", "by_type"] = "all",
    query_value: str | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """Query OSCAL Plan of Action and Milestones (POA&M) documents.

    POA&Ms document remediation plans for identified security issues.

    Args:
        ctx: MCP server context (injected automatically).
        query_type: ``"all"`` (paginated), ``"by_uuid"``, ``"by_title"``,
            or ``"by_type"``.
        query_value: Required for by_uuid, by_title, by_type queries.
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
    """
    return _get_store().query(
        ctx=ctx,
        oscal_model_type=OSCALModelType.PLAN_OF_ACTION_AND_MILESTONES,
        query_type=query_type,
        query_value=query_value,
        offset=offset,
        limit=limit,
    )


@tool()
def list_poams(
    ctx: Context | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """List loaded OSCAL Plans of Action and Milestones with summary metadata.

    Args:
        ctx: MCP server context (injected automatically).
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
    """
    return _get_store().list_documents(
        ctx=ctx,
        oscal_model_type=OSCALModelType.PLAN_OF_ACTION_AND_MILESTONES,
        offset=offset,
        limit=limit,
    )


# ------------------------------------------------------------------
# Mapping Collection tools
# ------------------------------------------------------------------

@tool()
def query_mapping_collection(
    ctx: Context | None = None,
    query_type: Literal["all", "by_uuid", "by_title", "by_type"] = "all",
    query_value: str | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """Query OSCAL Mapping Collection documents.

    Mapping Collections describe how one set of security controls relates
    to another set of controls.

    Args:
        ctx: MCP server context (injected automatically).
        query_type: ``"all"`` (paginated), ``"by_uuid"``, ``"by_title"``,
            or ``"by_type"``.
        query_value: Required for by_uuid, by_title, by_type queries.
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
    """
    return _get_store().query(
        ctx=ctx,
        oscal_model_type=OSCALModelType.MAPPING,
        query_type=query_type,
        query_value=query_value,
        offset=offset,
        limit=limit,
    )


@tool()
def list_mapping_collections(
    ctx: Context | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """List loaded OSCAL Mapping Collections with summary metadata.

    Args:
        ctx: MCP server context (injected automatically).
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
    """
    return _get_store().list_documents(
        ctx=ctx,
        oscal_model_type=OSCALModelType.MAPPING,
        offset=offset,
        limit=limit,
    )


# ------------------------------------------------------------------
# Cross-model text search
# ------------------------------------------------------------------

@tool()
def text_search_oscal(
    ctx: Context | None = None,
    query_text: str = "",
    oscal_model_type: str | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """Full-text search across all OSCAL documents and child elements.

    Searches titles, descriptions, and other indexed text fields using
    SQLite FTS5.  Results are ranked by relevance.  Optionally scope the
    search to a single OSCAL model type.

    Args:
        ctx: MCP server context (injected automatically).
        query_text: The search string.
        oscal_model_type: Optional model type value to scope results
            (e.g. ``"catalog"``, ``"system-security-plan"``).  When
            omitted, all model types are searched.
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
        Each item contains: entity_type, entity_id, title, description,
        model_type.
    """
    model_type_enum: OSCALModelType | None = None
    if oscal_model_type:
        try:
            model_type_enum = OSCALModelType(oscal_model_type)
        except ValueError:
            logger.warning(
                "Unknown oscal_model_type '%s'; searching all types",
                oscal_model_type,
            )

    return _get_store().text_search(
        query_text=query_text,
        oscal_model_type=model_type_enum,
        offset=offset,
        limit=limit,
    )


# ------------------------------------------------------------------
# Catalog child element tools
# ------------------------------------------------------------------


@tool()
def list_catalog_controls(
    ctx: Context | None = None,
    parent_doc_uuid: str | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """List controls within OSCAL Catalog documents.

    Controls are the primary structural elements of a catalog, each
    identified by a human-readable token ID (e.g. ``ac-1``, ``sc-7``).

    Args:
        ctx: MCP server context (injected automatically).
        parent_doc_uuid: Optional UUID to scope results to a single catalog.
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
        Each item contains: id, title, element_type, description,
        parentDocumentTitle, parentDocumentUuid.
    """
    return _get_store().list_child_elements(
        ctx=ctx,
        parent_doc_uuid=parent_doc_uuid,
        element_type="control",
        offset=offset,
        limit=limit,
    )


@tool()
def list_catalog_groups(
    ctx: Context | None = None,
    parent_doc_uuid: str | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """List groups within OSCAL Catalog documents.

    Groups organise controls into families (e.g. ``ac`` for Access
    Control).  Group IDs are human-readable tokens unique within the
    containing catalog.

    Args:
        ctx: MCP server context (injected automatically).
        parent_doc_uuid: Optional UUID to scope results to a single catalog.
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
        Each item contains: id, title, element_type, description,
        parentDocumentTitle, parentDocumentUuid.
    """
    return _get_store().list_child_elements(
        ctx=ctx,
        parent_doc_uuid=parent_doc_uuid,
        element_type="group",
        offset=offset,
        limit=limit,
    )


# ------------------------------------------------------------------
# SSP child element tools
# ------------------------------------------------------------------


@tool()
def list_ssp_control_implementations(
    ctx: Context | None = None,
    parent_doc_uuid: str | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """List control-implementation elements within OSCAL SSP documents.

    The control-implementation is a singleton element within each SSP
    that describes how the system implements required security controls.

    Args:
        ctx: MCP server context (injected automatically).
        parent_doc_uuid: Optional UUID to scope results to a single SSP.
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
        Each item contains: id, title, element_type, description,
        parentDocumentTitle, parentDocumentUuid.
    """
    return _get_store().list_child_elements(
        ctx=ctx,
        parent_doc_uuid=parent_doc_uuid,
        element_type="control-implementation",
        offset=offset,
        limit=limit,
    )


@tool()
def list_ssp_system_components(
    ctx: Context | None = None,
    parent_doc_uuid: str | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """List system-component elements within OSCAL SSP documents.

    System components describe the individual parts of a system (e.g.
    servers, services, software) and are identified by UUID.

    Args:
        ctx: MCP server context (injected automatically).
        parent_doc_uuid: Optional UUID to scope results to a single SSP.
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
        Each item contains: id, title, element_type, description,
        parentDocumentTitle, parentDocumentUuid.
    """
    return _get_store().list_child_elements(
        ctx=ctx,
        parent_doc_uuid=parent_doc_uuid,
        element_type="system-component",
        offset=offset,
        limit=limit,
    )


# ------------------------------------------------------------------
# Profile child element tools
# ------------------------------------------------------------------


@tool()
def list_profile_imports(
    ctx: Context | None = None,
    parent_doc_uuid: str | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """List import elements within OSCAL Profile documents.

    Imports reference the catalogs or profiles from which controls are
    selected.  Import IDs are synthetic positional identifiers
    (e.g. ``import-0``, ``import-1``).

    Args:
        ctx: MCP server context (injected automatically).
        parent_doc_uuid: Optional UUID to scope results to a single profile.
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
        Each item contains: id, title, element_type, description,
        parentDocumentTitle, parentDocumentUuid.
    """
    return _get_store().list_child_elements(
        ctx=ctx,
        parent_doc_uuid=parent_doc_uuid,
        element_type="import",
        offset=offset,
        limit=limit,
    )


@tool()
def list_profile_modify(
    ctx: Context | None = None,
    parent_doc_uuid: str | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """List modify elements within OSCAL Profile documents.

    The modify element is a singleton within each profile that describes
    customisations applied to imported controls (e.g. parameter settings,
    additions, alterations).

    Args:
        ctx: MCP server context (injected automatically).
        parent_doc_uuid: Optional UUID to scope results to a single profile.
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
        Each item contains: id, title, element_type, description,
        parentDocumentTitle, parentDocumentUuid.
    """
    return _get_store().list_child_elements(
        ctx=ctx,
        parent_doc_uuid=parent_doc_uuid,
        element_type="modify",
        offset=offset,
        limit=limit,
    )


# ------------------------------------------------------------------
# Assessment Plan child element tools
# ------------------------------------------------------------------


@tool()
def list_assessment_plan_tasks(
    ctx: Context | None = None,
    parent_doc_uuid: str | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """List task elements within OSCAL Assessment Plan documents.

    Tasks define the specific assessment activities to be performed.
    Each task is identified by a UUID.

    Args:
        ctx: MCP server context (injected automatically).
        parent_doc_uuid: Optional UUID to scope results to a single
            assessment plan.
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
        Each item contains: id, title, element_type, description,
        parentDocumentTitle, parentDocumentUuid.
    """
    return _get_store().list_child_elements(
        ctx=ctx,
        parent_doc_uuid=parent_doc_uuid,
        element_type="task",
        offset=offset,
        limit=limit,
    )


@tool()
def list_assessment_plan_activities(
    ctx: Context | None = None,
    parent_doc_uuid: str | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """List activity elements within OSCAL Assessment Plan documents.

    Activities describe the methods and procedures used to assess
    controls.  Each activity is identified by a UUID.

    Args:
        ctx: MCP server context (injected automatically).
        parent_doc_uuid: Optional UUID to scope results to a single
            assessment plan.
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
        Each item contains: id, title, element_type, description,
        parentDocumentTitle, parentDocumentUuid.
    """
    return _get_store().list_child_elements(
        ctx=ctx,
        parent_doc_uuid=parent_doc_uuid,
        element_type="activity",
        offset=offset,
        limit=limit,
    )


# ------------------------------------------------------------------
# Assessment Results child element tools
# ------------------------------------------------------------------


@tool()
def list_assessment_results_results(
    ctx: Context | None = None,
    parent_doc_uuid: str | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """List result elements within OSCAL Assessment Results documents.

    Results capture the outcome of an assessment, including observations
    and risk determinations.  Each result is identified by a UUID.

    Args:
        ctx: MCP server context (injected automatically).
        parent_doc_uuid: Optional UUID to scope results to a single
            assessment results document.
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
        Each item contains: id, title, element_type, description,
        parentDocumentTitle, parentDocumentUuid.
    """
    return _get_store().list_child_elements(
        ctx=ctx,
        parent_doc_uuid=parent_doc_uuid,
        element_type="result",
        offset=offset,
        limit=limit,
    )


@tool()
def list_assessment_results_findings(
    ctx: Context | None = None,
    parent_doc_uuid: str | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """List finding elements within OSCAL Assessment Results documents.

    Findings document specific determinations about control
    implementation status.  Each finding is identified by a UUID.

    Args:
        ctx: MCP server context (injected automatically).
        parent_doc_uuid: Optional UUID to scope results to a single
            assessment results document.
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
        Each item contains: id, title, element_type, description,
        parentDocumentTitle, parentDocumentUuid.
    """
    return _get_store().list_child_elements(
        ctx=ctx,
        parent_doc_uuid=parent_doc_uuid,
        element_type="finding",
        offset=offset,
        limit=limit,
    )


# ------------------------------------------------------------------
# POA&M child element tools
# ------------------------------------------------------------------


@tool()
def list_poam_items(
    ctx: Context | None = None,
    parent_doc_uuid: str | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """List POA&M item elements within OSCAL POA&M documents.

    POA&M items document specific security issues and their remediation
    plans.  Each item is identified by a UUID (optional in the OSCAL
    schema).

    Args:
        ctx: MCP server context (injected automatically).
        parent_doc_uuid: Optional UUID to scope results to a single
            POA&M document.
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
        Each item contains: id, title, element_type, description,
        parentDocumentTitle, parentDocumentUuid.
    """
    return _get_store().list_child_elements(
        ctx=ctx,
        parent_doc_uuid=parent_doc_uuid,
        element_type="poam-item",
        offset=offset,
        limit=limit,
    )


# ------------------------------------------------------------------
# Mapping Collection child element tools
# ------------------------------------------------------------------


@tool()
def list_mapping_collection_mappings(
    ctx: Context | None = None,
    parent_doc_uuid: str | None = None,
    offset: int = 0,
    limit: int = 10,
) -> dict:
    """List mapping elements within OSCAL Mapping Collection documents.

    Mappings describe how controls from one framework relate to controls
    in another framework.  Each mapping is identified by a UUID.

    Args:
        ctx: MCP server context (injected automatically).
        parent_doc_uuid: Optional UUID to scope results to a single
            mapping collection document.
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        Page_Response dict with keys: items, total, offset, limit, hasMore.
        Each item contains: id, title, element_type, description,
        parentDocumentTitle, parentDocumentUuid.
    """
    return _get_store().list_child_elements(
        ctx=ctx,
        parent_doc_uuid=parent_doc_uuid,
        element_type="mapping",
        offset=offset,
        limit=limit,
    )

# ------------------------------------------------------------------
# Get child element by ID (cross-model)
# ------------------------------------------------------------------


@tool()
def get_child_element(
    ctx: Context | None = None,
    element_id: str = "",
    parent_doc_uuid: str | None = None,
) -> dict | None:
    """Retrieve a single child element by its identifier.

    OSCAL uses two identifier schemes:
    - UUIDs (globally unique) for most elements such as tasks,
      activities, results, findings, POA&M items, mappings, and
      system-components.
    - Token IDs (e.g. ``ac-1``, ``sc``) for catalog controls and
      groups — these are human-readable but only unique within their
      containing document.

    For elements with token-based IDs, ``parent_doc_uuid`` should be
    provided to disambiguate.  For elements with UUIDs,
    ``parent_doc_uuid`` is optional.

    If ``parent_doc_uuid`` is omitted and the ``element_id`` matches
    elements in more than one document, an error dict is returned with
    ``error: "ambiguous_element_id"`` and a list of matching parent
    document UUIDs so the caller can retry with disambiguation.

    Args:
        ctx: MCP server context (injected automatically).
        element_id: The element identifier (UUID or token ID).
        parent_doc_uuid: Optional parent document UUID to scope the
            lookup using the composite key (element_id, parent_doc_uuid).

    Returns:
        A dict with keys: id, title, element_type, description,
        parentDocumentTitle, parentDocumentUuid, raw_json — or None if
        not found.  Returns an error dict if the element_id is ambiguous
        across documents.
    """
    return _get_store().get_child_element(
        element_id=element_id,
        parent_doc_uuid=parent_doc_uuid,
    )
